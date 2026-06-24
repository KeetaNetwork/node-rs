//! The peer-to-peer switch: coordinates messages between connected peers

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use keetanetwork_client::{Runtime, TaskHandle, WsConnection, WsMessage};
use rand::seq::SliceRandom;
use serde_json::Value;

use crate::connection::{P2PConnection, P2PWebSocket};
use crate::kv::KvStore;
use crate::message::P2PMessage;
use crate::node::NodeLike;
use crate::peer::P2PPeer;

/// The KV namespace claimed for message de-duplication.
const SEEN_NAMESPACE: &str = "seenMessageIDs";
/// The message type carrying a peer greeting.
const GREETING_KIND: &str = "greeting";
/// The message type that is rebroadcast across the mesh rather than delivered
/// to the node.
const TEST_KIND: &str = "test";

/// Tunables for the switch.
#[derive(Clone, Copy, Debug)]
pub struct P2PConfig {
	/// How long a seen message id is remembered, in milliseconds.
	pub seen_message_ttl_ms: i64,
	/// How many peers a rebroadcast samples (forwarding fan-out).
	pub forwarding_peer_count: usize,
}

impl Default for P2PConfig {
	fn default() -> Self {
		Self { seen_message_ttl_ms: 60_000, forwarding_peer_count: 16 }
	}
}

/// Coordinates messages between connected peers on behalf of a [`NodeLike`].
pub struct P2PSwitch {
	node: Arc<dyn NodeLike>,
	kv: Arc<dyn KvStore>,
	runtime: Arc<dyn Runtime>,
	config: P2PConfig,
	/// This node's own identity, announced in greetings.
	local_peer: P2PPeer,
	connections: Mutex<Vec<Arc<dyn P2PConnection>>>,
	readers: Mutex<Vec<Box<dyn TaskHandle>>>,
	message_counter: AtomicU64,
}

impl P2PSwitch {
	/// Build a switch serving `node`, backed by `kv`, driven by `runtime`.
	/// `local_peer` is this node's identity, announced in greetings.
	pub fn new(
		node: Arc<dyn NodeLike>,
		kv: Arc<dyn KvStore>,
		runtime: Arc<dyn Runtime>,
		config: P2PConfig,
		local_peer: P2PPeer,
	) -> Arc<Self> {
		Arc::new(Self {
			node,
			kv,
			runtime,
			config,
			local_peer,
			connections: Mutex::new(Vec::new()),
			readers: Mutex::new(Vec::new()),
			message_counter: AtomicU64::new(0),
		})
	}

	/// The number of currently registered connections.
	pub fn connection_count(&self) -> usize {
		self.connections.lock().map(|connections| connections.len()).unwrap_or(0)
	}

	/// Register a WebSocket peer connection and start reading from it. The
	/// returned handle can be used to send directly to that peer.
	pub fn register_websocket(
		self: &Arc<Self>,
		socket: Arc<dyn WsConnection>,
		conn_string: impl Into<String>,
	) -> Arc<dyn P2PConnection> {
		let websocket = P2PWebSocket::new(socket, conn_string);
		let connection: Arc<dyn P2PConnection> = Arc::clone(&websocket) as Arc<dyn P2PConnection>;

		if let Ok(mut connections) = self.connections.lock() {
			connections.push(Arc::clone(&connection));
		}

		self.spawn_reader(websocket, Arc::clone(&connection));
		connection
	}

	/// Spawn the read loop that drains frames from one connection and feeds
	/// them to [`recv_message_from_peer`](Self::recv_message_from_peer).
	fn spawn_reader(self: &Arc<Self>, websocket: Arc<P2PWebSocket>, connection: Arc<dyn P2PConnection>) {
		let switch = Arc::clone(self);
		let socket = websocket.socket();
		let handle = self.runtime.spawn(Box::pin(async move {
			loop {
				let text = match socket.recv().await {
					Ok(Some(WsMessage::Text(text))) => text,
					Ok(Some(WsMessage::Binary(bytes))) => match String::from_utf8(bytes) {
						Ok(text) => text,
						Err(_) => continue,
					},
					Ok(None) | Err(_) => break,
				};
				switch.recv_message_from_peer(&connection, &text).await;
			}

			switch.remove_connection(connection.conn_string().as_str());
		}));

		if let Ok(mut readers) = self.readers.lock() {
			readers.push(handle);
		}
	}

	/// Drop a connection from the registry by its connection string.
	fn remove_connection(&self, conn_string: &str) {
		if let Ok(mut connections) = self.connections.lock() {
			connections.retain(|connection| connection.conn_string() != conn_string);
		}
	}

	/// Announce this node's identity to a freshly connected peer. The
	/// initiator of a connection calls this; the responder echoes its own
	/// greeting from [`recv_message_from_peer`](Self::recv_message_from_peer).
	pub async fn greet(self: &Arc<Self>, connection: &Arc<dyn P2PConnection>) {
		let frame = self.greeting_frame();
		let _ = connection.send(&frame).await;
	}

	/// Handle a raw frame from `connection`: parse, de-duplicate, complete the
	/// greeting handshake, and forward greeted peers' messages to the node.
	pub async fn recv_message_from_peer(self: &Arc<Self>, connection: &Arc<dyn P2PConnection>, text: &str) {
		let message = match P2PMessage::parse(text) {
			Ok(message) => message,
			Err(_) => {
				tracing::error!(target: "p2p::switch", "dropping malformed p2p message");
				return;
			}
		};

		if !self.claim_unseen(&message.id).await {
			return;
		}

		// First contact must be a greeting. An un-greeted peer learns our
		// identity and we record theirs; nothing is forwarded until greeted.
		if connection.peer().is_none() {
			if message.kind == GREETING_KIND {
				if let Some(peer) = P2PPeer::from_json(&message.data) {
					connection.set_peer(peer);
					self.greet(connection).await;
				}
			}

			return;
		}

		// Already greeted: ignore further greetings, rebroadcast `test`
		// messages across the mesh, and forward everything else to the node.
		if message.kind == GREETING_KIND {
			return;
		}

		if message.kind == TEST_KIND {
			self.rebroadcast(&message, &connection.conn_string()).await;
			return;
		}

		self.node.recv_message_from_peer(connection.as_ref(), &message).await;
	}

	/// Rebroadcast `message` to other greeted peers, one hop closer to its TTL
	/// limit. A message with no remaining TTL is dropped. The `source`
	/// connection is excluded so it does not receive its own message back; peers
	/// drop the duplicate by id if it reaches them another way.
	async fn rebroadcast(self: &Arc<Self>, message: &P2PMessage, source: &str) {
		let Some(ttl) = message.ttl else {
			return;
		};
		if ttl < 1 {
			return;
		}

		let forwarded = P2PMessage {
			id: message.id.clone(),
			kind: message.kind.clone(),
			data: message.data.clone(),
			ttl: Some(ttl - 1),
		};

		let frame = forwarded.encode();
		for connection in self.rebroadcast_targets(source) {
			let _ = connection.send(&frame).await;
		}
	}

	/// A shuffled sample of greeted peers eligible to receive a rebroadcast,
	/// capped at [`P2PConfig::forwarding_peer_count`]. Excludes the `source`
	/// connection and any aborted or un-greeted peers.
	fn rebroadcast_targets(&self, source: &str) -> Vec<Arc<dyn P2PConnection>> {
		let Ok(connections) = self.connections.lock() else {
			return Vec::new();
		};

		let mut eligible: Vec<Arc<dyn P2PConnection>> = connections
			.iter()
			.filter(|connection| {
				!connection.is_aborted() && connection.peer().is_some() && connection.conn_string() != source
			})
			.cloned()
			.collect();

		eligible.shuffle(&mut rand::rng());
		eligible.truncate(self.config.forwarding_peer_count);
		eligible
	}

	/// Emit a message to every connected peer except those in `exclude`.
	/// Returns the generated message id.
	pub async fn send_message(
		self: &Arc<Self>,
		kind: &str,
		data: Value,
		ttl: Option<u32>,
		exclude: &[String],
	) -> String {
		let id = self.next_message_id();
		let message = P2PMessage { id: id.clone(), kind: kind.to_owned(), data, ttl };

		// Record our own message as seen so an echo does not loop back in.
		let now = self.runtime.unix_millis();
		self.kv.set(SEEN_NAMESPACE, &id, Value::from(now), Some(self.config.seen_message_ttl_ms), now).await;

		let frame = message.encode();
		let targets = match self.connections.lock() {
			Ok(connections) => connections.clone(),
			Err(_) => return id,
		};

		for connection in targets {
			let conn_string = connection.conn_string();
			let is_excluded = exclude.iter().any(|excluded| excluded == &conn_string);
			if connection.is_aborted() || is_excluded {
				continue;
			}

			let _ = connection.send(&frame).await;
		}

		id
	}

	/// The greeting frame announcing this node's identity.
	fn greeting_frame(&self) -> String {
		let message = P2PMessage {
			id: self.next_message_id(),
			kind: GREETING_KIND.to_owned(),
			data: self.local_peer.to_json(),
			ttl: Some(0),
		};
		message.encode()
	}

	/// Claim a message id the first time it is seen. Returns `false` when the
	/// id was already recorded (a duplicate to drop).
	async fn claim_unseen(&self, id: &str) -> bool {
		let now = self.runtime.unix_millis();
		self.kv
			.set_exclusive(SEEN_NAMESPACE, id, Value::from(now), Some(self.config.seen_message_ttl_ms), now)
			.await
	}

	/// A process-unique message id from the clock and a counter.
	fn next_message_id(&self) -> String {
		let counter = self.message_counter.fetch_add(1, Ordering::Relaxed);
		let millis = self.runtime.unix_millis();
		format!("{millis:x}-{counter:x}")
	}
}

impl Drop for P2PSwitch {
	fn drop(&mut self) {
		if let Ok(readers) = self.readers.get_mut() {
			for handle in readers.iter() {
				handle.abort();
			}
		}
	}
}
