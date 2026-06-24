//! Peer connection abstraction and its WebSocket implementation.
//!
//! A [`P2PConnection`] is the switch's handle to one peer: it carries the
//! (eventually greeted) peer identity and the means to send a frame.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use keetanetwork_client::WsConnection;

use crate::peer::P2PPeer;

/// The switch's handle to a single peer.
#[async_trait]
pub trait P2PConnection: Send + Sync {
	/// A stable string identifying this connection.
	fn conn_string(&self) -> String;
	/// The greeted peer identity, once known.
	fn peer(&self) -> Option<P2PPeer>;
	/// Record the peer identity learned from a greeting.
	fn set_peer(&self, peer: P2PPeer);
	/// Whether the connection has failed or been closed.
	fn is_aborted(&self) -> bool;
	/// Send a frame, returning `false` on failure.
	async fn send(&self, data: &str) -> bool;
	/// Close the connection.
	async fn close(&self);
}

/// A [`P2PConnection`] over a [`WsConnection`].
pub struct P2PWebSocket {
	socket: Arc<dyn WsConnection>,
	conn_string: String,
	peer: Mutex<Option<P2PPeer>>,
	aborted: AtomicBool,
}

impl P2PWebSocket {
	/// Wrap `socket`, identified by `conn_string`.
	pub fn new(socket: Arc<dyn WsConnection>, conn_string: impl Into<String>) -> Arc<Self> {
		Arc::new(Self {
			socket,
			conn_string: conn_string.into(),
			peer: Mutex::new(None),
			aborted: AtomicBool::new(false),
		})
	}

	/// The underlying socket, so the switch can drive the read loop.
	pub(crate) fn socket(&self) -> Arc<dyn WsConnection> {
		Arc::clone(&self.socket)
	}
}

#[async_trait]
impl P2PConnection for P2PWebSocket {
	fn conn_string(&self) -> String {
		self.conn_string.clone()
	}

	fn peer(&self) -> Option<P2PPeer> {
		self.peer.lock().ok().and_then(|peer| peer.clone())
	}

	fn set_peer(&self, peer: P2PPeer) {
		if let Ok(mut slot) = self.peer.lock() {
			*slot = Some(peer);
		}
	}

	fn is_aborted(&self) -> bool {
		self.aborted.load(Ordering::Relaxed)
	}

	async fn send(&self, data: &str) -> bool {
		match self.socket.send_text(data).await {
			Ok(()) => true,
			Err(_) => {
				self.aborted.store(true, Ordering::Relaxed);
				false
			}
		}
	}

	async fn close(&self) {
		self.aborted.store(true, Ordering::Relaxed);
		self.socket.close().await;
	}
}
