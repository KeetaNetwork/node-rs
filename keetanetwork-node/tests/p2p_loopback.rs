//! End-to-end P2P test: a message sent by one switch over a loopback
//! WebSocket is accepted by the inbound server and delivered to the peer
//! switch's node, exercising only public interfaces.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use keetanetwork_client::{TokioRuntime, WsConnection, WsConnector, WsMessage};
use keetanetwork_node::{bind, serve};
use keetanetwork_p2p::backends::TokioWsConnector;
use keetanetwork_p2p::{
	KvStore, MemoryKvStore, NodeLike, P2PConfig, P2PConnection, P2PMessage, P2PPeer, P2PSwitch,
};
use serde_json::Value;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::time::timeout;

/// A node that forwards every accepted message to a channel for assertions.
struct RecordingNode {
	sender: UnboundedSender<P2PMessage>,
}

#[async_trait]
impl NodeLike for RecordingNode {
	async fn recv_message_from_peer(&self, _connection: &dyn P2PConnection, message: &P2PMessage) {
		let _ = self.sender.send(message.clone());
	}
}

/// A node that ignores everything (used by the sending switch).
struct SilentNode;

#[async_trait]
impl NodeLike for SilentNode {
	async fn recv_message_from_peer(&self, _connection: &dyn P2PConnection, _message: &P2PMessage) {}
}

fn switch_with(node: Arc<dyn NodeLike>) -> Arc<P2PSwitch> {
	let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
	P2PSwitch::new(node, kv, Arc::new(TokioRuntime), P2PConfig::default(), P2PPeer::Participant)
}

/// Wait until `switch` has registered at least `count` connections.
async fn await_connections(switch: &Arc<P2PSwitch>, count: usize) {
	for _ in 0..50 {
		if switch.connection_count() >= count {
			return;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
}

/// The participant greeting frame a raw peer sends to complete the handshake.
fn participant_greeting() -> String {
	P2PMessage {
		id: "greet-raw-peer".to_owned(),
		kind: "greeting".to_owned(),
		data: P2PPeer::Participant.to_json(),
		ttl: Some(0),
	}
	.encode()
}

/// Read the next text frame from a raw socket, or `None` on timeout or close.
async fn read_text(socket: &Arc<dyn WsConnection>) -> Option<String> {
	match timeout(Duration::from_secs(2), socket.recv()).await {
		Ok(Ok(Some(WsMessage::Text(text)))) => Some(text),
		_ => None,
	}
}

#[tokio::test]
async fn message_traverses_loopback_websocket_to_peer_node() {
	let (sender, mut receiver) = unbounded_channel();
	let server_switch = switch_with(Arc::new(RecordingNode { sender }));

	let listener = bind("127.0.0.1:0").await.expect("listener must bind");
	let address = listener.local_addr().expect("listener must expose its address");
	tokio::spawn(serve(Arc::clone(&server_switch), listener));

	let client_switch = switch_with(Arc::new(SilentNode));
	let socket = TokioWsConnector
		.connect(&format!("ws://{address}"))
		.await
		.expect("client must dial the server");
	let connection = client_switch.register_websocket(socket, address.to_string());

	await_connections(&server_switch, 1).await;
	assert_eq!(server_switch.connection_count(), 1, "server must register the inbound peer");

	// Greet first: the server only forwards a peer's messages once greeted.
	client_switch.greet(&connection).await;
	client_switch
		.send_message("add", Value::from("hello"), Some(8), &[])
		.await;

	let delivered = timeout(Duration::from_secs(2), receiver.recv())
		.await
		.expect("a message must arrive before the timeout")
		.expect("the channel must yield the delivered message");
	assert_eq!(delivered.kind, "add", "the delivered message type must be preserved");
	assert_eq!(delivered.data, Value::from("hello"), "the delivered payload must be preserved");
	assert_eq!(delivered.ttl, Some(8), "the delivered ttl must be preserved");
}

#[tokio::test]
async fn duplicate_message_ids_are_dropped_once_seen() {
	let (sender, mut receiver) = unbounded_channel();
	let server_switch = switch_with(Arc::new(RecordingNode { sender }));

	let listener = bind("127.0.0.1:0").await.expect("listener must bind");
	let address = listener.local_addr().expect("listener must expose its address");
	tokio::spawn(serve(Arc::clone(&server_switch), listener));

	let client_switch = switch_with(Arc::new(SilentNode));
	let connection = {
		let socket = TokioWsConnector
			.connect(&format!("ws://{address}"))
			.await
			.expect("client must dial the server");
		client_switch.register_websocket(socket, address.to_string())
	};

	await_connections(&server_switch, 1).await;

	// Greet first: the server only forwards a peer's messages once greeted.
	client_switch.greet(&connection).await;

	// Send the same framed message twice; the switch must dedupe by id.
	let frame = P2PMessage {
		id: "dup-1".to_owned(),
		kind: "add".to_owned(),
		data: Value::from("once"),
		ttl: None,
	}
	.encode();
	assert!(connection.send(&frame).await, "first send must succeed");
	assert!(connection.send(&frame).await, "second send must succeed");

	let first = timeout(Duration::from_secs(2), receiver.recv())
		.await
		.expect("the first copy must arrive")
		.expect("channel must yield the first copy");
	assert_eq!(first.id, "dup-1", "the first copy must be delivered");

	let second = timeout(Duration::from_millis(300), receiver.recv()).await;
	assert!(second.is_err(), "the duplicate must be dropped, not delivered");
}

#[tokio::test]
async fn un_greeted_peer_messages_are_not_forwarded() {
	let (sender, mut receiver) = unbounded_channel();
	let server_switch = switch_with(Arc::new(RecordingNode { sender }));

	let listener = bind("127.0.0.1:0").await.expect("listener must bind");
	let address = listener.local_addr().expect("listener must expose its address");

	tokio::spawn(serve(Arc::clone(&server_switch), listener));

	let client_switch = switch_with(Arc::new(SilentNode));
	let socket = TokioWsConnector
		.connect(&format!("ws://{address}"))
		.await
		.expect("client must dial the server");
	let connection = client_switch.register_websocket(socket, address.to_string());

	await_connections(&server_switch, 1).await;

	// Send a message WITHOUT greeting first; the server must not forward it.
	let frame = P2PMessage {
		id: "ungreeted-1".to_owned(),
		kind: "add".to_owned(),
		data: Value::from("hello"),
		ttl: None,
	}
	.encode();
	assert!(connection.send(&frame).await, "send must succeed at the socket level");

	let delivered = timeout(Duration::from_millis(300), receiver.recv()).await;
	assert!(delivered.is_err(), "an un-greeted peer's message must not reach the node");
}

#[tokio::test]
async fn test_message_is_rebroadcast_to_other_greeted_peers() {
	let server_switch = switch_with(Arc::new(SilentNode));
	let listener = bind("127.0.0.1:0").await.expect("listener must bind");
	let address = listener.local_addr().expect("listener must expose its address");
	tokio::spawn(serve(Arc::clone(&server_switch), listener));

	// Source peer: greets, then originates a `test` message.
	let client_switch = switch_with(Arc::new(SilentNode));
	let source_socket = TokioWsConnector
		.connect(&format!("ws://{address}"))
		.await
		.expect("source must dial the server");
	let source = client_switch.register_websocket(source_socket, address.to_string());
	await_connections(&server_switch, 1).await;
	client_switch.greet(&source).await;

	// Observer peer: a raw socket that greets and watches for the rebroadcast.
	let observer = TokioWsConnector
		.connect(&format!("ws://{address}"))
		.await
		.expect("observer must dial the server");
	observer.send_text(&participant_greeting()).await.expect("observer must greet");
	await_connections(&server_switch, 2).await;
	// The server's greeting echo confirms the observer is now greeted.
	assert!(read_text(&observer).await.is_some(), "observer must receive the greeting echo");

	client_switch.send_message("test", Value::from("gossip"), Some(2), &[]).await;

	let frame = read_text(&observer).await.expect("observer must receive the rebroadcast");
	let message = P2PMessage::parse(&frame).expect("rebroadcast frame must parse");
	assert_eq!(message.kind, "test", "the rebroadcast type must be preserved");
	assert_eq!(message.data, Value::from("gossip"), "the rebroadcast payload must be preserved");
	assert_eq!(message.ttl, Some(1), "the rebroadcast ttl must be decremented by one hop");
}

#[tokio::test]
async fn test_message_with_exhausted_ttl_is_not_rebroadcast() {
	let server_switch = switch_with(Arc::new(SilentNode));
	let listener = bind("127.0.0.1:0").await.expect("listener must bind");
	let address = listener.local_addr().expect("listener must expose its address");
	tokio::spawn(serve(Arc::clone(&server_switch), listener));

	let client_switch = switch_with(Arc::new(SilentNode));
	let source_socket = TokioWsConnector
		.connect(&format!("ws://{address}"))
		.await
		.expect("source must dial the server");
	let source = client_switch.register_websocket(source_socket, address.to_string());

	await_connections(&server_switch, 1).await;
	client_switch.greet(&source).await;

	let observer = TokioWsConnector
		.connect(&format!("ws://{address}"))
		.await
		.expect("observer must dial the server");

	observer.send_text(&participant_greeting()).await.expect("observer must greet");
	await_connections(&server_switch, 2).await;
	assert!(read_text(&observer).await.is_some(), "observer must receive the greeting echo");

	// A zero-ttl message has no hops left, so the server must not rebroadcast it.
	client_switch.send_message("test", Value::from("gossip"), Some(0), &[]).await;
	assert!(read_text(&observer).await.is_none(), "an exhausted-ttl message must not be rebroadcast");
}
