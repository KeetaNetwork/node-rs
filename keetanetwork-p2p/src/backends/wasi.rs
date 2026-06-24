//! WASI Preview 2 WebSocket backend over `wstd-tungstenite`.
//!
//! `wstd` runs single-threaded, so the connection types are `!Send`; the
//! [`WsConnection`] / [`WsConnector`] traits relax their bounds on
//! `target_family = "wasm"`, which `wasm32-wasip2` satisfies.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::lock::Mutex;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use keetanetwork_client::{WsConnection, WsConnector, WsError, WsMessage};
use wstd::net::TcpStream;
use wstd_tungstenite::tungstenite::Message;
use wstd_tungstenite::{connect_async, WebSocketStream};

/// The duplex socket type yielded by [`connect_async`].
type Socket = WebSocketStream<TcpStream>;

/// Dials outbound connections with `wstd-tungstenite`.
///
/// `wss://` is unsupported (wstd has no TLS); use `ws://`.
#[derive(Clone, Copy, Debug, Default)]
pub struct WasiWsConnector;

#[async_trait(?Send)]
impl WsConnector for WasiWsConnector {
	async fn connect(&self, url: &str) -> Result<Arc<dyn WsConnection>, WsError> {
		let (socket, _response) = connect_async(url)
			.await
			.map_err(|source| WsError::Connect { source: Box::new(source) })?;
		let (sink, source) = socket.split();
		Ok(Arc::new(WasiWsConnection { sink: Mutex::new(sink), source: Mutex::new(source) }))
	}
}

/// An established connection; split halves behind async mutexes so the `&self`
/// trait methods can drive the `Sink`/`Stream`.
struct WasiWsConnection {
	sink: Mutex<SplitSink<Socket, Message>>,
	source: Mutex<SplitStream<Socket>>,
}

#[async_trait(?Send)]
impl WsConnection for WasiWsConnection {
	async fn send_text(&self, data: &str) -> Result<(), WsError> {
		let mut sink = self.sink.lock().await;
		sink.send(Message::Text(data.to_string().into()))
			.await
			.map_err(|source| WsError::Send { source: Box::new(source) })
	}

	async fn recv(&self) -> Result<Option<WsMessage>, WsError> {
		let mut source = self.source.lock().await;
		loop {
			return match source.next().await {
				None | Some(Ok(Message::Close(_))) => Ok(None),
				Some(Ok(Message::Text(text))) => Ok(Some(WsMessage::Text(text.as_str().to_owned()))),
				Some(Ok(Message::Binary(bytes))) => Ok(Some(WsMessage::Binary(bytes.to_vec()))),
				Some(Ok(_)) => continue,
				Some(Err(source)) => Err(WsError::Receive { source: Box::new(source) }),
			};
		}
	}

	async fn close(&self) {
		let mut sink = self.sink.lock().await;
		let _ = sink.close().await;
	}
}
