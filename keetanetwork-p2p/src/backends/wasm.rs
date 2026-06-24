//! Browser WebSocket backend over `gloo-net`.
//!
//! Browser values are `!Send`; the [`WsConnection`] / [`WsConnector`] traits
//! relax their bounds on `target_family = "wasm"`. `gloo-net`'s `WebSocket`
//! already presents a `Stream`/`Sink`, bridging the event-driven browser API.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::lock::Mutex;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::futures::WebSocket;
use gloo_net::websocket::Message;
use keetanetwork_client::{WsConnection, WsConnector, WsError, WsMessage};

/// Dials outbound connections with the browser `WebSocket` API.
#[derive(Clone, Copy, Debug, Default)]
pub struct BrowserWsConnector;

#[async_trait(?Send)]
impl WsConnector for BrowserWsConnector {
	async fn connect(&self, url: &str) -> Result<Arc<dyn WsConnection>, WsError> {
		let socket = WebSocket::open(url).map_err(|source| WsError::Connect { source: Box::new(source) })?;
		let (sink, source) = socket.split();
		Ok(Arc::new(BrowserWsConnection { sink: Mutex::new(sink), source: Mutex::new(source) }))
	}
}

/// An established connection; split halves behind async mutexes so the `&self`
/// trait methods can drive the `Sink`/`Stream`.
struct BrowserWsConnection {
	sink: Mutex<SplitSink<WebSocket, Message>>,
	source: Mutex<SplitStream<WebSocket>>,
}

#[async_trait(?Send)]
impl WsConnection for BrowserWsConnection {
	async fn send_text(&self, data: &str) -> Result<(), WsError> {
		let mut sink = self.sink.lock().await;
		sink.send(Message::Text(data.to_owned()))
			.await
			.map_err(|source| WsError::Send { source: Box::new(source) })
	}

	async fn recv(&self) -> Result<Option<WsMessage>, WsError> {
		let mut source = self.source.lock().await;
		match source.next().await {
			None => Ok(None),
			Some(Ok(Message::Text(text))) => Ok(Some(WsMessage::Text(text))),
			Some(Ok(Message::Bytes(bytes))) => Ok(Some(WsMessage::Binary(bytes))),
			Some(Err(source)) => Err(WsError::Receive { source: Box::new(source) }),
		}
	}

	async fn close(&self) {
		let mut sink = self.sink.lock().await;
		let _ = sink.close().await;
	}
}
