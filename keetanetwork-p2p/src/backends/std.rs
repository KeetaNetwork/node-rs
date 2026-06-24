//! Native WebSocket backend over `tokio-tungstenite`.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use keetanetwork_client::{WsConnection, WsConnector, WsError, WsMessage};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, WebSocketStream};

/// Dials outbound connections with `tokio-tungstenite`.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioWsConnector;

#[async_trait]
impl WsConnector for TokioWsConnector {
	async fn connect(&self, url: &str) -> Result<Arc<dyn WsConnection>, WsError> {
		let (socket, _response) = connect_async(url)
			.await
			.map_err(|source| WsError::Connect { source: Box::new(source) })?;
		Ok(wrap(socket))
	}
}

/// Wrap an already-established WebSocket stream (for example, one accepted by a
/// server) as a [`WsConnection`]. Lets the inbound accept path reuse the same
/// connection type as the dialer.
pub fn wrap<S>(socket: WebSocketStream<S>) -> Arc<dyn WsConnection>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let (sink, source) = socket.split();
	Arc::new(TokioWsConnection { sink: Mutex::new(sink), source: Mutex::new(source) })
}

/// An established connection. The split halves sit behind async mutexes so the
/// `&self` trait methods can drive the `Sink`/`Stream`, which need `&mut`.
struct TokioWsConnection<S> {
	sink: Mutex<SplitSink<WebSocketStream<S>, Message>>,
	source: Mutex<SplitStream<WebSocketStream<S>>>,
}

#[async_trait]
impl<S> WsConnection for TokioWsConnection<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	async fn send_text(&self, data: &str) -> Result<(), WsError> {
		let mut sink = self.sink.lock().await;
		sink.send(Message::text(data))
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
				// Control frames (ping/pong) are handled by the library; skip
				// them and await the next data frame.
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

/// The concrete socket type accepted from a `tokio` TCP listener after the
/// WebSocket upgrade; passed to [`wrap`] by the inbound accept path.
pub type ServerSocket = WebSocketStream<TcpStream>;
