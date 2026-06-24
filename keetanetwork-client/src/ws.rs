//! Outbound WebSocket abstraction used by the change subscription.
//!
//! [`NodeTransport`]: crate::NodeTransport
//! [`TransportFactory`]: crate::TransportFactory

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use async_trait::async_trait;
use snafu::Snafu;

use crate::marker::{MaybeSend, MaybeSync};

/// A frame received from a peer over a [`WsConnection`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WsMessage {
	/// A UTF-8 text frame (the node speaks JSON text frames).
	Text(String),
	/// A binary frame.
	Binary(Vec<u8>),
}

/// Failure modes of a WebSocket operation.
///
/// Backend-specific failures are boxed into the [`source`](WsError::Connect)
/// slots so the abstraction stays free of any concrete socket type.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum WsError {
	/// The outbound connection could not be established.
	#[snafu(display("websocket connection failed"))]
	Connect {
		/// Underlying backend error.
		#[cfg(not(target_family = "wasm"))]
		source: Box<dyn core::error::Error + Send + Sync>,
		/// Underlying backend error.
		#[cfg(target_family = "wasm")]
		source: Box<dyn core::error::Error>,
	},

	/// A frame could not be sent.
	#[snafu(display("websocket send failed"))]
	Send {
		/// Underlying backend error.
		#[cfg(not(target_family = "wasm"))]
		source: Box<dyn core::error::Error + Send + Sync>,
		/// Underlying backend error.
		#[cfg(target_family = "wasm")]
		source: Box<dyn core::error::Error>,
	},

	/// A frame could not be received.
	#[snafu(display("websocket receive failed"))]
	Receive {
		/// Underlying backend error.
		#[cfg(not(target_family = "wasm"))]
		source: Box<dyn core::error::Error + Send + Sync>,
		/// Underlying backend error.
		#[cfg(target_family = "wasm")]
		source: Box<dyn core::error::Error>,
	},

	/// The peer sent a frame that violated the expected protocol (for
	/// example, a malformed greeting). Strict validation at the untrusted
	/// boundary.
	#[snafu(display("websocket protocol violation"))]
	Protocol,
}

/// An active outbound WebSocket connection to a peer.
///
/// [`recv`](WsConnection::recv) yields frames until the peer closes the
/// connection, at which point it returns `Ok(None)`.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait WsConnection: MaybeSend + MaybeSync {
	/// Send a UTF-8 text frame.
	async fn send_text(&self, data: &str) -> Result<(), WsError>;
	/// Receive the next frame, or `None` once the connection has closed.
	async fn recv(&self) -> Result<Option<WsMessage>, WsError>;
	/// Close the connection. Idempotent.
	async fn close(&self);
}

/// Dials outbound WebSocket connections. Injected into the client so the
/// subscription can open sockets without naming a concrete backend.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait WsConnector: core::fmt::Debug + MaybeSend + MaybeSync {
	/// Open a connection to the WebSocket endpoint at `url`.
	async fn connect(&self, url: &str) -> Result<Arc<dyn WsConnection>, WsError>;
}
