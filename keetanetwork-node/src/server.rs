//! Inbound P2P WebSocket accept server.
//!
//! Accepts TCP connections, upgrades each to a WebSocket, wraps it via the
//! `keetanetwork-p2p` std backend, and registers it with the
//! [`P2PSwitch`](keetanetwork_p2p::P2PSwitch). The switch then drives that
//! connection's read loop.

use std::sync::Arc;

use keetanetwork_p2p::backends::wrap;
use keetanetwork_p2p::P2PSwitch;
use snafu::Snafu;
use tokio::net::{TcpListener, ToSocketAddrs};

/// Failure modes of the accept server.
#[derive(Debug, Snafu)]
pub enum ServerError {
	/// The listener could not bind the requested address.
	#[snafu(display("failed to bind p2p listener"))]
	Bind {
		/// Underlying I/O error.
		source: std::io::Error,
	},
}

/// Bind a TCP listener for inbound P2P connections.
///
/// # Errors
///
/// - [`ServerError::Bind`] -- the address could not be bound.
pub async fn bind(address: impl ToSocketAddrs) -> Result<TcpListener, ServerError> {
	TcpListener::bind(address)
		.await
		.map_err(|source| ServerError::Bind { source })
}

/// Accept inbound WebSocket peers on `listener` forever, registering each with
/// `switch`. Per-connection upgrade failures are skipped rather than fatal.
pub async fn serve(switch: Arc<P2PSwitch>, listener: TcpListener) {
	loop {
		let (stream, peer_address) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(_) => continue,
		};

		let switch = Arc::clone(&switch);
		tokio::spawn(async move {
			let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
				return;
			};
			switch.register_websocket(wrap(socket), peer_address.to_string());
		});
	}
}
