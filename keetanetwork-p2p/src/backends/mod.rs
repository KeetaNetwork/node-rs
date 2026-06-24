//! Concrete outbound WebSocket backends implementing the
//! [`WsConnector`](keetanetwork_client::WsConnector) /
//! [`WsConnection`](keetanetwork_client::WsConnection) abstraction.
//!
//! Exactly one backend is compiled per target: tokio-tungstenite on native,
//! `wstd-tungstenite` on WASI Preview 2, and `gloo-net` in the browser.

#[cfg(all(feature = "ws-std", not(target_family = "wasm")))]
mod std;
#[cfg(all(feature = "ws-std", not(target_family = "wasm")))]
pub use std::{wrap, ServerSocket, TokioWsConnector};

#[cfg(all(feature = "ws-wasi", target_os = "wasi"))]
mod wasi;
#[cfg(all(feature = "ws-wasi", target_os = "wasi"))]
pub use wasi::WasiWsConnector;

#[cfg(all(feature = "ws-wasm", target_family = "wasm", target_os = "unknown"))]
mod wasm;
#[cfg(all(feature = "ws-wasm", target_family = "wasm", target_os = "unknown"))]
pub use wasm::BrowserWsConnector;
