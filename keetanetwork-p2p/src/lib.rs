//! # Keetanetwork P2P
//!
//! Peer-to-peer layer for KeetaNet nodes: concrete WebSocket backends that
//! implement the [`WsConnector`]/[`WsConnection`] abstraction defined in
//! [`keetanetwork_client`].
//!
//! The crate is feature-gated so a consumer pulls only what it needs:
//!
//! - `ws-std` -- native WebSocket backend ([`TokioWsConnector`]).
//! - `ws-wasi` -- WASI Preview 2 backend ([`WasiWsConnector`]).
//! - `ws-wasm` -- browser backend ([`BrowserWsConnector`]).
//! - `switch` -- the [`switch::P2PSwitch`] and its supporting types.
//!
//! [`WsConnector`]: keetanetwork_client::WsConnector
//! [`WsConnection`]: keetanetwork_client::WsConnection

#[cfg(any(feature = "ws-std", feature = "ws-wasi", feature = "ws-wasm"))]
pub mod backends;

#[cfg(all(feature = "ws-std", not(target_family = "wasm")))]
pub use backends::TokioWsConnector;

#[cfg(all(feature = "ws-wasi", target_os = "wasi"))]
pub use backends::WasiWsConnector;

#[cfg(all(feature = "ws-wasm", target_family = "wasm", target_os = "unknown"))]
pub use backends::BrowserWsConnector;

#[cfg(feature = "switch")]
pub mod connection;
#[cfg(feature = "switch")]
pub mod kv;
#[cfg(feature = "switch")]
pub mod message;
#[cfg(feature = "switch")]
pub mod node;
#[cfg(feature = "switch")]
pub mod peer;
#[cfg(feature = "switch")]
pub mod switch;

#[cfg(feature = "switch")]
pub use connection::{P2PConnection, P2PWebSocket};
#[cfg(feature = "switch")]
pub use kv::{KvStore, MemoryKvStore};
#[cfg(feature = "switch")]
pub use message::{MessageError, P2PMessage};
#[cfg(feature = "switch")]
pub use node::NodeLike;
#[cfg(feature = "switch")]
pub use peer::{NodeKind, P2PPeer, RepEndpoints, UpdatePref};
#[cfg(feature = "switch")]
pub use switch::{P2PConfig, P2PSwitch};
