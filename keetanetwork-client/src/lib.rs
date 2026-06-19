//! Async REST client for a KeetaNet node.
//!
//! Provides [`KeetaClient`], a wrapper for assembling and transmitting
//! vote staples. The transport layer is generated at build time from
//! the committed OpenAPI document (`openapi/keetanet-node.yaml`) via
//! [`progenitor`](https://docs.rs/progenitor) and exposed as the
//! [`generated`] module.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use keetanetwork_account::GenericAccount;
//! use keetanetwork_block::AccountRef;
//! use keetanetwork_client::KeetaClient;
//! # use keetanetwork_account::doc_utils::create_ed25519_test_keys;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), keetanetwork_client::ClientError> {
//! let client = KeetaClient::new("http://localhost:8080/api").with_network(0u8);
//!
//! let (_, _, signer) = create_ed25519_test_keys(None);
//! let account: AccountRef = Arc::new(GenericAccount::Ed25519(signer));
//!
//! let blocks = client
//!     .builder(&account)
//!     .with_previous(account.to_opening_hash())
//!     .set_rep(&account)
//!     .build()
//!     .await?;
//!
//! assert_eq!(blocks.len(), 1);
//! assert_eq!(blocks[0].data().account().to_string(), account.to_string());
//! # Ok(())
//! # }
//! ```
//!
//! ## `no_std`
//!
//! The orchestrator ([`KeetaClient`]) is `no_std`+`alloc`: it is written
//! against the [`Runtime`] and [`NodeTransport`]/[`TransportFactory`] interfaces
//! and constructed with [`KeetaClient::with_parts`], so a `no_std` consumer
//! supplies its own executor and HTTP backend.

#![cfg_attr(not(any(feature = "std", feature = "http")), no_std)]
// On wasm the shared traits relax to `!Send`/`!Sync`, but the orchestrator
// still shares its state through `Arc` for one cross-target ownership type.
#![cfg_attr(target_family = "wasm", allow(clippy::arc_with_non_send_sync))]

// `http` supplies the HTTP backend but no clock or executor; it is only usable
// alongside a runtime selector.
#[cfg(all(
	feature = "http",
	not(any(all(feature = "std", not(target_family = "wasm")), all(feature = "wasm", target_family = "wasm")))
))]
compile_error!("feature `http` requires a runtime: enable `std` on native targets or wasm on wasm32");

extern crate alloc;

mod builder;
mod client;
mod config;
mod error;
mod marker;
pub mod math;
mod model;
mod rep;
mod runtime;
mod swap;
mod sync;
mod transport;
mod user;

#[cfg(feature = "std")]
mod genesis;
#[cfg(feature = "http")]
mod network;

/// Generated transport client (`Client`, request/response `types`, and the
/// transport `Error`). Emitted from the OpenAPI document at build time.
#[cfg(feature = "http")]
#[allow(clippy::all, dead_code, unused_imports, missing_docs)]
pub mod generated {
	include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
}

pub use builder::TransactionBuilder;
pub use client::KeetaClient;
pub use config::ClientConfig;
pub use error::ClientError;
pub use keetanetwork_error::{KeetaNetError, NodeErrorType};
pub use keetanetwork_vote::{Vote, VoteQuote, VoteStaple};
pub use marker::{MaybeSend, MaybeSync};
pub use model::{
	AccountOrPending, AccountState, Acl, Certificate, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum,
	PendingAccount, Representative, TokenBalance, TransmitOptions,
};
pub use runtime::{BoxFuture, Runtime, TaskHandle};
pub use swap::{AcceptSwapRequest, CreateSwapRequest, SwapExpectation, SwapTokenAmount};
pub use transport::{LedgerSide, NodeTransport, TransportFactory};
pub use user::UserClient;

#[cfg(feature = "http")]
pub use {
	network::{Network, NetworkConfig},
	rep::RepEndpoint,
	reqwest,
	transport::{ApiError, GeneratedTransport, GeneratedTransportFactory},
};

#[cfg(feature = "std")]
pub use {
	genesis::{BaseNetworkInfo, BaseTokenInfo, InitializeNetwork},
	model::RepStatus,
	runtime::TokioRuntime,
};

#[cfg(all(feature = "wasm", target_family = "wasm"))]
pub use runtime::WasmRuntime;
