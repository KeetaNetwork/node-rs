//! Async REST client for a KeetaNet node.
//!
//! Provides [`KeetaClient`], an ergonomic wrapper for assembling and
//! transmitting vote staples. The transport layer is generated at build time
//! from the committed OpenAPI document (`openapi/keetanet-node.yaml`) via
//! [`progenitor`](https://docs.rs/progenitor) and exposed as the
//! [`generated`] module.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use keetanetwork_account::GenericAccount;
//! use keetanetwork_account::doc_utils::create_ed25519_test_keys;
//! use keetanetwork_block::AccountRef;
//! use keetanetwork_client::KeetaClient;
//!
//! # fn main() -> Result<(), keetanetwork_client::ClientError> {
//! let client = KeetaClient::new("http://localhost:8080/api").with_network(0u8);
//!
//! let (_, _, signer) = create_ed25519_test_keys(None);
//! let account: AccountRef = Arc::new(GenericAccount::Ed25519(signer));
//!
//! let block = tokio::runtime::Runtime::new()
//!     .expect("doc runtime")
//!     .block_on(
//!         client
//!             .builder(&account)
//!             .with_previous(account.to_opening_hash())
//!             .set_rep(&account)
//!             .build(),
//!     )?;
//!
//! assert_eq!(block.data().account().to_string(), account.to_string());
//! # Ok(())
//! # }
//! ```
//!
//! Transmitting an assembled staple to the node (networked):
//!
//! ```no_run
//! use keetanetwork_client::KeetaClient;
//! use keetanetwork_vote::VoteStaple;
//!
//! # async fn run(staple: &VoteStaple) -> Result<(), keetanetwork_client::ClientError> {
//! let client = KeetaClient::new("http://localhost:8080/api");
//! let accepted = client.transmit_staple(staple).await?;
//! # let _ = accepted;
//! # Ok(())
//! # }
//! ```
//!
//! ## `no_std`
//!
//! The networking client requires `std` (it is built on `reqwest`/`tokio`) and
//! is gated behind the default-on `std` feature. With `--no-default-features`
//! the crate compiles as `no_std` and exposes only the transport-free pieces:
//! [`ClientConfig`] and the pure dispatch primitives in [`math`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
mod client;
mod config;
#[cfg(feature = "std")]
mod error;
pub mod math;
#[cfg(feature = "std")]
mod rep;

/// Generated transport client (`Client`, request/response `types`, and the
/// transport `Error`). Emitted from the OpenAPI document at build time.
#[cfg(feature = "std")]
#[allow(clippy::all, dead_code, unused_imports, missing_docs)]
pub mod generated {
	include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
}

#[cfg(feature = "std")]
pub use client::{
	AccountState, Acl, Certificate, ChainQuery, HistoryEntry, HistoryQuery, KeetaClient, LedgerChecksum,
	Representative, TokenBalance, TransactionBuilder,
};
pub use config::ClientConfig;
#[cfg(feature = "std")]
pub use error::{ApiError, ClientError};
#[cfg(feature = "std")]
pub use keetanetwork_error::{KeetaNetError, NodeErrorType};
#[cfg(feature = "std")]
pub use rep::RepEndpoint;
#[cfg(feature = "std")]
pub use reqwest;
