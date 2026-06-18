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
//! # #[tokio::main]
//! # async fn main() -> Result<(), keetanetwork_client::ClientError> {
//! let client = KeetaClient::new("http://localhost:8080/api").with_network(0u8);
//!
//! let (_, _, signer) = create_ed25519_test_keys(None);
//! let account: AccountRef = Arc::new(GenericAccount::Ed25519(signer));
//!
//! let block = client
//!     .builder(&account)
//!     .with_previous(account.to_opening_hash())
//!     .set_rep(&account)
//!     .build()
//!     .await?;
//!
//! assert_eq!(block.data().account().to_string(), account.to_string());
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

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod builder;
mod client;
mod config;
mod error;
pub mod math;
mod model;
mod rep;
mod runtime;
mod sync;
mod transport;

/// Generated transport client (`Client`, request/response `types`, and the
/// transport `Error`). Emitted from the OpenAPI document at build time.
#[cfg(feature = "std")]
#[allow(clippy::all, dead_code, unused_imports, missing_docs)]
pub mod generated {
	include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
}

pub use builder::TransactionBuilder;
pub use client::KeetaClient;
pub use config::ClientConfig;
pub use error::ClientError;
pub use keetanetwork_error::{KeetaNetError, NodeErrorType};
pub use keetanetwork_vote::VoteQuote;
pub use model::{
	AccountState, Acl, Certificate, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum, Representative,
	TokenBalance, TransmitOptions,
};
pub use runtime::{BoxFuture, Runtime, TaskHandle};
pub use transport::{LedgerSide, NodeTransport, TransportFactory};

#[cfg(feature = "std")]
pub use rep::RepEndpoint;
#[cfg(feature = "std")]
pub use reqwest;
#[cfg(feature = "std")]
pub use runtime::TokioRuntime;
#[cfg(feature = "std")]
pub use transport::{ApiError, GeneratedTransport, GeneratedTransportFactory};
