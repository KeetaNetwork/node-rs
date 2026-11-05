//! # Keetanetwork Contract Engine (Phase 0 spike)
//!
//! Runs CosmWasm-compatible Wasm contracts against an in-memory Keeta
//! ledger, and turns each committed call into the Keeta blocks a contract
//! sequencer would publish.
//!
//! What the spike establishes:
//!
//! - **Existing contracts run unmodified.** Contracts built with the
//!   standard CosmWasm toolchain (`cosmwasm-std` 2.x, cw-plus) are
//!   validated, metered and executed by the stock `cosmwasm-vm`.
//! - **Keeta extensions fit the CosmWasm model.** [`KeetaMsg`] and
//!   [`KeetaQuery`] (from `keetanetwork-contract-std`) ride on CosmWasm's
//!   custom message and query hooks.
//! - **Every effect is a real Keeta operation.** Contract outputs are built
//!   into [`UnsignedBlock`]s by `keetanetwork-block`, which applies the
//!   network's operation and field validation.
//! - **Execution is deterministic.** Identical calls on identical state give
//!   identical state roots and block hashes.
//!
//! What it deliberately leaves for later phases: signing and publishing
//! blocks, persistent storage, a Merkle state tree, fees, and migration.
//!
//! [`KeetaMsg`]: keetanetwork_contract_std::KeetaMsg
//! [`KeetaQuery`]: keetanetwork_contract_std::KeetaQuery
//! [`UnsignedBlock`]: keetanetwork_block::UnsignedBlock

#![deny(unsafe_code)]

mod address;
mod backend;
mod engine;
mod error;
mod output;
mod state;

pub use address::{parse_account, KeetaApi};
pub use backend::BlockContext;
pub use engine::{
	Call, Engine, EngineConfig, Event, Execution, Fund, CAPABILITIES, DEFAULT_GAS_LIMIT, QUERY_GAS_LIMIT,
};
pub use error::EngineError;
pub use state::{AccountInfo, LedgerOp};
