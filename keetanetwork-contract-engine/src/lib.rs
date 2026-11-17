//! # Keetanetwork Contract Engine
//!
//! Runs sBPF contracts for Keeta's representatives: each `CONTRACT_CALL`
//! on the ledger, with every representative reaching the same outcome.
//!
//! - **Contracts are sBPF programs, run Solana's way.** They are built with
//!   Solana's platform tools against `keetanetwork-contract-std`, and run in
//!   `solana-sbpf`'s interpreter. A call is an [`Instruction`]: a contract,
//!   the accounts it touches (each read-only or writable) and raw data.
//!   Account data is mapped into the contract's memory; a contract may
//!   change only its own writable accounts, and contracts invoke each other
//!   passing accounts on.
//! - **Every effect is a Keeta operation.** Contracts send tokens and set
//!   their account's info through host functions, held to the ledger's
//!   permissions and field rules. A call's [`LedgerOutcome`] lists those
//!   effects, with the state accounts it read and wrote, for the
//!   representative to vote on and apply.
//! - **State is the ledger's.** The engine reads through a [`Host`] and
//!   changes nothing itself. [`MemoryHost`] keeps a ledger in memory, for
//!   tests.
//! - **Execution is deterministic.** Identical calls on identical state give
//!   identical outcomes and gas.

#![deny(unsafe_code)]

mod address;
mod code_cache;
mod engine;
mod error;
pub mod gas;
pub mod host;
mod memory;
mod overlay;
mod vm;

pub use address::{from_address, parse_account, to_address};
pub use engine::{
	AccountMeta, Effect, Engine, EngineConfig, Event, Fund, Instruction, LedgerCall, LedgerOutcome, Log, StateAccess,
	DEFAULT_MAX_CACHED_CODE_SIZE, DEFAULT_MAX_CODE_SIZE,
};
pub use error::EngineError;
pub use host::{AccountInfo, CodeHash, ContractRecord, Host, HostError, HostResult};
/// The id of an account named by `seeds`: SHA-256 of their concatenation,
/// the same helper contracts use.
pub use keetanetwork_contract_std::state_id;
pub use keetanetwork_contract_std::{Address, StateId};
pub use memory::MemoryHost;
