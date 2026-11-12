//! # Keetanetwork Contract Std
//!
//! The SDK for Keeta contracts, and the binary interface ([`abi`]) they
//! share with the contract engine.
//!
//! Contracts are sBPF programs, built with Solana's platform tools
//! (`cargo build-sbf --arch v3`), and follow Solana's model:
//!
//! - **One entrypoint.** [`entrypoint!`] declares
//!   `process(&mut Context) -> ContractResult`. The instruction data is raw
//!   bytes; contracts decode it however they like (the examples use borsh).
//! - **State lives in accounts.** An account is a piece of one contract's
//!   state, named by a 32-byte [`StateId`] (usually [`state_id`] of some
//!   seeds). Each instruction lists the accounts it touches, each
//!   read-only or writable, and the engine maps their data into the
//!   contract's memory. A contract can read any account it is given but
//!   only change its own writable ones. An empty account does not exist.
//! - **Contracts call each other with [`invoke`]**, passing on accounts
//!   they were given. A contract cannot be re-entered.
//! - **Everything is atomic.** If any contract fails, or any host function
//!   does (such as a `SEND` the contract cannot afford), the whole call is
//!   undone.
//!
//! Keeta's ledger is reached through host functions: [`send`] (with an
//! `external` memo), [`balance`], [`supply`] and [`set_info`]. Each runs as
//! the contract's own Keeta account, which also holds the funds callers
//! attach.
//!
//! Every deploy pays by the byte, so the SDK keeps Rust's formatting code
//! (`format!`, `Display`, about 30 KB) out of contracts: errors, attributes
//! and logs are built from pieces with [`text!`], [`bail!`] and
//! [`ensure!`] (`bail!("attach exactly ", price, " of the token")`), and the
//! engine writes their numbers.
//!
//! ```ignore
//! use keetanetwork_contract_std::{entrypoint, Context, ContractResult};
//!
//! entrypoint!(process);
//!
//! fn process(ctx: &mut Context) -> ContractResult {
//!     let counter = ctx.account(0)?;
//!     let next = counter.load::<u64>()?.unwrap_or_default() + 1;
//!     counter.store(&next)
//! }
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod abi;
#[cfg(all(feature = "borsh", not(target_os = "solana")))]
pub mod interface;
mod runtime;
mod sys;
pub mod text;

pub use abi::{Address, StateId};
pub use runtime::{
	attribute, balance, invoke, log, report_panic, return_data, run, send, set_info, set_return_data, sha256, state_id,
	supply, Account, BumpAllocator, Context, ContractResult, Error, Fund,
};
pub use text::Text;
