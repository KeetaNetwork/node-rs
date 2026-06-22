//! Native UniFFI bindings for KeetaNet value types.
//!
//! Thin facade: re-exports core types and wraps only what UniFFI cannot
//! bind directly. One module per core crate.

uniffi::setup_scaffolding!();

mod account;
mod block;
mod error;
mod hash;
mod vote;

pub use account::*;
pub use block::*;
pub use error::*;
pub use hash::*;
pub use vote::*;
