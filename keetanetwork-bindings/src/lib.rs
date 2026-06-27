//! Shared, target-agnostic logic for the KeetaNet binding crates.
//!
//! Each FFI boundary repeats the same input parsing, account-algorithm
//! mapping, and core-error reduction.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod account;
pub mod error;
pub mod parse;
pub mod permissions;
pub mod time;
pub mod x509;

#[cfg(feature = "client")]
pub mod client;
