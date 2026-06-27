//! Utility macros for testing and common patterns across the workspace
//!
//! This crate provides reusable `macro_rules!` macros that can be shared
//! across all workspace members for common testing patterns and utilities.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod errors;
pub mod testing;

#[cfg(feature = "build")]
pub mod build;

#[cfg(feature = "node-harness")]
pub mod node_harness;
