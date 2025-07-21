/*
 * Import the necessary modules and re-export them for use in the main module.
 */

pub mod account;
pub mod error;
pub mod utils;

/// A 256-bit seed used for key derivation.
type Seed = [u8; 32];
/// An index used to derive keys from a seed.
type Index = u32;
