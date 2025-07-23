/*
 * Import the necessary modules and re-export them for use in the main module.
 */

pub mod account;
pub mod constants;
pub mod error;
pub mod utils;

use secrecy::SecretBox;

/// A 256-bit seed used for key derivation.
pub type Seed = SecretBox<[u8; 32]>;
/// A hex-encoded seed used for key derivation, stored securely.
pub type HexSeed = SecretBox<String>;
/// A passphrase used for key derivation, stored securely.
pub type Passphrase = SecretBox<Vec<String>>;
/// An index used to derive keys from a seed.
pub type Index = u32;

/// Type alias for a passphrase and its derivation index.
pub type PassphraseAndIndex = (Passphrase, Index);
/// Type alias for a hex-encoded seed and its derivation index.
pub type HexSeedAndIndex = (HexSeed, Index);
/// Type alias for a seed and its derivation index.
pub type SeedAndIndex = (Seed, Index);
