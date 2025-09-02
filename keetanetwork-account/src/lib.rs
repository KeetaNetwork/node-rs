/*
 * Import the necessary modules and re-export them for use in the main module.
 */

pub mod account;
pub mod constants;
#[doc(hidden)]
pub mod doc_utils;
pub mod error;
pub mod utils;

// Re-export the main types for easier use
pub use account::{
	Account, Accountable, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyMULTISIG, KeyNETWORK,
	KeyPair, KeyPairType, KeySTORAGE, KeyTOKEN, Keyable, PublicKeyStorage,
};
pub use error::AccountError;

use keetanetwork_crypto::prelude::SecretBox;

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
