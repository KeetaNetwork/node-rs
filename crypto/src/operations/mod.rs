//! Cryptographic operations module
//!
//! This module provides organized sub-modules for different types of
//! cryptographic operations, similar to the algorithms module structure.

pub mod encryption;
pub mod signature;

// Re-export commonly used items
pub use encryption::{CryptoAead, HybridEncryption, KeyExchange};
pub use signature::{CryptoSigner, CryptoVerifier, HybridSigner};

#[cfg(feature = "signature")]
pub use signature::{DigestSigner, DigestVerifier, RandomizedSigner, Signer, Verifier};

#[cfg(feature = "aead")]
pub use encryption::{Aead, AeadCore, AeadInPlace, KeyInit};
