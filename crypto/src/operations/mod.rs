//! Cryptographic operations module
//!
//! This module provides organized sub-modules for different types of
//! cryptographic operations, similar to the algorithms module structure.

#[cfg(feature = "encryption")]
pub mod encryption;
#[cfg(feature = "signature")]
pub mod signature;

// Re-export commonly used items
#[cfg(feature = "encryption")]
pub use encryption::{AsymmetricEncryption, CryptoAead, KeyExchange};
#[cfg(feature = "signature")]
pub use signature::{CryptoSigner, CryptoVerifier};

// Re-export RustCrypto traits for convenience
#[cfg(feature = "signature")]
pub use signature::{DigestSigner, DigestVerifier, Error, RandomizedSigner, Signer, Verifier};

// Re-export algorithm-specific signature types
#[cfg(feature = "signature")]
pub use signature::{Ed25519Signature, Secp256k1Signature};

#[cfg(feature = "encryption")]
pub use encryption::{Aead, AeadCore, AeadInPlace, KeyInit};
