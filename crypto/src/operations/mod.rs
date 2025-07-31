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
pub use signature::{CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions};

// Re-export RustCrypto traits for convenience
#[cfg(feature = "signature")]
pub use signature::{DigestSigner, DigestVerifier, RandomizedSigner, SignatureError, Signer, Verifier};

#[cfg(feature = "encryption")]
pub use encryption::{Aead, AeadCore, AeadInPlace, KeyInit};
