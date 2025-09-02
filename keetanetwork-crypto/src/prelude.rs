//! Prelude module for convenient imports
//!
//! This module re-exports the most commonly used types and traits from the crypto crate.
//! Users can import everything they need with a single line:
//!
//! ```rust
//! use keetanetwork_crypto::prelude::*;
//! ```

// Re-export external resources required for usage.
pub use secrecy::{ExposeSecret, SecretBox, SecretString, SerializableSecret};
pub use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-export the IntoSecret trait
pub use crate::IntoSecret;

// Core algorithm types and traits
pub use crate::algorithms::{Algorithm, AnyPrivateKey, AnyPublicKey, KeyDerivation, PrivateKey, PublicKey};

// Hash functions
pub use crate::hash::HashAlgorithm;
// KDF functions
pub use crate::kdf::KdfAlgorithm;

// RustCrypto traits when signature feature is enabled
#[cfg(feature = "signature")]
pub use ::signature::{Keypair, SignatureEncoding, Signer, Verifier};

// Signature types and operations
#[cfg(feature = "signature")]
pub use crate::algorithms::AnySignature;
#[cfg(feature = "signature")]
pub use crate::operations::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};

// Encryption
#[cfg(feature = "encryption")]
pub use crate::operations::encryption::{AsymmetricEncryption, CryptoAead, KeyGeneration, SymmetricEncryption};
#[cfg(feature = "encryption")]
pub use crate::operations::KeyExchange;

// Symmetric encryption algorithms
#[cfg(feature = "encryption")]
pub use crate::algorithms::aes_ctr::Aes128CtrCipher;

// ECIES implementations
#[cfg(feature = "encryption")]
pub use crate::algorithms::ecies::Ecies;
