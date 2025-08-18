//! Prelude module for convenient imports
//!
//! This module re-exports the most commonly used types and traits from the crypto crate.
//! Users can import everything they need with a single line:
//!
//! ```rust
//! use crypto::prelude::*;
//! ```

// Re-export external resources required for usage.
pub use secrecy::ExposeSecret;

// Core algorithm types and traits
pub use crate::algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey};

// Key implementations
pub use crate::algorithms::ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
pub use crate::algorithms::secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};
pub use crate::algorithms::secp256r1::{Secp256r1Derivation, Secp256r1PrivateKey, Secp256r1PublicKey};

// X25519 types for key exchange (used with Ed25519)
pub use crate::algorithms::ed25519::{X25519PrivateKey, X25519PublicKey};

// Any key types for algorithm-agnostic usage
pub use crate::{AnyPrivateKey, AnyPublicKey};

// Error handling
pub use crate::error::CryptoError;

// Utility functions
pub use crate::utils::{
	create_keypair_from_seed, generate_random_passphrase, generate_random_seed, seed_from_passphrase,
};

// Hash functions
// Hash functions and KDF
// Hash functions and KDF
pub use crate::hash::{hash, hash_array, hash_default, HashAlgorithm};
pub use crate::kdf::KdfAlgorithm;

// RustCrypto traits when signature feature is enabled
#[cfg(feature = "signature")]
pub use ::signature::{Keypair, SignatureEncoding, Signer, Verifier};

// Signature types and operations
#[cfg(feature = "signature")]
pub use crate::operations::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};
#[cfg(feature = "signature")]
pub use crate::AnySignature;

// Re-export algorithm-specific signature types
#[cfg(feature = "signature")]
pub use crate::algorithms::ed25519::Ed25519Signature;
#[cfg(feature = "signature")]
pub use crate::algorithms::secp256k1::Secp256k1Signature;
#[cfg(feature = "signature")]
pub use crate::algorithms::secp256r1::Secp256r1Signature;

// Encryption
#[cfg(feature = "encryption")]
pub use crate::operations::encryption::{AsymmetricEncryption, CryptoAead, SymmetricEncryption};
#[cfg(feature = "encryption")]
pub use crate::operations::KeyExchange;

// Symmetric encryption algorithms
#[cfg(feature = "encryption")]
pub use crate::algorithms::aes_ctr::Aes128CtrCipher;

// ECIES implementations
#[cfg(feature = "encryption")]
pub use crate::algorithms::ecies::Ecies;
#[cfg(feature = "encryption")]
pub use crate::algorithms::ecies::{EciesSecp256k1, EciesX25519};
