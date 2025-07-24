//! Prelude module for convenient imports
//!
//! This module re-exports the most commonly used types and traits from the crypto crate.
//! Users can import everything they need with a single line:
//!
//! ```rust
//! use crypto::prelude::*;
//! ```

// Core algorithm types and traits
pub use crate::algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey};

// Key implementations
pub use crate::algorithms::ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
pub use crate::algorithms::secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};

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
pub use crate::hash::{hash, hash_array, hash_default, HashAlgorithm};

// RustCrypto traits when signature feature is enabled
#[cfg(feature = "signature")]
pub use ::signature::Keypair;

// Signature types and operations
pub use crate::operations::{CryptoSigner, CryptoVerifier};
