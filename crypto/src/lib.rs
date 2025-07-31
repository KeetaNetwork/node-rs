//! Cryptographic primitives for KeetaNet node
//!
//! This crate provides algorithm-agnostic cryptographic operations including:
//! - Key generation and derivation
//! - Public key formatting with checksums
//! - Support for multiple algorithms (secp256k1, Ed25519)

pub mod algorithms;
pub mod constants;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod operations;
pub mod prelude;
pub mod utils;

// Re-exports for convenience
pub use algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey};
pub use error::CryptoError;

// Hash functions
pub use hash::{default_hash_algorithm, default_hash_algorithm_length, hash, hash_array, hash_default, HashAlgorithm};

// Keypair trait when signature feature is enabled
#[cfg(feature = "signature")]
pub use ::signature::Keypair;

// Signature types and crypto operations
#[cfg(feature = "signature")]
pub use operations::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, KeyExchange, SigningOptions,
};

#[cfg(feature = "encryption")]
pub use operations::{AsymmetricEncryption, CryptoAead};

// Algorithm-agnostic key types
pub use algorithms::{AnyPrivateKey, AnyPublicKey};

// Specific algorithm implementations
pub use algorithms::ed25519::{
	ed25519_to_x25519_private, ed25519_to_x25519_public, Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey,
	X25519PrivateKey, X25519PublicKey,
};
pub use algorithms::secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};

// Utility functions
pub use utils::{generate_random_passphrase, generate_random_seed, seed_from_passphrase};
