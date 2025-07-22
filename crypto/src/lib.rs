//! Cryptographic primitives for KeetaNet node
//!
//! This crate provides algorithm-agnostic cryptographic operations including:
//! - Key generation and derivation
//! - Public key formatting with checksums
//! - Support for multiple algorithms (secp256k1, Ed25519)

pub mod algorithms;
pub mod error;
pub mod utils;

// Re-exports for convenience
pub use algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey};
pub use error::CryptoError;

// Specific algorithm implementations
pub use algorithms::ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
pub use algorithms::secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};

/// Enum to hold different key types
#[derive(Debug, Clone)]
pub enum AnyPrivateKey {
	Secp256k1(Secp256k1PrivateKey),
	Ed25519(Ed25519PrivateKey),
}

/// Enum to hold different public key types
#[derive(Debug, Clone)]
pub enum AnyPublicKey {
	Secp256k1(Secp256k1PublicKey),
	Ed25519(Ed25519PublicKey),
}

impl AnyPrivateKey {
	pub fn derive_public_key(&self) -> AnyPublicKey {
		match self {
			AnyPrivateKey::Secp256k1(key) => AnyPublicKey::Secp256k1(key.derive_public_key()),
			AnyPrivateKey::Ed25519(key) => AnyPublicKey::Ed25519(key.derive_public_key()),
		}
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		match self {
			AnyPrivateKey::Secp256k1(key) => key.to_bytes(),
			AnyPrivateKey::Ed25519(key) => key.to_bytes(),
		}
	}

	pub fn algorithm(&self) -> Algorithm {
		match self {
			AnyPrivateKey::Secp256k1(_) => Algorithm::Secp256k1,
			AnyPrivateKey::Ed25519(_) => Algorithm::Ed25519,
		}
	}
}

impl AnyPublicKey {
	pub fn to_bytes(&self) -> Vec<u8> {
		match self {
			AnyPublicKey::Secp256k1(key) => key.to_bytes(),
			AnyPublicKey::Ed25519(key) => key.to_bytes(),
		}
	}

	pub fn to_formatted_string(&self) -> Result<String, CryptoError> {
		match self {
			AnyPublicKey::Secp256k1(key) => key.to_formatted_string(),
			AnyPublicKey::Ed25519(key) => key.to_formatted_string(),
		}
	}

	pub fn algorithm(&self) -> Algorithm {
		match self {
			AnyPublicKey::Secp256k1(_) => Algorithm::Secp256k1,
			AnyPublicKey::Ed25519(_) => Algorithm::Ed25519,
		}
	}
}

/// Create a key pair for the specified algorithm
pub fn create_keypair_from_seed(
	seed: &[u8],
	algorithm: Algorithm,
) -> Result<(AnyPrivateKey, AnyPublicKey), CryptoError> {
	match algorithm {
		Algorithm::Secp256k1 => {
			let private_key = Secp256k1Derivation::derive_from_seed(seed)?;
			let public_key = private_key.derive_public_key();
			Ok((AnyPrivateKey::Secp256k1(private_key), AnyPublicKey::Secp256k1(public_key)))
		}
		Algorithm::Ed25519 => {
			let private_key = Ed25519Derivation::derive_from_seed(seed)?;
			let public_key = private_key.derive_public_key();
			Ok((AnyPrivateKey::Ed25519(private_key), AnyPublicKey::Ed25519(public_key)))
		}
		Algorithm::Secp256r1 => {
			Err(CryptoError::UnsupportedAlgorithm { algorithm: "secp256r1 not implemented".to_string() })
		}
	}
}
