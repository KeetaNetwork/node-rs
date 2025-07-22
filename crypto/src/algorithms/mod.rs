use crate::error::CryptoError;

// Algorithm implementations
pub mod ed25519;
pub mod secp256k1;

// Re-export algorithm implementations
pub use ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
pub use secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};

/// Trait for cryptographic private keys
pub trait PrivateKey: Clone + Send + Sync + std::fmt::Debug {
	type PublicKey: PublicKey;

	/// Derive the corresponding public key
	fn derive_public_key(&self) -> Self::PublicKey;

	/// Get the raw bytes of the private key
	fn to_bytes(&self) -> Vec<u8>;

	/// Create from raw bytes
	fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
	where
		Self: Sized;
}

/// Trait for cryptographic public keys
pub trait PublicKey: Clone + Send + Sync + std::fmt::Debug {
	/// Get the raw bytes of the public key
	fn to_bytes(&self) -> Vec<u8>;

	/// Create from raw bytes
	fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
	where
		Self: Sized;

	/// Format as a string with checksum and encoding
	fn to_formatted_string(&self) -> Result<String, CryptoError>;
}

/// Trait for key derivation algorithms
pub trait KeyDerivation {
	type PrivateKey: PrivateKey;

	/// Derive a private key from seed material
	fn derive_from_seed(seed: &[u8]) -> Result<Self::PrivateKey, CryptoError>;

	/// Validate that bytes represent valid key material
	fn validate_key_material(bytes: &[u8]) -> bool;

	/// Get the expected key size in bytes
	fn key_size() -> usize;
}

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
	/// ECDSA over secp256k1 curve
	Secp256k1,
	/// Ed25519 digital signature algorithm
	Ed25519,
	/// ECDSA over secp256r1 curve (placeholder)
	Secp256r1,
}

impl Algorithm {
	/// Get the algorithm identifier
	pub fn id(&self) -> u8 {
		match self {
			Algorithm::Secp256k1 => 0,
			Algorithm::Ed25519 => 1,
			Algorithm::Secp256r1 => 6,
		}
	}

	/// Create from algorithm identifier
	pub fn from_id(id: u8) -> Result<Self, CryptoError> {
		match id {
			0 => Ok(Algorithm::Secp256k1),
			1 => Ok(Algorithm::Ed25519),
			6 => Ok(Algorithm::Secp256r1),
			_ => Err(CryptoError::UnsupportedAlgorithm { algorithm: format!("Unknown algorithm ID: {id}") }),
		}
	}
}
