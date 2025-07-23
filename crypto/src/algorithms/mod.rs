use core::fmt::Debug;

use crate::error::CryptoError;

#[cfg(feature = "signature")]
use ::signature::{Keypair, Verifier};

// Algorithm implementations
pub mod ed25519;
pub mod secp256k1;

// Re-export algorithm implementations
pub use ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
pub use secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};

/// Trait for cryptographic private keys that can be used for signing.
///
/// This extends RustCrypto's Keypair trait with serialization capabilities
#[cfg(feature = "signature")]
pub trait PrivateKey<S>:
	Keypair<VerifyingKey = Self::PublicKey>
	+ Clone
	+ Send
	+ Sync
	+ Debug
	+ for<'a> TryFrom<&'a [u8], Error = CryptoError>
	+ Into<Vec<u8>>
{
	type PublicKey: PublicKey<S>;
}

/// Fallback trait for when signature feature is disabled
#[cfg(not(feature = "signature"))]
pub trait PrivateKey:
	Clone + Send + Sync + Debug + for<'a> TryFrom<&'a [u8], Error = CryptoError> + Into<Vec<u8>>
{
	type PublicKey: PublicKey;

	/// Get the verifying key (public key) for this private key
	///
	/// This method name matches RustCrypto's Keypair trait for consistency
	fn verifying_key(&self) -> Self::PublicKey;
}

/// Trait for cryptographic public keys that can be used for verification
///
/// This extends RustCrypto's Verifier trait with serialization capabilities
#[cfg(feature = "signature")]
pub trait PublicKey<S>:
	Verifier<S> + Clone + Send + Sync + Debug + for<'a> TryFrom<&'a [u8], Error = CryptoError> + Into<Vec<u8>>
{
}

/// Fallback trait for when signature feature is disabled
#[cfg(not(feature = "signature"))]
pub trait PublicKey:
	Clone + Send + Sync + Debug + for<'a> TryFrom<&'a [u8], Error = CryptoError> + Into<Vec<u8>>
{
}

/// Trait for key derivation algorithms
#[cfg(feature = "signature")]
pub trait KeyDerivation<S> {
	type PrivateKey: PrivateKey<S>;

	/// Derive a private key from seed material
	fn derive_from_seed(seed: &[u8]) -> Result<Self::PrivateKey, CryptoError>;

	/// Validate that bytes represent valid key material
	fn validate_key_material(bytes: &[u8]) -> bool;

	/// Get the expected key size in bytes
	fn key_size() -> usize;
}

/// Fallback trait for when signature feature is disabled
#[cfg(not(feature = "signature"))]
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
		(*self).into()
	}

	/// Create from algorithm identifier
	pub fn from_id(id: u8) -> Result<Self, CryptoError> {
		id.try_into()
	}
}

impl From<Algorithm> for u8 {
	fn from(algorithm: Algorithm) -> Self {
		match algorithm {
			Algorithm::Secp256k1 => 0,
			Algorithm::Ed25519 => 1,
			Algorithm::Secp256r1 => 6,
		}
	}
}

impl TryFrom<u8> for Algorithm {
	type Error = CryptoError;

	fn try_from(id: u8) -> Result<Self, Self::Error> {
		match id {
			0 => Ok(Algorithm::Secp256k1),
			1 => Ok(Algorithm::Ed25519),
			6 => Ok(Algorithm::Secp256r1),
			_ => Err(CryptoError::UnsupportedAlgorithm { algorithm: format!("Unknown algorithm ID: {id}") }),
		}
	}
}
