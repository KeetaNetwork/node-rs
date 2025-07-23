use core::fmt::Debug;

use secrecy::SecretBox;

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
	+ Into<SecretBox<Vec<u8>>>
{
	type PublicKey: PublicKey<S>;
}

/// Fallback trait for when signature feature is disabled
#[cfg(not(feature = "signature"))]
pub trait PrivateKey:
	Clone + Send + Sync + Debug + for<'a> TryFrom<&'a [u8], Error = CryptoError> + Into<SecretBox<Vec<u8>>>
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
			AnyPrivateKey::Secp256k1(key) => AnyPublicKey::Secp256k1(key.verifying_key()),
			AnyPrivateKey::Ed25519(key) => AnyPublicKey::Ed25519(key.verifying_key()),
		}
	}

	pub fn to_bytes(&self) -> SecretBox<Vec<u8>> {
		match self {
			AnyPrivateKey::Secp256k1(key) => key.into(),
			AnyPrivateKey::Ed25519(key) => key.into(),
		}
	}
}

impl From<&AnyPrivateKey> for Algorithm {
	fn from(key: &AnyPrivateKey) -> Self {
		match key {
			AnyPrivateKey::Secp256k1(_) => Algorithm::Secp256k1,
			AnyPrivateKey::Ed25519(_) => Algorithm::Ed25519,
		}
	}
}

impl From<AnyPrivateKey> for Algorithm {
	fn from(key: AnyPrivateKey) -> Self {
		match key {
			AnyPrivateKey::Secp256k1(_) => Algorithm::Secp256k1,
			AnyPrivateKey::Ed25519(_) => Algorithm::Ed25519,
		}
	}
}

impl AnyPublicKey {
	pub fn to_bytes(&self) -> Vec<u8> {
		match self {
			AnyPublicKey::Secp256k1(key) => key.into(),
			AnyPublicKey::Ed25519(key) => key.into(),
		}
	}
}

impl From<&AnyPublicKey> for Algorithm {
	fn from(key: &AnyPublicKey) -> Self {
		match key {
			AnyPublicKey::Secp256k1(_) => Algorithm::Secp256k1,
			AnyPublicKey::Ed25519(_) => Algorithm::Ed25519,
		}
	}
}

impl From<AnyPublicKey> for Algorithm {
	fn from(key: AnyPublicKey) -> Self {
		match key {
			AnyPublicKey::Secp256k1(_) => Algorithm::Secp256k1,
			AnyPublicKey::Ed25519(_) => Algorithm::Ed25519,
		}
	}
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_algorithm_from_any_private_key() {
		let seed = b"test seed for algorithm conversion!!";

		let secp256k1_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let any_secp256k1 = AnyPrivateKey::Secp256k1(secp256k1_key);
		assert_eq!(Algorithm::from(&any_secp256k1), Algorithm::Secp256k1);
		assert_eq!(Algorithm::from(any_secp256k1), Algorithm::Secp256k1);

		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let any_ed25519 = AnyPrivateKey::Ed25519(ed25519_key);
		assert_eq!(Algorithm::from(&any_ed25519), Algorithm::Ed25519);
		assert_eq!(Algorithm::from(any_ed25519), Algorithm::Ed25519);
	}

	#[test]
	fn test_algorithm_from_any_public_key() {
		let seed = b"test seed for algorithm conversion!!";

		let secp256k1_private = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let secp256k1_public = secp256k1_private.verifying_key();
		let any_secp256k1_pub = AnyPublicKey::Secp256k1(secp256k1_public);
		assert_eq!(Algorithm::from(&any_secp256k1_pub), Algorithm::Secp256k1);
		assert_eq!(Algorithm::from(any_secp256k1_pub), Algorithm::Secp256k1);

		let ed25519_private = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let ed25519_public = ed25519_private.verifying_key();
		let any_ed25519_pub = AnyPublicKey::Ed25519(ed25519_public);
		assert_eq!(Algorithm::from(&any_ed25519_pub), Algorithm::Ed25519);
		assert_eq!(Algorithm::from(any_ed25519_pub), Algorithm::Ed25519);
	}
}
