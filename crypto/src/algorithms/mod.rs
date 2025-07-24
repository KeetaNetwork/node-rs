use core::fmt::Debug;

use secrecy::SecretBox;

use crate::error::CryptoError;

// Algorithm implementations
pub mod ed25519;
pub mod secp256k1;

// Re-export algorithm implementations
pub use ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
pub use secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};

/// Trait for cryptographic private keys that can be used for signing.
///
/// This extends RustCrypto's Keypair trait with serialization capabilities
pub trait PrivateKey:
	Clone + Send + Sync + Debug + for<'a> TryFrom<&'a [u8], Error = CryptoError> + Into<SecretBox<Vec<u8>>>
{
	type PublicKey: PublicKey;
	type Signature: Clone + Send + Sync + Debug;

	/// Get the public key for this private key
	fn as_public_key(&self) -> Self::PublicKey;
}

/// Trait for cryptographic public keys that can be used for verification
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
			AnyPrivateKey::Secp256k1(key) => AnyPublicKey::Secp256k1(key.as_public_key()),
			AnyPrivateKey::Ed25519(key) => AnyPublicKey::Ed25519(key.as_public_key()),
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
	use secrecy::{ExposeSecret, SecretBox};

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
		let secp256k1_public = secp256k1_private.as_public_key();
		let any_secp256k1_pub = AnyPublicKey::Secp256k1(secp256k1_public);
		assert_eq!(Algorithm::from(&any_secp256k1_pub), Algorithm::Secp256k1);
		assert_eq!(Algorithm::from(any_secp256k1_pub), Algorithm::Secp256k1);

		let ed25519_private = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let ed25519_public = ed25519_private.as_public_key();
		let any_ed25519_pub = AnyPublicKey::Ed25519(ed25519_public);
		assert_eq!(Algorithm::from(&any_ed25519_pub), Algorithm::Ed25519);
		assert_eq!(Algorithm::from(any_ed25519_pub), Algorithm::Ed25519);
	}

	#[test]
	fn test_any_private_key_operations() {
		let seed = b"test seed for any private key ops!!";

		// Test secp256k1 variant
		let secp256k1_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let any_secp256k1 = AnyPrivateKey::Secp256k1(secp256k1_key.clone());

		// Test derive_public_key
		let derived_public = any_secp256k1.derive_public_key();
		let expected_public = secp256k1_key.as_public_key();
		assert_eq!(derived_public.to_bytes(), Vec::<u8>::from(expected_public));

		// Test to_bytes
		let any_key_bytes = any_secp256k1.to_bytes();
		let expected_bytes = SecretBox::<Vec<u8>>::from(&secp256k1_key);
		assert_eq!(any_key_bytes.expose_secret(), expected_bytes.expose_secret());

		// Test Ed25519 variant
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let any_ed25519 = AnyPrivateKey::Ed25519(ed25519_key.clone());

		// Test derive_public_key
		let derived_public = any_ed25519.derive_public_key();
		let expected_public = ed25519_key.as_public_key();
		assert_eq!(derived_public.to_bytes(), Vec::<u8>::from(expected_public));

		// Test to_bytes
		let any_key_bytes = any_ed25519.to_bytes();
		let expected_bytes = SecretBox::<Vec<u8>>::from(&ed25519_key);
		assert_eq!(any_key_bytes.expose_secret(), expected_bytes.expose_secret());
	}

	#[test]
	fn test_any_public_key_operations() {
		let seed = b"test seed for any public key ops!!!";

		// Test secp256k1 variant
		let secp256k1_private = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let secp256k1_public = secp256k1_private.as_public_key();
		let any_secp256k1_pub = AnyPublicKey::Secp256k1(secp256k1_public.clone());

		// Test to_bytes
		let any_pub_bytes = any_secp256k1_pub.to_bytes();
		let expected_bytes = Vec::<u8>::from(&secp256k1_public);
		assert_eq!(any_pub_bytes, expected_bytes);

		// Test Ed25519 variant
		let ed25519_private = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let ed25519_public = ed25519_private.as_public_key();
		let any_ed25519_pub = AnyPublicKey::Ed25519(ed25519_public.clone());

		// Test to_bytes
		let any_pub_bytes = any_ed25519_pub.to_bytes();
		let expected_bytes = Vec::<u8>::from(&ed25519_public);
		assert_eq!(any_pub_bytes, expected_bytes);
	}

	#[test]
	fn test_algorithm_id_and_conversion() {
		// Test algorithm IDs
		assert_eq!(Algorithm::Secp256k1.id(), 0);
		assert_eq!(Algorithm::Ed25519.id(), 1);
		assert_eq!(Algorithm::Secp256r1.id(), 6);

		// Test from_id
		assert_eq!(Algorithm::from_id(0).unwrap(), Algorithm::Secp256k1);
		assert_eq!(Algorithm::from_id(1).unwrap(), Algorithm::Ed25519);
		assert_eq!(Algorithm::from_id(6).unwrap(), Algorithm::Secp256r1);

		// Test invalid ID
		assert!(Algorithm::from_id(99).is_err());

		// Test u8 conversions
		assert_eq!(u8::from(Algorithm::Secp256k1), 0);
		assert_eq!(u8::from(Algorithm::Ed25519), 1);
		assert_eq!(u8::from(Algorithm::Secp256r1), 6);

		// Test TryFrom<u8>
		assert_eq!(Algorithm::try_from(0u8).unwrap(), Algorithm::Secp256k1);
		assert_eq!(Algorithm::try_from(1u8).unwrap(), Algorithm::Ed25519);
		assert_eq!(Algorithm::try_from(6u8).unwrap(), Algorithm::Secp256r1);
		assert!(Algorithm::try_from(99u8).is_err());
	}
}
