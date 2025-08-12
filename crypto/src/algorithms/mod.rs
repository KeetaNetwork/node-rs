use core::fmt::Debug;
use secrecy::SecretBox;
use strum_macros::{Display, EnumIter, EnumString};

#[cfg(feature = "der")]
use asn1::oids;
#[cfg(feature = "der")]
use asn1::{AlgorithmIdentifier, Any, ObjectIdentifier, SubjectPublicKeyInfo};

use crate::error::CryptoError;

// Algorithm implementations
pub mod ed25519;
pub mod secp256k1;
pub mod secp256r1;

// Encryption-related modules
#[cfg(feature = "encryption")]
pub mod aes_cbc;
#[cfg(feature = "encryption")]
pub mod aes_ctr;
#[cfg(feature = "encryption")]
pub mod aes_gcm;
#[cfg(feature = "encryption")]
pub mod ecies;

// Re-export algorithm implementations
pub use ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
pub use secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};
pub use secp256r1::{Secp256r1Derivation, Secp256r1PrivateKey, Secp256r1PublicKey};

// Re-export ECIES implementations when encryption is enabled
#[cfg(feature = "encryption")]
pub use ecies::{Ecies, EciesSecp256k1, EciesSecp256r1, EciesX25519};

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
	/// Get uncompressed public key bytes.
	///
	/// # Returns
	/// Returns the public key in uncompressed format
	fn to_uncompressed_bytes(&self) -> Vec<u8>;
}

macro_rules! impl_any_key {
	(
		$any_key_type:ident,
		$any_public_key_type:ident,
		$(($variant:ident, $key_type:ty, $algorithm:expr)),* $(,)?
	) => {
		/// Enum to hold different key types
		#[derive(Debug, Clone)]
		pub enum $any_key_type {
			$(
				$variant($key_type),
			)*
		}

		impl From<&$any_key_type> for Algorithm {
			fn from(key: &$any_key_type) -> Self {
				match key {
					$(
						$any_key_type::$variant(_) => $algorithm,
					)*
				}
			}
		}

		impl From<$any_key_type> for Algorithm {
			fn from(key: $any_key_type) -> Self {
				match key {
					$(
						$any_key_type::$variant(_) => $algorithm,
					)*
				}
			}
		}
	};
}

impl_any_key!(
	AnyPrivateKey,
	AnyPublicKey,
	(Secp256k1, Secp256k1PrivateKey, Algorithm::Secp256k1),
	(Ed25519, Ed25519PrivateKey, Algorithm::Ed25519),
	(Secp256r1, Secp256r1PrivateKey, Algorithm::Secp256r1),
);

impl AnyPrivateKey {
	pub fn derive_public_key(&self) -> AnyPublicKey {
		match self {
			AnyPrivateKey::Secp256k1(key) => AnyPublicKey::Secp256k1(key.as_public_key()),
			AnyPrivateKey::Ed25519(key) => AnyPublicKey::Ed25519(key.as_public_key()),
			AnyPrivateKey::Secp256r1(key) => AnyPublicKey::Secp256r1(key.as_public_key()),
		}
	}

	pub fn to_bytes(&self) -> SecretBox<Vec<u8>> {
		match self {
			AnyPrivateKey::Secp256k1(key) => key.into(),
			AnyPrivateKey::Ed25519(key) => key.into(),
			AnyPrivateKey::Secp256r1(key) => key.into(),
		}
	}
}

impl_any_key!(
	AnyPublicKey,
	AnyPublicKey,
	(Secp256k1, Secp256k1PublicKey, Algorithm::Secp256k1),
	(Ed25519, Ed25519PublicKey, Algorithm::Ed25519),
	(Secp256r1, Secp256r1PublicKey, Algorithm::Secp256r1),
);

impl AnyPublicKey {
	pub fn to_bytes(&self) -> Vec<u8> {
		match self {
			AnyPublicKey::Secp256k1(key) => key.into(),
			AnyPublicKey::Ed25519(key) => key.into(),
			AnyPublicKey::Secp256r1(key) => key.into(),
		}
	}
}

#[cfg(feature = "der")]
macro_rules! impl_subject_public_key_info {
	($(($variant:ident, $oid:expr, $params_oid:expr)),* $(,)?) => {
		impl From<AnyPublicKey> for SubjectPublicKeyInfo {
			fn from(key: AnyPublicKey) -> Self {
				match key {
					$(
						AnyPublicKey::$variant(public_key) => {
							let algorithm = ObjectIdentifier::new($oid).unwrap();
							let parameters = $params_oid.map(|oid| Any::from(ObjectIdentifier::new(oid).unwrap()));
							let algorithm_id = AlgorithmIdentifier { algorithm, parameters };

							SubjectPublicKeyInfo::new(algorithm_id, &Vec::<u8>::from(public_key)).unwrap()
						}
					)*
				}
			}
		}
	};
}

#[cfg(feature = "der")]
impl_subject_public_key_info!(
	(Secp256k1, oids::EC_PUBLIC_KEY, Some(oids::SECP256K1)),
	(Ed25519, oids::ED25519, None),
	(Secp256r1, oids::EC_PUBLIC_KEY, Some(oids::SECP256R1)),
);

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, EnumIter, Display)]
pub enum Algorithm {
	/// ECDSA over secp256k1 curve
	#[strum(serialize = "secp256k1")]
	Secp256k1,
	/// Ed25519 digital signature algorithm
	#[strum(serialize = "Ed25519")]
	Ed25519,
	/// ECDSA over secp256r1 curve (NIST P-256)
	#[strum(serialize = "secp256r1")]
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
	use secrecy::ExposeSecret;

	const TEST_SEED: &str =
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

	struct AlgorithmTestData {
		algorithm: Algorithm,
		seed_suffix: &'static str,
		expected_id: u8,
	}

	impl AlgorithmTestData {
		const TEST_CASES: &'static [Self] = &[
			Self { algorithm: Algorithm::Secp256k1, seed_suffix: "secp256k1", expected_id: 0 },
			Self { algorithm: Algorithm::Ed25519, seed_suffix: "ed25519", expected_id: 1 },
			Self { algorithm: Algorithm::Secp256r1, seed_suffix: "secp256r1", expected_id: 6 },
		];

		fn create_any_private_key(&self, base_seed: &[u8]) -> AnyPrivateKey {
			let mut seed = base_seed.to_vec();
			seed.extend_from_slice(self.seed_suffix.as_bytes());

			match self.algorithm {
				Algorithm::Secp256k1 => {
					let key = Secp256k1Derivation::derive_from_seed(&seed).unwrap();
					AnyPrivateKey::Secp256k1(key)
				}
				Algorithm::Ed25519 => {
					let key = Ed25519Derivation::derive_from_seed(&seed).unwrap();
					AnyPrivateKey::Ed25519(key)
				}
				Algorithm::Secp256r1 => {
					let key = Secp256r1Derivation::derive_from_seed(&seed).unwrap();
					AnyPrivateKey::Secp256r1(key)
				}
			}
		}

		fn create_any_public_key(&self, base_seed: &[u8]) -> AnyPublicKey {
			self.create_any_private_key(base_seed).derive_public_key()
		}
	}

	#[test]
	fn test_algorithm_from_any_private_key() {
		for test_case in AlgorithmTestData::TEST_CASES {
			let any_private_key = test_case.create_any_private_key(TEST_SEED.as_bytes());
			assert_eq!(Algorithm::from(&any_private_key), test_case.algorithm);
			assert_eq!(Algorithm::from(any_private_key), test_case.algorithm);
		}
	}

	#[test]
	fn test_algorithm_from_any_public_key() {
		for test_case in AlgorithmTestData::TEST_CASES {
			let any_public_key = test_case.create_any_public_key(TEST_SEED.as_bytes());
			assert_eq!(Algorithm::from(&any_public_key), test_case.algorithm);
			assert_eq!(Algorithm::from(any_public_key), test_case.algorithm);
		}
	}

	#[test]
	fn test_any_private_key_operations() {
		for test_case in AlgorithmTestData::TEST_CASES {
			let any_private_key = test_case.create_any_private_key(TEST_SEED.as_bytes());

			// Test derive_public_key preserves the key data
			let derived_public = any_private_key.derive_public_key();
			let expected_public = test_case.create_any_public_key(TEST_SEED.as_bytes());
			assert_eq!(derived_public.to_bytes(), expected_public.to_bytes());

			// Test to_bytes returns non-empty secret data
			let any_key_bytes = any_private_key.to_bytes();
			assert!(!any_key_bytes.expose_secret().is_empty());
		}
	}

	#[test]
	fn test_any_public_key_operations() {
		for test_case in AlgorithmTestData::TEST_CASES {
			let any_public_key = test_case.create_any_public_key(TEST_SEED.as_bytes());

			// Test to_bytes returns non-empty public key data
			let any_pub_bytes = any_public_key.to_bytes();
			assert!(!any_pub_bytes.is_empty());
			// Test algorithm detection
			assert_eq!(Algorithm::from(&any_public_key), test_case.algorithm);
		}
	}

	#[test]
	fn test_algorithm_id_and_conversion() {
		for test_case in AlgorithmTestData::TEST_CASES {
			// Test algorithm ID
			assert_eq!(test_case.algorithm.id(), test_case.expected_id);
			// Test from_id
			assert_eq!(Algorithm::from_id(test_case.expected_id).unwrap(), test_case.algorithm);
			// Test u8 conversions
			assert_eq!(u8::from(test_case.algorithm), test_case.expected_id);
			// Test TryFrom<u8>
			assert_eq!(Algorithm::try_from(test_case.expected_id).unwrap(), test_case.algorithm);
		}

		// Test invalid ID
		assert!(Algorithm::from_id(99).is_err());
		assert!(Algorithm::try_from(99u8).is_err());
	}

	#[cfg(feature = "der")]
	#[test]
	fn test_any_public_key_to_subject_public_key_info() {
		struct SubjectPublicKeyInfoTestCase {
			algorithm: Algorithm,
			expected_algorithm_oid: &'static str,
			has_parameters: bool,
		}

		const TEST_CASES: &[SubjectPublicKeyInfoTestCase] = &[
			SubjectPublicKeyInfoTestCase {
				algorithm: Algorithm::Secp256k1,
				expected_algorithm_oid: oids::EC_PUBLIC_KEY,
				has_parameters: true,
			},
			SubjectPublicKeyInfoTestCase {
				algorithm: Algorithm::Ed25519,
				expected_algorithm_oid: oids::ED25519,
				has_parameters: false,
			},
			SubjectPublicKeyInfoTestCase {
				algorithm: Algorithm::Secp256r1,
				expected_algorithm_oid: oids::EC_PUBLIC_KEY,
				has_parameters: true,
			},
		];

		for test_case in TEST_CASES {
			let test_data = AlgorithmTestData::TEST_CASES
				.iter()
				.find(|data| data.algorithm == test_case.algorithm)
				.unwrap();

			// Test data persistence
			let any_public_key = test_data.create_any_public_key(TEST_SEED.as_bytes());
			let subject_public_key_info = SubjectPublicKeyInfo::from(any_public_key.clone());
			assert_eq!(subject_public_key_info.algorithm.algorithm.to_string(), test_case.expected_algorithm_oid);
			assert_eq!(subject_public_key_info.algorithm.parameters.is_some(), test_case.has_parameters);

			// Test that public key bytes are preserved
			let original_bytes = any_public_key.to_bytes();
			let spki_bytes = subject_public_key_info.subject_public_key.raw_bytes();
			assert_eq!(original_bytes, spki_bytes);
		}
	}
}
