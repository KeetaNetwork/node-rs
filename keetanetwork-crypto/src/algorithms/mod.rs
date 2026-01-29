use core::fmt::Debug;

use secrecy::SecretBox;
use strum_macros::{Display, EnumIter, EnumString};
use zeroize::ZeroizeOnDrop;

#[cfg(any(feature = "der", feature = "rasn"))]
use keetanetwork_asn1::oids;
#[cfg(all(feature = "rasn", not(feature = "der")))]
use keetanetwork_asn1::ObjectIdentifierExt;
#[cfg(any(feature = "der", feature = "rasn"))]
use keetanetwork_asn1::{AlgorithmIdentifier, Any, ObjectIdentifier, SubjectPublicKeyInfo};

use crate::algorithms::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::algorithms::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::algorithms::secp256r1::{Secp256r1PrivateKey, Secp256r1PublicKey};
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

/// Trait for cryptographic private keys that can be used for signing.
pub trait PrivateKey:
	Send + Sync + Debug + ZeroizeOnDrop + for<'a> TryFrom<&'a [u8], Error = CryptoError> + Into<SecretBox<Vec<u8>>>
{
	type PublicKey: PublicKey;
	type Signature: Clone + Send + Sync + Debug;

	/// Get the public key for this private key
	///
	/// # Returns
	/// Returns the public key
	fn as_public_key(&self) -> Self::PublicKey;
}

/// Trait for cryptographic public keys that can be used for verification.
pub trait PublicKey:
	Clone + Send + Sync + Debug + for<'a> TryFrom<&'a [u8], Error = CryptoError> + Into<Vec<u8>> + AsRef<[u8]>
{
	/// Get uncompressed public key bytes.
	///
	/// # Returns
	/// Returns the public key in uncompressed format
	fn to_uncompressed_bytes(&self) -> Vec<u8>;
}

macro_rules! impl_any_private_key {
	(
		$any_key_type:ident,
		$any_public_key_type:ident,
		$(($variant:ident, $key_type:ty, $algorithm:expr)),* $(,)?
	) => {
		/// Enum to hold different key types
		#[derive(Debug)]
		pub enum $any_key_type {
			$(
				$variant($key_type),
			)*
		}

		impl $any_key_type {
			pub fn derive_public_key(&self) -> $any_public_key_type {
				match self {
					$(
						$any_key_type::$variant(key) => $any_public_key_type::$variant(key.as_public_key()),
					)*
				}
			}

			pub fn to_bytes(&self) -> SecretBox<Vec<u8>> {
				match self {
					$(
						$any_key_type::$variant(key) => key.into(),
					)*
				}
			}
		}

		impl CryptoAlgorithm for $any_key_type {
			fn to_algorithm(&self) -> Algorithm {
				match self {
					$(
						$any_key_type::$variant(key) => key.into(),
					)*
				}
			}
		}
	};
}

impl_any_private_key!(
	AnyPrivateKey,
	AnyPublicKey,
	(Secp256k1, Secp256k1PrivateKey, Algorithm::Secp256k1),
	(Ed25519, Ed25519PrivateKey, Algorithm::Ed25519),
	(Secp256r1, Secp256r1PrivateKey, Algorithm::Secp256r1),
);

macro_rules! impl_any_public_key {
	(
		$any_key_type:ident,
		$any_public_key_type:ident,
		$(($variant:ident, $key_type:ty, $algorithm:expr)),* $(,)?
	) => {
		/// Enum to hold different key types
		#[derive(Clone, Debug, Eq, PartialEq)]
		pub enum $any_key_type {
			$(
				$variant($key_type),
			)*
		}

		impl $any_key_type {
			pub fn to_bytes(&self) -> Vec<u8> {
				match self {
					$(
						$any_key_type::$variant(key) => key.into(),
					)*
				}
			}
		}

		impl CryptoAlgorithm for $any_key_type {
			fn to_algorithm(&self) -> Algorithm {
				match self {
					$(
						$any_key_type::$variant(key) => key.into(),
					)*
				}
			}
		}

		// From implementations for AnyPublicKey
		$(
			impl From<$key_type> for $any_key_type {
				fn from(key: $key_type) -> Self {
					$any_key_type::$variant(key)
				}
			}
		)*

		// TryFrom implementations from AnyPublicKey to specific types
		$(
			impl TryFrom<$any_key_type> for $key_type {
				type Error = CryptoError;

				fn try_from(key: $any_key_type) -> Result<Self, Self::Error> {
					match key {
						$any_key_type::$variant(key) => Ok(key),
						_ => Err(CryptoError::UnsupportedAlgorithm {
							algorithm: format!("Expected {}, found {:?}", stringify!($variant), key.to_algorithm()),
						}),
					}
				}
			}
		)*
	};
}

impl_any_public_key!(
	AnyPublicKey,
	AnyPublicKey,
	(Secp256k1, Secp256k1PublicKey, Algorithm::Secp256k1),
	(Ed25519, Ed25519PublicKey, Algorithm::Ed25519),
	(Secp256r1, Secp256r1PublicKey, Algorithm::Secp256r1),
);

#[cfg(feature = "signature")]
macro_rules! impl_any_signature {
	(
		$any_signature_type:ident,
		$(($variant:ident, $signature_type:ty, $algorithm:expr)),* $(,)?
	) => {
		/// Enum to hold different signature types
		#[derive(Debug, Clone)]
		pub enum $any_signature_type {
			$(
				$variant($signature_type),
			)*
		}

		impl $any_signature_type {
			pub fn to_bytes(&self) -> Vec<u8> {
				match self {
					$(
						$any_signature_type::$variant(sig) => sig.to_vec(),
					)*
				}
			}
		}

		impl CryptoAlgorithm for $any_signature_type {
			fn to_algorithm(&self) -> Algorithm {
				match self {
					$(
						$any_signature_type::$variant(_) => $algorithm,
					)*
				}
			}
		}
	};
}

#[cfg(feature = "signature")]
impl_any_signature!(
	AnySignature,
	(Secp256k1, crate::algorithms::secp256k1::Secp256k1Signature, Algorithm::Secp256k1),
	(Ed25519, crate::algorithms::ed25519::Ed25519Signature, Algorithm::Ed25519),
	(Secp256r1, crate::algorithms::secp256r1::Secp256r1Signature, Algorithm::Secp256r1),
);

/// Helper function to wrap an ObjectIdentifier in Any for parameters (rasn backend)
#[cfg(all(feature = "rasn", not(feature = "der")))]
fn create_parameter_any(oid: ObjectIdentifier) -> Any {
	let encoded_bytes = oid
		.to_der()
		.expect("invariant: valid OID always encodes to DER");
	Any::from(encoded_bytes)
}

/// Helper function to wrap an ObjectIdentifier in Any for parameters (der backend)
#[cfg(feature = "der")]
fn create_parameter_any(oid: ObjectIdentifier) -> Any {
	Any::from(oid)
}

#[cfg(any(feature = "der", feature = "rasn"))]
macro_rules! impl_subject_public_key_info {
	($(($variant:ident, $public_key_type:ty, $oid:expr, $params_oid:expr)),* $(,)?) => {
		impl From<Algorithm> for ObjectIdentifier {
			fn from(algorithm: Algorithm) -> Self {
				match algorithm {
					$(
						Algorithm::$variant => $oid,
					)*
				}
			}
		}

		$(
			impl From<$public_key_type> for SubjectPublicKeyInfo {
				fn from(public_key: $public_key_type) -> Self {
					let algorithm = ObjectIdentifier::from(Algorithm::$variant);
					let parameters: Option<ObjectIdentifier> = $params_oid;
					let parameters = parameters.map(create_parameter_any);
					let algorithm_id = AlgorithmIdentifier { algorithm, parameters };
				let public_key_bytes = Vec::from(public_key);
				SubjectPublicKeyInfo::new(algorithm_id, &public_key_bytes).expect("invariant: valid algorithm and key bytes create SubjectPublicKeyInfo")
				}
			}
		)*

		impl From<AnyPublicKey> for SubjectPublicKeyInfo {
			fn from(key: AnyPublicKey) -> Self {
				match key {
					$(
						AnyPublicKey::$variant(public_key) => SubjectPublicKeyInfo::from(public_key),
					)*
				}
			}
		}

		impl From<Algorithm> for AlgorithmIdentifier {
			fn from(algorithm: Algorithm) -> Self {
				let oid = ObjectIdentifier::from(algorithm);
				let parameters: Option<ObjectIdentifier> = match algorithm {
					$(
						Algorithm::$variant => $params_oid,
					)*
				};
				let parameters = parameters.map(create_parameter_any);
				AlgorithmIdentifier { algorithm: oid, parameters }
			}
		}
	};
}

#[cfg(feature = "der")]
impl_subject_public_key_info!(
	(Secp256k1, Secp256k1PublicKey, oids::typed::EC_PUBLIC_KEY, Some(oids::typed::SECP256K1)),
	(Ed25519, Ed25519PublicKey, oids::typed::ED25519, None),
	(Secp256r1, Secp256r1PublicKey, oids::typed::EC_PUBLIC_KEY, Some(oids::typed::SECP256R1)),
);

#[cfg(all(feature = "rasn", not(feature = "der")))]
impl_subject_public_key_info!(
	(Secp256k1, Secp256k1PublicKey, oids::typed::EC_PUBLIC_KEY.clone(), Some(oids::typed::SECP256K1.clone())),
	(Ed25519, Ed25519PublicKey, oids::typed::ED25519.clone(), None),
	(Secp256r1, Secp256r1PublicKey, oids::typed::EC_PUBLIC_KEY.clone(), Some(oids::typed::SECP256R1.clone())),
);

/// Trait for key derivation algorithms
pub trait KeyDerivation {
	type PrivateKey: PrivateKey;

	/// Derive a private key from seed material
	fn derive_from_seed<T>(seed: SecretBox<T>) -> Result<Self::PrivateKey, CryptoError>
	where
		T: IntoIterator<Item = u8> + AsRef<[u8]> + zeroize::Zeroize + Clone;

	/// Validate that bytes represent valid key material
	fn is_valid_key_material<T: AsRef<[u8]>>(bytes: T) -> bool;

	/// Get the expected key size in bytes
	fn key_size() -> usize;
}

/// Macro to implement constant-time key derivation from seed.
///
/// This macro generates a secure, constant-time `derive_from_seed`:
/// - Always performs exactly 100 iterations even when a valid key is found
/// - Uses memory fences to prevent timing leaks from speculative execution
/// - Stores the first valid key found but continues the full loop
/// - Provides resistance against timing-based side-channel attacks
///
/// # Usage
/// ```rust,ignore
/// impl_constant_time_key_derivation!(Secp256k1PrivateKey, K256SecretKey, Secp256k1Derivation);
/// ```
///
/// # Parameters
/// - `$private_key_type`: The wrapper type for the private key (e.g., Secp256k1PrivateKey)
/// - `$secret_key_type`: The inner secret key type (e.g., K256SecretKey)
/// - `$derivation_type`: The derivation struct type (e.g., Secp256k1Derivation)
#[macro_export]
macro_rules! impl_constant_time_key_derivation {
	($private_key_type:ty, $secret_key_type:ty, $derivation_type:ty) => {
		impl KeyDerivation for $derivation_type {
			type PrivateKey = $private_key_type;

			fn derive_from_seed<T>(seed: SecretBox<T>) -> Result<Self::PrivateKey, CryptoError>
			where
				T: IntoIterator<Item = u8> + AsRef<[u8]> + zeroize::Zeroize + Clone + ?Sized,
			{
				use secrecy::ExposeSecret;

				let seed_iter = <T as Clone>::clone(&seed.expose_secret()).into_iter();
				let mut attempt_seed = seed_iter.collect::<Vec<u8>>();
				let original_seed_len = attempt_seed.len();
				let mut result_key: Option<$secret_key_type> = None;
				let mut found_valid = false;

				// Pre-derivation fence: Ensure no prior operations leak timing info
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

				// Always perform exactly 100 iterations for constant time
				for attempt in 0u32..100 {
					// For attempts > 0, append the attempt counter
					if attempt > 0 {
						// Remove any previous attempt counter and add the new one
						attempt_seed.truncate(original_seed_len);
						attempt_seed.extend_from_slice(&attempt.to_be_bytes());
					}

					// Use our KDF's expand-only method
					let key_bytes = KdfAlgorithm::HkdfSha3_256.expand_only_array::<32>(&attempt_seed, &[])?;
					// Constant-time: always attempt to create the secret key
					if let Ok(secret_key) = <$secret_key_type>::from_slice(&key_bytes) {
						// Only store the first valid key we find, but continue the loop
						if !found_valid {
							result_key = Some(secret_key);
							found_valid = true;
						}
					}
				}

				// Post-attempt fence: Ensure operations complete before next iteration
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

				match result_key {
					Some(secret_key) => Ok(<$private_key_type>::from_inner(secret_key)),
					None => Err(CryptoError::KeyDerivationFailed),
				}
			}

			fn is_valid_key_material<T: AsRef<[u8]>>(bytes: T) -> bool {
				let bytes = bytes.as_ref();
				bytes.len() == 32 && <$secret_key_type>::from_slice(bytes).is_ok()
			}

			fn key_size() -> usize {
				32
			}
		}
	};
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

/// Core cryptographic algorithm trait
pub trait CryptoAlgorithm: Send + Sync {
	/// Get the cryptographic algorithm used by this implementation
	fn to_algorithm(&self) -> Algorithm;
}

/// Blanket implementation: anything that implements CryptoAlgorithm can be converted to Algorithm
impl<T: CryptoAlgorithm> From<&T> for Algorithm {
	fn from(crypto_algo: &T) -> Self {
		crypto_algo.to_algorithm()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::algorithms::ed25519::Ed25519Derivation;
	use crate::algorithms::secp256k1::Secp256k1Derivation;
	use crate::algorithms::secp256r1::Secp256r1Derivation;
	use crate::prelude::{ExposeSecret, IntoSecret};

	#[cfg(feature = "signature")]
	use crate::prelude::{CryptoSignerWithOptions, SigningOptions};

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	use keetanetwork_asn1::BitStringExt;

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
			let secret_seed = seed.into_secret();

			match self.algorithm {
				Algorithm::Secp256k1 => {
					let key = Secp256k1Derivation::derive_from_seed(secret_seed).unwrap();
					AnyPrivateKey::Secp256k1(key)
				}
				Algorithm::Ed25519 => {
					let key = Ed25519Derivation::derive_from_seed(secret_seed).unwrap();
					AnyPrivateKey::Ed25519(key)
				}
				Algorithm::Secp256r1 => {
					let key = Secp256r1Derivation::derive_from_seed(secret_seed).unwrap();
					AnyPrivateKey::Secp256r1(key)
				}
			}
		}

		fn create_any_public_key(&self, base_seed: &[u8]) -> AnyPublicKey {
			self.create_any_private_key(base_seed).derive_public_key()
		}

		#[cfg(feature = "signature")]
		fn create_any_signature(&self, base_seed: &[u8], message: &[u8]) -> AnySignature {
			let private_key = self.create_any_private_key(base_seed);
			match private_key {
				AnyPrivateKey::Secp256k1(key) => {
					let sig = key
						.sign_with_options(message, SigningOptions::default())
						.unwrap();
					AnySignature::Secp256k1(sig)
				}
				AnyPrivateKey::Ed25519(key) => {
					let sig = key
						.sign_with_options(message, SigningOptions::default())
						.unwrap();
					AnySignature::Ed25519(sig)
				}
				AnyPrivateKey::Secp256r1(key) => {
					let sig = key
						.sign_with_options(message, SigningOptions::default())
						.unwrap();
					AnySignature::Secp256r1(sig)
				}
			}
		}
	}

	#[test]
	fn test_to_algorithm() {
		for test_case in AlgorithmTestData::TEST_CASES {
			let any_private_key = test_case.create_any_private_key(TEST_SEED.as_bytes());
			assert_eq!(any_private_key.to_algorithm(), test_case.algorithm);
			assert_eq!(Algorithm::from(&any_private_key), test_case.algorithm);

			let any_public_key = test_case.create_any_public_key(TEST_SEED.as_bytes());
			assert_eq!(any_public_key.to_algorithm(), test_case.algorithm);
			assert_eq!(Algorithm::from(&any_public_key), test_case.algorithm);
		}
	}

	#[test]
	fn test_algorithm_from_any_private_key() {
		for test_case in AlgorithmTestData::TEST_CASES {
			let any_private_key = test_case.create_any_private_key(TEST_SEED.as_bytes());
			assert_eq!(Algorithm::from(&any_private_key), test_case.algorithm);
		}
	}

	#[test]
	fn test_algorithm_from_any_public_key() {
		for test_case in AlgorithmTestData::TEST_CASES {
			let any_public_key = test_case.create_any_public_key(TEST_SEED.as_bytes());
			assert_eq!(Algorithm::from(&any_public_key), test_case.algorithm);
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
	fn test_any_public_key_conversions() {
		macro_rules! test_conversion {
			($test_case:expr, $key_type:ty) => {{
				// Create keys using existing test data
				// Test From conversion (specific -> Any)
				let any_key = $test_case.create_any_public_key(TEST_SEED.as_bytes());
				assert_eq!(any_key.to_algorithm(), $test_case.algorithm);

				// Test round-trip conversion (Any -> specific -> Any)
				let converted_specific: $key_type = any_key.clone().try_into().unwrap();
				let converted_back: AnyPublicKey = converted_specific.into();
				assert_eq!(converted_back, any_key);

				// Test wrong type conversions fail
				for other_case in AlgorithmTestData::TEST_CASES {
					if other_case.algorithm != $test_case.algorithm {
						let other_key = other_case.create_any_public_key(TEST_SEED.as_bytes());
						let wrong_conversion: Result<$key_type, _> = other_key.try_into();
						assert!(wrong_conversion.is_err());
					}
				}
			}};
		}

		for test_case in AlgorithmTestData::TEST_CASES {
			match test_case.algorithm {
				Algorithm::Secp256k1 => test_conversion!(test_case, Secp256k1PublicKey),
				Algorithm::Ed25519 => test_conversion!(test_case, Ed25519PublicKey),
				Algorithm::Secp256r1 => test_conversion!(test_case, Secp256r1PublicKey),
			}
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

	#[cfg(any(feature = "der", feature = "rasn"))]
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

			// Test ObjectIdentifier
			let algorithm_oid = ObjectIdentifier::from(test_case.algorithm);
			assert_eq!(algorithm_oid.to_string(), test_case.expected_algorithm_oid);

			// Test AlgorithmIdentifier
			let algorithm_info = AlgorithmIdentifier::from(test_case.algorithm);
			assert_eq!(algorithm_info.algorithm.to_string(), test_case.expected_algorithm_oid);
			assert_eq!(algorithm_info.parameters.is_some(), test_case.has_parameters);

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

	#[cfg(feature = "signature")]
	#[test]
	fn test_any_signature_operations() {
		const TEST_MESSAGE: &[u8] = b"test message for signing";
		for test_case in AlgorithmTestData::TEST_CASES {
			// Test algorithm detection
			let any_signature = test_case.create_any_signature(TEST_SEED.as_bytes(), TEST_MESSAGE);
			assert_eq!(any_signature.to_algorithm(), test_case.algorithm);
			assert_eq!(Algorithm::from(&any_signature), test_case.algorithm);

			// Test to_bytes returns non-empty signature data
			let signature_bytes = any_signature.to_bytes();
			assert!(!signature_bytes.is_empty());
		}
	}
}
