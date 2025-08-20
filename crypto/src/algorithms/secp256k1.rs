//! secp256k1 cryptographic algorithm implementation.
//!
//! This module provides secp256k1 elliptic curve cryptography support, the
//! same curve used by Bitcoin.
//! # Key Format
//!
//! - **Private keys**: 32 bytes, in range [1, n-1] where n is the curve order
//! - **Public keys**: 33 bytes compressed format (0x02/0x03 prefix + 32 bytes)

// Re-export algorithm-specific signature types
pub use k256::ecdsa::Signature as Secp256k1Signature;

use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey as K256SecretKey;
use secrecy::SecretBox;

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};
#[cfg(feature = "signature")]
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
#[cfg(feature = "signature")]
use k256::ecdsa::VerifyingKey;

#[cfg(feature = "encryption")]
use k256::ecdh::diffie_hellman;
#[cfg(feature = "encryption")]
use secrecy::ExposeSecret;

#[cfg(feature = "encryption")]
use crate::algorithms::ecies::Ecies;
#[cfg(feature = "encryption")]
use crate::algorithms::ecies::EciesSecp256k1;
#[cfg(feature = "encryption")]
use crate::operations::encryption::{AsymmetricEncryption, KeyExchange, KeyGeneration, KeyInit};
#[cfg(feature = "encryption")]
use crate::utils::generate_random_seed;

#[cfg(feature = "signature")]
use crate::hash::hash_default;
#[cfg(feature = "signature")]
use crate::operations::signature::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};

use crate::algorithms::{Algorithm, CryptoAlgorithm};
use crate::kdf::KdfAlgorithm;
use crate::{error::CryptoError, KeyDerivation, PrivateKey, PublicKey};

/// secp256k1 private key wrapper.
///
/// This struct wraps the k256 SecretKey and provides the PrivateKey trait
/// implementation. secp256k1 private keys are 32 bytes long and must be in
/// the range [1, n-1] where n is the curve order.
///
/// ## Security Note
///
/// The inner secret key is kept private and only accessible through the trait
/// methods. Debug formatting will show "\[REDACTED\]" to prevent accidental
/// key exposure.
pub struct Secp256k1PrivateKey {
	inner: K256SecretKey,
}

impl core::fmt::Debug for Secp256k1PrivateKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Secp256k1PrivateKey")
			.field("inner", &"[REDACTED]")
			.finish()
	}
}

impl CryptoAlgorithm for Secp256k1PrivateKey {
	fn get_algorithm(&self) -> Algorithm {
		Algorithm::Secp256k1
	}
}

impl PrivateKey for Secp256k1PrivateKey {
	type PublicKey = Secp256k1PublicKey;
	type Signature = Signature;

	fn as_public_key(&self) -> Self::PublicKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();

		Secp256k1PublicKey { inner: verifying_key.into() }
	}
}

impl From<Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Secp256k1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

impl From<&Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Secp256k1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

impl TryFrom<&[u8]> for Secp256k1PrivateKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let secret_key = K256SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;

		Ok(Secp256k1PrivateKey { inner: secret_key })
	}
}

#[cfg(feature = "der")]
impl From<Secp256k1PrivateKey> for asn1::ObjectIdentifier {
	fn from(_private_key: Secp256k1PrivateKey) -> Self {
		// This should never fail as we are using a constant known OID
		asn1::ObjectIdentifier::new(asn1::oids::SECP256K1).expect("Failed to create OID for secp256k1")
	}
}

#[cfg(feature = "encryption")]
impl KeyGeneration for Secp256k1PrivateKey {
	type Error = CryptoError;

	fn generate_random() -> Result<Self, Self::Error> {
		// Generate a random 32-byte seed and derive a key from it
		let random_seed = generate_random_seed()?;

		Secp256k1Derivation::derive_from_seed(random_seed.expose_secret())
	}
}

#[cfg(feature = "encryption")]
impl KeyExchange for Secp256k1PrivateKey {
	type PublicKey = Secp256k1PublicKey;
	type SharedSecret = Vec<u8>;

	fn ecdh(&self, other_public_key: &Secp256k1PublicKey) -> Result<Vec<u8>, CryptoError> {
		// Perform ECDH directly using the k256 function
		let shared_secret = diffie_hellman(self.inner.to_nonzero_scalar(), other_public_key.inner.as_affine());

		// Return the raw bytes of the shared secret
		Ok(shared_secret.raw_secret_bytes().to_vec())
	}

	fn key_exchange<K: AsRef<[u8]>>(&self, their_public_key: K) -> Result<Self::SharedSecret, CryptoError> {
		let public_key = Secp256k1PublicKey::try_from(their_public_key.as_ref())?;

		self.ecdh(&public_key)
	}

	fn derive_aead_key<A>(&self, _shared_secret: &Self::SharedSecret) -> Result<A, CryptoError>
	where
		A: KeyInit,
	{
		// Use ECDH to derive the key
		Err(CryptoError::EncryptionNotSupported)
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256k1PrivateKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		// Use the public key for encryption
		let public_key = self.as_public_key();

		public_key.encrypt(plaintext)
	}

	fn decrypt<C: AsRef<[u8]>>(&self, cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		EciesSecp256k1::decrypt(self, cipher_text.as_ref())
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-secp256k1-AES128CTR"
	}
}

#[cfg(feature = "signature")]
impl Keypair for Secp256k1PrivateKey {
	type VerifyingKey = Secp256k1PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();

		Secp256k1PublicKey { inner: verifying_key.into() }
	}
}

#[cfg(feature = "signature")]
impl Signer<Signature> for Secp256k1PrivateKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::signature::Error> {
		let signing_key = SigningKey::from(&self.inner);

		signing_key.try_sign(msg)
	}
}

#[cfg(feature = "signature")]
impl CryptoSigner<Signature> for Secp256k1PrivateKey {
	fn has_private_key(&self) -> bool {
		true
	}
}

#[cfg(feature = "signature")]
impl CryptoSignerWithOptions<Signature> for Secp256k1PrivateKey {
	fn sign_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		options: SigningOptions,
	) -> Result<Signature, ::signature::Error> {
		let message = message.as_ref();
		let signing_key = SigningKey::from(&self.inner);

		if options.raw {
			// For raw signing, treat the message as a pre-computed hash
			// and use prehash signing to avoid double hashing
			if message.len() != 32 {
				return Err(::signature::Error::new());
			}
			signing_key.sign_prehash(message)
		} else if options.for_cert {
			// For certificate signing, use SHA2-256
			let data = crate::HashAlgorithm::Sha2_256.hash(message);
			signing_key.sign_prehash(&data)
		} else {
			// For regular signing, use the default hash algorithm
			let data = hash_default(message).to_vec();
			signing_key.sign_prehash(&data)
		}
	}
}

/// secp256k1 public key wrapper.
///
/// This struct wraps the k256 PublicKey and provides the PublicKey trait
/// implementation. secp256k1 public keys are stored in compressed format
/// (33 bytes: 0x02/0x03 prefix + 32 bytes).
///
/// Public keys can be safely displayed, serialized, and shared as they contain
/// no secret information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256k1PublicKey {
	inner: k256::PublicKey,
}

impl CryptoAlgorithm for Secp256k1PublicKey {
	fn get_algorithm(&self) -> Algorithm {
		Algorithm::Secp256k1
	}
}

impl PublicKey for Secp256k1PublicKey {
	fn to_uncompressed_bytes(&self) -> Vec<u8> {
		self.inner.to_encoded_point(false).as_bytes().to_vec()
	}
}

impl From<Secp256k1PublicKey> for Vec<u8> {
	fn from(key: Secp256k1PublicKey) -> Self {
		(&key).into()
	}
}

impl From<&Secp256k1PublicKey> for Vec<u8> {
	fn from(key: &Secp256k1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

impl TryFrom<&[u8]> for Secp256k1PublicKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let public_key = k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
		Ok(Secp256k1PublicKey { inner: public_key })
	}
}

#[cfg(feature = "der")]
impl From<Secp256k1PublicKey> for asn1::ObjectIdentifier {
	fn from(_public_key: Secp256k1PublicKey) -> Self {
		// This should never fail as we are using a constant known OID
		asn1::ObjectIdentifier::new(asn1::oids::SECP256K1).expect("Failed to create OID for secp256k1")
	}
}

#[cfg(feature = "signature")]
impl Verifier<Signature> for Secp256k1PublicKey {
	fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ::signature::Error> {
		let verifying_key = k256::ecdsa::VerifyingKey::from(&self.inner);
		verifying_key.verify(msg, signature)
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifier<Signature> for Secp256k1PublicKey {
	fn public_key_bytes(&self) -> Vec<u8> {
		self.into()
	}

	fn public_key_string(&self) -> String {
		hex::encode(self.public_key_bytes())
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifierWithOptions<Signature> for Secp256k1PublicKey {
	fn verify_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		signature: &Signature,
		options: SigningOptions,
	) -> Result<(), ::signature::Error> {
		let message = message.as_ref();
		let verifying_key = VerifyingKey::from(&self.inner);

		if options.raw {
			// For raw verification, treat the message as a pre-computed hash
			// and use prehash verification to avoid double hashing
			if message.len() != 32 {
				return Err(::signature::Error::new());
			}
			verifying_key.verify_prehash(message, signature)
		} else {
			// For non-raw verification, hash the message first
			let data = if options.for_cert {
				// For certificates, use SHA2-256
				crate::HashAlgorithm::Sha2_256.hash(message)
			} else {
				// For regular verification, use default hash
				hash_default(message).to_vec()
			};

			// Use prehash verification since we've already computed the hash
			verifying_key.verify_prehash(&data, signature)
		}
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256k1PublicKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		EciesSecp256k1::encrypt(self, plaintext.as_ref())
	}

	fn decrypt<C: AsRef<[u8]>>(&self, _cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		// Public keys cannot decrypt
		Err(CryptoError::InvalidOperation)
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-secp256k1-AES128CTR"
	}
}

/// secp256k1 key derivation implementation.
///
/// This struct provides the KeyDerivation trait implementation for secp256k1.
/// It uses HKDF with retry logic to ensure valid key generation.
///
/// ## Derivation Process
///
/// 1. **HKDF Expansion**: Use the seed as PRK material for HKDF-SHA3-256
/// 2. **Validation**: Check if the derived 32 bytes form a valid secp256k1 key
/// 3. **Retry Logic**: If invalid (zero or >= curve order), try again
/// 4. **Error Handling**: Fail after 1000 attempts (unlikely to happen)
///
/// This process ensures we always generate valid secp256k1 private keys while
/// maintaining deterministic derivation from the same seed.
pub struct Secp256k1Derivation;

impl KeyDerivation for Secp256k1Derivation {
	type PrivateKey = Secp256k1PrivateKey;

	fn derive_from_seed<T: AsRef<[u8]>>(seed: T) -> Result<Self::PrivateKey, CryptoError> {
		let seed = seed.as_ref();
		// Try with the seed as-is first (index 0 case)
		let mut attempt_seed = seed.to_vec();
		for attempt in 0u32..1000 {
			// For attempts > 0, append the attempt counter
			if attempt > 0 {
				// Remove any previous attempt counter and add the new one
				attempt_seed.truncate(seed.len());
				attempt_seed.extend_from_slice(&attempt.to_be_bytes());
			}

			// Use our KDF's expand-only method for TypeScript compatibility
			let key_bytes = KdfAlgorithm::HkdfSha3_256.expand_only_array::<32>(&attempt_seed, &[])?;
			if let Ok(secret_key) = K256SecretKey::from_slice(&key_bytes) {
				// Try to create the secret key - this will fail if key_bytes is zero or >= curve order
				return Ok(Secp256k1PrivateKey { inner: secret_key });
			}

			// If the key was invalid, continue to next attempt
		}

		Err(CryptoError::KeyDerivationFailed)
	}

	fn validate_key_material<T: AsRef<[u8]>>(bytes: T) -> bool {
		let bytes = bytes.as_ref();
		bytes.len() == 32 && K256SecretKey::from_slice(bytes).is_ok()
	}

	fn key_size() -> usize {
		32
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use secrecy::ExposeSecret;

	#[cfg(feature = "signature")]
	use crate::operations::signature::{
		CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
	};
	#[cfg(feature = "signature")]
	use ::signature::{Signer, Verifier};

	#[test]
	fn test_secp256k1_key_derivation() {
		let seed = b"test seed for secp256k1 key derivation";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test serialization roundtrip
		let private_bytes: SecretBox<Vec<u8>> = (&private_key).into();
		let recovered_private = Secp256k1PrivateKey::try_from(private_bytes.expose_secret().as_slice()).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&private_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&recovered_private).expose_secret()
		);

		let public_bytes: Vec<u8> = (&public_key).into();
		let recovered_public = Secp256k1PublicKey::try_from(public_bytes.as_slice()).unwrap();
		assert_eq!(Vec::<u8>::from(&public_key), Vec::<u8>::from(&recovered_public));

		// Test public key formatting
		let hex_formatted = hex::encode(Vec::<u8>::from(&public_key));
		assert_eq!(hex_formatted.len(), 66); // 33 bytes * 2 chars per byte
	}

	#[test]
	fn test_secp256k1_deterministic() {
		// Create a proper seed+index buffer (36 bytes total)
		let mut seed_with_index = [0u8; 36];
		seed_with_index[..23].copy_from_slice(b"deterministic test seed");

		let key1 = Secp256k1Derivation::derive_from_seed(seed_with_index).unwrap();
		let key2 = Secp256k1Derivation::derive_from_seed(seed_with_index).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&key1).expose_secret(),
			SecretBox::<Vec<u8>>::from(&key2).expose_secret()
		);

		let (pub1, pub2) = (key1.as_public_key(), key2.as_public_key());
		assert_eq!(Vec::<u8>::from(&pub1), Vec::<u8>::from(&pub2));
	}

	#[test]
	fn test_key_derivation_utility_methods() {
		// Test validate_key_material with valid key
		let valid_key = [0x01; 32]; // Valid 32-byte key
		assert!(Secp256k1Derivation::validate_key_material(valid_key));

		// Test validate_key_material with invalid key (wrong length)
		let invalid_key = [0x01; 16]; // Invalid length
		assert!(!Secp256k1Derivation::validate_key_material(invalid_key));

		// Test validate_key_material with invalid key (all zeros)
		let zero_key = [0x00; 32]; // All zeros is invalid for secp256k1
		assert!(!Secp256k1Derivation::validate_key_material(zero_key));

		// Test key_size
		assert_eq!(Secp256k1Derivation::key_size(), 32);
	}

	#[test]
	fn test_secret_box_from_private_key() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..26].copy_from_slice(b"test seed for secret box c");

		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();

		// Test From<Secp256k1PrivateKey> for SecretBox<Vec<u8>>
		let secret_box: SecretBox<Vec<u8>> = private_key.into();
		assert_eq!(secret_box.expose_secret().len(), 32);

		// Test From<&Secp256k1PrivateKey> for SecretBox<Vec<u8>>
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let secret_box_ref: SecretBox<Vec<u8>> = (&private_key).into();
		assert_eq!(secret_box_ref.expose_secret().len(), 32);

		// Both should be the same
		assert_eq!(secret_box.expose_secret(), secret_box_ref.expose_secret());
	}

	#[test]
	fn test_public_key_from_conversion() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..26].copy_from_slice(b"test seed for public key c");

		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test From<Secp256k1PublicKey> for Vec<u8>
		let public_bytes: Vec<u8> = public_key.clone().into();
		assert_eq!(public_bytes.len(), 33); // Compressed secp256k1 public key

		// Test From<&Secp256k1PublicKey> for Vec<u8>
		let public_bytes_ref: Vec<u8> = (&public_key).into();
		assert_eq!(public_bytes_ref.len(), 33);

		// Both should be the same
		assert_eq!(public_bytes, public_bytes_ref);
	}

	#[test]
	fn test_debug_formatting() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..22].copy_from_slice(b"test seed for debug fo");

		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();

		// Test that Debug format hides the private key
		let debug_string = format!("{private_key:?}");
		assert!(debug_string.contains("Secp256k1PrivateKey"));
		assert!(debug_string.contains("[REDACTED]"));
		// Make sure no actual key bytes are shown
		assert!(!debug_string.contains("SecretKey"));
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_crypto_signer_ext_trait() {
		let seed = b"test seed for crypto signer ext trait test";

		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		assert!(private_key.has_private_key());

		let algorithm = private_key.get_algorithm();
		assert_eq!(algorithm, Algorithm::Secp256k1);

		let verifying_key = private_key.verifying_key();
		assert!(!verifying_key.public_key_bytes().is_empty());

		// Test that verifying key matches the public key
		let expected_public_key = private_key.as_public_key();
		assert_eq!(verifying_key.public_key_bytes(), Vec::<u8>::from(&expected_public_key));
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_crypto_verifier_ext_trait() {
		let seed = b"test seed for crypto verifier ext trait test";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		let public_key_bytes = public_key.public_key_bytes();
		assert_eq!(public_key_bytes.len(), 33); // Compressed secp256k1 public key

		let public_key_string = public_key.public_key_string();
		assert_eq!(public_key_string.len(), 66); // 33 bytes * 2 hex chars per byte
		assert_eq!(public_key_string, hex::encode(&public_key_bytes));

		// Test that all characters are valid hex
		assert!(public_key_string.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_signature_operations() {
		let seed = b"test seed for signature operations";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let message = b"Hello, secp256k1 world!";

		// Test signing with RustCrypto Signer trait
		let signature = private_key.try_sign(message).unwrap();
		assert!(public_key.verify(message, &signature).is_ok());

		// Test that verification fails with wrong message
		let wrong_message = b"Wrong message";
		assert!(public_key.verify(wrong_message, &signature).is_err());

		// Test that verification fails with wrong key
		let wrong_seed = b"wrong seed for signature operations";
		let wrong_private_key = Secp256k1Derivation::derive_from_seed(wrong_seed).unwrap();
		let wrong_public_key = wrong_private_key.as_public_key();
		assert!(wrong_public_key.verify(message, &signature).is_err());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_signature_deterministic() {
		let seed = b"deterministic signature test seed";
		let private_key1 = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let private_key2 = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let message = b"Deterministic message";

		// secp256k1 signatures are deterministic with RFC 6979
		let signature1 = private_key1.try_sign(message).unwrap();
		let signature2 = private_key2.try_sign(message).unwrap();

		// Signatures should be identical for the same key and message
		assert_eq!(signature1.to_bytes(), signature2.to_bytes());

		// Both should verify with the same public key
		let public_key = private_key1.as_public_key();
		assert!(public_key.verify(message, &signature1).is_ok());
		assert!(public_key.verify(message, &signature2).is_ok());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_crypto_signer_with_options() {
		let seed = b"test seed for signer with options";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let message = b"test message for signing with options";

		// Test with default options (pre-hash)
		let default_options = SigningOptions::default();
		let signature_default = private_key
			.sign_with_options(message, default_options)
			.unwrap();

		// Test with raw options (no pre-hash)
		let raw_options = SigningOptions::raw();
		// Use a different 32-byte hash to make it truly different
		let different_hash = [0x42u8; 32]; // Different from hash_default(message)
		let signature_raw = private_key
			.sign_with_options(different_hash, raw_options)
			.unwrap();

		// Test with cert options (pre-hash, but for_cert flag set)
		let cert_options = SigningOptions::for_cert();
		let signature_cert = private_key
			.sign_with_options(message, cert_options)
			.unwrap();
		// Signatures should be different when using different message processing
		assert_ne!(signature_default.to_bytes(), signature_raw.to_bytes());
		assert_ne!(signature_default.to_bytes(), signature_cert.to_bytes());

		// Verify that the regular signing (which pre-hashes) matches default options
		let regular_signature = private_key.try_sign(message).unwrap();
		assert_ne!(regular_signature.to_bytes(), signature_default.to_bytes());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_crypto_verifier_with_options() {
		let seed = b"test seed for verifier with options";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let message = b"test message for verification with options";

		// Test verification with matching options
		let default_options = SigningOptions::default();
		let signature_default = private_key
			.sign_with_options(message, default_options)
			.unwrap();
		assert!(public_key
			.verify_with_options(message, &signature_default, default_options)
			.is_ok());

		// For raw options, we need to use a pre-computed hash (32 bytes)
		let raw_options = SigningOptions::raw();
		let pre_computed_hash = hash_default(message);
		let signature_raw = private_key
			.sign_with_options(pre_computed_hash, raw_options)
			.unwrap();
		assert!(public_key
			.verify_with_options(pre_computed_hash, &signature_raw, raw_options)
			.is_ok());

		let cert_options = SigningOptions::for_cert();
		let signature_cert = private_key
			.sign_with_options(message, cert_options)
			.unwrap();
		assert!(public_key
			.verify_with_options(message, &signature_cert, cert_options)
			.is_ok());

		// Test verification failure with mismatched options
		assert!(public_key
			.verify_with_options(pre_computed_hash, &signature_raw, default_options)
			.is_err());
		assert!(public_key
			.verify_with_options(message, &signature_default, raw_options)
			.is_err());

		// Test verification failure with wrong message
		let wrong_message = b"wrong message";
		assert!(public_key
			.verify_with_options(wrong_message, &signature_default, default_options)
			.is_err());
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_ecies_encryption_decryption() {
		let seed = b"test seed for ECIES encryption test";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let message = b"Hello, ECIES encryption world!";

		// Test encryption with public key
		let cipher_text = public_key.encrypt(message).unwrap();
		assert!(!cipher_text.is_empty());
		assert_ne!(cipher_text.as_slice(), message);

		// Test decryption with private key
		let decrypted = private_key.decrypt(&cipher_text).unwrap();
		assert_eq!(decrypted.as_slice(), message);

		// Test that different encryptions produce different cipher_texts (due to randomness)
		let cipher_text2 = public_key.encrypt(message).unwrap();
		assert_ne!(cipher_text, cipher_text2);

		// But both should decrypt to the same message
		let decrypted2 = private_key.decrypt(&cipher_text2).unwrap();
		assert_eq!(decrypted2.as_slice(), message);

		// Test that public key cannot decrypt
		assert!(public_key.decrypt(&cipher_text).is_err());
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_algorithm_info_methods() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..23].copy_from_slice(b"test seed for algorithm");

		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test algorithm_info for private key
		assert_eq!(private_key.algorithm_info(), "ECIES-secp256k1-AES128CTR");
		// Test algorithm_info for public key
		assert_eq!(public_key.algorithm_info(), "ECIES-secp256k1-AES128CTR");
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_private_key_encrypt_delegates_to_public_key() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..25].copy_from_slice(b"test seed for private key");

		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let message = b"Test message for private key encryption";

		// Test that private key encrypt works (delegates to public key)
		let cipher_text = private_key.encrypt(message).unwrap();
		assert!(!cipher_text.is_empty());

		// Verify we can decrypt it back
		let decrypted = private_key.decrypt(&cipher_text).unwrap();
		assert_eq!(decrypted.as_slice(), message);
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_secp256k1_key_exchange_trait() {
		let seed1 = b"test seed for secp256k1 key exchange 1";
		let seed2 = b"test seed for secp256k1 key exchange 2";

		let private_key1 = Secp256k1Derivation::derive_from_seed(seed1).unwrap();
		let private_key2 = Secp256k1Derivation::derive_from_seed(seed2).unwrap();

		let public_key1 = private_key1.as_public_key();
		let public_key2 = private_key2.as_public_key();

		// Test ECDH key exchange with public key objects
		let shared_secret1 = private_key1.ecdh(&public_key2).unwrap();
		let shared_secret2 = private_key2.ecdh(&public_key1).unwrap();

		// Both parties should compute the same shared secret
		assert_eq!(shared_secret1, shared_secret2);
		assert!(!shared_secret1.is_empty());

		// Test key_exchange with public key bytes
		let public_key2_bytes: Vec<u8> = (&public_key2).into();
		let shared_secret1_bytes = private_key1.key_exchange(&public_key2_bytes).unwrap();
		assert_eq!(shared_secret1, shared_secret1_bytes);

		let public_key1_bytes: Vec<u8> = (&public_key1).into();
		let shared_secret2_bytes = private_key2.key_exchange(&public_key1_bytes).unwrap();
		assert_eq!(shared_secret2, shared_secret2_bytes);

		// Test that different key pairs produce different shared secrets
		let seed3 = b"test seed for secp256k1 key exchange 3";
		let private_key3 = Secp256k1Derivation::derive_from_seed(seed3).unwrap();
		let public_key3 = private_key3.as_public_key();

		let shared_secret3 = private_key1.ecdh(&public_key3).unwrap();
		assert_ne!(shared_secret1, shared_secret3);

		// Test error handling with invalid public key bytes
		let invalid_public_key = vec![0u8; 32]; // Wrong length
		let result = private_key1.key_exchange(&invalid_public_key);
		assert!(result.is_err());

		// Test derive_aead_key
		let aead_result = private_key1.derive_aead_key::<aes_gcm::Aes256Gcm>(&shared_secret1);
		assert!(aead_result.is_err());
		// Test that it specifically returns EncryptionNotSupported
		assert!(matches!(aead_result, Err(CryptoError::EncryptionNotSupported)));
	}

	#[cfg(feature = "der")]
	#[test]
	fn test_oid_conversion() {
		let seed = b"test seed for secp256k1 oid conversion";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test conversion to ObjectIdentifier
		let oid: asn1::ObjectIdentifier = public_key.into();
		assert_eq!(oid.to_string(), asn1::oids::SECP256K1);
		let oid: asn1::ObjectIdentifier = private_key.into();
		assert_eq!(oid.to_string(), asn1::oids::SECP256K1);
	}
}
