//! secp256r1 (NIST P-256) cryptographic algorithm implementation.
//!
//! This module provides secp256r1 elliptic curve cryptography support.
//!
//! # Key Format
//!
//! - **Private keys**: 32 bytes, in range [1, n-1] where n is the curve order
//! - **Public keys**: 33 bytes compressed format (0x02/0x03 prefix + 32 bytes)

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};
use p256::{
	ecdsa::{Signature, SigningKey},
	elliptic_curve::sec1::ToEncodedPoint,
	SecretKey as P256SecretKey,
};
use secrecy::SecretBox;

#[cfg(feature = "encryption")]
use crate::operations::encryption::AsymmetricEncryption;
#[cfg(feature = "signature")]
use crate::operations::signature::{CryptoSigner, CryptoVerifier};

use crate::{error::CryptoError, KeyDerivation, PrivateKey, PublicKey};

// Import for key derivation (matching SECP256K1)
use hkdf;
use sha3;

/// secp256r1 (NIST P-256) private key wrapper.
///
/// This struct wraps the p256 SecretKey and provides the PrivateKey trait
/// implementation.
///
/// ## Security Note
///
/// The inner secret key is kept private and only accessible through the trait
/// methods. Debug formatting will show "\[REDACTED\]" to prevent accidental
/// key exposure.
#[derive(Clone)]
pub struct Secp256r1PrivateKey {
	inner: P256SecretKey,
}

impl core::fmt::Debug for Secp256r1PrivateKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Secp256r1PrivateKey").field("inner", &"[REDACTED]").finish()
	}
}

/// secp256r1 (NIST P-256) public key wrapper.
///
/// This struct wraps the p256 PublicKey and provides the PublicKey trait
/// implementation. secp256r1 public keys are stored in compressed format
/// (33 bytes: 0x02/0x03 prefix + 32 bytes).
///
/// Public keys can be safely displayed, serialized, and shared as they contain
/// no secret information.
#[derive(Clone, Debug)]
pub struct Secp256r1PublicKey {
	inner: p256::PublicKey,
}

impl PrivateKey for Secp256r1PrivateKey {
	type PublicKey = Secp256r1PublicKey;
	type Signature = Signature;

	fn as_public_key(&self) -> Self::PublicKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();

		Secp256r1PublicKey { inner: verifying_key.into() }
	}
}

impl From<Secp256r1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Secp256r1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

impl From<&Secp256r1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Secp256r1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

impl TryFrom<&[u8]> for Secp256r1PrivateKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let secret_key = P256SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;

		Ok(Secp256r1PrivateKey { inner: secret_key })
	}
}

// RustCrypto Keypair trait implementation
#[cfg(feature = "signature")]
impl Keypair for Secp256r1PrivateKey {
	type VerifyingKey = Secp256r1PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();

		Secp256r1PublicKey { inner: verifying_key.into() }
	}
}

// RustCrypto Signer trait implementation
#[cfg(feature = "signature")]
impl Signer<Signature> for Secp256r1PrivateKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::signature::Error> {
		let signing_key = SigningKey::from(&self.inner);

		signing_key.try_sign(msg)
	}
}

// CryptoSigner trait implementation
impl CryptoSigner<Signature> for Secp256r1PrivateKey {
	fn has_private_key(&self) -> bool {
		true // Private key always has access to private key material
	}
}

impl PublicKey for Secp256r1PublicKey {}

impl From<Secp256r1PublicKey> for Vec<u8> {
	fn from(key: Secp256r1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

impl From<&Secp256r1PublicKey> for Vec<u8> {
	fn from(key: &Secp256r1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

impl TryFrom<&[u8]> for Secp256r1PublicKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let public_key = p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;

		Ok(Secp256r1PublicKey { inner: public_key })
	}
}

// RustCrypto Verifier trait implementation
#[cfg(feature = "signature")]
impl Verifier<Signature> for Secp256r1PublicKey {
	fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ::signature::Error> {
		let verifying_key = p256::ecdsa::VerifyingKey::from(&self.inner);

		verifying_key.verify(msg, signature)
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifier<Signature> for Secp256r1PublicKey {
	fn public_key_bytes(&self) -> Vec<u8> {
		self.into()
	}

	fn public_key_string(&self) -> Result<String, CryptoError> {
		Ok(hex::encode(self.public_key_bytes()))
	}
}

// ECIES implementation for secp256r1 (similar to secp256k1 but with P-256 curve)
#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256r1PrivateKey {
	fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Use ECIES encryption with our private key for decryption later
		// For encryption, we need the corresponding public key
		let public_key = self.as_public_key();
		public_key.encrypt(plaintext)
	}

	fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// NOTE: The ecies crate primarily supports secp256k1
		// For secp256r1, we need to implement a different approach or use a different library
		// For now, return an error to indicate this is not yet implemented
		let _ = cipher_text; // Avoid unused warning
		Err(CryptoError::UnsupportedAlgorithm {
			algorithm: "ECIES encryption not yet implemented for secp256r1".to_string(),
		})
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-secp256r1 (not yet implemented)"
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256r1PublicKey {
	fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// NOTE: The ecies crate primarily supports secp256k1
		// For secp256r1, we need to implement a different approach or use a different library
		// For now, return an error to indicate this is not yet implemented
		let _ = plaintext; // Avoid unused warning
		Err(CryptoError::UnsupportedAlgorithm {
			algorithm: "ECIES encryption not yet implemented for secp256r1".to_string(),
		})
	}

	fn decrypt(&self, _cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Public key cannot decrypt
		Err(CryptoError::InvalidOperation)
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-secp256r1 (not yet implemented)"
	}
}

/// Key derivation implementation for secp256r1.
///
/// This struct provides HKDF-based key derivation for secp256r1 private keys,
/// ensuring generated keys are always valid for the curve.
pub struct Secp256r1Derivation;

impl KeyDerivation for Secp256r1Derivation {
	type PrivateKey = Secp256r1PrivateKey;

	fn derive_from_seed(seed: &[u8]) -> Result<Self::PrivateKey, CryptoError> {
		// Use the same key derivation process as SECP256K1

		// Try with the seed as-is first (index 0 case)
		let mut attempt_seed = seed.to_vec();
		for attempt in 0u32..1000 {
			let mut key_bytes = [0u8; 32];

			// For attempts > 0, append the attempt counter
			if attempt > 0 {
				// Remove any previous attempt counter and add the new one
				attempt_seed.truncate(seed.len());
				attempt_seed.extend_from_slice(&attempt.to_be_bytes());
			}

			// Use HKDF expand-only, treating the seed(+attempt) buffer as PRK
			let hkdf =
				hkdf::Hkdf::<sha3::Sha3_256>::from_prk(&attempt_seed).map_err(|_| CryptoError::KeyDerivationFailed)?;
			hkdf.expand(&[], &mut key_bytes).map_err(|_| CryptoError::KeyDerivationFailed)?;

			// Try to create the secret key - this will fail if key_bytes is zero or >= curve order
			if let Ok(secret_key) = P256SecretKey::from_slice(&key_bytes) {
				return Ok(Secp256r1PrivateKey { inner: secret_key });
			}

			// If the key was invalid, continue to next attempt
		}

		Err(CryptoError::KeyDerivationFailed)
	}

	fn validate_key_material(bytes: &[u8]) -> bool {
		bytes.len() == 32 && P256SecretKey::from_slice(bytes).is_ok()
	}

	fn key_size() -> usize {
		32
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use secrecy::ExposeSecret;

	#[cfg(feature = "signature")]
	use crate::operations::signature::{CryptoSigner, CryptoVerifier};
	#[cfg(feature = "signature")]
	use ::signature::{Signer, Verifier};

	#[test]
	fn test_secp256r1_key_derivation() {
		let seed = b"test seed for secp256r1 key derivation";
		let private_key = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test serialization roundtrip
		let private_bytes: SecretBox<Vec<u8>> = (&private_key).into();
		let recovered_private = Secp256r1PrivateKey::try_from(private_bytes.expose_secret().as_slice()).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&private_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&recovered_private).expose_secret()
		);

		let public_bytes: Vec<u8> = (&public_key).into();
		let recovered_public = Secp256r1PublicKey::try_from(public_bytes.as_slice()).unwrap();
		assert_eq!(Vec::<u8>::from(&public_key), Vec::<u8>::from(&recovered_public));

		// Test public key formatting
		let hex_formatted = hex::encode(Vec::<u8>::from(&public_key));
		assert_eq!(hex_formatted.len(), 66); // 33 bytes * 2 chars per byte

		// Verify we can derive a public key
		let public_key_bytes = Vec::<u8>::from(&public_key);
		// secp256r1 compressed public keys should be 33 bytes
		assert_eq!(public_key_bytes.len(), 33);
		// First byte should be 0x02 or 0x03 for compressed format
		assert!(public_key_bytes[0] == 0x02 || public_key_bytes[0] == 0x03);
	}

	#[test]
	fn test_secp256r1_deterministic() {
		// Create a proper seed+index buffer (36 bytes total)
		let mut seed_with_index = [0u8; 36];
		seed_with_index[..23].copy_from_slice(b"deterministic test seed");

		let key1 = Secp256r1Derivation::derive_from_seed(&seed_with_index).unwrap();
		let key2 = Secp256r1Derivation::derive_from_seed(&seed_with_index).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&key1).expose_secret(),
			SecretBox::<Vec<u8>>::from(&key2).expose_secret()
		);

		let (pub1, pub2) = (key1.as_public_key(), key2.as_public_key());
		assert_eq!(Vec::<u8>::from(&pub1), Vec::<u8>::from(&pub2));

		// Also test the old simple test case
		let seed = b"test seed for secp256r1 deterministic";
		// Derive the same key twice
		let private_key_1 = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let private_key_2 = Secp256r1Derivation::derive_from_seed(seed).unwrap();

		// They should produce the same public key
		let public_key_1 = private_key_1.as_public_key();
		let public_key_2 = private_key_2.as_public_key();
		assert_eq!(Vec::<u8>::from(&public_key_1), Vec::<u8>::from(&public_key_2));
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_crypto_signer_ext_trait() {
		let seed = b"test seed for crypto signer ext trait test";

		let private_key = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		assert!(private_key.has_private_key());

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
		let private_key = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		let public_key_bytes = public_key.public_key_bytes();
		assert_eq!(public_key_bytes.len(), 33); // Compressed secp256r1 public key

		let public_key_string = public_key.public_key_string().unwrap();
		assert_eq!(public_key_string.len(), 66); // 33 bytes * 2 hex chars per byte
		assert_eq!(public_key_string, hex::encode(&public_key_bytes));

		// Test that all characters are valid hex
		assert!(public_key_string.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_signature_operations() {
		let seed = b"test seed for signature operations";
		let private_key = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let message = b"Hello, secp256r1 world!";

		// Test signing with RustCrypto Signer trait
		let signature = private_key.try_sign(message).unwrap();
		assert!(public_key.verify(message, &signature).is_ok());

		// Test that verification fails with wrong message
		let wrong_message = b"Wrong message";
		assert!(public_key.verify(wrong_message, &signature).is_err());

		// Test that verification fails with wrong key
		let wrong_seed = b"wrong seed for signature operations";
		let wrong_private_key = Secp256r1Derivation::derive_from_seed(wrong_seed).unwrap();
		let wrong_public_key = wrong_private_key.as_public_key();
		assert!(wrong_public_key.verify(message, &signature).is_err());

		// Also test the old test case
		let seed2 = b"test seed for secp256r1 sign verify!";
		let private_key2 = Secp256r1Derivation::derive_from_seed(seed2).unwrap();
		let public_key2 = private_key2.as_public_key();
		let message2 = b"Hello, secp256r1 world!";

		// Verify we can sign and verify a message
		let signature2 = private_key2.try_sign(message2).unwrap();
		assert!(public_key2.verify(message2, &signature2).is_ok());

		// Verify with wrong message should fail
		let wrong_message2 = b"Hello, wrong world!";
		assert!(public_key2.verify(wrong_message2, &signature2).is_err());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_signature_deterministic() {
		let seed = b"deterministic signature test seed";
		let private_key1 = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let private_key2 = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let message = b"Deterministic message";

		// secp256r1 signatures are deterministic with RFC 6979
		let signature1 = private_key1.try_sign(message).unwrap();
		let signature2 = private_key2.try_sign(message).unwrap();

		// Signatures should be identical for the same key and message
		assert_eq!(signature1.to_bytes(), signature2.to_bytes());

		// Both should verify with the same public key
		let public_key = private_key1.as_public_key();
		assert!(public_key.verify(message, &signature1).is_ok());
		assert!(public_key.verify(message, &signature2).is_ok());
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_encryption_not_implemented() {
		let seed = b"test seed for ECIES encryption test";
		let private_key = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let message = b"Hello, ECIES encryption world!";

		// Test encryption with private key - should delegate to public key and return error
		let private_encrypt_result = private_key.encrypt(message);
		assert!(private_encrypt_result.is_err());
		assert!(matches!(private_encrypt_result.unwrap_err(), CryptoError::UnsupportedAlgorithm { .. }));

		// Test encryption with public key - should return error since not implemented
		let encrypt_result = public_key.encrypt(message);
		assert!(encrypt_result.is_err());
		assert!(matches!(encrypt_result.unwrap_err(), CryptoError::UnsupportedAlgorithm { .. }));

		// Test decryption with private key - should also return error since not implemented
		let dummy_cipher = vec![0u8; 64];
		let decrypt_result = private_key.decrypt(&dummy_cipher);
		assert!(decrypt_result.is_err());
		assert!(matches!(decrypt_result.unwrap_err(), CryptoError::UnsupportedAlgorithm { .. }));

		// Test that public key cannot decrypt (different error)
		let public_decrypt_result = public_key.decrypt(&dummy_cipher);
		assert!(public_decrypt_result.is_err());
		assert!(matches!(public_decrypt_result.unwrap_err(), CryptoError::InvalidOperation));
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_algorithm_info_methods() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..23].copy_from_slice(b"test seed for algorithm");

		let private_key = Secp256r1Derivation::derive_from_seed(&seed).unwrap();
		let public_key = private_key.as_public_key();
		// Test algorithm_info for private key
		assert_eq!(private_key.algorithm_info(), "ECIES-secp256r1 (not yet implemented)");
		// Test algorithm_info for public key
		assert_eq!(public_key.algorithm_info(), "ECIES-secp256r1 (not yet implemented)");
	}

	#[test]
	fn test_private_key_roundtrip() {
		let seed = b"test seed for secp256r1 roundtrip!!";
		let original_key = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		// Convert to bytes and back
		let key_bytes = SecretBox::<Vec<u8>>::from(&original_key);
		let key_bytes_exposed = key_bytes.expose_secret();
		let reconstructed_key = Secp256r1PrivateKey::try_from(key_bytes_exposed.as_slice()).unwrap();

		// They should produce the same public key
		let original_public = original_key.as_public_key();
		let reconstructed_public = reconstructed_key.as_public_key();
		assert_eq!(Vec::<u8>::from(&original_public), Vec::<u8>::from(&reconstructed_public));
	}

	#[test]
	fn test_public_key_roundtrip() {
		let seed = b"test seed for secp256r1 public rt!!";
		let private_key = Secp256r1Derivation::derive_from_seed(seed).unwrap();
		let original_public_key = private_key.as_public_key();

		// Convert to bytes and back
		let public_key_bytes = Vec::<u8>::from(&original_public_key);
		let reconstructed_public_key = Secp256r1PublicKey::try_from(public_key_bytes.as_slice()).unwrap();
		assert_eq!(Vec::<u8>::from(&original_public_key), Vec::<u8>::from(&reconstructed_public_key));
	}

	#[test]
	fn test_key_derivation_utility_methods() {
		// Test validate_key_material with valid key
		let valid_key = [0x01; 32]; // Valid 32-byte key
		assert!(Secp256r1Derivation::validate_key_material(&valid_key));

		// Test validate_key_material with invalid key (wrong length)
		let invalid_key = [0x01; 16]; // Invalid length
		assert!(!Secp256r1Derivation::validate_key_material(&invalid_key));

		// Test validate_key_material with invalid key (all zeros)
		let zero_key = [0x00; 32]; // All zeros is invalid for secp256r1
		assert!(!Secp256r1Derivation::validate_key_material(&zero_key));

		// Test key_size
		assert_eq!(Secp256r1Derivation::key_size(), 32);

		// Also test the old specific tests
		// Valid 32-byte key material
		let valid_key2 = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
		assert!(Secp256r1Derivation::validate_key_material(&valid_key2));

		// Invalid length
		let invalid_short = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f67");
		assert!(!Secp256r1Derivation::validate_key_material(&invalid_short));

		let invalid_long = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672100");
		assert!(!Secp256r1Derivation::validate_key_material(&invalid_long));

		// Zero key (invalid for ECDSA)
		let zero_key2 = [0u8; 32];
		assert!(!Secp256r1Derivation::validate_key_material(&zero_key2));
	}

	#[test]
	fn test_secret_box_from_private_key() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..26].copy_from_slice(b"test seed for secret box c");

		let private_key = Secp256r1Derivation::derive_from_seed(&seed).unwrap();

		// Test From<Secp256r1PrivateKey> for SecretBox<Vec<u8>>
		let secret_box: SecretBox<Vec<u8>> = private_key.clone().into();
		assert_eq!(secret_box.expose_secret().len(), 32);

		// Test From<&Secp256r1PrivateKey> for SecretBox<Vec<u8>>
		let secret_box_ref: SecretBox<Vec<u8>> = (&private_key).into();
		assert_eq!(secret_box_ref.expose_secret().len(), 32);
		// Both should be the same
		assert_eq!(secret_box.expose_secret(), secret_box_ref.expose_secret());
	}

	#[test]
	fn test_public_key_from_conversion() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..26].copy_from_slice(b"test seed for public key c");

		let private_key = Secp256r1Derivation::derive_from_seed(&seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test From<Secp256r1PublicKey> for Vec<u8>
		let public_bytes: Vec<u8> = public_key.clone().into();
		assert_eq!(public_bytes.len(), 33); // Compressed secp256r1 public key

		// Test From<&Secp256r1PublicKey> for Vec<u8>
		let public_bytes_ref: Vec<u8> = (&public_key).into();
		assert_eq!(public_bytes_ref.len(), 33);
		// Both should be the same
		assert_eq!(public_bytes, public_bytes_ref);
	}

	#[test]
	fn test_debug_formatting() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..22].copy_from_slice(b"test seed for debug fo");

		let private_key = Secp256r1Derivation::derive_from_seed(&seed).unwrap();

		// Test that Debug format hides the private key
		let debug_string = format!("{private_key:?}");
		assert!(debug_string.contains("Secp256r1PrivateKey"));
		assert!(debug_string.contains("[REDACTED]"));
		// Make sure no actual key bytes are shown
		assert!(!debug_string.contains("SecretKey"));
	}
}
