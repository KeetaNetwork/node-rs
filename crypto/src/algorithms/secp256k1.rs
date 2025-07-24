//! secp256k1 cryptographic algorithm implementation.
//!
//! This module provides secp256k1 elliptic curve cryptography support, the
//! same curve used by Bitcoin.
//! # Key Format
//!
//! - **Private keys**: 32 bytes, in range [1, n-1] where n is the curve order
//! - **Public keys**: 33 bytes compressed format (0x02/0x03 prefix + 32 bytes)

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};
#[cfg(feature = "encryption")]
use ecies;
use k256::{
	ecdsa::{Signature, SigningKey},
	elliptic_curve::sec1::ToEncodedPoint,
	SecretKey as K256SecretKey,
};
use secrecy::SecretBox;

#[cfg(feature = "encryption")]
use crate::operations::encryption::AsymmetricEncryption;
#[cfg(feature = "signature")]
use crate::operations::signature::{CryptoSigner, CryptoVerifier};

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
#[derive(Clone)]
pub struct Secp256k1PrivateKey {
	inner: K256SecretKey,
}

impl core::fmt::Debug for Secp256k1PrivateKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Secp256k1PrivateKey").field("inner", &"[REDACTED]").finish()
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
#[derive(Clone, Debug)]
pub struct Secp256k1PublicKey {
	inner: k256::PublicKey,
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

// RustCrypto Keypair trait implementation
#[cfg(feature = "signature")]
impl Keypair for Secp256k1PrivateKey {
	type VerifyingKey = Secp256k1PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();

		Secp256k1PublicKey { inner: verifying_key.into() }
	}
}

// RustCrypto Signer trait implementation
#[cfg(feature = "signature")]
impl Signer<Signature> for Secp256k1PrivateKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::signature::Error> {
		let signing_key = SigningKey::from(&self.inner);

		signing_key.try_sign(msg)
	}
}

// CryptoSigner trait implementation (extends Signer<Signature>)
impl CryptoSigner<Signature> for Secp256k1PrivateKey {
	fn has_private_key(&self) -> bool {
		true // Private key always has access to private key material
	}
}

impl PublicKey for Secp256k1PublicKey {}

impl From<Secp256k1PublicKey> for Vec<u8> {
	fn from(key: Secp256k1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
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

// RustCrypto Verifier trait implementation
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

	fn public_key_string(&self) -> Result<String, CryptoError> {
		Ok(hex::encode(self.public_key_bytes()))
	}
}

// ECIES implementation for secp256k1 (matches TypeScript ecies-geth behavior)
#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256k1PrivateKey {
	fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Use ECIES encryption with our private key for decryption later
		// For encryption, we need the corresponding public key
		let public_key = self.as_public_key();
		public_key.encrypt(plaintext)
	}

	fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Use ECIES decryption with our private key
		let private_key_bytes = self.inner.to_bytes();
		ecies::decrypt(private_key_bytes.as_slice(), cipher_text).map_err(|_| CryptoError::DecryptionFailed)
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-secp256k1"
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256k1PublicKey {
	fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Use ECIES encryption with the public key
		let public_key_bytes = Vec::<u8>::from(self);
		ecies::encrypt(&public_key_bytes, plaintext).map_err(|_| CryptoError::EncryptionFailed)
	}

	fn decrypt(&self, _cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Public keys cannot decrypt
		Err(CryptoError::InvalidOperation)
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-secp256k1"
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

	fn derive_from_seed(seed: &[u8]) -> Result<Self::PrivateKey, CryptoError> {
		// The seed here is the seed + index (36 bytes total: 32-byte seed + 4-byte index)

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
			if let Ok(secret_key) = K256SecretKey::from_slice(&key_bytes) {
				return Ok(Secp256k1PrivateKey { inner: secret_key });
			}

			// If the key was invalid, continue to next attempt
		}

		Err(CryptoError::KeyDerivationFailed)
	}

	fn validate_key_material(bytes: &[u8]) -> bool {
		bytes.len() == 32 && K256SecretKey::from_slice(bytes).is_ok()
	}

	fn key_size() -> usize {
		32
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::operations::signature::{CryptoSigner, CryptoVerifier};
	use secrecy::ExposeSecret;

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

		let key1 = Secp256k1Derivation::derive_from_seed(&seed_with_index).unwrap();
		let key2 = Secp256k1Derivation::derive_from_seed(&seed_with_index).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&key1).expose_secret(),
			SecretBox::<Vec<u8>>::from(&key2).expose_secret()
		);

		let (pub1, pub2) = (key1.as_public_key(), key2.as_public_key());
		assert_eq!(Vec::<u8>::from(&pub1), Vec::<u8>::from(&pub2));
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_crypto_signer_ext_trait() {
		let seed = b"test seed for crypto signer ext trait test";

		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
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
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		let public_key_bytes = public_key.public_key_bytes();
		assert_eq!(public_key_bytes.len(), 33); // Compressed secp256k1 public key

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

		let private_key = Secp256k1Derivation::derive_from_seed(&seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test algorithm_info for private key
		assert_eq!(private_key.algorithm_info(), "ECIES-secp256k1");

		// Test algorithm_info for public key
		assert_eq!(public_key.algorithm_info(), "ECIES-secp256k1");
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_private_key_encrypt_delegates_to_public_key() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..25].copy_from_slice(b"test seed for private key");

		let private_key = Secp256k1Derivation::derive_from_seed(&seed).unwrap();
		let message = b"Test message for private key encryption";

		// Test that private key encrypt works (delegates to public key)
		let cipher_text = private_key.encrypt(message).unwrap();
		assert!(!cipher_text.is_empty());

		// Verify we can decrypt it back
		let decrypted = private_key.decrypt(&cipher_text).unwrap();
		assert_eq!(decrypted.as_slice(), message);
	}

	#[test]
	fn test_key_derivation_utility_methods() {
		// Test validate_key_material with valid key
		let valid_key = [0x01; 32]; // Valid 32-byte key
		assert!(Secp256k1Derivation::validate_key_material(&valid_key));

		// Test validate_key_material with invalid key (wrong length)
		let invalid_key = [0x01; 16]; // Invalid length
		assert!(!Secp256k1Derivation::validate_key_material(&invalid_key));

		// Test validate_key_material with invalid key (all zeros)
		let zero_key = [0x00; 32]; // All zeros is invalid for secp256k1
		assert!(!Secp256k1Derivation::validate_key_material(&zero_key));

		// Test key_size
		assert_eq!(Secp256k1Derivation::key_size(), 32);
	}

	#[test]
	fn test_secret_box_from_private_key() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..26].copy_from_slice(b"test seed for secret box c");

		let private_key = Secp256k1Derivation::derive_from_seed(&seed).unwrap();

		// Test From<Secp256k1PrivateKey> for SecretBox<Vec<u8>>
		let secret_box: SecretBox<Vec<u8>> = private_key.clone().into();
		assert_eq!(secret_box.expose_secret().len(), 32);

		// Test From<&Secp256k1PrivateKey> for SecretBox<Vec<u8>>
		let secret_box_ref: SecretBox<Vec<u8>> = (&private_key).into();
		assert_eq!(secret_box_ref.expose_secret().len(), 32);

		// Both should be the same
		assert_eq!(secret_box.expose_secret(), secret_box_ref.expose_secret());
	}

	#[test]
	fn test_public_key_from_conversion() {
		let mut seed = [0u8; 36]; // Proper seed + index length
		seed[..26].copy_from_slice(b"test seed for public key c");

		let private_key = Secp256k1Derivation::derive_from_seed(&seed).unwrap();
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

		let private_key = Secp256k1Derivation::derive_from_seed(&seed).unwrap();

		// Test that Debug format hides the private key
		let debug_string = format!("{private_key:?}");
		assert!(debug_string.contains("Secp256k1PrivateKey"));
		assert!(debug_string.contains("[REDACTED]"));
		// Make sure no actual key bytes are shown
		assert!(!debug_string.contains("SecretKey"));
	}
}
