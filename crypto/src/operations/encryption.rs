//! Encryption and key exchange operations using RustCrypto patterns.
//!
//! This module provides idiomatic traits and types for encryption,
//! decryption, and key exchange operations.

use crate::error::CryptoError;

// Re-export key RustCrypto AEAD traits for easier use
pub use aead::{Aead, AeadCore, AeadInPlace, KeyInit};

/// AEAD operations that extend RustCrypto's Aead trait
///
/// This trait extends the RustCrypto Aead trait with additional convenience
/// methods while avoiding method name conflicts. It provides the standard
/// AEAD interface through inheritance from Aead.
pub trait CryptoAead: Aead {
	/// Get algorithm-specific metadata or configuration
	fn algorithm_info(&self) -> &'static str;
}

/// Asymmetric encryption operations
///
/// This trait provides encryption functionality for asymmetric encryption
/// schemes like ECIES that don't follow the AEAD pattern but provide
/// authenticated encryption.
pub trait AsymmetricEncryption {
	/// Encrypt data using asymmetric encryption
	///
	/// This typically uses the public key for encryption.
	fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

	/// Decrypt data using asymmetric encryption
	///
	/// This typically uses the private key for decryption.
	fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError>;

	/// Get algorithm-specific metadata or configuration
	fn algorithm_info(&self) -> &'static str;
}

/// Key exchange operations for asymmetric encryption
///
/// This trait provides key agreement/exchange functionality for asymmetric
/// encryption schemes like X25519.
pub trait KeyExchange {
	/// The shared secret type produced by key exchange
	type SharedSecret: AsRef<[u8]>;

	/// Perform key exchange with another public key
	fn key_exchange(&self, their_public_key: &[u8]) -> Result<Self::SharedSecret, CryptoError>;

	/// Derive an AEAD key from the shared secret
	fn derive_aead_key<A>(&self, shared_secret: &Self::SharedSecret) -> Result<A, CryptoError>
	where
		A: KeyInit;
}

#[cfg(test)]
mod tests {
	use super::*;
	use aes_gcm::{Aes128Gcm, Aes256Gcm};

	// Simplified mock implementations for testing
	// Note: Real AEAD testing is done in algorithm-specific modules

	// Mock AsymmetricEncryption implementation
	struct MockAsymmetricEncryption {
		has_private_key: bool,
	}

	impl MockAsymmetricEncryption {
		fn new_private() -> Self {
			Self { has_private_key: true }
		}

		fn new_public() -> Self {
			Self { has_private_key: false }
		}
	}

	impl AsymmetricEncryption for MockAsymmetricEncryption {
		fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
			// Mock encryption: reverse bytes and add prefix
			let mut result = vec![0xFF, 0xEE]; // Mock header
			let mut encrypted = plaintext.to_vec();

			encrypted.reverse(); // Simple transformation
			result.extend_from_slice(&encrypted);

			Ok(result)
		}

		fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
			if !self.has_private_key {
				return Err(CryptoError::InvalidOperation);
			}

			if cipher_text.len() < 2 || cipher_text[..2] != [0xFF, 0xEE] {
				return Err(CryptoError::DecryptionFailed);
			}

			// Mock decryption: remove header and reverse
			let mut result = cipher_text[2..].to_vec();
			result.reverse();

			Ok(result)
		}

		fn algorithm_info(&self) -> &'static str {
			"Mock-Asymmetric-Encryption"
		}
	}

	// Mock KeyExchange implementation
	struct MockKeyExchange {
		private_key: [u8; 32],
	}

	impl MockKeyExchange {
		fn new() -> Self {
			Self {
				private_key: [0x42; 32], // Mock private key
			}
		}
	}

	impl KeyExchange for MockKeyExchange {
		type SharedSecret = [u8; 32];

		fn key_exchange(&self, their_public_key: &[u8]) -> Result<Self::SharedSecret, CryptoError> {
			if their_public_key.len() != 32 {
				return Err(CryptoError::InvalidPublicKey);
			}

			// Mock key exchange: XOR our private key with their public key
			let mut shared_secret = [0u8; 32];
			for i in 0..32 {
				shared_secret[i] = self.private_key[i] ^ their_public_key[i];
			}
			Ok(shared_secret)
		}

		fn derive_aead_key<A>(&self, shared_secret: &Self::SharedSecret) -> Result<A, CryptoError>
		where
			A: KeyInit,
		{
			// Mock AEAD key derivation
			A::new_from_slice(shared_secret.as_ref()).map_err(|_| CryptoError::KeyDerivationFailed)
		}
	}

	// Mock failing implementations for error testing
	struct FailingMockAsymmetricEncryption;

	impl AsymmetricEncryption for FailingMockAsymmetricEncryption {
		fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
			Err(CryptoError::EncryptionFailed)
		}

		fn decrypt(&self, _cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
			Err(CryptoError::DecryptionFailed)
		}

		fn algorithm_info(&self) -> &'static str {
			"Failing-Mock-Encryption"
		}
	}

	#[test]
	fn test_asymmetric_encryption_trait() {
		let private_enc = MockAsymmetricEncryption::new_private();
		let public_enc = MockAsymmetricEncryption::new_public();
		let plaintext = b"test message for asymmetric encryption";

		// Test encryption (works with both private and public)
		let ciphertext1 = private_enc.encrypt(plaintext).unwrap();
		let ciphertext2 = public_enc.encrypt(plaintext).unwrap();
		assert_eq!(ciphertext1, ciphertext2); // Same algorithm

		// Test decryption (only works with private key)
		let decrypted = private_enc.decrypt(&ciphertext1).unwrap();
		assert_eq!(decrypted, plaintext);
		// Public key cannot decrypt
		assert!(public_enc.decrypt(&ciphertext1).is_err());
		// Test algorithm info
		assert_eq!(private_enc.algorithm_info(), "Mock-Asymmetric-Encryption");
	}

	#[test]
	fn test_key_exchange_trait() {
		let alice = MockKeyExchange::new();
		let bob_public_key = [0x33; 32]; // Mock Bob's public key

		// Test key exchange
		let shared_secret = alice.key_exchange(&bob_public_key).unwrap();
		assert_eq!(shared_secret.len(), 32);

		// Test that the shared secret is deterministic
		let shared_secret2 = alice.key_exchange(&bob_public_key).unwrap();
		assert_eq!(shared_secret, shared_secret2);

		// Test error case with wrong key length
		let wrong_key = [0x44; 16]; // Wrong length
		assert!(alice.key_exchange(&wrong_key).is_err());
	}

	#[test]
	fn test_derive_aead_key() {
		let alice = MockKeyExchange::new();
		let bob_public_key = [0x33; 32]; // Mock Bob's public key

		let shared_secret = alice.key_exchange(&bob_public_key).unwrap();
		assert_eq!(shared_secret.len(), 32);

		// Test derive_aead_key with a concrete AEAD implementation
		let _aead_key: Aes256Gcm = alice.derive_aead_key(&shared_secret).unwrap();
		let _aead_key2: Aes256Gcm = alice.derive_aead_key(&shared_secret).unwrap();
		assert!(!shared_secret.is_empty());
	}

	#[test]
	fn test_derive_aead_key_error() {
		let alice = MockKeyExchange::new();
		let bob_public_key = [0x33; 32]; // Mock Bob's public key
		let shared_secret = alice.key_exchange(&bob_public_key).unwrap();

		// Error case: Try to derive AES-128 key (16 bytes) from 32-byte secret
		// This should fail because the mock derive_aead_key just passes the
		// secret directly but AES-128 expects exactly 16 bytes
		let result: Result<Aes128Gcm, _> = alice.derive_aead_key(&shared_secret);
		assert!(result.is_err());

		if let Err(error) = result {
			assert!(matches!(error, CryptoError::KeyDerivationFailed));
		}
	}

	#[test]
	fn test_asymmetric_encryption_error_cases() {
		let failing_enc = FailingMockAsymmetricEncryption;
		let plaintext = b"test data";

		// Test encryption failure
		let encrypt_result = failing_enc.encrypt(plaintext);
		assert!(encrypt_result.is_err());
		assert!(matches!(encrypt_result.unwrap_err(), CryptoError::EncryptionFailed));

		// Test decryption failure
		let decrypt_result = failing_enc.decrypt(plaintext);
		assert!(decrypt_result.is_err());
		assert!(matches!(decrypt_result.unwrap_err(), CryptoError::DecryptionFailed));

		// Test algorithm info
		assert_eq!(failing_enc.algorithm_info(), "Failing-Mock-Encryption");
	}

	#[test]
	fn test_trait_object_compatibility() {
		let mock_encryption = MockAsymmetricEncryption::new_private();
		// Test AsymmetricEncryption trait object
		let asymmetric_encryption: &dyn AsymmetricEncryption = &mock_encryption;
		let plaintext = b"test";
		let ciphertext = asymmetric_encryption.encrypt(plaintext).unwrap();

		let decrypted = asymmetric_encryption.decrypt(&ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
		assert!(!asymmetric_encryption.algorithm_info().is_empty());
	}

	#[test]
	fn test_encryption_round_trip() {
		let enc = MockAsymmetricEncryption::new_private();
		let original_data = b"round trip test data with various characters: 123!@#$%^&*()";

		// Test full round-trip
		let encrypted = enc.encrypt(original_data).unwrap();
		assert_ne!(encrypted.as_slice(), original_data); // Should be different after encryption

		let decrypted = enc.decrypt(&encrypted).unwrap();
		assert_eq!(decrypted, original_data); // Should match original after decryption
	}

	#[test]
	fn test_key_exchange_different_keys() {
		let alice = MockKeyExchange::new();
		let bob_key1 = [0x11; 32];
		let bob_key2 = [0x22; 32];

		// Different public keys should produce different shared secrets
		let secret1 = alice.key_exchange(&bob_key1).unwrap();
		let secret2 = alice.key_exchange(&bob_key2).unwrap();
		assert_ne!(secret1, secret2);
	}
}
