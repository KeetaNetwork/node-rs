//! AES-GCM authenticated encryption implementation.
//!
//! This module provides AES-GCM AEAD.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm as AesGcmCipher, Key};

// Re-export the Nonce type for convenience
pub use aes_gcm::Nonce;

use crate::error::CryptoError;
use crate::operations::encryption::{CryptoAead, NonceGeneration};

/// AES-256-GCM authenticated encryption implementation.
///
/// This implementation provides a wrapper for AES-GCM encryption.
pub struct Aes256Gcm {
	cipher: AesGcmCipher,
}

impl Aes256Gcm {
	/// Create a new AES-256-GCM instance with the given key
	pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
		if key.len() != 32 {
			return Err(CryptoError::InvalidKeySize);
		}

		let key = Key::<AesGcmCipher>::from_slice(key);
		let cipher = AesGcmCipher::new(key);

		Ok(Self { cipher })
	}

	/// Get the expected key size in bytes
	pub fn key_size() -> usize {
		32 // AES-256 uses 32-byte keys
	}

	/// Get the nonce size in bytes
	pub fn nonce_size() -> usize {
		12 // GCM standard nonce size
	}

	/// Get the authentication tag size in bytes
	pub fn tag_size() -> usize {
		16 // GCM standard tag size
	}
}

// Implement the underlying AEAD traits by delegating to the inner cipher
impl Aead for Aes256Gcm {
	fn encrypt<'msg, 'aad>(
		&self,
		nonce: &aes_gcm::aead::Nonce<Self>,
		plaintext: impl Into<aes_gcm::aead::Payload<'msg, 'aad>>,
	) -> Result<Vec<u8>, aes_gcm::aead::Error> {
		self.cipher.encrypt(nonce, plaintext)
	}

	fn decrypt<'msg, 'aad>(
		&self,
		nonce: &aes_gcm::aead::Nonce<Self>,
		ciphertext: impl Into<aes_gcm::aead::Payload<'msg, 'aad>>,
	) -> Result<Vec<u8>, aes_gcm::aead::Error> {
		self.cipher.decrypt(nonce, ciphertext)
	}
}

impl AeadCore for Aes256Gcm {
	type NonceSize = <AesGcmCipher as AeadCore>::NonceSize;
	type TagSize = <AesGcmCipher as AeadCore>::TagSize;
	type CiphertextOverhead = <AesGcmCipher as AeadCore>::CiphertextOverhead;
}

impl CryptoAead for Aes256Gcm {
	fn algorithm_info(&self) -> &'static str {
		"AES-256-GCM"
	}
}

impl NonceGeneration for Aes256Gcm {
	type Nonce = aes_gcm::aead::Nonce<Self>;

	fn generate_nonce() -> Self::Nonce {
		AesGcmCipher::generate_nonce(&mut OsRng)
	}

	fn nonce_size() -> usize {
		12 // GCM standard nonce size
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::operations::encryption::NonceGeneration;

	#[test]
	fn test_aes_256_gcm_basic() {
		let key = [0x42u8; 32]; // 256-bit key
		let aes_gcm = Aes256Gcm::new(&key).unwrap();
		let plaintext = b"Hello, AES-GCM world!";

		// Generate nonce for testing
		let nonce = AesGcmCipher::generate_nonce(&mut OsRng);

		// Test encryption
		let ciphertext = aes_gcm
			.encrypt(&nonce, plaintext.as_ref())
			.unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext); // Should be different
		assert!(ciphertext.len() > plaintext.len()); // Should include tag

		// Test decryption
		let decrypted = aes_gcm
			.decrypt(&nonce, ciphertext.as_ref())
			.unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_256_gcm_properties() {
		let key = [0x42u8; 32];

		let aes_gcm = Aes256Gcm::new(&key).unwrap();
		assert_eq!(aes_gcm.algorithm_info(), "AES-256-GCM");
		assert_eq!(Aes256Gcm::key_size(), 32);
		assert_eq!(Aes256Gcm::nonce_size(), 12);
		assert_eq!(Aes256Gcm::tag_size(), 16);
	}

	#[test]
	fn test_aes_256_gcm_wrong_key_size() {
		let wrong_key = [0x42u8; 16]; // Wrong size (should be 32)
		let result = Aes256Gcm::new(&wrong_key);
		assert!(result.is_err());

		if let Err(err) = result {
			assert!(matches!(err, CryptoError::InvalidKeySize));
		}
	}

	#[test]
	fn test_aes_256_gcm_random_nonce() {
		let key = [0x42u8; 32];
		let aes_gcm = Aes256Gcm::new(&key).unwrap();
		let plaintext = b"Same plaintext";

		// Generate two different nonces
		let nonce1 = AesGcmCipher::generate_nonce(&mut OsRng);
		let nonce2 = AesGcmCipher::generate_nonce(&mut OsRng);

		// Encrypt the same plaintext with different nonces
		// Should be different due to different nonces
		let ciphertext1 = aes_gcm
			.encrypt(&nonce1, plaintext.as_ref())
			.unwrap();
		let ciphertext2 = aes_gcm
			.encrypt(&nonce2, plaintext.as_ref())
			.unwrap();
		assert_ne!(ciphertext1, ciphertext2);

		// But both should decrypt to the same plaintext
		let decrypted1 = aes_gcm
			.decrypt(&nonce1, ciphertext1.as_ref())
			.unwrap();
		let decrypted2 = aes_gcm
			.decrypt(&nonce2, ciphertext2.as_ref())
			.unwrap();
		assert_eq!(decrypted1, plaintext);
		assert_eq!(decrypted2, plaintext);
	}

	#[test]
	fn test_aes_256_gcm_authentication() {
		let key = [0x42u8; 32];
		let aes_gcm = Aes256Gcm::new(&key).unwrap();
		let plaintext = b"Authenticated message";
		let nonce = AesGcmCipher::generate_nonce(&mut OsRng);

		// Encrypt data
		let mut ciphertext = aes_gcm
			.encrypt(&nonce, plaintext.as_ref())
			.unwrap();
		// Tamper with the ciphertext (modify the last byte)
		let last_idx = ciphertext.len() - 1;
		ciphertext[last_idx] ^= 0x01;

		// Decryption should fail due to authentication failure
		let result = aes_gcm.decrypt(&nonce, ciphertext.as_ref());
		assert!(result.is_err());
	}

	#[test]
	fn test_aes_256_gcm_with_aad() {
		let key = [0x42u8; 32];
		let aes_gcm = Aes256Gcm::new(&key).unwrap();
		let plaintext = b"Secret message";
		let aad = b"additional data";
		let nonce = AesGcmCipher::generate_nonce(&mut OsRng);

		// Create payload with AAD
		let payload = aes_gcm::aead::Payload { msg: plaintext.as_ref(), aad: aad.as_ref() };
		// Test encryption with AAD
		let ciphertext = aes_gcm.encrypt(&nonce, payload).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext);

		// Test decryption with correct AAD
		let payload_decrypt = aes_gcm::aead::Payload { msg: ciphertext.as_ref(), aad: aad.as_ref() };
		let decrypted = aes_gcm.decrypt(&nonce, payload_decrypt).unwrap();
		assert_eq!(decrypted, plaintext);

		// Test decryption with wrong AAD should fail
		let wrong_aad = b"wrong additional data";
		let wrong_payload = aes_gcm::aead::Payload { msg: ciphertext.as_ref(), aad: wrong_aad.as_ref() };
		let result = aes_gcm.decrypt(&nonce, wrong_payload);
		assert!(result.is_err());
	}

	#[test]
	fn test_aes_256_gcm_empty_plaintext() {
		let key = [0x42u8; 32];
		let aes_gcm = Aes256Gcm::new(&key).unwrap();
		let plaintext = b"";
		let nonce = AesGcmCipher::generate_nonce(&mut OsRng);

		// Should handle empty plaintext correctly
		let ciphertext = aes_gcm
			.encrypt(&nonce, plaintext.as_ref())
			.unwrap();
		assert_eq!(ciphertext.len(), 16); // tag only

		let decrypted = aes_gcm
			.decrypt(&nonce, ciphertext.as_ref())
			.unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_256_gcm_large_data() {
		let key = [0x42u8; 32];
		let aes_gcm = Aes256Gcm::new(&key).unwrap();
		let plaintext = vec![0x55u8; 8192]; // 8KB of data
		let nonce = AesGcmCipher::generate_nonce(&mut OsRng);

		// Should handle large data efficiently
		let ciphertext = aes_gcm
			.encrypt(&nonce, plaintext.as_ref())
			.unwrap();
		assert_eq!(ciphertext.len(), 8192 + 16); // data + tag

		let decrypted = aes_gcm
			.decrypt(&nonce, ciphertext.as_ref())
			.unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_256_gcm_nonce_generation() {
		// Test that nonce generation works
		let nonce1 = <Aes256Gcm as NonceGeneration>::generate_nonce();
		let nonce2 = <Aes256Gcm as NonceGeneration>::generate_nonce();
		// Nonces should be different
		assert_ne!(&nonce1[..], &nonce2[..]);
		// Nonces should be the expected size
		assert_eq!(nonce1.len(), 12);
		assert_eq!(nonce2.len(), 12);
		assert_eq!(<Aes256Gcm as NonceGeneration>::nonce_size(), 12);
	}
}
