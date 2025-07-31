//! AES-CTR stream cipher implementation.
//!
//! This module provides AES-CTR symmetric encryption.

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand_core::{OsRng, TryRngCore};

use crate::error::CryptoError;
use crate::operations::encryption::SymmetricEncryption;

/// AES-128-CTR stream cipher type alias
type Aes128Ctr = Ctr128BE<Aes128>;

/// AES-128-CTR symmetric encryption implementation.
///
/// This implementation provides CTR mode encryption which converts a block
/// cipher into a stream cipher. CTR mode does not provide authentication
///
/// Security: it only provides confidentiality. For authenticated encryption,
/// use AES-GCM instead.
pub struct Aes128CtrCipher;

impl Aes128CtrCipher {
	/// Create a new AES-128-CTR cipher instance
	pub fn new() -> Self {
		Self
	}

	/// Get the expected key size in bytes
	pub fn key_size() -> usize {
		16 // AES-128 uses 16-byte keys
	}

	/// Get the IV size in bytes
	pub fn iv_size() -> usize {
		16 // CTR mode uses 16-byte IVs
	}

	/// Generate a random IV for CTR mode
	pub fn generate_iv() -> [u8; 16] {
		let mut iv = [0u8; 16];
		OsRng.try_fill_bytes(&mut iv).expect("Failed to generate random IV");

		iv
	}

	/// Encrypt data with a provided IV
	///
	/// # Arguments
	/// * `key` - 16-byte encryption key
	/// * `iv` - 16-byte initialization vector
	/// * `plaintext` - Data to encrypt
	///
	/// # Returns
	/// Encrypted data (same length as plaintext)
	pub fn encrypt_with_iv(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		if key.len() != 16 {
			return Err(CryptoError::InvalidKeySize);
		}
		if iv.len() != 16 {
			return Err(CryptoError::InvalidOperation);
		}

		// Create CTR cipher instance
		let mut cipher = Aes128Ctr::new_from_slices(key, iv)?;
		// CTR mode works in-place, so we need a mutable copy
		let mut ciphertext = plaintext.to_vec();

		cipher.apply_keystream(&mut ciphertext);

		Ok(ciphertext)
	}

	/// Decrypt data with a provided IV
	///
	/// # Arguments
	/// * `key` - 16-byte encryption key
	/// * `iv` - 16-byte initialization vector
	/// * `ciphertext` - Data to decrypt
	///
	/// # Returns
	/// Decrypted plaintext (same length as ciphertext)
	pub fn decrypt_with_iv(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		if key.len() != 16 {
			return Err(CryptoError::InvalidKeySize);
		}
		if iv.len() != 16 {
			return Err(CryptoError::InvalidOperation);
		}

		// Create CTR cipher instance
		let mut cipher = Aes128Ctr::new_from_slices(key, iv)?;
		// CTR mode is symmetric - decryption is the same as encryption
		let mut plaintext = ciphertext.to_vec();

		cipher.apply_keystream(&mut plaintext);

		Ok(plaintext)
	}
}

impl Default for Aes128CtrCipher {
	fn default() -> Self {
		Self::new()
	}
}

impl SymmetricEncryption for Aes128CtrCipher {
	/// Encrypt data with optional IV prepended
	///
	/// Format: iv (16 bytes) + ciphertext
	fn encrypt(&self, key: &[u8], iv: Option<&[u8]>, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		if key.len() != 16 {
			return Err(CryptoError::InvalidKeySize);
		}

		// Use provided IV or generate random one
		let iv_bytes = match iv {
			Some(iv_slice) => {
				if iv_slice.len() != 16 {
					return Err(CryptoError::InvalidIvSize);
				}
				let mut iv_array = [0u8; 16];
				iv_array.copy_from_slice(iv_slice);
				iv_array
			}
			None => Self::generate_iv(),
		};

		// Encrypt with the IV
		let ciphertext = self.encrypt_with_iv(key, &iv_bytes, plaintext)?;

		// Prepend IV to ciphertext
		let mut result = Vec::with_capacity(16 + ciphertext.len());
		result.extend_from_slice(&iv_bytes);
		result.extend_from_slice(&ciphertext);

		Ok(result)
	}

	/// Decrypt data with IV extracted from the beginning
	///
	/// Expected format: iv (16 bytes) + ciphertext
	fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		if key.len() != 16 {
			return Err(CryptoError::InvalidKeySize);
		}
		if ciphertext.len() < 16 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Extract IV from the beginning
		let iv = &ciphertext[..16];
		let encrypted_data = &ciphertext[16..];

		// Decrypt with the extracted IV
		self.decrypt_with_iv(key, iv, encrypted_data)
	}

	fn algorithm_info(&self) -> &'static str {
		"AES-128-CTR"
	}

	fn key_size(&self) -> usize {
		16
	}

	fn block_size(&self) -> usize {
		16 // AES block size
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_aes_128_ctr_basic() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16]; // 128-bit key
		let plaintext = b"Hello, AES-CTR world!";

		// Test encryption
		let ciphertext = cipher.encrypt(&key, None, plaintext).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext); // Should be different
		assert_eq!(ciphertext.len(), 16 + plaintext.len()); // IV + plaintext length

		// Test decryption
		let decrypted = cipher.decrypt(&key, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_128_ctr_properties() {
		let cipher = Aes128CtrCipher::new();

		assert_eq!(cipher.algorithm_info(), "AES-128-CTR");
		assert_eq!(cipher.key_size(), 16);
		assert_eq!(cipher.block_size(), 16);
		assert_eq!(Aes128CtrCipher::key_size(), 16);
		assert_eq!(Aes128CtrCipher::iv_size(), 16);
	}

	#[test]
	fn test_aes_128_ctr_wrong_key_size() {
		let cipher = Aes128CtrCipher::new();
		let wrong_key = [0x42u8; 32]; // Wrong size (should be 16)
		let plaintext = b"test";

		let result = cipher.encrypt(&wrong_key, None, plaintext);
		assert!(matches!(result, Err(CryptoError::InvalidKeySize)));
	}

	#[test]
	fn test_aes_128_ctr_with_iv() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16];
		let iv = [0x12u8; 16];
		let plaintext = b"Test with specific IV";

		// Test encryption with specific IV
		let ciphertext = cipher.encrypt_with_iv(&key, &iv, plaintext).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext);
		assert_eq!(ciphertext.len(), plaintext.len()); // CTR preserves length

		// Test decryption with same IV
		let decrypted = cipher.decrypt_with_iv(&key, &iv, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_128_ctr_deterministic_with_same_iv() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16];
		let iv = [0x12u8; 16];
		let plaintext = b"Same plaintext";

		// Encrypt the same plaintext with the same IV twice
		// Should be identical (deterministic with same key + IV)
		let ciphertext1 = cipher.encrypt_with_iv(&key, &iv, plaintext).unwrap();
		let ciphertext2 = cipher.encrypt_with_iv(&key, &iv, plaintext).unwrap();
		assert_eq!(ciphertext1, ciphertext2);

		// Both should decrypt correctly
		let decrypted1 = cipher.decrypt_with_iv(&key, &iv, &ciphertext1).unwrap();
		let decrypted2 = cipher.decrypt_with_iv(&key, &iv, &ciphertext2).unwrap();
		assert_eq!(decrypted1, plaintext);
		assert_eq!(decrypted2, plaintext);
	}

	#[test]
	fn test_aes_128_ctr_random_ivs() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16];
		let plaintext = b"Same message";

		// Encrypt the same message twice (should use different random IVs)
		let ciphertext1 = cipher.encrypt(&key, None, plaintext).unwrap();
		let ciphertext2 = cipher.encrypt(&key, None, plaintext).unwrap();

		// Cipher texts should be different due to different IVs
		assert_ne!(ciphertext1, ciphertext2);

		// But both should decrypt to the same plaintext
		let decrypted1 = cipher.decrypt(&key, &ciphertext1).unwrap();
		let decrypted2 = cipher.decrypt(&key, &ciphertext2).unwrap();
		assert_eq!(decrypted1, plaintext);
		assert_eq!(decrypted2, plaintext);
	}

	#[test]
	fn test_aes_128_ctr_iv_generation() {
		// Test that IV generation produces different values
		let iv1 = Aes128CtrCipher::generate_iv();
		let iv2 = Aes128CtrCipher::generate_iv();

		// IVs should be different
		assert_ne!(iv1, iv2);
		// IVs should be the expected size
		assert_eq!(iv1.len(), 16);
		assert_eq!(iv2.len(), 16);
	}

	#[test]
	fn test_aes_128_ctr_short_ciphertext() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16];
		let short_ciphertext = [0u8; 15]; // Too short (less than IV size)

		let result = cipher.decrypt(&key, &short_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));
	}

	#[test]
	fn test_aes_128_ctr_empty_plaintext() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16];
		let plaintext = b"";

		// Should handle empty plaintext correctly
		let ciphertext = cipher.encrypt(&key, None, plaintext).unwrap();
		assert_eq!(ciphertext.len(), 16); // IV only

		let decrypted = cipher.decrypt(&key, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_128_ctr_large_data() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16];
		let plaintext = vec![0x55u8; 8192]; // 8KB of data

		let ciphertext = cipher.encrypt(&key, None, &plaintext).unwrap();
		assert_eq!(ciphertext.len(), 16 + 8192); // IV + data

		let decrypted = cipher.decrypt(&key, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_128_ctr_stream_property() {
		let cipher = Aes128CtrCipher::new();
		let key = [0x42u8; 16];
		let iv = [0x12u8; 16];

		let plaintext1 = b"short";
		let plaintext2 = b"a much longer plaintext message";

		let ciphertext1 = cipher.encrypt_with_iv(&key, &iv, plaintext1).unwrap();
		let ciphertext2 = cipher.encrypt_with_iv(&key, &iv, plaintext2).unwrap();
		assert_eq!(ciphertext1.len(), plaintext1.len());
		assert_eq!(ciphertext2.len(), plaintext2.len());

		// Verify decryption works correctly
		let decrypted1 = cipher.decrypt_with_iv(&key, &iv, &ciphertext1).unwrap();
		let decrypted2 = cipher.decrypt_with_iv(&key, &iv, &ciphertext2).unwrap();
		assert_eq!(decrypted1, plaintext1);
		assert_eq!(decrypted2, plaintext2);
	}
}
