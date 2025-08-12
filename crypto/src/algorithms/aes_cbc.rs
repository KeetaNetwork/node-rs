//! AES-CBC symmetric encryption implementation.
//!
//! This module provides AES-CBC encryption.

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use rand_core::{OsRng, TryRngCore};

use crate::error::CryptoError;
use crate::operations::encryption::SymmetricEncryption;

/// AES-256-CBC symmetric encryption implementation.
type Aes256CbcEnc = Encryptor<Aes256>;
/// AES-256-CBC symmetric decryption implementation.
type Aes256CbcDec = Decryptor<Aes256>;

/// AES-256-CBC symmetric encryption implementation.
///
/// This implementation provides AES-CBC encryption.
pub struct Aes256Cbc;

impl SymmetricEncryption for Aes256Cbc {
	/// Encrypt data using AES-256-CBC.
	///
	/// # Returns
	/// Encrypted data with PKCS#7 padding applied.
	fn encrypt<K: AsRef<[u8]>, P: AsRef<[u8]>>(
		&self,
		key: K,
		iv: Option<&[u8]>,
		plaintext: P,
	) -> Result<Vec<u8>, CryptoError> {
		let key = key.as_ref();
		let plaintext = plaintext.as_ref();

		if key.len() != 32 {
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
			None => {
				let mut iv_array = [0u8; 16];
				OsRng
					.try_fill_bytes(&mut iv_array)
					.map_err(|_| CryptoError::EncryptionFailed)?;
				iv_array
			}
		};

		// Create cipher
		let cipher = Aes256CbcEnc::new_from_slices(key, &iv_bytes)?;
		// Encrypt with PKCS#7 padding
		let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

		// Return IV + ciphertext
		let mut result = Vec::with_capacity(16 + ciphertext.len());
		result.extend_from_slice(&iv_bytes);
		result.extend_from_slice(&ciphertext);

		Ok(result)
	}

	/// Decrypt data using AES-256-CBC.
	///
	/// # Returns
	/// Decrypted data with PKCS#7 padding removed.
	fn decrypt<K: AsRef<[u8]>, C: AsRef<[u8]>>(&self, key: K, ciphertext: C) -> Result<Vec<u8>, CryptoError> {
		let key = key.as_ref();
		let ciphertext = ciphertext.as_ref();

		if key.len() != 32 {
			return Err(CryptoError::InvalidKeySize);
		}

		if ciphertext.len() < 16 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Extract IV and ciphertext
		let iv = &ciphertext[0..16];
		// Ensure ciphertext is long enough
		let encrypted_data = &ciphertext[16..];
		// Create cipher
		let cipher = Aes256CbcDec::new_from_slices(key, iv)?;
		// Decrypt with PKCS#7 padding removal
		let decrypted = cipher.decrypt_padded_vec_mut::<Pkcs7>(encrypted_data)?;

		Ok(decrypted)
	}

	fn algorithm_info(&self) -> &'static str {
		"AES-256-CBC"
	}

	fn key_size(&self) -> usize {
		32 // AES-256 uses 32-byte keys
	}

	fn block_size(&self) -> usize {
		16 // AES has 16-byte blocks
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_aes_256_cbc_basic() {
		let aes_cbc = Aes256Cbc;
		let key = [0x42u8; 32]; // 256-bit key
		let plaintext = b"Hello, AES-CBC world!";

		// Test encryption
		let ciphertext = aes_cbc.encrypt(key, None, plaintext).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext); // Should be different
		assert!(ciphertext.len() > plaintext.len()); // Should include IV and padding

		// Test decryption
		let decrypted = aes_cbc.decrypt(key, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_aes_256_cbc_properties() {
		let aes_cbc = Aes256Cbc;
		assert_eq!(aes_cbc.key_size(), 32);
		assert_eq!(aes_cbc.block_size(), 16);
		assert_eq!(aes_cbc.algorithm_info(), "AES-256-CBC");
	}

	#[test]
	fn test_aes_256_cbc_wrong_key_size() {
		let aes_cbc = Aes256Cbc;
		let wrong_key = [0x42u8; 16]; // Wrong size (should be 32)
		let plaintext = b"test";

		// Test encryption with wrong key size
		let result = aes_cbc.encrypt(wrong_key, None, plaintext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeySize));

		// Test decryption with wrong key size
		let fake_ciphertext = [0u8; 32];
		let result = aes_cbc.decrypt(wrong_key, fake_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeySize));
	}

	#[test]
	fn test_aes_256_cbc_short_ciphertext() {
		let aes_cbc = Aes256Cbc;
		let key = [0x42u8; 32];
		let short_ciphertext = [0u8; 8]; // Too short (needs at least 16 bytes for IV)

		let result = aes_cbc.decrypt(key, short_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));
	}

	#[test]
	fn test_aes_256_cbc_random_iv() {
		let aes_cbc = Aes256Cbc;
		let key = [0x42u8; 32];
		let plaintext = b"Same plaintext";

		// Encrypt the same plaintext twice
		// Cipher texts should be different due to random IV
		let ciphertext1 = aes_cbc.encrypt(key, None, plaintext).unwrap();
		let ciphertext2 = aes_cbc.encrypt(key, None, plaintext).unwrap();
		assert_ne!(ciphertext1, ciphertext2);

		// But both should decrypt to the same plaintext
		let decrypted1 = aes_cbc.decrypt(key, &ciphertext1).unwrap();
		let decrypted2 = aes_cbc.decrypt(key, &ciphertext2).unwrap();
		assert_eq!(decrypted1, plaintext);
		assert_eq!(decrypted2, plaintext);
	}

	#[test]
	fn test_aes_256_cbc_pkcs7_padding() {
		let aes_cbc = Aes256Cbc;
		let key = [0x42u8; 32];

		// Test with data that's exactly block-aligned (16 bytes)
		let block_aligned = [0x55u8; 16];
		let ciphertext = aes_cbc.encrypt(key, None, block_aligned).unwrap();
		let decrypted = aes_cbc.decrypt(key, &ciphertext).unwrap();
		assert_eq!(decrypted, block_aligned);

		// Test with data that needs padding (15 bytes)
		let needs_padding = [0x66u8; 15];
		let ciphertext = aes_cbc.encrypt(key, None, needs_padding).unwrap();
		let decrypted = aes_cbc.decrypt(key, &ciphertext).unwrap();
		assert_eq!(decrypted, needs_padding);

		// Test with data that needs lots of padding (1 byte)
		let minimal_data = [0x77u8; 1];
		let ciphertext = aes_cbc.encrypt(key, None, minimal_data).unwrap();
		let decrypted = aes_cbc.decrypt(key, &ciphertext).unwrap();
		assert_eq!(decrypted, minimal_data);
	}
}
