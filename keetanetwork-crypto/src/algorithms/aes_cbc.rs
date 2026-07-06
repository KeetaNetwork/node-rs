//! AES-CBC symmetric encryption implementation.
//!
//! This module provides AES-CBC encryption.

use alloc::vec::Vec;

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};

use crate::algorithms::aes_common::{ensure_key_size, prepend_iv, resolve_iv, split_iv};
use crate::error::CryptoError;
use crate::operations::encryption::SymmetricEncryption;

/// AES-256-CBC symmetric encryption implementation.
type Aes256CbcEnc = Encryptor<Aes256>;
/// AES-256-CBC symmetric decryption implementation.
type Aes256CbcDec = Decryptor<Aes256>;

/// AES-256-CBC symmetric encryption implementation.
///
/// This implementation provides AES-CBC encryption.
#[derive(Debug, Default, Copy, Clone)]
pub struct Aes256Cbc;

impl Aes256Cbc {
	/// Create a new AES-256-CBC instance
	pub fn new() -> Self {
		Self
	}
}

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
		ensure_key_size(key, 32)?;

		// Use provided IV or generate random one
		let iv_bytes = resolve_iv(iv)?;
		// Create cipher
		let cipher = Aes256CbcEnc::new_from_slices(key, &iv_bytes)?;
		// Encrypt with PKCS#7 padding
		let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_ref());

		// Return IV + ciphertext
		Ok(prepend_iv(&iv_bytes, &ciphertext))
	}

	/// Decrypt data using AES-256-CBC.
	///
	/// # Returns
	/// Decrypted data with PKCS#7 padding removed.
	fn decrypt<K: AsRef<[u8]>, C: AsRef<[u8]>>(&self, key: K, ciphertext: C) -> Result<Vec<u8>, CryptoError> {
		let key = key.as_ref();
		ensure_key_size(key, 32)?;

		// Extract IV and encrypted payload
		let (iv, encrypted_data) = split_iv(ciphertext.as_ref())?;
		// Create cipher
		let cipher = Aes256CbcDec::new_from_slices(key, iv)?;

		// Decrypt with PKCS#7 padding removal
		let decrypted = cipher.decrypt_padded_vec_mut::<Pkcs7>(encrypted_data)?;
		Ok(decrypted)
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

	crate::test_utils::test_aes_symmetric!(Aes256Cbc, 32, "AES-256-CBC");

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
