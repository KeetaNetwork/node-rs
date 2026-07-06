//! Shared helpers for AES cipher modes that transport the IV alongside the
//! ciphertext (IV prepended to the encrypted payload).

use alloc::vec::Vec;

use rand_core::{OsRng, TryRngCore};

use crate::error::CryptoError;

/// AES block/IV size in bytes.
pub(crate) const IV_SIZE: usize = 16;

/// Validate that a key has the expected length.
pub(crate) fn ensure_key_size(key: &[u8], expected: usize) -> Result<(), CryptoError> {
	if key.len() != expected {
		return Err(CryptoError::InvalidKeySize);
	}

	Ok(())
}

/// Resolve the IV for encryption: validate a caller-provided IV or generate a
/// cryptographically random one.
pub(crate) fn resolve_iv(iv: Option<&[u8]>) -> Result<[u8; IV_SIZE], CryptoError> {
	let mut iv_array = [0u8; IV_SIZE];
	match iv {
		Some(iv_slice) => {
			if iv_slice.len() != IV_SIZE {
				return Err(CryptoError::InvalidIvSize);
			}

			iv_array.copy_from_slice(iv_slice);
		}
		None => OsRng.try_fill_bytes(&mut iv_array)?,
	}

	Ok(iv_array)
}

/// Assemble the transport format: IV followed by ciphertext.
pub(crate) fn prepend_iv(iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Vec<u8> {
	let mut result = Vec::with_capacity(IV_SIZE + ciphertext.len());
	result.extend_from_slice(iv);
	result.extend_from_slice(ciphertext);

	result
}

/// Split the transport format back into (IV, encrypted payload).
pub(crate) fn split_iv(ciphertext: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
	if ciphertext.len() < IV_SIZE {
		return Err(CryptoError::DecryptionFailed);
	}

	let iv_and_payload = ciphertext.split_at(IV_SIZE);
	Ok(iv_and_payload)
}
