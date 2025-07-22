//! secp256k1 cryptographic algorithm implementation.
//!
//! This module provides secp256k1 elliptic curve cryptography support, the
//! same curve used by Bitcoin.
//!
//! ## Key Format
//!
//! - **Private keys**: 32 bytes, in range [1, n-1] where n is the curve order
//! - **Public keys**: 33 bytes compressed format (0x02/0x03 prefix + 32 bytes)
//! - **Addresses**: Formatted with "keeta_" prefix and checksum
//!
//! ## Usage
//!
//! ```rust
//! use crypto::{Secp256k1Derivation, KeyDerivation, PrivateKey, PublicKey};
//!
//! // Generate key from seed
//! let seed = b"my secure seed data with 32+ bytes!!";
//! let private_key = Secp256k1Derivation::derive_from_seed(seed)?;
//! let public_key = private_key.derive_public_key();
//!
//! // Format for display
//! let address = public_key.to_formatted_string()?;
//! println!("secp256k1 address: {}", address);
//!
//! // Keys can be serialized and deserialized
//! let private_bytes = private_key.to_bytes();
//! let restored_key = crypto::algorithms::secp256k1::Secp256k1PrivateKey::from_bytes(&private_bytes)?;
//! # Ok::<(), crypto::CryptoError>(())
//! ```

use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, SecretKey as K256SecretKey};

use crate::{
	algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey},
	error::CryptoError,
	utils::format_public_key,
};

/// secp256k1 private key wrapper.
///
/// This struct wraps the k256 SecretKey and provides the PrivateKey trait
/// implementation. secp256k1 private keys are 32 bytes long and must be in
/// the range [1, n-1] where n is the curve order.
///
/// ## Security Note
///
/// The inner secret key is kept private and only accessible through the trait
/// methods. Debug formatting will show "[REDACTED]" to prevent accidental
/// key exposure.
#[derive(Clone)]
pub struct Secp256k1PrivateKey {
	inner: K256SecretKey,
}

impl std::fmt::Debug for Secp256k1PrivateKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

	fn derive_public_key(&self) -> Self::PublicKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();

		Secp256k1PublicKey { inner: verifying_key.into() }
	}

	fn to_bytes(&self) -> Vec<u8> {
		self.inner.to_bytes().to_vec()
	}

	fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
		let secret_key = K256SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;
		Ok(Secp256k1PrivateKey { inner: secret_key })
	}
}

impl PublicKey for Secp256k1PublicKey {
	fn to_bytes(&self) -> Vec<u8> {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		self.inner.to_encoded_point(true).as_bytes().to_vec()
	}

	fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
		let public_key = k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
		Ok(Secp256k1PublicKey { inner: public_key })
	}

	fn to_formatted_string(&self) -> Result<String, CryptoError> {
		let compressed_bytes = self.to_bytes();
		format_public_key(&compressed_bytes, Algorithm::Secp256k1)
	}
}

/// secp256k1 key derivation implementation
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

	#[test]
	fn test_secp256k1_key_derivation() {
		let seed = b"test seed for secp256k1 key derivation";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.derive_public_key();

		// Test serialization roundtrip
		let private_bytes = private_key.to_bytes();
		let recovered_private = Secp256k1PrivateKey::from_bytes(&private_bytes).unwrap();
		assert_eq!(private_key.to_bytes(), recovered_private.to_bytes());

		let public_bytes = public_key.to_bytes();
		let recovered_public = Secp256k1PublicKey::from_bytes(&public_bytes).unwrap();
		assert_eq!(public_key.to_bytes(), recovered_public.to_bytes());

		// Test public key formatting
		let formatted = public_key.to_formatted_string().unwrap();
		assert!(formatted.starts_with("keeta_"));
	}

	#[test]
	fn test_secp256k1_deterministic() {
		// Create a proper seed+index buffer (36 bytes total)
		let mut seed_with_index = [0u8; 36];
		seed_with_index[..23].copy_from_slice(b"deterministic test seed");
		// index 0 is already set (last 4 bytes are 0)

		let key1 = Secp256k1Derivation::derive_from_seed(&seed_with_index).unwrap();
		let key2 = Secp256k1Derivation::derive_from_seed(&seed_with_index).unwrap();

		assert_eq!(key1.to_bytes(), key2.to_bytes());

		let pub1 = key1.derive_public_key();
		let pub2 = key2.derive_public_key();

		assert_eq!(pub1.to_bytes(), pub2.to_bytes());
	}
}
