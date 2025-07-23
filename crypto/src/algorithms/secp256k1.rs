//! secp256k1 cryptographic algorithm implementation.
//!
//! This module provides secp256k1 elliptic curve cryptography support, the
//! same curve used by Bitcoin.
//!
//! ## Key Format
//!
//! - **Private keys**: 32 bytes, in range [1, n-1] where n is the curve order
//! - **Public keys**: 33 bytes compressed format (0x02/0x03 prefix + 32 bytes)

use k256::{
	ecdsa::{Signature, SigningKey},
	elliptic_curve::sec1::ToEncodedPoint,
	SecretKey as K256SecretKey,
};
use secrecy::SecretBox;

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};

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

#[cfg(feature = "signature")]
impl PrivateKey<Signature> for Secp256k1PrivateKey {
	type PublicKey = Secp256k1PublicKey;
}

#[cfg(feature = "signature")]
impl From<Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Secp256k1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

#[cfg(feature = "signature")]
impl From<&Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Secp256k1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

#[cfg(feature = "signature")]
impl TryFrom<&[u8]> for Secp256k1PrivateKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let secret_key = K256SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;

		Ok(Secp256k1PrivateKey { inner: secret_key })
	}
}

#[cfg(not(feature = "signature"))]
impl PrivateKey for Secp256k1PrivateKey {
	type PublicKey = Secp256k1PublicKey;

	fn verifying_key(&self) -> Self::PublicKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();

		Secp256k1PublicKey { inner: verifying_key.into() }
	}
}

#[cfg(not(feature = "signature"))]
impl From<Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Secp256k1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

#[cfg(not(feature = "signature"))]
impl From<&Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Secp256k1PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

#[cfg(not(feature = "signature"))]
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

#[cfg(feature = "signature")]
impl PublicKey<Signature> for Secp256k1PublicKey {}

#[cfg(feature = "signature")]
impl From<Secp256k1PublicKey> for Vec<u8> {
	fn from(key: Secp256k1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

#[cfg(feature = "signature")]
impl From<&Secp256k1PublicKey> for Vec<u8> {
	fn from(key: &Secp256k1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

#[cfg(feature = "signature")]
impl TryFrom<&[u8]> for Secp256k1PublicKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let public_key = k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;

		Ok(Secp256k1PublicKey { inner: public_key })
	}
}

#[cfg(not(feature = "signature"))]
impl PublicKey for Secp256k1PublicKey {}

#[cfg(not(feature = "signature"))]
impl From<Secp256k1PublicKey> for Vec<u8> {
	fn from(key: Secp256k1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

#[cfg(not(feature = "signature"))]
impl From<&Secp256k1PublicKey> for Vec<u8> {
	fn from(key: &Secp256k1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

#[cfg(not(feature = "signature"))]
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

#[cfg(feature = "signature")]
impl KeyDerivation<Signature> for Secp256k1Derivation {
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

#[cfg(not(feature = "signature"))]
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
	use secrecy::ExposeSecret;

	#[test]
	fn test_secp256k1_key_derivation() {
		let seed = b"test seed for secp256k1 key derivation";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.verifying_key();

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

		// Test public key formatting - now handled by accounts crate
		let hex_formatted = hex::encode(Vec::<u8>::from(&public_key));
		assert_eq!(hex_formatted.len(), 66); // 33 bytes * 2 chars per byte
	}

	#[test]
	fn test_secp256k1_deterministic() {
		// Create a proper seed+index buffer (36 bytes total)
		let mut seed_with_index = [0u8; 36];
		seed_with_index[..23].copy_from_slice(b"deterministic test seed");
		// index 0 is already set (last 4 bytes are 0)

		let key1 = Secp256k1Derivation::derive_from_seed(&seed_with_index).unwrap();
		let key2 = Secp256k1Derivation::derive_from_seed(&seed_with_index).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&key1).expose_secret(),
			SecretBox::<Vec<u8>>::from(&key2).expose_secret()
		);

		let (pub1, pub2) = (key1.verifying_key(), key2.verifying_key());
		assert_eq!(Vec::<u8>::from(&pub1), Vec::<u8>::from(&pub2));
	}
}
