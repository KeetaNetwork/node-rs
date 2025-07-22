use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{
	algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey},
	error::CryptoError,
	utils::format_public_key,
};

/// Ed25519 private key
#[derive(Clone)]
pub struct Ed25519PrivateKey {
	inner: SigningKey,
}

impl std::fmt::Debug for Ed25519PrivateKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Ed25519PrivateKey").field("inner", &"[REDACTED]").finish()
	}
}

/// Ed25519 public key
#[derive(Clone, Debug)]
pub struct Ed25519PublicKey {
	inner: VerifyingKey,
}

impl PrivateKey for Ed25519PrivateKey {
	type PublicKey = Ed25519PublicKey;

	fn derive_public_key(&self) -> Self::PublicKey {
		Ed25519PublicKey { inner: self.inner.verifying_key() }
	}

	fn to_bytes(&self) -> Vec<u8> {
		self.inner.to_bytes().to_vec()
	}

	fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
		let bytes_array: [u8; ed25519_dalek::SECRET_KEY_LENGTH] =
			bytes.try_into().map_err(|_| CryptoError::InvalidPrivateKey)?;
		let signing_key = SigningKey::from_bytes(&bytes_array);
		Ok(Ed25519PrivateKey { inner: signing_key })
	}
}

impl PublicKey for Ed25519PublicKey {
	fn to_bytes(&self) -> Vec<u8> {
		self.inner.to_bytes().to_vec()
	}

	fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
		let bytes_array: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
			bytes.try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
		let verifying_key = VerifyingKey::from_bytes(&bytes_array).map_err(|_| CryptoError::InvalidPublicKey)?;
		Ok(Ed25519PublicKey { inner: verifying_key })
	}

	fn to_formatted_string(&self) -> Result<String, CryptoError> {
		let raw_bytes = self.to_bytes();
		format_public_key(&raw_bytes, Algorithm::Ed25519)
	}
}

/// Ed25519 key derivation
pub struct Ed25519Derivation;

impl KeyDerivation for Ed25519Derivation {
	type PrivateKey = Ed25519PrivateKey;

	fn derive_from_seed(seed: &[u8]) -> Result<Self::PrivateKey, CryptoError> {
		// Ed25519 keys can be derived directly from 32 bytes
		// Use HKDF to get exactly 32 bytes
		let mut key_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];

		let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(seed).map_err(|_| CryptoError::KeyDerivationFailed)?;

		hkdf.expand(b"ed25519-key", &mut key_bytes).map_err(|_| CryptoError::KeyDerivationFailed)?;

		let signing_key = SigningKey::from_bytes(&key_bytes);

		Ok(Ed25519PrivateKey { inner: signing_key })
	}

	fn validate_key_material(bytes: &[u8]) -> bool {
		bytes.len() == ed25519_dalek::SECRET_KEY_LENGTH
	}

	fn key_size() -> usize {
		ed25519_dalek::SECRET_KEY_LENGTH
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ed25519_key_derivation() {
		let seed = b"test seed for ed25519 key derivation!!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.derive_public_key();

		// Test serialization roundtrip
		let private_bytes = private_key.to_bytes();
		let recovered_private = Ed25519PrivateKey::from_bytes(&private_bytes).unwrap();
		assert_eq!(private_key.to_bytes(), recovered_private.to_bytes());

		let public_bytes = public_key.to_bytes();
		let recovered_public = Ed25519PublicKey::from_bytes(&public_bytes).unwrap();
		assert_eq!(public_key.to_bytes(), recovered_public.to_bytes());

		// Test public key formatting
		let formatted = public_key.to_formatted_string().unwrap();
		assert!(formatted.starts_with("keeta_"));
	}

	#[test]
	fn test_ed25519_deterministic() {
		let seed = b"deterministic test seed for ed25519!!";

		let key1 = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let key2 = Ed25519Derivation::derive_from_seed(seed).unwrap();

		assert_eq!(key1.to_bytes(), key2.to_bytes());

		let pub1 = key1.derive_public_key();
		let pub2 = key2.derive_public_key();

		assert_eq!(pub1.to_bytes(), pub2.to_bytes());
	}

	#[test]
	fn test_ed25519_different_from_secp256k1() {
		use crate::algorithms::secp256k1::Secp256k1Derivation;

		let seed = b"same seed for both algorithms!!!!!!";

		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let secp256k1_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();

		// Keys should be different even with same seed
		assert_ne!(ed25519_key.to_bytes(), secp256k1_key.to_bytes());

		let ed25519_pub = ed25519_key.derive_public_key();
		let secp256k1_pub = secp256k1_key.derive_public_key();

		// Public keys should also be different
		assert_ne!(ed25519_pub.to_bytes(), secp256k1_pub.to_bytes());
	}
}
