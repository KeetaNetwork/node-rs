use k256::{
	ecdsa::SigningKey,
	elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
	NonZeroScalar, Scalar, SecretKey as K256SecretKey, U256,
};

use crate::{
	algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey},
	error::CryptoError,
	utils::format_public_key,
};

/// secp256k1 private key
#[derive(Clone)]
pub struct Secp256k1PrivateKey {
	inner: K256SecretKey,
}

impl std::fmt::Debug for Secp256k1PrivateKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Secp256k1PrivateKey").field("inner", &"[REDACTED]").finish()
	}
}

/// secp256k1 public key
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
		// Return compressed format (33 bytes)
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

/// secp256k1 key derivation
pub struct Secp256k1Derivation;

impl KeyDerivation for Secp256k1Derivation {
	type PrivateKey = Secp256k1PrivateKey;

	fn derive_from_seed(seed: &[u8]) -> Result<Self::PrivateKey, CryptoError> {
		// Use HKDF with retry logic similar to the current implementation
		// We will try multiple times to find a valid non-zero scalar which
		// is necessary for secp256k1 keys
		for attempt in 0u32..1000 {
			let mut key_bytes = [0u8; 32];

			// Create HKDF from the seed with attempt counter
			let mut seed_with_attempt = seed.to_vec();
			seed_with_attempt.extend_from_slice(&attempt.to_be_bytes());

			// First extract, then expand
			let (prk, _) = hkdf::Hkdf::<sha3::Sha3_256>::extract(None, &seed_with_attempt);
			let hkdf = hkdf::Hkdf::<sha3::Sha3_256>::from_prk(&prk).map_err(|_| CryptoError::KeyDerivationFailed)?;
			hkdf.expand(&[0u8; 0], &mut key_bytes).map_err(|_| CryptoError::KeyDerivationFailed)?;

			// Convert bytes to U256 and reduce modulo curve order
			let x = U256::from_be_slice(&key_bytes);
			let scalar = Scalar::reduce(x);

			// Try to create NonZeroScalar
			if let Some(nonzero_scalar) = NonZeroScalar::new(scalar).into_option() {
				let secret_key = K256SecretKey::from(nonzero_scalar);
				return Ok(Secp256k1PrivateKey { inner: secret_key });
			}

			// If scalar was zero, continue to next attempt
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
		let seed = b"deterministic test seed";

		let key1 = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let key2 = Secp256k1Derivation::derive_from_seed(seed).unwrap();

		assert_eq!(key1.to_bytes(), key2.to_bytes());

		let pub1 = key1.derive_public_key();
		let pub2 = key2.derive_public_key();

		assert_eq!(pub1.to_bytes(), pub2.to_bytes());
	}
}
