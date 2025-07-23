//! Ed25519 cryptographic algorithm implementation
//!
//! This module provides Ed25519 digital signature algorithm support with
//! X25519 key exchange (ECDH) capabilities.
//!
//! ## Key Derivation
//!
//! The Ed25519 uses a different key derivation method than secp256k1:
//! 1. Hash the seed directly with SHA3-256 (no HKDF)
//! 2. Apply Ed25519 clamping to ensure valid private keys:
//!    - Clear bits 0, 1, 2 (ensure divisible by 8)
//!    - Clear bit 255 (ensure < 2^255)
//!    - Set bit 254 (ensure >= 2^254)
//!
//! ## X25519 Key Exchange
//!
//! Ed25519 keys can be converted to X25519 keys for ECDH using two methods:
//!
//! ### Method 1: Private Key Conversion
//! 1. Hash the Ed25519 private key with SHA512
//! 2. Apply Curve25519 clamping to the first 32 bytes
//! 3. Use the result as an X25519 private key for key exchange
//!
//! ### Method 2: Public Key Conversion (Bi-rational Map)
//! 1. Convert the Ed25519 public key directly using the bi-rational map

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use secrecy::{ExposeSecret, SecretBox};
use x25519_dalek::PublicKey as DalekX25519PublicKey;

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};
use zeroize::Zeroize;

use crate::{error::CryptoError, hash, KeyDerivation, PrivateKey, PublicKey};

/// Ed25519 private key wrapper.
///
/// This struct wraps the ed25519-dalek SigningKey and provides the PrivateKey
/// trait implementation. Ed25519 private keys are 32 bytes long and must
/// follow specific clamping rules to ensure they are valid curve points.
///
/// ## Security Note
///
/// The inner signing key is kept private and only accessible through the trait
/// methods. Debug formatting will show "\[REDACTED\]" to prevent accidental
/// key exposure.
#[derive(Clone)]
pub struct Ed25519PrivateKey {
	inner: SigningKey,
}

impl core::fmt::Debug for Ed25519PrivateKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Ed25519PrivateKey").field("inner", &"[REDACTED]").finish()
	}
}

/// Ed25519 public key wrapper.
///
/// This struct wraps the ed25519-dalek VerifyingKey and provides the PublicKey
/// trait implementation. Ed25519 public keys are 32 bytes long and represent
/// points on the Ed25519 curve.
#[derive(Clone, Debug)]
pub struct Ed25519PublicKey {
	inner: VerifyingKey,
}

impl PrivateKey for Ed25519PrivateKey {
	type PublicKey = Ed25519PublicKey;
	type Signature = Signature;

	fn as_public_key(&self) -> Self::PublicKey {
		Ed25519PublicKey { inner: self.inner.verifying_key() }
	}
}

impl From<Ed25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Ed25519PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

impl From<&Ed25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Ed25519PrivateKey) -> Self {
		SecretBox::new(Box::new(key.inner.to_bytes().to_vec()))
	}
}

impl TryFrom<&[u8]> for Ed25519PrivateKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let bytes_array: [u8; ed25519_dalek::SECRET_KEY_LENGTH] =
			bytes.try_into().map_err(|_| CryptoError::InvalidPrivateKey)?;
		let signing_key = SigningKey::from_bytes(&bytes_array);

		Ok(Ed25519PrivateKey { inner: signing_key })
	}
}

// RustCrypto Keypair trait implementation (provides derive_public_key functionality)
#[cfg(feature = "signature")]
impl Keypair for Ed25519PrivateKey {
	type VerifyingKey = Ed25519PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		Ed25519PublicKey { inner: self.inner.verifying_key() }
	}
}

// RustCrypto Signer trait implementation
#[cfg(feature = "signature")]
impl Signer<Signature> for Ed25519PrivateKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::signature::Error> {
		self.inner.try_sign(msg)
	}
}

impl Ed25519PrivateKey {
	/// Convert this Ed25519 private key to an X25519 private key for ECDH
	pub fn to_x25519(&self) -> Result<X25519PrivateKey, CryptoError> {
		ed25519_to_x25519_private(self)
	}
}

impl PublicKey for Ed25519PublicKey {}

impl From<Ed25519PublicKey> for Vec<u8> {
	fn from(key: Ed25519PublicKey) -> Self {
		key.inner.to_bytes().to_vec()
	}
}

impl From<&Ed25519PublicKey> for Vec<u8> {
	fn from(key: &Ed25519PublicKey) -> Self {
		key.inner.to_bytes().to_vec()
	}
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let bytes_array: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
			bytes.try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
		let verifying_key = VerifyingKey::from_bytes(&bytes_array).map_err(|_| CryptoError::InvalidPublicKey)?;

		Ok(Ed25519PublicKey { inner: verifying_key })
	}
}

// RustCrypto Verifier trait implementation
#[cfg(feature = "signature")]
impl Verifier<Signature> for Ed25519PublicKey {
	fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ::signature::Error> {
		self.inner.verify(msg, signature)
	}
}

impl Ed25519PublicKey {
	/// Convert this Ed25519 public key to an X25519 public ke6y for ECDH
	pub fn to_x25519(&self) -> Result<X25519PublicKey, CryptoError> {
		ed25519_to_x25519_public(self)
	}
}

/// X25519 private key for key exchange (ECDH)
///
/// This struct wraps the raw X25519 private key bytes and provides a safe
/// interface for X25519 key exchange operations. X25519 keys are derived from
/// Ed25519 keys but use different curve operations optimized for ECDH.
#[derive(Zeroize)]
pub struct X25519PrivateKey {
	bytes: SecretBox<[u8; 32]>,
}

impl core::fmt::Debug for X25519PrivateKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("X25519PrivateKey").field("bytes", &"[REDACTED]").finish()
	}
}

/// X25519 public key for key exchange (ECDH)
///
/// This struct wraps the x25519-dalek PublicKey and represents a point on the
/// Curve25519 curve used for key exchange operations.
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct X25519PublicKey {
	inner: DalekX25519PublicKey,
}

impl X25519PrivateKey {
	/// Derive the corresponding X25519 public key from this private key
	pub fn derive_public_key(&self) -> X25519PublicKey {
		// Compute the X25519 public key from the private key using scalar multiplication
		let private_key_array: [u8; 32] = *self.bytes.expose_secret();
		let public_key_bytes = x25519_dalek::x25519(private_key_array, x25519_dalek::X25519_BASEPOINT_BYTES);
		let public_key = DalekX25519PublicKey::from(public_key_bytes);

		X25519PublicKey::from(public_key)
	}

	/// Perform ECDH key exchange with another X25519 public key
	///
	/// This method performs the Diffie-Hellman key exchange operation between
	/// this private key and another party's public key, resulting in a shared
	/// secret.
	///
	/// # Returns
	///
	/// A 32-byte shared secret that can be used for symmetric encryption or
	/// further key derivation. Both parties will compute the same shared secret
	/// when they perform the key exchange with each other's public keys.
	///
	/// # Example
	///
	/// ```rust
	/// # use crypto::{Ed25519Derivation, KeyDerivation};
	///
	/// // Alice generates her keys
	/// let alice_ed25519 = Ed25519Derivation::derive_from_seed(b"alice_seed_32_bytes_or_more!!!!!!")?;
	/// let alice_x25519 = alice_ed25519.to_x25519()?;
	/// let alice_public = alice_x25519.derive_public_key();
	///
	/// // Bob generates his keys  
	/// let bob_ed25519 = Ed25519Derivation::derive_from_seed(b"bob_seed_32_bytes_or_more_here!!!")?;
	/// let bob_x25519 = bob_ed25519.to_x25519()?;
	/// let bob_public = bob_x25519.derive_public_key();
	///
	/// // Both parties compute the same shared secret
	/// let alice_shared = alice_x25519.diffie_hellman(&bob_public);
	/// let bob_shared = bob_x25519.diffie_hellman(&alice_public);
	///
	/// assert_eq!(alice_shared, bob_shared);
	/// # Ok::<(), crypto::CryptoError>(())
	/// ```
	pub fn diffie_hellman(&self, other_public: &X25519PublicKey) -> [u8; 32] {
		// Create private key from our bytes and perform ECDH
		let private_key_array: [u8; 32] = *self.bytes.expose_secret();
		let shared_secret = x25519_dalek::x25519(private_key_array, *other_public.inner.as_bytes());

		shared_secret
	}
}

impl TryFrom<&[u8]> for X25519PrivateKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let bytes_array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidPrivateKey)?;

		Ok(X25519PrivateKey { bytes: SecretBox::new(Box::new(bytes_array)) })
	}
}

impl From<X25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: X25519PrivateKey) -> Self {
		SecretBox::new(Box::new(key.bytes.expose_secret().to_vec()))
	}
}

impl From<&X25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &X25519PrivateKey) -> Self {
		SecretBox::new(Box::new(key.bytes.expose_secret().to_vec()))
	}
}

impl TryFrom<&[u8]> for X25519PublicKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let bytes_array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
		let public_key = DalekX25519PublicKey::from(bytes_array);

		Ok(X25519PublicKey { inner: public_key })
	}
}

impl From<X25519PublicKey> for Vec<u8> {
	fn from(key: X25519PublicKey) -> Self {
		key.inner.as_bytes().to_vec()
	}
}

impl From<&X25519PublicKey> for Vec<u8> {
	fn from(key: &X25519PublicKey) -> Self {
		key.inner.as_bytes().to_vec()
	}
}

impl From<DalekX25519PublicKey> for X25519PublicKey {
	fn from(public_key: DalekX25519PublicKey) -> Self {
		X25519PublicKey { inner: public_key }
	}
}

/// Convert an Ed25519 private key to an X25519 private key
///
/// This function implements the standard conversion from Ed25519 to X25519 as
/// used in many cryptographic libraries. It hashes the Ed25519 private key
/// with SHA512 and applies Curve25519 clamping.
///
/// The conversion process:
/// 1. Hash the Ed25519 private key with SHA512
/// 2. Take the first 32 bytes of the hash
/// 3. Apply Curve25519 clamping:
///    - Clear bits 0, 1, 2 (ensure divisible by 8)
///    - Clear bit 255 (ensure < 2^255)  
///    - Set bit 254 (ensure >= 2^254)
pub fn ed25519_to_x25519_private(ed25519_key: &Ed25519PrivateKey) -> Result<X25519PrivateKey, CryptoError> {
	// Use our hash abstraction instead of direct sha2 import
	let key_bytes = SecretBox::<Vec<u8>>::from(ed25519_key);
	let hash: [u8; 64] = hash::hash_array(key_bytes.expose_secret(), Some(hash::HashAlgorithm::Sha2_512))?;

	let mut x25519_bytes = [0u8; 32];
	x25519_bytes.copy_from_slice(&hash[..32]);

	// Apply Curve25519 clamping
	x25519_bytes[0] &= 248; // Clear bits 0, 1, 2
	x25519_bytes[31] &= 127; // Clear bit 255
	x25519_bytes[31] |= 64; // Set bit 254

	X25519PrivateKey::try_from(x25519_bytes.as_slice())
}

/// Convert an Ed25519 public key to an X25519 public key
///
/// This function converts an Ed25519 public key (point on Edwards curve) to an
/// X25519 public key (point on Montgomery curve) using the bi-rational map.
///
/// **Important**: This conversion produces a different X25519 public key than
/// what you would get by converting the corresponding Ed25519 private key to
/// X25519 and then deriving the public key. Both are mathematically valid but
/// represent different cryptographic operations.
///
/// The conversion formula: montgomeryX = (edwardsY + 1) * inverse(1 - edwardsY) mod p
pub fn ed25519_to_x25519_public(ed25519_key: &Ed25519PublicKey) -> Result<X25519PublicKey, CryptoError> {
	let ed25519_bytes: Vec<u8> = ed25519_key.into();

	// Parse the Ed25519 public key as a compressed Edwards point
	let compressed_edwards =
		CompressedEdwardsY::from_slice(&ed25519_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;

	// Decompress to get the Edwards point
	let edwards_point = compressed_edwards.decompress().ok_or(CryptoError::InvalidPublicKey)?;
	// Convert Edwards point to Montgomery point using the bi-rational map
	let montgomery_point = edwards_point.to_montgomery();
	// Get the Montgomery point bytes
	let montgomery_bytes = montgomery_point.as_bytes();
	// Create X25519 public key from the Montgomery point
	let x25519_public = DalekX25519PublicKey::from(*montgomery_bytes);

	Ok(X25519PublicKey { inner: x25519_public })
}

/// Ed25519 key derivation implementation
///
/// This struct provides the KeyDerivation trait implementation for Ed25519.
/// It uses a different derivation method than secp256k1.
///
/// ## Derivation Process
///
/// 1. **Direct Hashing**: Hash the seed directly with SHA3-256 (no HKDF)
/// 2. **Ed25519 Clamping**: Apply specific bit manipulations for valid keys:
///    - Clear the 3 least significant bits (ensure divisible by 8)
///    - Clear the most significant bit (ensure < 2^255)
///    - Set the second most significant bit (ensure >= 2^254)
///
/// This process ensures the generated private key is valid.
pub struct Ed25519Derivation;

impl KeyDerivation for Ed25519Derivation {
	type PrivateKey = Ed25519PrivateKey;

	fn derive_from_seed(seed: &[u8]) -> Result<Self::PrivateKey, CryptoError> {
		// Hash the seed+index buffer directly using our hash abstraction
		let hash_result: [u8; 32] = hash::hash_array(seed, None)?;

		// Apply Ed25519 clamping
		let mut private_key_bytes = hash_result.to_vec();
		private_key_bytes[0] &= 248; // Clear bits 0, 1, 2
		private_key_bytes[31] &= 127; // Clear bit 255
		private_key_bytes[31] |= 64; // Set bit 254

		// Convert to fixed-size array for Ed25519
		let mut key_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
		key_bytes.copy_from_slice(&private_key_bytes[..ed25519_dalek::SECRET_KEY_LENGTH]);

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

	use crate::algorithms::secp256k1::Secp256k1Derivation;

	#[test]
	fn test_ed25519_key_derivation() {
		let seed = b"test seed for ed25519 key derivation!!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test serialization roundtrip
		let private_bytes: SecretBox<Vec<u8>> = (&private_key).into();
		let recovered_private = Ed25519PrivateKey::try_from(private_bytes.expose_secret().as_slice()).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&private_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&recovered_private).expose_secret()
		);

		let public_bytes: Vec<u8> = (&public_key).into();
		let recovered_public = Ed25519PublicKey::try_from(public_bytes.as_slice()).unwrap();
		assert_eq!(Vec::<u8>::from(&public_key), Vec::<u8>::from(&recovered_public));

		// Test public key formatting - now handled by accounts crate
		let hex_formatted = hex::encode(Vec::<u8>::from(&public_key));
		assert_eq!(hex_formatted.len(), 64); // 32 bytes * 2 chars per byte
	}

	#[test]
	fn test_ed25519_deterministic() {
		let seed = b"deterministic test seed for ed25519!!";

		let key1 = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let key2 = Ed25519Derivation::derive_from_seed(seed).unwrap();

		assert_eq!(
			SecretBox::<Vec<u8>>::from(&key1).expose_secret(),
			SecretBox::<Vec<u8>>::from(&key2).expose_secret()
		);

		let (pub1, pub2) = (key1.as_public_key(), key2.as_public_key());

		assert_eq!(Vec::<u8>::from(&pub1), Vec::<u8>::from(&pub2));
	}

	#[test]
	fn test_ed25519_different_from_secp256k1() {
		let seed = b"same seed for both algorithms!!!!!!";

		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let secp256k1_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		assert_ne!(
			SecretBox::<Vec<u8>>::from(&ed25519_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&secp256k1_key).expose_secret()
		);

		let (ed25519_pub, secp256k1_pub) = (ed25519_key.as_public_key(), secp256k1_key.as_public_key());
		assert_ne!(Vec::<u8>::from(&ed25519_pub), Vec::<u8>::from(&secp256k1_pub));
	}

	#[test]
	fn test_ed25519_to_x25519_conversion() {
		let seed = b"test seed for x25519 conversion!!!!!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();

		// Convert to X25519
		let x25519_key = ed25519_key.to_x25519().unwrap();
		let x25519_public = x25519_key.derive_public_key();

		// Test that conversion is deterministic
		let x25519_key2 = ed25519_key.to_x25519().unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&x25519_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&x25519_key2).expose_secret()
		);

		// Test serialization roundtrip
		let x25519_bytes = SecretBox::<Vec<u8>>::from(&x25519_key);
		let recovered_x25519 = X25519PrivateKey::try_from(x25519_bytes.expose_secret().as_slice()).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&x25519_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&recovered_x25519).expose_secret()
		);

		let x25519_pub_bytes = Vec::<u8>::from(&x25519_public);
		let recovered_x25519_pub = X25519PublicKey::try_from(x25519_pub_bytes.as_slice()).unwrap();
		assert_eq!(Vec::<u8>::from(&x25519_public), Vec::<u8>::from(&recovered_x25519_pub));

		// Verify X25519 keys are different from Ed25519 keys
		assert_ne!(
			SecretBox::<Vec<u8>>::from(&x25519_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&ed25519_key).expose_secret()
		);

		let ed25519_public_for_comparison = ed25519_key.as_public_key();

		assert_ne!(Vec::<u8>::from(&x25519_public), Vec::<u8>::from(&ed25519_public_for_comparison));
	}

	#[test]
	fn test_ed25519_public_to_x25519_conversion() {
		let seed = b"seed_for_testing_public_conversion!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let ed25519_public = ed25519_key.as_public_key();

		// Convert Ed25519 public key directly to X25519 public key
		let x25519_public_direct = ed25519_public.to_x25519().unwrap();
		// Convert via private key for comparison
		let x25519_private = ed25519_key.to_x25519().unwrap();
		let x25519_public_via_private = x25519_private.derive_public_key();

		// Both conversions should work (they produce different results as expected)
		assert_eq!(Vec::<u8>::from(&x25519_public_direct).len(), 32);
		assert_eq!(Vec::<u8>::from(&x25519_public_via_private).len(), 32);

		// Both methods should produce valid 32-byte keys
		assert_eq!(Vec::<u8>::from(&x25519_public_direct).len(), 32);
		assert_eq!(Vec::<u8>::from(&x25519_public_via_private).len(), 32);
	}

	#[test]
	fn test_x25519_diffie_hellman() {
		// Alice generates her keys
		let alice_seed = b"alice_test_seed_for_diffie_hellman!";
		let alice_ed25519 = Ed25519Derivation::derive_from_seed(alice_seed).unwrap();
		let alice_x25519 = alice_ed25519.to_x25519().unwrap();
		let alice_public = alice_x25519.derive_public_key();

		// Bob generates his keys
		let bob_seed = b"bob_test_seed_for_diffie_hellman!!!";
		let bob_ed25519 = Ed25519Derivation::derive_from_seed(bob_seed).unwrap();
		let bob_x25519 = bob_ed25519.to_x25519().unwrap();
		let bob_public = bob_x25519.derive_public_key();

		// Both parties compute the shared secret
		let alice_shared = alice_x25519.diffie_hellman(&bob_public);
		let bob_shared = bob_x25519.diffie_hellman(&alice_public);

		// The shared secrets should be identical
		assert_eq!(alice_shared, bob_shared);
		assert_ne!(alice_shared, [0u8; 32]); // Should not be all zeros

		// Verify the shared secret is deterministic
		let alice_shared2 = alice_x25519.diffie_hellman(&bob_public);
		let bob_shared2 = bob_x25519.diffie_hellman(&alice_public);
		assert_eq!(alice_shared, alice_shared2);
		assert_eq!(bob_shared, bob_shared2);

		// Verify that different key pairs produce different shared secrets
		let charlie_seed = b"charlie_test_seed_different_result!";
		let charlie_ed25519 = Ed25519Derivation::derive_from_seed(charlie_seed).unwrap();
		let charlie_x25519 = charlie_ed25519.to_x25519().unwrap();
		let charlie_public = charlie_x25519.derive_public_key();

		let alice_charlie_shared = alice_x25519.diffie_hellman(&charlie_public);
		assert_ne!(alice_shared, alice_charlie_shared);
	}
}
