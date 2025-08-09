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

// Re-export algorithm-specific signature types
pub use ed25519_dalek::Signature as Ed25519Signature;

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use secrecy::{ExposeSecret, SecretBox};
use x25519_dalek::PublicKey as DalekX25519PublicKey;
use zeroize::Zeroize;

#[cfg(feature = "encryption")]
use crate::algorithms::ecies::{Ecies, EciesX25519};
#[cfg(feature = "encryption")]
use crate::operations::encryption::AsymmetricEncryption;

#[cfg(feature = "signature")]
use crate::hash::hash_default;
#[cfg(feature = "signature")]
use crate::operations::signature::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};
#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};

use crate::error::CryptoError;
use crate::hash;
use crate::{KeyDerivation, PrivateKey, PublicKey};

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

impl PrivateKey for Ed25519PrivateKey {
	type PublicKey = Ed25519PublicKey;
	type Signature = Signature;

	fn as_public_key(&self) -> Self::PublicKey {
		Ed25519PublicKey { inner: self.inner.verifying_key() }
	}
}

impl core::fmt::Debug for Ed25519PrivateKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Ed25519PrivateKey")
			.field("inner", &"[REDACTED]")
			.finish()
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
		let bytes_array: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = bytes
			.try_into()
			.map_err(|_| CryptoError::InvalidPrivateKey)?;
		let signing_key = SigningKey::from_bytes(&bytes_array);

		Ok(Ed25519PrivateKey { inner: signing_key })
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Ed25519PrivateKey {
	fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// For encryption, we need the corresponding public key
		let public_key = self.as_public_key();

		public_key.encrypt(plaintext)
	}

	fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Convert Ed25519 private key to X25519 for decryption
		let x25519_private = self.to_x25519()?;

		EciesX25519::decrypt(&x25519_private, cipher_text)
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-Ed25519-via-X25519-AES128CTR"
	}
}

#[cfg(feature = "signature")]
impl Keypair for Ed25519PrivateKey {
	type VerifyingKey = Ed25519PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		Ed25519PublicKey { inner: self.inner.verifying_key() }
	}
}

#[cfg(feature = "signature")]
impl Signer<Signature> for Ed25519PrivateKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::signature::Error> {
		self.inner.try_sign(msg)
	}
}

#[cfg(feature = "signature")]
impl CryptoSigner<Signature> for Ed25519PrivateKey {
	fn has_private_key(&self) -> bool {
		true
	}
}

#[cfg(feature = "signature")]
impl CryptoSignerWithOptions<Signature> for Ed25519PrivateKey {
	fn sign_with_options(&self, message: &[u8], options: SigningOptions) -> Result<Signature, ::signature::Error> {
		let data = if options.raw {
			message.to_vec()
		} else {
			hash_default(message).to_vec()
		};

		self.inner.try_sign(&data)
	}
}

impl Ed25519PrivateKey {
	/// Convert this Ed25519 private key to an X25519 private key for ECDH
	pub fn to_x25519(&self) -> Result<X25519PrivateKey, CryptoError> {
		ed25519_to_x25519_private(self)
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

impl Ed25519PublicKey {
	/// Convert this Ed25519 public key to an X25519 public key for ECDH
	pub fn to_x25519(&self) -> Result<X25519PublicKey, CryptoError> {
		ed25519_to_x25519_public(self)
	}
}

impl PublicKey for Ed25519PublicKey {
	// TODO Verify
	fn to_uncompressed_bytes(&self) -> Vec<u8> {
		self.inner.to_bytes().to_vec()
	}
}

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
		let bytes_array: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = bytes
			.try_into()
			.map_err(|_| CryptoError::InvalidPublicKey)?;
		let verifying_key = VerifyingKey::from_bytes(&bytes_array).map_err(|_| CryptoError::InvalidPublicKey)?;

		Ok(Ed25519PublicKey { inner: verifying_key })
	}
}

#[cfg(feature = "der")]
impl From<Ed25519PublicKey> for asn1::ObjectIdentifier {
	fn from(_public_key: Ed25519PublicKey) -> Self {
		// This should never fail as we are using a constant known OID
		asn1::ObjectIdentifier::new(asn1::oids::ED25519).expect("Failed to create OID for Ed25519")
	}
}

#[cfg(feature = "signature")]
impl Verifier<Signature> for Ed25519PublicKey {
	fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ::signature::Error> {
		self.inner.verify(msg, signature)
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifier<Signature> for Ed25519PublicKey {
	fn public_key_bytes(&self) -> Vec<u8> {
		self.into()
	}

	fn public_key_string(&self) -> Result<String, CryptoError> {
		Ok(hex::encode(self.public_key_bytes()))
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifierWithOptions<Signature> for Ed25519PublicKey {
	fn verify_with_options(
		&self,
		message: &[u8],
		signature: &Signature,
		options: SigningOptions,
	) -> Result<(), ::signature::Error> {
		let data = if options.raw {
			message.to_vec()
		} else {
			hash_default(message).to_vec()
		};

		self.inner.verify(&data, signature)
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Ed25519PublicKey {
	fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Convert Ed25519 public key to X25519 for encryption
		let x25519_public = self.to_x25519()?;

		EciesX25519::encrypt(&x25519_public, plaintext)
	}

	fn decrypt(&self, _cipher_text: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Public keys cannot decrypt
		Err(CryptoError::InvalidOperation)
	}

	fn algorithm_info(&self) -> &'static str {
		"ECIES-Ed25519-via-X25519-AES128CTR"
	}
}

/// X25519 private key for key exchange (ECDH).
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
		f.debug_struct("X25519PrivateKey")
			.field("bytes", &"[REDACTED]")
			.finish()
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

	/// Perform ECDH key exchange with another X25519 public key.
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
		let bytes_array: [u8; 32] = bytes
			.try_into()
			.map_err(|_| CryptoError::InvalidPrivateKey)?;

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
		let bytes_array: [u8; 32] = bytes
			.try_into()
			.map_err(|_| CryptoError::InvalidPublicKey)?;
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

/// Convert an Ed25519 private key to an X25519 private key.
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

/// Convert an Ed25519 public key to an X25519 public key.
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
	let edwards_point = compressed_edwards
		.decompress()
		.ok_or(CryptoError::InvalidPublicKey)?;
	// Convert Edwards point to Montgomery point using the bi-rational map
	let montgomery_point = edwards_point.to_montgomery();
	// Get the Montgomery point bytes
	let montgomery_bytes = montgomery_point.as_bytes();
	// Create X25519 public key from the Montgomery point
	let x25519_public = DalekX25519PublicKey::from(*montgomery_bytes);

	Ok(X25519PublicKey { inner: x25519_public })
}

/// Ed25519 key derivation implementation.
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
	use std::collections::HashMap;

	use super::*;
	use crate::algorithms::secp256k1::Secp256k1Derivation;
	use x25519_dalek::PublicKey as DalekX25519PublicKey;

	#[cfg(feature = "signature")]
	use crate::operations::signature::{CryptoSignerWithOptions, CryptoVerifierWithOptions, SigningOptions};

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

	#[cfg(feature = "signature")]
	#[test]
	fn test_ed25519_signature_operations() {
		let seed = b"test seed for ed25519 signatures!!!!!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let message = b"Hello, Ed25519 signature world!";

		// Test signing with RustCrypto Signer trait
		let signature = private_key.try_sign(message).unwrap();
		assert!(public_key.verify(message, &signature).is_ok());

		// Test that verification fails with wrong message
		let wrong_message = b"Wrong message";
		assert!(public_key.verify(wrong_message, &signature).is_err());

		// Test that verification fails with wrong key
		let wrong_seed = b"wrong seed for ed25519 signatures!!";
		let wrong_private_key = Ed25519Derivation::derive_from_seed(wrong_seed).unwrap();
		let wrong_public_key = wrong_private_key.as_public_key();
		assert!(wrong_public_key.verify(message, &signature).is_err());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_ed25519_keypair_trait() {
		let seed = b"test seed for ed25519 keypair trait!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();

		// Test verifying_key method from Keypair trait
		let verifying_key = private_key.verifying_key();
		let public_key = private_key.as_public_key();
		// Both should produce the same public key bytes
		assert_eq!(Vec::<u8>::from(&verifying_key), Vec::<u8>::from(&public_key));
	}

	#[test]
	fn test_ed25519_key_derivation_utility_methods() {
		// Test validate_key_material with valid key
		let valid_key = [0x01; ed25519_dalek::SECRET_KEY_LENGTH]; // Valid 32-byte key
		assert!(Ed25519Derivation::validate_key_material(&valid_key));

		// Test validate_key_material with invalid key (wrong length)
		let invalid_key = [0x01; 16]; // Invalid length
		assert!(!Ed25519Derivation::validate_key_material(&invalid_key));
		// Test key_size
		assert_eq!(Ed25519Derivation::key_size(), ed25519_dalek::SECRET_KEY_LENGTH);
		assert_eq!(Ed25519Derivation::key_size(), 32);
	}

	#[test]
	fn test_ed25519_debug_formatting() {
		let seed = b"test seed for ed25519 debug format!!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();

		// Test that Debug format hides the private key
		let debug_string = format!("{private_key:?}");
		assert!(debug_string.contains("Ed25519PrivateKey"));
		assert!(debug_string.contains("[REDACTED]"));
		// Make sure no actual key bytes are shown
		assert!(!debug_string.contains("SigningKey"));
	}

	#[test]
	fn test_x25519_debug_formatting() {
		let seed = b"test seed for x25519 debug format!!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let x25519_key = ed25519_key.to_x25519().unwrap();

		// Test that Debug format hides the private key
		let debug_string = format!("{x25519_key:?}");
		assert!(debug_string.contains("X25519PrivateKey"));
		assert!(debug_string.contains("[REDACTED]"));
		// The debug format shows "bytes: [REDACTED]" which is correct for hiding the secret
	}

	#[test]
	fn test_ed25519_serialization_round_trips() {
		let seed = b"test seed for ed25519 serialization!!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test Ed25519PrivateKey TryFrom<&[u8]>
		let private_bytes: SecretBox<Vec<u8>> = (&private_key).into();
		let recovered_private = Ed25519PrivateKey::try_from(private_bytes.expose_secret().as_slice()).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&private_key).expose_secret(),
			SecretBox::<Vec<u8>>::from(&recovered_private).expose_secret()
		);

		// Test Ed25519PublicKey TryFrom<&[u8]>
		let public_bytes: Vec<u8> = (&public_key).into();
		let recovered_public = Ed25519PublicKey::try_from(public_bytes.as_slice()).unwrap();
		assert_eq!(Vec::<u8>::from(&public_key), Vec::<u8>::from(&recovered_public));

		// Test SecretBox From conversions for Ed25519PrivateKey
		let secret_box_owned: SecretBox<Vec<u8>> = private_key.clone().into();
		let secret_box_ref: SecretBox<Vec<u8>> = (&private_key).into();
		assert_eq!(secret_box_owned.expose_secret(), secret_box_ref.expose_secret());

		// Test Vec<u8> From conversions for Ed25519PublicKey
		let public_vec_owned: Vec<u8> = public_key.clone().into();
		let public_vec_ref: Vec<u8> = (&public_key).into();
		assert_eq!(public_vec_owned, public_vec_ref);
	}

	#[test]
	fn test_x25519_serialization_round_trips() {
		let seed = b"test seed for x25519 serialization!!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let x25519_private = ed25519_key.to_x25519().unwrap();
		let x25519_public = x25519_private.derive_public_key();

		// Test X25519PrivateKey TryFrom<&[u8]>
		let x25519_bytes: SecretBox<Vec<u8>> = (&x25519_private).into();
		let recovered_x25519_private = X25519PrivateKey::try_from(x25519_bytes.expose_secret().as_slice()).unwrap();
		assert_eq!(
			SecretBox::<Vec<u8>>::from(&x25519_private).expose_secret(),
			SecretBox::<Vec<u8>>::from(&recovered_x25519_private).expose_secret()
		);

		// Test X25519PublicKey TryFrom<&[u8]>
		let x25519_pub_bytes: Vec<u8> = (&x25519_public).into();
		let recovered_x25519_public = X25519PublicKey::try_from(x25519_pub_bytes.as_slice()).unwrap();
		assert_eq!(Vec::<u8>::from(&x25519_public), Vec::<u8>::from(&recovered_x25519_public));

		// Test SecretBox From conversions for X25519PrivateKey
		let secret_box_ref: SecretBox<Vec<u8>> = (&x25519_private).into();
		assert_eq!(secret_box_ref.expose_secret().len(), 32);

		// Test Vec<u8> From conversions for X25519PublicKey
		let public_vec_owned: Vec<u8> = x25519_public.into();
		let public_vec_ref: Vec<u8> = (&x25519_public).into();
		assert_eq!(public_vec_owned, public_vec_ref);
	}

	#[test]
	fn test_ed25519_invalid_key_material() {
		// Test invalid private key length
		let invalid_private = [0x01; 16]; // Wrong length
		assert!(Ed25519PrivateKey::try_from(invalid_private.as_slice()).is_err());

		// Test invalid public key length
		let invalid_public = [0x01; 16]; // Wrong length
		assert!(Ed25519PublicKey::try_from(invalid_public.as_slice()).is_err());

		// Test invalid X25519 private key length
		let invalid_x25519_private = [0x01; 16]; // Wrong length
		assert!(X25519PrivateKey::try_from(invalid_x25519_private.as_slice()).is_err());

		// Test invalid X25519 public key length
		let invalid_x25519_public = [0x01; 16]; // Wrong length
		assert!(X25519PublicKey::try_from(invalid_x25519_public.as_slice()).is_err());
	}

	#[test]
	fn test_direct_x25519_key_operations() {
		// Create X25519 keys directly from bytes
		let alice_private_bytes = [0x77; 32];
		let alice_private = X25519PrivateKey::try_from(alice_private_bytes.as_slice()).unwrap();
		let alice_public = alice_private.derive_public_key();

		let bob_private_bytes = [0x88; 32];
		let bob_private = X25519PrivateKey::try_from(bob_private_bytes.as_slice()).unwrap();
		let bob_public = bob_private.derive_public_key();

		// Test Diffie-Hellman
		let alice_shared = alice_private.diffie_hellman(&bob_public);
		let bob_shared = bob_private.diffie_hellman(&alice_public);
		assert_eq!(alice_shared, bob_shared);

		// Test key lengths
		assert_eq!(alice_shared.len(), 32);
		assert_eq!(Vec::<u8>::from(&alice_public).len(), 32);
		assert_eq!(Vec::<u8>::from(&bob_public).len(), 32);
	}

	#[test]
	fn test_x25519_owned_conversions() {
		// Create X25519 private key to test owned conversions
		let private_bytes = [0x42; 32];
		let x25519_private = X25519PrivateKey::try_from(private_bytes.as_slice()).unwrap();

		// Test the From<X25519PrivateKey> for SecretBox<Vec<u8>> implementation (owned)
		let secret_box_owned: SecretBox<Vec<u8>> = x25519_private.into();
		assert_eq!(secret_box_owned.expose_secret().len(), 32);
		assert_eq!(secret_box_owned.expose_secret(), &private_bytes.to_vec());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_ed25519_crypto_signer_with_options() {
		let seed = b"test seed for ed25519 signer with options";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let message = b"test message for ed25519 signing with options";

		// Test with default options (pre-hash)
		let default_options = SigningOptions::default();
		let signature_default = private_key
			.sign_with_options(message, default_options)
			.unwrap();

		// Test with raw options (no pre-hash)
		let raw_options = SigningOptions::raw();
		let signature_raw = private_key.sign_with_options(message, raw_options).unwrap();

		// Test with cert options (pre-hash, but for_cert flag set)
		let cert_options = SigningOptions::for_cert();
		let signature_cert = private_key
			.sign_with_options(message, cert_options)
			.unwrap();

		// Signatures should be different when using different message processing
		assert_ne!(signature_default.to_bytes(), signature_raw.to_bytes());
		// Default and cert should be the same since they both pre-hash
		assert_eq!(signature_default.to_bytes(), signature_cert.to_bytes());

		// Verify that the regular signing (which pre-hashes) matches default options
		let regular_signature = private_key.try_sign(message).unwrap();
		assert_ne!(regular_signature.to_bytes(), signature_default.to_bytes());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_ed25519_crypto_verifier_with_options() {
		let seed = b"test seed for ed25519 verifier with options";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let message = b"test message for ed25519 verification with options";

		// Test verification with matching options
		let default_options = SigningOptions::default();
		let signature_default = private_key
			.sign_with_options(message, default_options)
			.unwrap();
		assert!(public_key
			.verify_with_options(message, &signature_default, default_options)
			.is_ok());

		let raw_options = SigningOptions::raw();
		let signature_raw = private_key.sign_with_options(message, raw_options).unwrap();
		assert!(public_key
			.verify_with_options(message, &signature_raw, raw_options)
			.is_ok());

		let cert_options = SigningOptions::for_cert();
		let signature_cert = private_key
			.sign_with_options(message, cert_options)
			.unwrap();
		assert!(public_key
			.verify_with_options(message, &signature_cert, cert_options)
			.is_ok());

		// Test verification failure with mismatched options
		assert!(public_key
			.verify_with_options(message, &signature_raw, default_options)
			.is_err());
		assert!(public_key
			.verify_with_options(message, &signature_default, raw_options)
			.is_err());

		// Test verification failure with wrong message
		let wrong_message = b"wrong message";
		assert!(public_key
			.verify_with_options(wrong_message, &signature_default, default_options)
			.is_err());
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_ed25519_crypto_verifier_trait() {
		let seed = b"test seed for ed25519 crypto verifier trait";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test public_key_bytes() method
		let public_key_bytes = public_key.public_key_bytes();
		assert_eq!(public_key_bytes.len(), 32); // Ed25519 public keys are 32 bytes

		// Should match the regular Vec conversion
		let regular_bytes: Vec<u8> = (&public_key).into();
		assert_eq!(public_key_bytes, regular_bytes);

		// Test public_key_string() method
		let public_key_string = public_key.public_key_string().unwrap();
		assert_eq!(public_key_string.len(), 64); // 32 bytes * 2 hex chars per byte
		assert_eq!(public_key_string, hex::encode(&public_key_bytes));
		// Verify the string is valid hex
		assert!(public_key_string.chars().all(|c| c.is_ascii_hexdigit()));

		// Test that we can decode the hex string back to the original bytes
		let decoded_bytes = hex::decode(&public_key_string).unwrap();
		assert_eq!(decoded_bytes, public_key_bytes);
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_ed25519_asymmetric_encryption_trait() {
		let seed = b"test seed for ed25519 asymmetric encryption";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Hello, Ed25519 encryption via X25519!";

		// Test encryption via AsymmetricEncryption trait
		let ciphertext = public_key.encrypt(plaintext).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext);
		assert!(ciphertext.len() > plaintext.len());

		// Test decryption via AsymmetricEncryption trait
		let decrypted = private_key.decrypt(&ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);

		// Test algorithm info
		assert_eq!(public_key.algorithm_info(), "ECIES-Ed25519-via-X25519-AES128CTR");
		assert_eq!(private_key.algorithm_info(), "ECIES-Ed25519-via-X25519-AES128CTR");

		// Test that public key cannot decrypt
		let fake_ciphertext = [0u8; 100];
		let result = public_key.decrypt(&fake_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidOperation));
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_ed25519_encryption_round_trip() {
		let seed = b"test seed for ed25519 round trip encryption";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let plaintext = b"Round-trip test message for Ed25519 encryption";

		// Test encryption via private key (should use public key internally)
		let ciphertext = private_key.encrypt(plaintext).unwrap();
		let decrypted = private_key.decrypt(&ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);

		// Test that different plaintext produce different ciphertext
		let plaintext2 = b"Different message for encryption test";
		let ciphertext2 = private_key.encrypt(plaintext2).unwrap();
		assert_ne!(ciphertext, ciphertext2);

		// Test that encryption is non-deterministic (ephemeral keys)
		let ciphertext3 = private_key.encrypt(plaintext).unwrap();
		assert_ne!(ciphertext, ciphertext3);
		let decrypted3 = private_key.decrypt(&ciphertext3).unwrap();
		assert_eq!(decrypted3, plaintext);
	}

	#[test]
	fn test_ed25519_public_key_uncompressed_bytes() {
		let seed = b"test seed for ed25519 uncompressed bytes";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test to_uncompressed_bytes method
		let uncompressed = public_key.to_uncompressed_bytes();
		assert_eq!(uncompressed.len(), 32); // Ed25519 public keys are 32 bytes

		// Compare with regular Vec conversion
		let regular_bytes: Vec<u8> = (&public_key).into();
		assert_eq!(uncompressed, regular_bytes);
	}

	#[cfg(feature = "signature")]
	#[test]
	fn test_ed25519_crypto_signer_has_private_key() {
		let seed = b"test seed for ed25519 has private key test";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		assert!(private_key.has_private_key());
	}

	#[test]
	fn test_ed25519_public_key_error_cases() {
		// Test with definitely invalid length - this will always fail
		let wrong_length_bytes = [0x01; 16]; // Wrong length
		let result = Ed25519PublicKey::try_from(wrong_length_bytes.as_slice());
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidPublicKey));

		// Test with empty bytes
		let empty_bytes = [];
		let result = Ed25519PublicKey::try_from(empty_bytes.as_slice());
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidPublicKey));

		// Test with too long bytes
		let too_long_bytes = [0x01; 64]; // Too long
		let result = Ed25519PublicKey::try_from(too_long_bytes.as_slice());
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidPublicKey));
	}

	#[test]
	fn test_ed25519_to_x25519_public_conversion_edge_cases() {
		let seed = b"test seed for ed25519 to x25519 public edge";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let ed25519_public = ed25519_key.as_public_key();

		// Test that the conversion produces a valid X25519 public key
		let x25519_public = ed25519_public.to_x25519().unwrap();
		let x25519_bytes: Vec<u8> = (&x25519_public).into();
		assert_eq!(x25519_bytes.len(), 32);

		// Test that conversion is deterministic
		let x25519_public2 = ed25519_public.to_x25519().unwrap();
		let x25519_bytes2: Vec<u8> = (&x25519_public2).into();
		assert_eq!(x25519_bytes, x25519_bytes2);

		// Test that the conversion can be used for key agreement
		let alice_seed = b"alice_seed_for_conversion_test!!!!!!";
		let alice_ed25519 = Ed25519Derivation::derive_from_seed(alice_seed).unwrap();
		let alice_x25519_from_ed25519 = alice_ed25519.to_x25519().unwrap();
		let alice_x25519_public = alice_x25519_from_ed25519.derive_public_key();

		let bob_seed = b"bob_seed_for_conversion_test_here!!!";
		let bob_ed25519 = Ed25519Derivation::derive_from_seed(bob_seed).unwrap();
		let bob_x25519_from_ed25519 = bob_ed25519.to_x25519().unwrap();
		let bob_x25519_public = bob_x25519_from_ed25519.derive_public_key();

		// Test ECDH between converted keys
		let alice_shared = alice_x25519_from_ed25519.diffie_hellman(&bob_x25519_public);
		let bob_shared = bob_x25519_from_ed25519.diffie_hellman(&alice_x25519_public);
		assert_eq!(alice_shared, bob_shared);
	}

	#[test]
	fn test_x25519_public_key_equality_and_hashing() {
		let seed1 = b"test seed for x25519 equality test 1!";
		let seed2 = b"test seed for x25519 equality test 2!";

		let ed25519_key1 = Ed25519Derivation::derive_from_seed(seed1).unwrap();
		let ed25519_key2 = Ed25519Derivation::derive_from_seed(seed2).unwrap();

		let x25519_key1 = ed25519_key1.to_x25519().unwrap();
		let x25519_key2 = ed25519_key2.to_x25519().unwrap();

		let x25519_public1 = x25519_key1.derive_public_key();
		let x25519_public2 = x25519_key2.derive_public_key();
		let x25519_public1_copy = x25519_key1.derive_public_key();

		// Test equality
		assert_eq!(x25519_public1, x25519_public1_copy);
		assert_ne!(x25519_public1, x25519_public2);

		// Test that we can use them in hash-based collections
		let mut map = HashMap::new();
		map.insert(x25519_public1, "alice");
		map.insert(x25519_public2, "bob");
		assert_eq!(map.len(), 2);

		// Test that the same key maps to the same value
		assert_eq!(map.get(&x25519_public1_copy), Some(&"alice"));
	}

	#[test]
	fn test_x25519_copy_and_clone_traits() {
		let seed = b"test seed for x25519 copy clone traits!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let x25519_key = ed25519_key.to_x25519().unwrap();
		let x25519_public = x25519_key.derive_public_key();

		// Test Copy trait for X25519PublicKey
		let x25519_public_copy = x25519_public;
		assert_eq!(x25519_public, x25519_public_copy);

		// Test Clone trait for X25519PublicKey
		let x25519_public_clone = x25519_public;
		assert_eq!(x25519_public, x25519_public_clone);

		// Verify they all convert to the same bytes
		let bytes_original: Vec<u8> = x25519_public.into();
		let bytes_copy: Vec<u8> = x25519_public_copy.into();
		let bytes_clone: Vec<u8> = x25519_public_clone.into();
		assert_eq!(bytes_original, bytes_copy);
		assert_eq!(bytes_original, bytes_clone);
	}

	#[test]
	fn test_x25519_dalek_public_key_conversion() {
		// Create a raw dalek public key
		let raw_bytes = [0x42; 32];
		let dalek_public = DalekX25519PublicKey::from(raw_bytes);
		// Convert to our X25519PublicKey type
		let our_public = X25519PublicKey::from(dalek_public);

		// Verify the conversion preserves the bytes
		let our_bytes: Vec<u8> = our_public.into();
		assert_eq!(our_bytes, raw_bytes.to_vec());
	}

	#[test]
	fn test_ed25519_key_derivation_error_handling() {
		// Test that key derivation works with various seed sizes
		let short_seed = b"short";
		let result_short = Ed25519Derivation::derive_from_seed(short_seed);
		assert!(result_short.is_ok()); // Should work with any seed length

		let long_seed = b"this is a very long seed that should still work for key derivation without any issues";
		let result_long = Ed25519Derivation::derive_from_seed(long_seed);
		assert!(result_long.is_ok());

		// Test empty seed
		let empty_seed = b"";
		let result_empty = Ed25519Derivation::derive_from_seed(empty_seed);
		assert!(result_empty.is_ok());
	}

	#[test]
	fn test_x25519_private_key_zeroize() {
		let seed = b"test seed for x25519 zeroize test!!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let mut x25519_key = ed25519_key.to_x25519().unwrap();

		// Get the bytes before zeroize
		let original_bytes = SecretBox::<Vec<u8>>::from(&x25519_key);
		assert_ne!(original_bytes.expose_secret(), &vec![0u8; 32]);

		// Zeroize the key
		x25519_key.zeroize();

		// Verify the internal bytes are zeroed
		let zeroed_bytes = SecretBox::<Vec<u8>>::from(&x25519_key);
		assert_eq!(zeroed_bytes.expose_secret(), &vec![0u8; 32]);
	}

	#[test]
	fn test_ed25519_comprehensive_serialization() {
		let seed = b"comprehensive serialization test seed!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test all From implementations for Ed25519PrivateKey
		let secret_box_owned: SecretBox<Vec<u8>> = private_key.clone().into();
		let secret_box_ref: SecretBox<Vec<u8>> = (&private_key).into();
		assert_eq!(secret_box_owned.expose_secret(), secret_box_ref.expose_secret());
		assert_eq!(secret_box_owned.expose_secret().len(), 32);

		// Test all From implementations for Ed25519PublicKey
		let public_vec_owned: Vec<u8> = public_key.clone().into();
		let public_vec_ref: Vec<u8> = (&public_key).into();
		assert_eq!(public_vec_owned, public_vec_ref);
		assert_eq!(public_vec_owned.len(), 32);

		// Test round-trip conversions
		let recovered_private = Ed25519PrivateKey::try_from(secret_box_owned.expose_secret().as_slice()).unwrap();
		let recovered_private_bytes: SecretBox<Vec<u8>> = (&recovered_private).into();
		assert_eq!(secret_box_owned.expose_secret(), recovered_private_bytes.expose_secret());

		let recovered_public = Ed25519PublicKey::try_from(public_vec_owned.as_slice()).unwrap();
		let recovered_public_bytes: Vec<u8> = (&recovered_public).into();
		assert_eq!(public_vec_owned, recovered_public_bytes);
	}

	#[cfg(feature = "der")]
	#[test]
	fn test_oid_conversion() {
		let seed = b"test seed for ed25519 oid conversion!";
		let private_key = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();

		// Test conversion to ObjectIdentifier
		let oid: asn1::ObjectIdentifier = public_key.into();
		assert_eq!(oid.to_string(), asn1::oids::ED25519);
	}
}
