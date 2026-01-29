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

use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::sync::atomic::{fence, Ordering};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use secrecy::{ExposeSecret, SecretBox};
use x25519_dalek::PublicKey as DalekX25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};

#[cfg(feature = "encryption")]
use crate::algorithms::ecies::{Ecies, EciesX25519};
#[cfg(feature = "encryption")]
use crate::operations::encryption::{AsymmetricEncryption, KeyGeneration};
#[cfg(feature = "encryption")]
use crate::utils::generate_random_seed;

#[cfg(feature = "signature")]
use crate::hash::hash_default;
#[cfg(feature = "signature")]
use crate::operations::signature::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};

use crate::algorithms::{Algorithm, CryptoAlgorithm, KeyDerivation, PrivateKey, PublicKey};
use crate::error::CryptoError;
use crate::hash::{hash_array, HashAlgorithm};
use crate::IntoSecret;

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
#[derive(Clone, ZeroizeOnDrop)]
pub struct Ed25519PrivateKey {
	inner: SigningKey,
}

// Generate secure zeroization implementation for Ed25519PrivateKey
crate::impl_secure_zeroize!(Ed25519PrivateKey, SigningKey, inner);

impl Ed25519PrivateKey {
	/// Convert this Ed25519 private key to an X25519 private key for ECDH
	pub fn to_x25519(&self) -> Result<X25519PrivateKey, CryptoError> {
		ed25519_to_x25519_private(self)
	}
}

impl PrivateKey for Ed25519PrivateKey {
	type PublicKey = Ed25519PublicKey;
	type Signature = Signature;

	fn as_public_key(&self) -> Self::PublicKey {
		let bytes = self.inner.verifying_key().to_bytes().to_vec();
		Ed25519PublicKey { inner: self.inner.verifying_key(), bytes }
	}
}

impl CryptoAlgorithm for Ed25519PrivateKey {
	fn to_algorithm(&self) -> Algorithm {
		Algorithm::Ed25519
	}
}

impl Debug for Ed25519PrivateKey {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		f.debug_struct("Ed25519PrivateKey")
			.field("inner", &"[REDACTED]")
			.finish()
	}
}

impl From<Ed25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Ed25519PrivateKey) -> Self {
		key.inner.to_bytes().to_vec().into_secret()
	}
}

impl From<&Ed25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Ed25519PrivateKey) -> Self {
		key.inner.to_bytes().to_vec().into_secret()
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

#[cfg(any(feature = "der", feature = "rasn"))]
impl From<Ed25519PrivateKey> for keetanetwork_asn1::ObjectIdentifier {
	fn from(_private_key: Ed25519PrivateKey) -> Self {
		#[cfg(feature = "der")]
		{
			keetanetwork_asn1::oids::typed::ED25519
		}
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		{
			keetanetwork_asn1::oids::typed::ED25519.clone()
		}
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Ed25519PrivateKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		// For encryption, we need the corresponding public key
		let public_key = self.as_public_key();
		public_key.encrypt(plaintext)
	}

	fn decrypt<C: AsRef<[u8]>>(&self, cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		// Convert Ed25519 private key to X25519 for decryption
		let x25519_private = self.to_x25519()?;
		EciesX25519::decrypt(&x25519_private, cipher_text.as_ref())
	}
}

#[cfg(feature = "encryption")]
impl KeyGeneration for Ed25519PrivateKey {
	type Error = CryptoError;

	fn generate_random() -> Result<Self, Self::Error> {
		// Generate a random 32-byte seed and derive a key from it
		let random_seed = generate_random_seed()?;
		Ed25519Derivation::derive_from_seed(random_seed)
	}
}

#[cfg(feature = "signature")]
impl Keypair for Ed25519PrivateKey {
	type VerifyingKey = Ed25519PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		let bytes = self.inner.verifying_key().to_bytes().to_vec();
		Ed25519PublicKey { inner: self.inner.verifying_key(), bytes }
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
	fn sign_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		options: SigningOptions,
	) -> Result<Signature, ::signature::Error> {
		let message = message.as_ref();
		let data = if options.raw {
			message.to_vec()
		} else {
			hash_default(message).to_vec()
		};

		self.inner.try_sign(&data)
	}
}

/// Ed25519 public key wrapper.
///
/// This struct wraps the ed25519-dalek VerifyingKey and provides the PublicKey
/// trait implementation. Ed25519 public keys are 32 bytes long and represent
/// points on the Ed25519 curve.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Ed25519PublicKey {
	bytes: Vec<u8>,
	inner: VerifyingKey,
}

impl Ed25519PublicKey {
	/// Convert this Ed25519 public key to an X25519 public key for ECDH
	pub fn to_x25519(&self) -> Result<X25519PublicKey, CryptoError> {
		ed25519_to_x25519_public(self)
	}
}

impl CryptoAlgorithm for Ed25519PublicKey {
	fn to_algorithm(&self) -> Algorithm {
		Algorithm::Ed25519
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
		(&key).into()
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
		Ok(Ed25519PublicKey { inner: verifying_key, bytes: bytes.to_vec() })
	}
}

impl AsRef<[u8]> for Ed25519PublicKey {
	fn as_ref(&self) -> &[u8] {
		self.bytes.as_ref()
	}
}

#[cfg(any(feature = "der", feature = "rasn"))]
impl From<Ed25519PublicKey> for keetanetwork_asn1::ObjectIdentifier {
	fn from(_public_key: Ed25519PublicKey) -> Self {
		#[cfg(feature = "der")]
		{
			keetanetwork_asn1::oids::typed::ED25519
		}
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		{
			keetanetwork_asn1::oids::typed::ED25519.clone()
		}
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
}

#[cfg(feature = "signature")]
impl CryptoVerifierWithOptions<Signature> for Ed25519PublicKey {
	fn verify_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		signature: &Signature,
		options: SigningOptions,
	) -> Result<(), ::signature::Error> {
		let message = message.as_ref();
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
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		// Convert Ed25519 public key to X25519 for encryption
		let x25519_public = self.to_x25519()?;
		EciesX25519::encrypt(&x25519_public, plaintext.as_ref())
	}

	fn decrypt<C: AsRef<[u8]>>(&self, _cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		// Public keys cannot decrypt
		Err(CryptoError::InvalidOperation)
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

impl Debug for X25519PrivateKey {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		f.debug_struct("X25519PrivateKey")
			.field("bytes", &"[REDACTED]")
			.finish()
	}
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
	/// use keetanetwork_crypto::prelude::{KeyDerivation, IntoSecret};
	/// use keetanetwork_crypto::algorithms::ed25519::Ed25519Derivation;
	///
	/// // Alice generates her keys
	/// let alice_seed = b"alice_seed_32_bytes_or_more!!!!!!".into_secret();
	/// let alice_ed25519 = Ed25519Derivation::derive_from_seed(alice_seed)?;
	/// let alice_x25519 = alice_ed25519.to_x25519()?;
	/// let alice_public = alice_x25519.derive_public_key();
	///
	/// // Bob generates his keys
	/// let bob_seed = b"bob_seed_32_bytes_or_more_here!!!".into_secret();
	/// let bob_ed25519 = Ed25519Derivation::derive_from_seed(bob_seed)?;
	/// let bob_x25519 = bob_ed25519.to_x25519()?;
	/// let bob_public = bob_x25519.derive_public_key();
	///
	/// // Both parties compute the same shared secret
	/// let alice_shared = alice_x25519.diffie_hellman(&bob_public);
	/// let bob_shared = bob_x25519.diffie_hellman(&alice_public);
	///
	/// assert_eq!(alice_shared, bob_shared);
	/// # Ok::<(), keetanetwork_crypto::error::CryptoError>(())
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

		let bytes = bytes_array.into_secret();
		Ok(X25519PrivateKey { bytes })
	}
}

impl From<X25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: X25519PrivateKey) -> Self {
		key.bytes.expose_secret().to_vec().into_secret()
	}
}

impl From<&X25519PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &X25519PrivateKey) -> Self {
		key.bytes.expose_secret().to_vec().into_secret()
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for X25519PrivateKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		// For encryption, we need the corresponding public key
		let public_key = self.derive_public_key();
		EciesX25519::encrypt(&public_key, plaintext.as_ref())
	}

	fn decrypt<C: AsRef<[u8]>>(&self, cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		EciesX25519::decrypt(self, cipher_text.as_ref())
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

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for X25519PublicKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		EciesX25519::encrypt(self, plaintext.as_ref())
	}

	fn decrypt<C: AsRef<[u8]>>(&self, _cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		// Public keys cannot decrypt
		Err(CryptoError::InvalidOperation)
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
	let hash: [u8; 64] = hash_array(key_bytes.expose_secret(), Some(HashAlgorithm::Sha2_512))?;

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

	fn derive_from_seed<T>(seed: SecretBox<T>) -> Result<Self::PrivateKey, CryptoError>
	where
		T: IntoIterator<Item = u8> + AsRef<[u8]> + zeroize::Zeroize + Clone,
	{
		// Pre-derivation fence: Ensure no prior operations leak timing info
		fence(Ordering::SeqCst);

		let seed = seed.expose_secret();
		// Hash the seed+index buffer directly using our hash abstraction
		let hash_result: [u8; 32] = hash_array(seed, None)?;

		// Apply Ed25519 clamping
		let mut private_key_bytes = hash_result.to_vec();
		private_key_bytes[0] &= 248; // Clear bits 0, 1, 2
		private_key_bytes[31] &= 127; // Clear bit 255
		private_key_bytes[31] |= 64; // Set bit 254

		// Convert to fixed-size array for Ed25519
		let mut key_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
		key_bytes.copy_from_slice(&private_key_bytes[..ed25519_dalek::SECRET_KEY_LENGTH]);

		let signing_key = SigningKey::from_bytes(&key_bytes);

		// Post-attempt fence: Ensure operations complete before
		fence(Ordering::SeqCst);

		Ok(Ed25519PrivateKey { inner: signing_key })
	}

	fn is_valid_key_material<T: AsRef<[u8]>>(bytes: T) -> bool {
		bytes.as_ref().len() == ed25519_dalek::SECRET_KEY_LENGTH
	}

	fn key_size() -> usize {
		ed25519_dalek::SECRET_KEY_LENGTH
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use super::*;
	use x25519_dalek::PublicKey as DalekX25519PublicKey;

	#[cfg(feature = "signature")]
	use crate::operations::signature::{CryptoSignerWithOptions, CryptoVerifierWithOptions};

	crate::test_utils::test_key_derivation!(
		Ed25519Derivation,
		Ed25519PrivateKey,
		Ed25519PublicKey,
		32, // Ed25519 public keys are 32 bytes
		64, // 32 bytes * 2 hex chars per byte
		"ed25519"
	);

	crate::test_utils::test_crypto_utils!(Ed25519Derivation, Ed25519PrivateKey, 32, "ed25519", "ed25519");

	#[cfg(feature = "encryption")]
	crate::test_utils::test_asymmetric_encryption!(Ed25519Derivation, "ed25519");

	#[cfg(feature = "signature")]
	crate::test_utils::test_signatures!(Ed25519Derivation, "ed25519");

	#[cfg(any(feature = "der", feature = "rasn"))]
	crate::test_utils::test_der!(Ed25519Derivation, keetanetwork_asn1::oids::ED25519, "ed25519");

	#[test]
	fn test_ed25519_to_x25519_conversion() {
		let seed = b"test seed for x25519 conversion!!!!!!".into_secret();
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
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
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
		let alice_ed25519 = Ed25519Derivation::derive_from_seed(alice_seed.into_secret()).unwrap();
		let alice_x25519 = alice_ed25519.to_x25519().unwrap();
		let alice_public = alice_x25519.derive_public_key();

		// Bob generates his keys
		let bob_seed = b"bob_test_seed_for_diffie_hellman!!!";
		let bob_ed25519 = Ed25519Derivation::derive_from_seed(bob_seed.into_secret()).unwrap();
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
		let charlie_ed25519 = Ed25519Derivation::derive_from_seed(charlie_seed.into_secret()).unwrap();
		let charlie_x25519 = charlie_ed25519.to_x25519().unwrap();
		let charlie_public = charlie_x25519.derive_public_key();

		let alice_charlie_shared = alice_x25519.diffie_hellman(&charlie_public);
		assert_ne!(alice_shared, alice_charlie_shared);
	}

	#[test]
	fn test_x25519_debug_formatting() {
		let seed = b"test seed for x25519 debug format!!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
		let x25519_key = ed25519_key.to_x25519().unwrap();

		// Test that Debug format hides the private key
		let debug_string = format!("{x25519_key:?}");
		assert!(debug_string.contains("X25519PrivateKey"));
		assert!(debug_string.contains("[REDACTED]"));
		// The debug format shows "bytes: [REDACTED]" which is correct for hiding the secret
	}

	#[test]
	fn test_x25519_serialization_round_trips() {
		let seed = b"test seed for x25519 serialization!!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
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

	#[test]
	fn test_ed25519_public_key_uncompressed_bytes() {
		let seed = b"test seed for ed25519 uncompressed bytes";
		let private_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
		let public_key = private_key.as_public_key();

		// Test to_uncompressed_bytes method
		let uncompressed = public_key.to_uncompressed_bytes();
		assert_eq!(uncompressed.len(), 32); // Ed25519 public keys are 32 bytes

		// Compare with regular Vec conversion
		let regular_bytes: Vec<u8> = (&public_key).into();
		assert_eq!(uncompressed, regular_bytes);
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
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
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
		let alice_ed25519 = Ed25519Derivation::derive_from_seed(alice_seed.into_secret()).unwrap();
		let alice_x25519_from_ed25519 = alice_ed25519.to_x25519().unwrap();
		let alice_x25519_public = alice_x25519_from_ed25519.derive_public_key();

		let bob_seed = b"bob_seed_for_conversion_test_here!!!";
		let bob_ed25519 = Ed25519Derivation::derive_from_seed(bob_seed.into_secret()).unwrap();
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

		let ed25519_key1 = Ed25519Derivation::derive_from_seed(seed1.into_secret()).unwrap();
		let ed25519_key2 = Ed25519Derivation::derive_from_seed(seed2.into_secret()).unwrap();

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
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
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
		let result_short = Ed25519Derivation::derive_from_seed(short_seed.into_secret());
		assert!(result_short.is_ok()); // Should work with any seed length

		let long_seed = b"this is a very long seed that should still work for key derivation without any issues";
		let result_long = Ed25519Derivation::derive_from_seed(long_seed.into_secret());
		assert!(result_long.is_ok());

		// Test empty seed
		let empty_seed = b"";
		let result_empty = Ed25519Derivation::derive_from_seed(empty_seed.into_secret());
		assert!(result_empty.is_ok());
	}

	#[test]
	fn test_x25519_private_key_zeroize() {
		let seed = b"test seed for x25519 zeroize test!!!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
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

	#[cfg(feature = "encryption")]
	#[test]
	fn test_x25519_encrypt_decrypt() {
		let seed = b"test seed for x25519 encrypt decrypt!";
		let ed25519_key = Ed25519Derivation::derive_from_seed(seed.into_secret()).unwrap();
		let x25519_private = ed25519_key.to_x25519().unwrap();
		let x25519_public = x25519_private.derive_public_key();

		let plaintext = b"X25519 ECIES encryption test message";

		// Test encryption with X25519 private key (should delegate to public key)
		let ciphertext_from_private = x25519_private.encrypt(plaintext).unwrap();
		assert!(!ciphertext_from_private.is_empty());
		assert_ne!(ciphertext_from_private.as_slice(), plaintext);

		// Test encryption with X25519 public key directly
		let ciphertext_from_public = x25519_public.encrypt(plaintext).unwrap();
		assert!(!ciphertext_from_public.is_empty());
		assert_ne!(ciphertext_from_public.as_slice(), plaintext);
		// Both should be different due to ephemeral keys in ECIES
		assert_ne!(ciphertext_from_private, ciphertext_from_public);

		// Test decryption with X25519 private key
		let decrypted_from_private = x25519_private.decrypt(&ciphertext_from_private).unwrap();
		assert_eq!(decrypted_from_private, plaintext);

		let decrypted_from_public = x25519_private.decrypt(&ciphertext_from_public).unwrap();
		assert_eq!(decrypted_from_public, plaintext);

		// Test that X25519 public key cannot decrypt
		let decrypt_result1 = x25519_public.decrypt(&ciphertext_from_private);
		assert!(decrypt_result1.is_err());
		assert!(matches!(decrypt_result1.unwrap_err(), CryptoError::InvalidOperation));

		let decrypt_result2 = x25519_public.decrypt(&ciphertext_from_public);
		assert!(decrypt_result2.is_err());
		assert!(matches!(decrypt_result2.unwrap_err(), CryptoError::InvalidOperation));

		// Test cross-key encryption (different X25519 keys)
		let bob_seed = b"bob_seed_for_x25519_encryption_test!";
		let bob_ed25519 = Ed25519Derivation::derive_from_seed(bob_seed.into_secret()).unwrap();
		let bob_x25519_private = bob_ed25519.to_x25519().unwrap();
		let bob_x25519_public = bob_x25519_private.derive_public_key();

		// Encrypt with Bob's public key
		let ciphertext_for_bob = bob_x25519_public.encrypt(plaintext).unwrap();

		// Bob should be able to decrypt
		let decrypted_by_bob = bob_x25519_private.decrypt(&ciphertext_for_bob).unwrap();
		assert_eq!(decrypted_by_bob, plaintext);

		// Original private key should NOT be able to decrypt Bob's message
		let cross_decrypt_result = x25519_private.decrypt(&ciphertext_for_bob);
		assert!(cross_decrypt_result.is_err());
	}
}
