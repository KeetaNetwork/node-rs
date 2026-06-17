//! secp256k1 cryptographic algorithm implementation.
//!
//! This module provides secp256k1 elliptic curve cryptography support, the
//! same curve used by Bitcoin.
//! # Key Format
//!
//! - **Private keys**: 32 bytes, in range [1, n-1] where n is the curve order
//! - **Public keys**: 33 bytes compressed format (0x02/0x03 prefix + 32 bytes)

// Re-export algorithm-specific signature types
pub use k256::ecdsa::Signature as Secp256k1Signature;

use alloc::vec::Vec;

use core::fmt::{Debug, Formatter, Result as FmtResult};

use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey as K256SecretKey;
use secrecy::SecretBox;

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};
#[cfg(feature = "signature")]
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
#[cfg(feature = "signature")]
use k256::ecdsa::VerifyingKey;

#[cfg(feature = "encryption")]
use k256::ecdh::diffie_hellman;

#[cfg(feature = "encryption")]
use crate::algorithms::ecies::Ecies;
#[cfg(feature = "encryption")]
use crate::algorithms::ecies::EciesSecp256k1;
#[cfg(feature = "encryption")]
use crate::operations::encryption::{AsymmetricEncryption, KeyExchange, KeyGeneration, KeyInit};
#[cfg(feature = "encryption")]
use crate::utils::generate_random_seed;

#[cfg(feature = "signature")]
use crate::hash::{hash_default, HashAlgorithm};
#[cfg(feature = "signature")]
use crate::operations::signature::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};

use crate::algorithms::{Algorithm, CryptoAlgorithm};
use crate::algorithms::{KeyDerivation, PrivateKey, PublicKey};
use crate::error::CryptoError;
use crate::kdf::KdfAlgorithm;
use crate::IntoSecret;

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
pub struct Secp256k1PrivateKey {
	inner: K256SecretKey,
}

impl Secp256k1PrivateKey {
	/// Create a new private key from the inner secret key.
	/// Used by the constant-time key derivation macro.
	pub(crate) fn from_inner(inner: K256SecretKey) -> Self {
		Self { inner }
	}
}

impl Debug for Secp256k1PrivateKey {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		f.debug_struct("Secp256k1PrivateKey")
			.field("inner", &"[REDACTED]")
			.finish()
	}
}

// Generate secure zeroization implementation for Secp256k1PrivateKey
crate::impl_secure_zeroize!(Secp256k1PrivateKey, K256SecretKey, inner);
impl zeroize::ZeroizeOnDrop for Secp256k1PrivateKey {}

impl CryptoAlgorithm for Secp256k1PrivateKey {
	fn to_algorithm(&self) -> Algorithm {
		Algorithm::Secp256k1
	}
}

impl PrivateKey for Secp256k1PrivateKey {
	type PublicKey = Secp256k1PublicKey;
	type Signature = Signature;

	fn as_public_key(&self) -> Self::PublicKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();
		let bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
		Secp256k1PublicKey { inner: verifying_key.into(), bytes }
	}
}

impl From<Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Secp256k1PrivateKey) -> Self {
		key.inner.to_bytes().to_vec().into_secret()
	}
}

impl From<&Secp256k1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Secp256k1PrivateKey) -> Self {
		key.inner.to_bytes().to_vec().into_secret()
	}
}

impl TryFrom<&[u8]> for Secp256k1PrivateKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let secret_key = K256SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;
		Ok(Secp256k1PrivateKey { inner: secret_key })
	}
}

#[cfg(any(feature = "der", feature = "rasn"))]
impl From<Secp256k1PrivateKey> for keetanetwork_asn1::ObjectIdentifier {
	fn from(_private_key: Secp256k1PrivateKey) -> Self {
		#[cfg(feature = "der")]
		{
			keetanetwork_asn1::oids::typed::SECP256K1
		}
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		{
			keetanetwork_asn1::oids::typed::SECP256K1.clone()
		}
	}
}

#[cfg(feature = "encryption")]
impl KeyGeneration for Secp256k1PrivateKey {
	type Error = CryptoError;

	fn generate_random() -> Result<Self, Self::Error> {
		// Generate a random 32-byte seed and derive a key from it
		let random_seed = generate_random_seed()?;
		Secp256k1Derivation::derive_from_seed(random_seed)
	}
}

#[cfg(feature = "encryption")]
impl KeyExchange for Secp256k1PrivateKey {
	type PublicKey = Secp256k1PublicKey;
	type SharedSecret = Vec<u8>;

	fn ecdh(&self, other_public_key: &Secp256k1PublicKey) -> Result<Vec<u8>, CryptoError> {
		// Perform ECDH directly using the k256 function
		let shared_secret = diffie_hellman(self.inner.to_nonzero_scalar(), other_public_key.inner.as_affine());
		// Return the raw bytes of the shared secret
		Ok(shared_secret.raw_secret_bytes().to_vec())
	}

	fn key_exchange<K: AsRef<[u8]>>(&self, their_public_key: K) -> Result<Self::SharedSecret, CryptoError> {
		let public_key = Secp256k1PublicKey::try_from(their_public_key.as_ref())?;
		self.ecdh(&public_key)
	}

	fn derive_aead_key<A>(&self, _shared_secret: &Self::SharedSecret) -> Result<A, CryptoError>
	where
		A: KeyInit,
	{
		// Use ECDH to derive the key
		Err(CryptoError::EncryptionNotSupported)
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256k1PrivateKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		// Use the public key for encryption
		let public_key = self.as_public_key();
		public_key.encrypt(plaintext)
	}

	fn decrypt<C: AsRef<[u8]>>(&self, cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		EciesSecp256k1::decrypt(self, cipher_text.as_ref())
	}
}

#[cfg(feature = "signature")]
impl Keypair for Secp256k1PrivateKey {
	type VerifyingKey = Secp256k1PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();
		let bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
		Secp256k1PublicKey { inner: verifying_key.into(), bytes }
	}
}

#[cfg(feature = "signature")]
impl Signer<Signature> for Secp256k1PrivateKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::signature::Error> {
		let signing_key = SigningKey::from(&self.inner);
		signing_key.try_sign(msg)
	}
}

#[cfg(feature = "signature")]
impl CryptoSigner<Signature> for Secp256k1PrivateKey {
	fn has_private_key(&self) -> bool {
		true
	}
}

#[cfg(feature = "signature")]
impl CryptoSignerWithOptions<Signature> for Secp256k1PrivateKey {
	fn sign_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		options: SigningOptions,
	) -> Result<Signature, ::signature::Error> {
		let message = message.as_ref();
		let signing_key = SigningKey::from(&self.inner);

		if options.raw {
			// For raw signing, treat the message as a pre-computed hash
			// and use prehash signing to avoid double hashing
			if message.len() != 32 {
				return Err(::signature::Error::new());
			}
			signing_key.sign_prehash(message)
		} else if options.for_cert {
			// For certificate signing, use SHA2-256
			let data = HashAlgorithm::Sha2_256.hash(message);
			signing_key.sign_prehash(&data)
		} else {
			// For regular signing, use the default hash algorithm
			let data = hash_default(message).to_vec();
			signing_key.sign_prehash(&data)
		}
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256k1PublicKey {
	bytes: Vec<u8>,
	inner: k256::PublicKey,
}

impl CryptoAlgorithm for Secp256k1PublicKey {
	fn to_algorithm(&self) -> Algorithm {
		Algorithm::Secp256k1
	}
}

impl PublicKey for Secp256k1PublicKey {
	fn to_uncompressed_bytes(&self) -> Vec<u8> {
		self.inner.to_encoded_point(false).as_bytes().to_vec()
	}
}

impl From<Secp256k1PublicKey> for Vec<u8> {
	fn from(key: Secp256k1PublicKey) -> Self {
		(&key).into()
	}
}

impl From<&Secp256k1PublicKey> for Vec<u8> {
	fn from(key: &Secp256k1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

impl AsRef<[u8]> for Secp256k1PublicKey {
	fn as_ref(&self) -> &[u8] {
		self.bytes.as_ref()
	}
}

impl TryFrom<&[u8]> for Secp256k1PublicKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let public_key = k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
		let bytes = public_key.to_encoded_point(true).as_bytes().to_vec();
		Ok(Secp256k1PublicKey { inner: public_key, bytes })
	}
}

#[cfg(any(feature = "der", feature = "rasn"))]
impl From<Secp256k1PublicKey> for keetanetwork_asn1::ObjectIdentifier {
	fn from(_public_key: Secp256k1PublicKey) -> Self {
		#[cfg(feature = "der")]
		{
			keetanetwork_asn1::oids::typed::SECP256K1
		}
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		{
			keetanetwork_asn1::oids::typed::SECP256K1.clone()
		}
	}
}

#[cfg(feature = "signature")]
impl Verifier<Signature> for Secp256k1PublicKey {
	fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ::signature::Error> {
		let verifying_key = k256::ecdsa::VerifyingKey::from(&self.inner);
		verifying_key.verify(msg, signature)
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifier<Signature> for Secp256k1PublicKey {
	fn public_key_bytes(&self) -> Vec<u8> {
		self.into()
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifierWithOptions<Signature> for Secp256k1PublicKey {
	fn verify_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		signature: &Signature,
		options: SigningOptions,
	) -> Result<(), ::signature::Error> {
		let message = message.as_ref();
		let verifying_key = VerifyingKey::from(&self.inner);

		// Always enforce low-S signatures (BIP-62 compliance)
		// Use normalize_low_s() to convert high-S signatures before verification
		let sig_bytes: [u8; 64] = signature.to_bytes().into();
		if !crate::utils::is_low_s(&sig_bytes, Algorithm::Secp256k1) {
			return Err(::signature::Error::new());
		}

		if options.raw {
			// For raw verification, treat the message as a pre-computed hash
			// and use prehash verification to avoid double hashing
			if message.len() != 32 {
				return Err(::signature::Error::new());
			}
			verifying_key.verify_prehash(message, signature)
		} else {
			// For non-raw verification, hash the message first
			let data = if options.for_cert {
				// For certificates, use SHA2-256
				HashAlgorithm::Sha2_256.hash(message)
			} else {
				// For regular verification, use default hash
				hash_default(message).to_vec()
			};

			// Use prehash verification since we've already computed the hash
			verifying_key.verify_prehash(&data, signature)
		}
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256k1PublicKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		EciesSecp256k1::encrypt(self, plaintext.as_ref())
	}

	fn decrypt<C: AsRef<[u8]>>(&self, _cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		// Public keys cannot decrypt
		Err(CryptoError::InvalidOperation)
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
/// 4. **Error Handling**: Fail after 100 attempts (unlikely to happen)
///
/// This process ensures we always generate valid secp256k1 private keys while
/// maintaining deterministic derivation from the same seed.
pub struct Secp256k1Derivation;

// Use the constant-time key derivation macro
crate::impl_constant_time_key_derivation!(Secp256k1PrivateKey, K256SecretKey, Secp256k1Derivation);

#[cfg(test)]
mod tests {
	use super::*;
	use secrecy::ExposeSecret;

	// Use the individual test macros for shared functionality
	crate::test_utils::test_key_derivation!(
		Secp256k1Derivation,
		Secp256k1PrivateKey,
		Secp256k1PublicKey,
		33, // secp256k1 compressed public keys are 33 bytes
		66, // 33 bytes * 2 hex chars per byte
		"secp256k1"
	);

	crate::test_utils::test_crypto_utils!(Secp256k1Derivation, Secp256k1PrivateKey, 32, "secp256k1", "secp256k1");

	#[cfg(feature = "signature")]
	crate::test_utils::test_signatures!(Secp256k1Derivation, "secp256k1");

	#[cfg(feature = "encryption")]
	crate::test_utils::test_key_exchange!(Secp256k1Derivation, "secp256k1");

	#[cfg(feature = "encryption")]
	crate::test_utils::test_ecdh!(Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey, "secp256k1");

	#[cfg(feature = "encryption")]
	crate::test_utils::test_asymmetric_encryption!(Secp256k1Derivation, "secp256k1");

	#[cfg(any(feature = "der", feature = "rasn"))]
	crate::test_utils::test_der!(Secp256k1Derivation, keetanetwork_asn1::oids::SECP256K1, "secp256k1");
}
