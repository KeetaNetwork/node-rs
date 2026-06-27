//! secp256r1 (NIST P-256) cryptographic algorithm implementation.
//!
//! This module provides secp256r1 elliptic curve cryptography support.
//!
//! # Key Format
//!
//! - **Private keys**: 32 bytes, in range [1, n-1] where n is the curve order
//! - **Public keys**: 33 bytes compressed format (0x02/0x03 prefix + 32 bytes)

// Re-export algorithm-specific signature types
pub use p256::ecdsa::Signature as Secp256r1Signature;

use alloc::vec::Vec;

use core::fmt::{Debug, Formatter, Result as FmtResult};

use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey as P256SecretKey;
use secrecy::SecretBox;

#[cfg(feature = "signature")]
use ::signature::{Keypair, Signer, Verifier};
#[cfg(feature = "signature")]
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
#[cfg(feature = "signature")]
use p256::ecdsa::VerifyingKey;

#[cfg(feature = "encryption")]
use aead::KeyInit;
#[cfg(feature = "encryption")]
use p256::ecdh::diffie_hellman;

#[cfg(feature = "signature")]
use crate::hash::{hash_default, HashAlgorithm};
#[cfg(feature = "signature")]
use crate::operations::signature::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};

#[cfg(feature = "encryption")]
use crate::algorithms::ecies::{Ecies, EciesSecp256r1};
#[cfg(feature = "encryption")]
use crate::operations::encryption::{AsymmetricEncryption, KeyExchange, KeyGeneration};
#[cfg(feature = "encryption")]
use crate::utils::generate_random_seed;

use crate::algorithms::{Algorithm, CryptoAlgorithm, KeyDerivation, PrivateKey, PublicKey};
use crate::error::{CryptoError, OrCryptoError};
use crate::kdf::KdfAlgorithm;
use crate::IntoSecret;

/// secp256r1 (NIST P-256) private key wrapper.
///
/// This struct wraps the p256 SecretKey and provides the PrivateKey trait
/// implementation.
///
/// ## Security Note
///
/// The inner secret key is kept private and only accessible through the trait
/// methods.
pub struct Secp256r1PrivateKey {
	inner: P256SecretKey,
}

impl Secp256r1PrivateKey {
	/// Create a new private key from the inner secret key.
	/// Used by the constant-time key derivation macro.
	pub(crate) fn from_inner(inner: P256SecretKey) -> Self {
		Self { inner }
	}
}

// Generate secure zeroization implementation for Secp256r1PrivateKey
crate::impl_secure_zeroize!(Secp256r1PrivateKey, P256SecretKey, inner);
impl zeroize::ZeroizeOnDrop for Secp256r1PrivateKey {}

impl CryptoAlgorithm for Secp256r1PrivateKey {
	fn to_algorithm(&self) -> Algorithm {
		Algorithm::Secp256r1
	}
}

impl PrivateKey for Secp256r1PrivateKey {
	type PublicKey = Secp256r1PublicKey;
	type Signature = Signature;

	fn as_public_key(&self) -> Self::PublicKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();
		let bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

		Secp256r1PublicKey { inner: verifying_key.into(), bytes }
	}
}

impl From<Secp256r1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: Secp256r1PrivateKey) -> Self {
		key.inner.to_bytes().to_vec().into_secret()
	}
}

impl From<&Secp256r1PrivateKey> for SecretBox<Vec<u8>> {
	fn from(key: &Secp256r1PrivateKey) -> Self {
		key.inner.to_bytes().to_vec().into_secret()
	}
}

impl TryFrom<&[u8]> for Secp256r1PrivateKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let secret_key = P256SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;

		Ok(Secp256r1PrivateKey { inner: secret_key })
	}
}

/// Debug formatting will show "\[REDACTED\]" to prevent accidental
/// key exposure.
impl Debug for Secp256r1PrivateKey {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		f.debug_struct("Secp256r1PrivateKey")
			.field("inner", &"[REDACTED]")
			.finish()
	}
}

#[cfg(any(feature = "der", feature = "rasn"))]
impl From<Secp256r1PrivateKey> for keetanetwork_asn1::ObjectIdentifier {
	fn from(_private_key: Secp256r1PrivateKey) -> Self {
		#[cfg(feature = "der")]
		{
			keetanetwork_asn1::oids::typed::SECP256R1
		}
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		{
			keetanetwork_asn1::oids::typed::SECP256R1.clone()
		}
	}
}

#[cfg(feature = "encryption")]
impl KeyGeneration for Secp256r1PrivateKey {
	type Error = CryptoError;

	fn generate_random() -> Result<Self, Self::Error> {
		// Generate a random 32-byte seed and derive a key from it
		let random_seed = generate_random_seed()?;
		Secp256r1Derivation::derive_from_seed(random_seed)
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256r1PrivateKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		let public_key = self.as_public_key();
		public_key.encrypt(plaintext)
	}

	fn decrypt<C: AsRef<[u8]>>(&self, cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		EciesSecp256r1::decrypt(self, cipher_text.as_ref())
	}
}

#[cfg(feature = "encryption")]
impl KeyExchange for Secp256r1PrivateKey {
	type PublicKey = Secp256r1PublicKey;
	type SharedSecret = Vec<u8>;

	fn ecdh(&self, other_public_key: &Secp256r1PublicKey) -> Result<Vec<u8>, CryptoError> {
		// Perform ECDH directly using the p256 function
		let shared_secret = diffie_hellman(self.inner.to_nonzero_scalar(), other_public_key.inner.as_affine());
		// Return the raw bytes of the shared secret
		Ok(shared_secret.raw_secret_bytes().to_vec())
	}

	fn key_exchange<K: AsRef<[u8]>>(&self, their_public_key: K) -> Result<Self::SharedSecret, CryptoError> {
		let public_key = Secp256r1PublicKey::try_from(their_public_key.as_ref())?;
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

#[cfg(feature = "signature")]
impl Keypair for Secp256r1PrivateKey {
	type VerifyingKey = Secp256r1PublicKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		let signing_key = SigningKey::from(&self.inner);
		let verifying_key = signing_key.verifying_key();
		let bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

		Secp256r1PublicKey { inner: verifying_key.into(), bytes }
	}
}

#[cfg(feature = "signature")]
impl Signer<Signature> for Secp256r1PrivateKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::signature::Error> {
		let signing_key = SigningKey::from(&self.inner);
		signing_key.try_sign(msg)
	}
}

#[cfg(feature = "signature")]
impl CryptoSigner<Signature> for Secp256r1PrivateKey {
	fn has_private_key(&self) -> bool {
		true
	}
}

#[cfg(feature = "signature")]
impl CryptoSignerWithOptions<Signature> for Secp256r1PrivateKey {
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
			// For regular signing, use the default hash algorithm (SHA3-256)
			let data = hash_default(message).to_vec();
			signing_key.sign_prehash(&data)
		}
	}
}

/// secp256r1 (NIST P-256) public key wrapper.
///
/// This struct wraps the p256 PublicKey and provides the PublicKey trait
/// implementation. secp256r1 public keys are stored in compressed format
/// (33 bytes: 0x02/0x03 prefix + 32 bytes).
///
/// Public keys can be safely displayed, serialized, and shared as they contain
/// no secret information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256r1PublicKey {
	bytes: Vec<u8>,
	inner: p256::PublicKey,
}

impl CryptoAlgorithm for Secp256r1PublicKey {
	fn to_algorithm(&self) -> Algorithm {
		Algorithm::Secp256r1
	}
}

impl PublicKey for Secp256r1PublicKey {
	fn to_uncompressed_bytes(&self) -> Vec<u8> {
		self.inner.to_encoded_point(false).as_bytes().to_vec()
	}
}

impl From<Secp256r1PublicKey> for Vec<u8> {
	fn from(key: Secp256r1PublicKey) -> Self {
		(&key).into()
	}
}

impl From<&Secp256r1PublicKey> for Vec<u8> {
	fn from(key: &Secp256r1PublicKey) -> Self {
		// Return compressed format (33 bytes: 0x02/0x03 prefix + 32 bytes)
		// This is more space-efficient than uncompressed format (65 bytes)
		key.inner.to_encoded_point(true).as_bytes().to_vec()
	}
}

impl TryFrom<&[u8]> for Secp256r1PublicKey {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let public_key = p256::PublicKey::from_sec1_bytes(bytes).or_invalid_public_key()?;
		Ok(Secp256r1PublicKey { inner: public_key, bytes: bytes.to_vec() })
	}
}

impl AsRef<[u8]> for Secp256r1PublicKey {
	fn as_ref(&self) -> &[u8] {
		self.bytes.as_ref()
	}
}

#[cfg(any(feature = "der", feature = "rasn"))]
impl From<Secp256r1PublicKey> for keetanetwork_asn1::ObjectIdentifier {
	fn from(_public_key: Secp256r1PublicKey) -> Self {
		#[cfg(feature = "der")]
		{
			keetanetwork_asn1::oids::typed::SECP256R1
		}
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		{
			keetanetwork_asn1::oids::typed::SECP256R1.clone()
		}
	}
}

#[cfg(feature = "signature")]
impl Verifier<Signature> for Secp256r1PublicKey {
	fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ::signature::Error> {
		let verifying_key = p256::ecdsa::VerifyingKey::from(&self.inner);
		verifying_key.verify(msg, signature)
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifier<Signature> for Secp256r1PublicKey {
	fn public_key_bytes(&self) -> Vec<u8> {
		self.into()
	}
}

#[cfg(feature = "signature")]
impl CryptoVerifierWithOptions<Signature> for Secp256r1PublicKey {
	fn verify_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		signature: &Signature,
		options: SigningOptions,
	) -> Result<(), ::signature::Error> {
		let message = message.as_ref();
		let verifying_key = VerifyingKey::from(&self.inner);

		if options.raw {
			// For raw verification, treat the message as a pre-computed hash
			// and use prehash verification to avoid double hashing
			if message.len() != 32 {
				return Err(::signature::Error::new());
			}
			verifying_key.verify_prehash(message, signature)
		} else if options.for_cert {
			// For certificate verification, use SHA2-256
			let data = HashAlgorithm::Sha2_256.hash(message);
			verifying_key.verify_prehash(&data, signature)
		} else {
			// For regular verification, use the default hash algorithm
			let data = hash_default(message).to_vec();
			verifying_key.verify_prehash(&data, signature)
		}
	}
}

#[cfg(feature = "encryption")]
impl AsymmetricEncryption for Secp256r1PublicKey {
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError> {
		EciesSecp256r1::encrypt(self, plaintext.as_ref())
	}

	fn decrypt<C: AsRef<[u8]>>(&self, _cipher_text: C) -> Result<Vec<u8>, CryptoError> {
		// Public key cannot decrypt
		Err(CryptoError::InvalidOperation)
	}
}

/// Key derivation implementation for secp256r1.
///
/// This struct provides HKDF-based key derivation for secp256r1 private keys,
/// ensuring generated keys are always valid for the curve.
pub struct Secp256r1Derivation;

crate::impl_constant_time_key_derivation!(Secp256r1PrivateKey, P256SecretKey, Secp256r1Derivation);

#[cfg(test)]
mod tests {
	use super::*;
	use crate::prelude::ExposeSecret;

	// Use the individual test macros for shared functionality
	crate::test_utils::test_key_derivation!(
		Secp256r1Derivation,
		Secp256r1PrivateKey,
		Secp256r1PublicKey,
		33, // secp256r1 compressed public keys are 33 bytes
		66, // 33 bytes * 2 hex chars per byte
		"secp256r1"
	);

	crate::test_utils::test_crypto_utils!(Secp256r1Derivation, Secp256r1PrivateKey, 32, "secp256r1", "secp256r1");

	#[cfg(feature = "signature")]
	crate::test_utils::test_signatures!(Secp256r1Derivation, "secp256r1");

	#[cfg(feature = "encryption")]
	crate::test_utils::test_key_exchange!(Secp256r1Derivation, "secp256r1");

	#[cfg(feature = "encryption")]
	crate::test_utils::test_ecdh!(Secp256r1Derivation, Secp256r1PrivateKey, Secp256r1PublicKey, "secp256r1");

	#[cfg(feature = "encryption")]
	crate::test_utils::test_asymmetric_encryption!(Secp256r1Derivation, "secp256r1");

	#[cfg(any(feature = "der", feature = "rasn"))]
	crate::test_utils::test_der!(Secp256r1Derivation, keetanetwork_asn1::oids::SECP256R1, "secp256r1");
}
