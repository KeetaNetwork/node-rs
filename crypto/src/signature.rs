//! Cryptographic signature types and operations
//!
//! This module provides signature storage and wrapper types for different
//! cryptographic algorithms, with proper error handling and type safety.

use crate::error::CryptoError;
use zeroize::Zeroize;

#[cfg(feature = "signature")]
use signature::SignatureEncoding;

/// Generic signature storage for cryptographic signatures.
///
/// All supported signature algorithms use 64-byte signatures
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct SignatureStorage {
	data: [u8; 64],
}

impl TryFrom<&[u8]> for SignatureStorage {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		if bytes.len() != 64 {
			return Err(CryptoError::InvalidLength);
		}

		let mut data = [0u8; 64];
		data.copy_from_slice(bytes);

		Ok(Self { data })
	}
}

impl TryFrom<Vec<u8>> for SignatureStorage {
	type Error = CryptoError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		Self::try_from(bytes.as_slice())
	}
}

impl AsRef<[u8; 64]> for SignatureStorage {
	fn as_ref(&self) -> &[u8; 64] {
		&self.data
	}
}

impl AsRef<[u8]> for SignatureStorage {
	fn as_ref(&self) -> &[u8] {
		&self.data
	}
}

/// ECDSA signature wrapper for secp256k1 and secp256r1 curves.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct EcdsaSignature(SignatureStorage);

#[cfg(not(feature = "signature"))]
impl TryFrom<&[u8]> for EcdsaSignature {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Ok(Self(SignatureStorage::try_from(bytes)?))
	}
}

#[cfg(feature = "signature")]
impl TryFrom<&[u8]> for EcdsaSignature {
	type Error = signature::Error;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		SignatureStorage::try_from(bytes).map(Self).map_err(|_| signature::Error::new())
	}
}

#[cfg(not(feature = "signature"))]
impl TryFrom<Vec<u8>> for EcdsaSignature {
	type Error = CryptoError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		Self::try_from(bytes.as_slice())
	}
}

#[cfg(feature = "signature")]
impl TryFrom<Vec<u8>> for EcdsaSignature {
	type Error = signature::Error;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		Self::try_from(bytes.as_slice())
	}
}

impl AsRef<[u8; 64]> for EcdsaSignature {
	fn as_ref(&self) -> &[u8; 64] {
		self.0.as_ref()
	}
}

impl AsRef<[u8]> for EcdsaSignature {
	fn as_ref(&self) -> &[u8] {
		self.0.as_ref()
	}
}

/// Ed25519 signature wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Ed25519Signature(SignatureStorage);

#[cfg(not(feature = "signature"))]
impl TryFrom<&[u8]> for Ed25519Signature {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Ok(Self(SignatureStorage::try_from(bytes)?))
	}
}

#[cfg(feature = "signature")]
impl TryFrom<&[u8]> for Ed25519Signature {
	type Error = signature::Error;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		SignatureStorage::try_from(bytes).map(Self).map_err(|_| signature::Error::new())
	}
}

#[cfg(not(feature = "signature"))]
impl TryFrom<Vec<u8>> for Ed25519Signature {
	type Error = CryptoError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		Self::try_from(bytes.as_slice())
	}
}

#[cfg(feature = "signature")]
impl TryFrom<Vec<u8>> for Ed25519Signature {
	type Error = signature::Error;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		Self::try_from(bytes.as_slice())
	}
}

impl AsRef<[u8; 64]> for Ed25519Signature {
	fn as_ref(&self) -> &[u8; 64] {
		self.0.as_ref()
	}
}

impl AsRef<[u8]> for Ed25519Signature {
	fn as_ref(&self) -> &[u8] {
		self.0.as_ref()
	}
}

// Implement SignatureEncoding for RustCrypto compatibility.
#[cfg(feature = "signature")]
impl SignatureEncoding for EcdsaSignature {
	type Repr = [u8; 64];
}

#[cfg(feature = "signature")]
impl TryInto<[u8; 64]> for EcdsaSignature {
	type Error = signature::Error;

	fn try_into(self) -> Result<[u8; 64], Self::Error> {
		Ok(*self.0.as_ref())
	}
}

#[cfg(feature = "signature")]
impl SignatureEncoding for Ed25519Signature {
	type Repr = [u8; 64];
}

#[cfg(feature = "signature")]
impl TryInto<[u8; 64]> for Ed25519Signature {
	type Error = signature::Error;

	fn try_into(self) -> Result<[u8; 64], Self::Error> {
		Ok(*self.0.as_ref())
	}
}

/// Options for signing and verification operations
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
	/// Perform signing/verification on raw data (skip hashing)
	pub raw: bool,
	/// Format for X.509 certificate compatibility
	pub for_cert: bool,
}
