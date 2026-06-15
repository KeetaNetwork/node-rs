//! Digital signature operations using RustCrypto patterns.
//!
//! This module provides idiomatic traits and types for cryptographic signing
//! and verification operations, leveraging the RustCrypto ecosystem.

use alloc::vec::Vec;

use crate::algorithms::CryptoAlgorithm;

// Re-export key RustCrypto signature traits for easier use
pub use signature::{
	DigestSigner, DigestVerifier, Error as SignatureError, Keypair, RandomizedSigner, Signer, Verifier,
};

/// Core cryptographic signing operations.
///
/// This trait extends RustCrypto's Signer trait with additional functionality
/// needed for our cryptographic operations.
pub trait CryptoSigner<S>: CryptoAlgorithm + Signer<S> {
	/// Check if this signer has access to the private key
	fn has_private_key(&self) -> bool;
}

/// Core cryptographic verification operations.
///
/// This trait extends RustCrypto's Verifier trait with additional functionality
/// needed for our cryptographic operations.
pub trait CryptoVerifier<S>: CryptoAlgorithm + Verifier<S> {
	/// Get the public key bytes for this verifier
	fn public_key_bytes(&self) -> Vec<u8>;
}

/// Extended cryptographic key pair operations.
pub trait CryptoKeyPair<S>: CryptoAlgorithm + Keypair + Signer<S> + Clone
where
	Self::VerifyingKey: CryptoVerifier<S>,
{
	type SigningKey: CryptoSigner<S>;

	/// Extract the verifying key (public key) from this key pair.
	fn to_public_key(&self) -> Self::VerifyingKey {
		self.verifying_key()
	}

	/// Take ownership of the private key, consuming this key pair.
	/// This is useful when you need to move the private key out of the key pair.
	fn take_private_key(self) -> Self::SigningKey;
}

/// Signing and verification options for cryptographic operations.
///
/// Default options are:
/// - raw: false (will pre-hash the message)
/// - for_cert: false (use SEC format, not DER)
#[derive(Debug, Copy, Clone, Default)]
pub struct SigningOptions {
	/// If true, use the raw message without hashing
	/// If false, pre-hash the message before signing/verification
	pub raw: bool,

	/// For certificate processing
	pub for_cert: bool,
}

impl SigningOptions {
	/// Create options for raw message processing (no pre-hashing)
	pub fn raw() -> Self {
		Self { raw: true, for_cert: false }
	}

	/// Create options for certificate processing
	pub fn for_cert() -> Self {
		Self { raw: false, for_cert: true }
	}
}

/// Extended signing operations with configurable options.
///
/// This trait provides signing operations with additional configuration
/// options for message preprocessing and encoding formats.
pub trait CryptoSignerWithOptions<S>: CryptoSigner<S> {
	/// Sign a message with the specified options.
	fn sign_with_options<T: AsRef<[u8]>>(&self, message: T, options: SigningOptions) -> Result<S, SignatureError>;
}

/// Extended verification operations with configurable options.
///
/// This trait provides verification operations with additional configuration
/// options for message preprocessing and encoding formats.
pub trait CryptoVerifierWithOptions<S>: CryptoVerifier<S> {
	/// Verify a signature against a message using the specified options.
	fn verify_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		signature: &S,
		options: SigningOptions,
	) -> Result<(), SignatureError>;
}
