//! Digital signature operations using RustCrypto patterns.
//!
//! This module provides idiomatic traits and types for cryptographic signing
//! and verification operations, leveraging the RustCrypto ecosystem.

use crate::error::CryptoError;

// Re-export key RustCrypto signature traits for easier use
#[cfg(feature = "signature")]
pub use signature::{DigestSigner, DigestVerifier, RandomizedSigner, Signer, Verifier};

/// Core cryptographic signing operations
///
/// This trait provides signing functionality with conditional RustCrypto integration.
/// When the "signature" feature is enabled, it extends RustCrypto's Signer trait.
pub trait CryptoSigner<S> {
	/// Check if this signer has access to the private key
	fn has_private_key(&self) -> bool;

	/// Get the verifying key (public key) for this signer
	fn verifying_key(&self) -> impl CryptoVerifier<S>;

	/// Sign data (available when signature feature is enabled)
	#[cfg(feature = "signature")]
	fn try_sign(&self, msg: &[u8]) -> Result<S, signature::Error>
	where
		Self: Signer<S>,
		S: signature::SignatureEncoding;
}

/// Core cryptographic verification operations
///
/// This trait provides verification functionality with conditional RustCrypto integration.
/// When the "signature" feature is enabled, it extends RustCrypto's Verifier trait.
pub trait CryptoVerifier<S> {
	/// Get the public key bytes for this verifier
	fn public_key_bytes(&self) -> Vec<u8>;

	/// Get the formatted public key string
	fn public_key_string(&self) -> Result<String, CryptoError>;

	/// Verify a signature (available when signature feature is enabled)
	#[cfg(feature = "signature")]
	fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error>
	where
		Self: Verifier<S>,
		S: signature::SignatureEncoding;
}

/// Combined trait for keys that support both signing and key exchange
///
/// This trait combines signing capabilities with key exchange for hybrid
/// crypto systems that need both operations.
pub trait HybridSigner<S>: CryptoSigner<S> {
	/// Sign and prepare data for encrypted transmission
	fn sign_for_encryption(&self, data: &[u8], recipient_pubkey: &[u8]) -> Result<Vec<u8>, CryptoError>;

	/// Verify and decrypt data in one operation  
	fn verify_from_encryption(&self, encrypted_data: &[u8], sender_pubkey: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_signature_trait_bounds() {
		// This test ensures our trait bounds compile correctly
		fn _test_crypto_signer<S, T>(_signer: T)
		where
			T: CryptoSigner<S>,
		{
			// This function compiles if the bounds are correct
		}

		fn _test_crypto_verifier<S, T>(_verifier: T)
		where
			T: CryptoVerifier<S>,
		{
			// This function compiles if the bounds are correct
		}

		fn _test_hybrid_signer<S, T>(_signer: T)
		where
			T: HybridSigner<S>,
		{
			// This function compiles if the bounds are correct
		}
	}
}
