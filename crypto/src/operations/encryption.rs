//! Encryption and key exchange operations using RustCrypto patterns
//!
//! This module provides idiomatic traits and types for cryptographic encryption,
//! decryption, and key exchange operations.

use crate::error::CryptoError;

// Re-export key RustCrypto AEAD traits for easier use
#[cfg(feature = "aead")]
pub use aead::{Aead, AeadCore, AeadInPlace, KeyInit};

/// Authenticated encryption operations
///
/// This trait provides encryption functionality with conditional RustCrypto AEAD integration.
/// When the "aead" feature is enabled, it can integrate with RustCrypto AEAD traits.
pub trait CryptoAead {
	/// Encrypt data with authenticated encryption
	///
	/// This provides a simplified interface over the full AEAD API,
	/// automatically handling nonce generation when not provided.
	fn encrypt_data(&self, data: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>, CryptoError>;

	/// Decrypt and authenticate data
	///
	/// This provides a simplified interface over the full AEAD API.
	fn decrypt_data(&self, cipher_text: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>, CryptoError>;

	/// Get the nonce size for this AEAD algorithm (available when aead feature is enabled)
	#[cfg(feature = "aead")]
	fn nonce_size(&self) -> usize
	where
		Self: AeadCore;

	/// Get the tag size for this AEAD algorithm (available when aead feature is enabled)
	#[cfg(feature = "aead")]
	fn tag_size(&self) -> usize
	where
		Self: AeadCore;
}

/// Key exchange operations for asymmetric encryption
///
/// This trait provides key agreement/exchange functionality for asymmetric
/// encryption schemes like X25519.
pub trait KeyExchange {
	/// The shared secret type produced by key exchange
	type SharedSecret: AsRef<[u8]>;

	/// Perform key exchange with another public key
	fn key_exchange(&self, their_public_key: &[u8]) -> Result<Self::SharedSecret, CryptoError>;

	/// Derive an AEAD key from the shared secret
	#[cfg(feature = "aead")]
	fn derive_aead_key<A>(&self, shared_secret: &Self::SharedSecret) -> Result<A, CryptoError>
	where
		A: KeyInit;
}

/// Combined trait for keys that support both encryption and key exchange
///
/// This trait combines encryption capabilities with key exchange for hybrid
/// crypto systems.
pub trait HybridEncryption: KeyExchange {
	/// Encrypt data using key exchange and AEAD
	fn encrypt_with_key_exchange(&self, data: &[u8], recipient_pubkey: &[u8]) -> Result<Vec<u8>, CryptoError>;

	/// Decrypt data using key exchange and AEAD
	fn decrypt_with_key_exchange(&self, encrypted_data: &[u8], sender_pubkey: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_key_exchange_trait() {
		// Test that KeyExchange trait compiles
		fn _test_key_exchange<T: KeyExchange>(_kex: T) {
			// This function compiles if the bounds are correct
		}
	}

	#[test]
	fn test_crypto_aead_trait() {
		// Test that CryptoAead trait compiles
		fn _test_crypto_aead<T: CryptoAead>(_aead: T) {
			// This function compiles if the bounds are correct
		}
	}

	#[test]
	fn test_hybrid_encryption_trait() {
		// Test that HybridEncryption trait compiles
		fn _test_hybrid_encryption<T: HybridEncryption>(_hybrid: T) {
			// This function compiles if the bounds are correct
		}
	}
}
