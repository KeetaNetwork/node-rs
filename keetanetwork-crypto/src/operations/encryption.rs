//! Encryption and key exchange operations using RustCrypto patterns.
//!
//! This module provides idiomatic traits and types for encryption,
//! decryption, and key exchange operations.

use crate::error::CryptoError;

// Re-export key RustCrypto AEAD traits for easier use
pub use aead::{Aead, AeadCore, AeadInPlace, KeyInit};

/// AEAD operations that extend RustCrypto's Aead trait.
///
/// This trait extends the RustCrypto Aead trait with additional convenience
/// methods while avoiding method name conflicts. It provides the standard
/// AEAD interface through inheritance from Aead.
pub trait CryptoAead: Aead {}

/// Symmetric encryption operations.
///
/// This trait provides encryption functionality for symmetric encryption
/// schemes like AES-CBC that use the same key for both encryption and decryption.
pub trait SymmetricEncryption {
	/// Encrypt data using symmetric encryption
	///
	/// # Arguments
	/// * `key` - The symmetric encryption key
	/// * `iv` - Optional initialization vector/nonce.
	/// * `plaintext` - Data to encrypt
	///
	/// # Returns
	/// Encrypted data (may include IV/nonce)
	fn encrypt<K: AsRef<[u8]>, P: AsRef<[u8]>>(
		&self,
		key: K,
		iv: Option<&[u8]>,
		plaintext: P,
	) -> Result<Vec<u8>, CryptoError>;

	/// Decrypt data using symmetric encryption.
	///
	/// # Arguments
	/// * `key` - The symmetric encryption key
	/// * `ciphertext` - Data to decrypt (may include IV/nonce)
	///
	/// # Returns
	/// Decrypted plaintext data
	fn decrypt<K: AsRef<[u8]>, C: AsRef<[u8]>>(&self, key: K, ciphertext: C) -> Result<Vec<u8>, CryptoError>;

	/// Get the expected key size in bytes
	fn key_size(&self) -> usize;

	/// Get the block size in bytes (for block ciphers)
	fn block_size(&self) -> usize;
}

/// Asymmetric encryption operations.
///
/// This trait provides encryption functionality for asymmetric encryption
/// schemes like ECIES that do not follow the AEAD pattern but provide
/// authenticated encryption.
pub trait AsymmetricEncryption {
	/// Encrypt data using asymmetric encryption
	///
	/// This typically uses the public key for encryption.
	fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Vec<u8>, CryptoError>;

	/// Decrypt data using asymmetric encryption
	///
	/// This typically uses the private key for decryption.
	fn decrypt<C: AsRef<[u8]>>(&self, cipher_text: C) -> Result<Vec<u8>, CryptoError>;
}

/// Key generation operations for cryptographic keys.
///
/// This trait provides random key generation functionality for cryptographic
/// algorithms. Implementations should use cryptographically secure random
/// number generators.
pub trait KeyGeneration {
	/// The error type returned by key generation
	type Error;

	/// Generate a new random private key
	fn generate_random() -> Result<Self, Self::Error>
	where
		Self: Sized;
}

/// Nonce generation for cryptographic operations.
///
/// This trait provides a unified interface for generating nonces across
/// different cryptographic algorithms that require them.
pub trait NonceGeneration {
	/// The type of nonce this algorithm uses
	type Nonce: AsRef<[u8]>;

	/// Generate a cryptographically secure random nonce
	///
	/// # Returns
	/// A new random nonce suitable for use with this algorithm
	fn generate_nonce() -> Self::Nonce;

	/// Get the expected nonce size in bytes
	fn nonce_size() -> usize;
}

/// Key exchange operations for asymmetric encryption.
///
/// This trait provides key agreement/exchange functionality for asymmetric
/// encryption schemes like ECDH, X25519, etc.
pub trait KeyExchange {
	/// The public key type for key exchange
	type PublicKey;
	/// The shared secret type produced by key exchange
	type SharedSecret: AsRef<[u8]>;

	/// Perform ECDH key exchange with another public key.
	///
	/// # Arguments
	/// * `other_public_key` - The other party's public key
	///
	/// # Returns
	/// The shared secret as raw bytes
	fn ecdh(&self, other_public_key: &Self::PublicKey) -> Result<Self::SharedSecret, CryptoError>;

	/// Perform key exchange with another public key from bytes.
	///
	/// # Arguments
	/// * `their_public_key` - The other party's public key as bytes
	///
	/// # Returns
	/// The shared secret as raw bytes
	fn key_exchange<K: AsRef<[u8]>>(&self, their_public_key: K) -> Result<Self::SharedSecret, CryptoError>;

	/// Derive an AEAD key from the shared secret.
	///
	/// # Arguments
	/// * `shared_secret` - The shared secret produced by key exchange
	///
	/// # Returns
	/// An AEAD key suitable for use with the specified algorithm
	fn derive_aead_key<A>(&self, shared_secret: &Self::SharedSecret) -> Result<A, CryptoError>
	where
		A: KeyInit;
}
