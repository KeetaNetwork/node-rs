//! Cryptographic primitives for KeetaNet node
//!
//! This crate provides algorithm-agnostic cryptographic operations including:
//! - Key generation and derivation
//! - Public key formatting with checksums
//! - Support for multiple algorithms (secp256k1, Ed25519)

pub mod algorithms;
pub mod bigint;
pub mod constants;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod operations;
pub mod prelude;
pub mod utils;

// Re-exports from external libraries
pub use secrecy::{ExposeSecret, SecretBox};

// Re-exports for convenience
pub use algorithms::{Algorithm, KeyDerivation, PrivateKey, PublicKey};
pub use error::CryptoError;

// Hash functions
pub use hash::{default_hash_algorithm, default_hash_algorithm_length, hash, hash_array, hash_default, HashAlgorithm};

// Algorithm-agnostic key types
pub use algorithms::{AnyPrivateKey, AnyPublicKey, CryptoAlgorithm};

// Algorithm-agnostic signature type
#[cfg(feature = "signature")]
pub use algorithms::AnySignature;

// Specific algorithm implementations
pub use algorithms::ed25519::{
	ed25519_to_x25519_private, ed25519_to_x25519_public, Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey,
	X25519PrivateKey, X25519PublicKey,
};
pub use algorithms::secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};
pub use algorithms::secp256r1::{Secp256r1Derivation, Secp256r1PrivateKey, Secp256r1PublicKey};

// Signature types when signature feature is enabled
#[cfg(feature = "signature")]
pub use algorithms::{Ed25519Signature, Secp256k1Signature, Secp256r1Signature};

// Utility functions
pub use utils::{generate_random_passphrase, generate_random_seed, seed_from_passphrase};

// Keypair trait when signature feature is enabled
#[cfg(feature = "signature")]
pub use ::signature::Keypair;
#[cfg(feature = "signature")]
pub use operations::{
	CryptoSigner, CryptoSignerWithOptions, CryptoVerifier, CryptoVerifierWithOptions, SigningOptions,
};

// Signature types and crypto operations
#[cfg(feature = "encryption")]
pub use operations::KeyExchange;
#[cfg(feature = "encryption")]
pub use operations::{AsymmetricEncryption, CryptoAead};

/// Trait for converting types into their corresponding SecretBox versions.
pub trait IntoSecret<T: zeroize::Zeroize> {
	/// Convert the value into a SecretBox.
	fn into_secret(self) -> SecretBox<T>;
}

impl<T: zeroize::Zeroize> IntoSecret<Vec<T>> for Vec<T> {
	fn into_secret(self) -> SecretBox<Vec<T>> {
		SecretBox::new(Box::new(self))
	}
}

impl IntoSecret<[u8; 32]> for [u8; 32] {
	fn into_secret(self) -> SecretBox<[u8; 32]> {
		SecretBox::new(Box::new(self))
	}
}

impl IntoSecret<String> for String {
	fn into_secret(self) -> SecretBox<String> {
		SecretBox::new(Box::new(self))
	}
}

#[cfg(test)]
mod tests {
	use secrecy::ExposeSecret;

	use super::*;

	#[test]
	fn test_into_secret_implementations() {
		// Macro to test IntoSecret implementations
		macro_rules! test_into_secret {
			($test_name:ident, $input:expr, $secret_type:ty) => {
				let input = $input;
				let secret: SecretBox<$secret_type> = input.clone().into_secret();
				assert_eq!(*secret.expose_secret(), input);
			};
		}

		// Test data-driven cases
		test_into_secret!(seed, [1u8; 32], [u8; 32]);
		test_into_secret!(hex_seed, "deadbeef".to_string(), String);
		test_into_secret!(passphrase, vec!["word1".to_string(), "word2".to_string()], Vec<String>);
	}
}
