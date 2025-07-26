//! Digital signature operations using RustCrypto patterns.
//!
//! This module provides idiomatic traits and types for cryptographic signing
//! and verification operations, leveraging the RustCrypto ecosystem.

use crate::error::CryptoError;

// Re-export key RustCrypto signature traits for easier use
pub use signature::{DigestSigner, DigestVerifier, Error, RandomizedSigner, Signer, Verifier};

// Re-export algorithm-specific signature types
pub use ed25519_dalek::Signature as Ed25519Signature;
pub use k256::ecdsa::Signature as Secp256k1Signature;
pub use p256::ecdsa::Signature as Secp256r1Signature;

/// Core cryptographic signing operations
///
/// This trait extends RustCrypto's Signer trait with additional functionality
/// needed for our cryptographic operations.
pub trait CryptoSigner<S>: Signer<S> {
	/// Check if this signer has access to the private key
	fn has_private_key(&self) -> bool;
}

/// Core cryptographic verification operations
///
/// This trait extends RustCrypto's Verifier trait with additional functionality
/// needed for our cryptographic operations.
pub trait CryptoVerifier<S>: Verifier<S> {
	/// Get the public key bytes for this verifier
	fn public_key_bytes(&self) -> Vec<u8>;

	/// Get the formatted public key string
	fn public_key_string(&self) -> Result<String, CryptoError>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use signature::{Signer, Verifier};

	// Mock implementations for testing
	// Note: There are algorithm-specific tests for real implementations
	struct MockSigner;
	struct MockVerifier;

	#[derive(Clone)]
	struct MockSignature([u8; 32]);

	impl signature::SignatureEncoding for MockSignature {
		type Repr = [u8; 32];
	}

	impl TryFrom<&[u8]> for MockSignature {
		type Error = signature::Error;

		fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
			if bytes.len() != 32 {
				return Err(signature::Error::new());
			}

			let mut arr = [0u8; 32];
			arr.copy_from_slice(bytes);

			Ok(MockSignature(arr))
		}
	}

	impl TryInto<[u8; 32]> for MockSignature {
		type Error = signature::Error;

		fn try_into(self) -> Result<[u8; 32], Self::Error> {
			Ok(self.0)
		}
	}

	impl AsRef<[u8]> for MockSignature {
		fn as_ref(&self) -> &[u8] {
			&self.0
		}
	}

	impl Signer<MockSignature> for MockSigner {
		fn try_sign(&self, _msg: &[u8]) -> Result<MockSignature, signature::Error> {
			Ok(MockSignature([1u8; 32]))
		}
	}

	impl CryptoSigner<MockSignature> for MockSigner {
		fn has_private_key(&self) -> bool {
			true
		}
	}

	impl Verifier<MockSignature> for MockVerifier {
		fn verify(&self, _msg: &[u8], _signature: &MockSignature) -> Result<(), signature::Error> {
			Ok(())
		}
	}

	impl CryptoVerifier<MockSignature> for MockVerifier {
		fn public_key_bytes(&self) -> Vec<u8> {
			vec![0x02, 0x03, 0x04, 0x05] // Mock 4-byte public key
		}

		fn public_key_string(&self) -> Result<String, CryptoError> {
			Ok("02030405".to_string())
		}
	}

	// Mock implementations that can fail for error testing
	struct FailingMockVerifier;

	impl Verifier<MockSignature> for FailingMockVerifier {
		fn verify(&self, _msg: &[u8], _signature: &MockSignature) -> Result<(), signature::Error> {
			Err(signature::Error::new())
		}
	}

	impl CryptoVerifier<MockSignature> for FailingMockVerifier {
		fn public_key_bytes(&self) -> Vec<u8> {
			vec![] // Empty bytes to test edge case
		}

		fn public_key_string(&self) -> Result<String, CryptoError> {
			Err(CryptoError::InvalidPublicKey) // Test error case
		}
	}

	#[test]
	fn test_crypto_signer_trait() {
		let signer = MockSigner;

		// Test CryptoSigner trait method
		assert!(signer.has_private_key());

		// Test signing a message
		let message = b"test message for signer trait";
		let signature = signer.try_sign(message).unwrap();
		assert_eq!(signature.as_ref(), &[1u8; 32]);
	}

	#[test]
	fn test_crypto_verifier_trait() {
		let verifier = MockVerifier;
		let signer = MockSigner;
		let message = b"test message for verifier trait";
		let signature = signer.try_sign(message).unwrap();

		// Test CryptoVerifier trait methods
		let public_key_bytes = verifier.public_key_bytes();
		assert_eq!(public_key_bytes, vec![0x02, 0x03, 0x04, 0x05]);

		let public_key_string = verifier.public_key_string().unwrap();
		assert_eq!(public_key_string, "02030405");

		// Test the verify method
		assert!(verifier.verify(message, &signature).is_ok());
	}

	#[test]
	fn test_crypto_verifier_error_handling() {
		let verifier = MockVerifier;

		// Test that public_key_string() succeeds for valid keys
		let result = verifier.public_key_string();
		assert!(result.is_ok());

		// Test that the string is valid hex
		let hex_string = result.unwrap();
		assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
		assert_eq!(hex_string.len(), 8); // 4 bytes * 2 hex chars
	}

	#[test]
	fn test_crypto_verifier_failure_cases() {
		let failing_verifier = FailingMockVerifier;
		let signer = MockSigner;
		let message = b"test message";
		let signature = signer.try_sign(message).unwrap();

		// Test verification failure
		assert!(failing_verifier.verify(message, &signature).is_err());

		// Test empty public key bytes
		let empty_bytes = failing_verifier.public_key_bytes();
		assert!(empty_bytes.is_empty());

		// Test public_key_string error
		let result = failing_verifier.public_key_string();
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidPublicKey));
	}

	#[test]
	fn test_mock_signature_encoding() {
		// Test MockSignature creation from bytes
		let bytes = [5u8; 32];
		let signature = MockSignature::try_from(&bytes[..]).unwrap();
		assert_eq!(signature.as_ref(), &bytes);

		// Test conversion back to array
		let array: [u8; 32] = signature.try_into().unwrap();
		assert_eq!(array, bytes);

		// Test error case with wrong length
		let wrong_bytes = [1u8; 16]; // Wrong length
		let result = MockSignature::try_from(&wrong_bytes[..]);
		assert!(result.is_err());
	}

	#[test]
	fn test_trait_object_compatibility() {
		// Test that our traits can be used as trait objects
		let signer = MockSigner;
		let verifier = MockVerifier;

		// Test CryptoSigner as trait object
		let crypto_signer: &dyn CryptoSigner<MockSignature> = &signer;
		assert!(crypto_signer.has_private_key());

		// Test CryptoVerifier as trait object
		let crypto_verifier: &dyn CryptoVerifier<MockSignature> = &verifier;
		assert!(!crypto_verifier.public_key_bytes().is_empty());
		assert!(crypto_verifier.public_key_string().is_ok());
	}
}
