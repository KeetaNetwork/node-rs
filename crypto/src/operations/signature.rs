//! Digital signature operations using RustCrypto patterns.
//!
//! This module provides idiomatic traits and types for cryptographic signing
//! and verification operations, leveraging the RustCrypto ecosystem.

use crate::algorithms::CryptoAlgorithm;
use crate::error::CryptoError;

// Re-export key RustCrypto signature traits for easier use
pub use signature::{DigestSigner, DigestVerifier, Error as SignatureError, RandomizedSigner, Signer, Verifier};

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

	/// Get the formatted public key string
	fn public_key_string(&self) -> Result<String, CryptoError>;
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

#[cfg(test)]
mod tests {
	use crate::algorithms::CryptoAlgorithm;
	use crate::Algorithm;

	use super::*;
	use signature::{Signer, Verifier};

	/// Mock implementations for testing
	/// Note: There are algorithm-specific tests for real implementations
	struct MockSigner;
	struct MockVerifier;

	impl CryptoAlgorithm for MockSigner {
		fn get_algorithm(&self) -> Algorithm {
			Algorithm::Ed25519
		}
	}

	impl CryptoAlgorithm for MockVerifier {
		fn get_algorithm(&self) -> Algorithm {
			Algorithm::Ed25519
		}
	}

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
		fn try_sign(&self, _msg: &[u8]) -> Result<MockSignature, SignatureError> {
			Ok(MockSignature([1u8; 32]))
		}
	}

	impl CryptoSigner<MockSignature> for MockSigner {
		fn has_private_key(&self) -> bool {
			true
		}
	}

	impl CryptoSignerWithOptions<MockSignature> for MockSigner {
		fn sign_with_options<T: AsRef<[u8]>>(
			&self,
			message: T,
			options: SigningOptions,
		) -> Result<MockSignature, SignatureError> {
			// Mock implementation: use different signature based on options
			let message = message.as_ref();
			let mut signature_bytes = [1u8; 32];

			if options.raw {
				signature_bytes[0] = 0xAA; // Mark as raw
			}

			if options.for_cert {
				signature_bytes[1] = 0xCC; // Mark as cert
			}

			// Include message length in signature for test validation
			if !message.is_empty() {
				signature_bytes[2] = (message.len() % 256) as u8;
			}

			Ok(MockSignature(signature_bytes))
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

	impl CryptoVerifierWithOptions<MockSignature> for MockVerifier {
		fn verify_with_options<T: AsRef<[u8]>>(
			&self,
			message: T,
			signature: &MockSignature,
			options: SigningOptions,
		) -> Result<(), SignatureError> {
			// Mock implementation: validate signature was created with matching options
			let message = message.as_ref();
			let sig_bytes = signature.as_ref();

			// Check if signature was marked for raw processing
			let expected_raw_marker = if options.raw {
				0xAA
			} else {
				0x01
			};
			if sig_bytes[0] != expected_raw_marker {
				return Err(signature::Error::new());
			}

			// Check if signature was marked for cert processing
			let expected_cert_marker = if options.for_cert {
				0xCC
			} else {
				0x01
			};
			if sig_bytes[1] != expected_cert_marker {
				return Err(signature::Error::new());
			}

			// Validate message length matches what was encoded in signature
			if !message.is_empty() {
				let expected_len = (message.len() % 256) as u8;
				if sig_bytes[2] != expected_len {
					return Err(signature::Error::new());
				}
			}

			Ok(())
		}
	}

	// Mock implementations that can fail for error testing
	struct FailingMockVerifier;

	impl CryptoAlgorithm for FailingMockVerifier {
		fn get_algorithm(&self) -> Algorithm {
			Algorithm::Ed25519
		}
	}

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
		// Test CryptoSigner trait method
		let signer = MockSigner;
		assert!(signer.has_private_key());

		// Test getting the algorithm
		let algorithm = signer.get_algorithm();
		assert_eq!(algorithm, Algorithm::Ed25519);

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
		let algorithm = verifier.get_algorithm();
		assert_eq!(algorithm, Algorithm::Ed25519);

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

		let algorithm = failing_verifier.get_algorithm();
		assert_eq!(algorithm, Algorithm::Ed25519);

		// Test verification failure
		let signature = signer.try_sign(message).unwrap();
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

	#[test]
	fn test_signing_options() {
		// Test default options
		let default_opts = SigningOptions::default();
		assert!(!default_opts.raw);
		assert!(!default_opts.for_cert);

		// Test raw options
		let raw_opts = SigningOptions::raw();
		assert!(raw_opts.raw);
		assert!(!raw_opts.for_cert);

		// Test cert options
		let cert_opts = SigningOptions::for_cert();
		assert!(!cert_opts.raw);
		assert!(cert_opts.for_cert);

		// Test custom options
		let custom_opts = SigningOptions { raw: true, for_cert: true };
		assert!(custom_opts.raw);
		assert!(custom_opts.for_cert);
	}

	#[test]
	fn test_crypto_signer_with_options() {
		let signer = MockSigner;
		let message = b"test message for options";

		// Test with default options
		let default_opts = SigningOptions::default();
		let signature = signer.sign_with_options(message, default_opts).unwrap();
		let sig_bytes = signature.as_ref();
		assert_eq!(sig_bytes[0], 0x01); // Not raw
		assert_eq!(sig_bytes[1], 0x01); // Not cert
		assert_eq!(sig_bytes[2], (message.len() % 256) as u8); // Message length

		// Test with raw options
		let raw_opts = SigningOptions::raw();
		let signature = signer.sign_with_options(message, raw_opts).unwrap();
		let sig_bytes = signature.as_ref();
		assert_eq!(sig_bytes[0], 0xAA); // Raw marker
		assert_eq!(sig_bytes[1], 0x01); // Not cert
		assert_eq!(sig_bytes[2], (message.len() % 256) as u8); // Message length

		// Test with cert options
		let cert_opts = SigningOptions::for_cert();
		let signature = signer.sign_with_options(message, cert_opts).unwrap();
		let sig_bytes = signature.as_ref();
		assert_eq!(sig_bytes[0], 0x01); // Not raw
		assert_eq!(sig_bytes[1], 0xCC); // Cert marker
		assert_eq!(sig_bytes[2], (message.len() % 256) as u8); // Message length

		// Test with both raw and cert options
		let both_opts = SigningOptions { raw: true, for_cert: true };
		let signature = signer.sign_with_options(message, both_opts).unwrap();
		let sig_bytes = signature.as_ref();
		assert_eq!(sig_bytes[0], 0xAA); // Raw marker
		assert_eq!(sig_bytes[1], 0xCC); // Cert marker
		assert_eq!(sig_bytes[2], (message.len() % 256) as u8); // Message length
	}

	#[test]
	fn test_crypto_verifier_with_options() {
		let signer = MockSigner;
		let verifier = MockVerifier;
		let message = b"test message for verification options";

		// Test successful verification with matching options
		let default_options = SigningOptions::default();
		let signature = signer.sign_with_options(message, default_options).unwrap();
		assert!(verifier
			.verify_with_options(message, &signature, default_options)
			.is_ok());

		let raw_options = SigningOptions::raw();
		let signature = signer.sign_with_options(message, raw_options).unwrap();
		assert!(verifier
			.verify_with_options(message, &signature, raw_options)
			.is_ok());

		let cert_options = SigningOptions::for_cert();
		let signature = signer.sign_with_options(message, cert_options).unwrap();
		assert!(verifier
			.verify_with_options(message, &signature, cert_options)
			.is_ok());

		// Test verification failure with mismatched options
		let signature_raw = signer.sign_with_options(message, raw_options).unwrap();
		assert!(verifier
			.verify_with_options(message, &signature_raw, default_options)
			.is_err());

		let signature_cert = signer.sign_with_options(message, cert_options).unwrap();
		assert!(verifier
			.verify_with_options(message, &signature_cert, default_options)
			.is_err());

		// Test verification failure with wrong message
		let other_message = b"different message";
		let signature = signer.sign_with_options(message, default_options).unwrap();
		assert!(verifier
			.verify_with_options(other_message, &signature, default_options)
			.is_err());
	}

	#[test]
	fn test_extended_traits_with_ref_compatibility() {
		let signer = MockSigner;
		let verifier = MockVerifier;
		let options = SigningOptions::default();

		let message_vec = b"test message".to_vec();
		let signature = signer.sign_with_options(&message_vec, options).unwrap();
		assert_eq!(signature.as_ref().len(), 32);

		let verification = verifier.verify_with_options(&message_vec, &signature, options);
		assert!(verification.is_ok());
	}
}
