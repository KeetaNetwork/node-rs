use keetanetwork_utils::impl_variant_error_from;
use snafu::Snafu;

// Re-export errors
#[cfg(feature = "encryption")]
pub use aead::Error as AeadError;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Snafu, Clone, PartialEq)]
#[snafu(visibility(pub))]
pub enum CryptoError {
	/// Invalid key material provided
	#[snafu(display("Invalid key material"))]
	InvalidKeyMaterial,
	/// Key derivation failed
	#[snafu(display("Key derivation failed"))]
	KeyDerivationFailed,
	/// Invalid public key format
	#[snafu(display("Invalid public key format"))]
	InvalidPublicKey,
	/// Invalid private key format
	#[snafu(display("Invalid private key format"))]
	InvalidPrivateKey,
	/// Signature verification failed
	#[snafu(display("Signature verification failed"))]
	SignatureVerificationFailed,
	/// Generic signature error
	#[snafu(display("Signature error"))]
	SignatureError,
	/// Unsupported algorithm
	#[snafu(display("Unsupported algorithm: {algorithm}"))]
	UnsupportedAlgorithm { algorithm: String },
	/// Internal cryptographic error
	#[snafu(display("Internal cryptographic error: {message}"))]
	InternalError { message: String },
	/// Invalid length specified
	#[snafu(display("Invalid length specified: {message}"))]
	InvalidLength { message: String },
	/// Invalid input provided
	#[snafu(display("Invalid input provided"))]
	InvalidInput,
	/// Encryption operation failed
	#[snafu(display("Encryption failed"))]
	EncryptionFailed,
	/// Decryption operation failed
	#[snafu(display("Decryption failed"))]
	DecryptionFailed,
	/// Invalid operation for this key type
	#[snafu(display("Invalid operation for this key type"))]
	InvalidOperation,
	/// Invalid key size provided
	#[snafu(display("Invalid key size provided"))]
	InvalidKeySize,
	/// Invalid IV size provided
	#[snafu(display("Invalid IV size provided"))]
	InvalidIvSize,
	/// Encryption not supported for this algorithm
	#[snafu(display("Encryption not supported for this algorithm"))]
	EncryptionNotSupported,
}

// Use macros for simple variant mappings
impl_variant_error_from!(CryptoError, {
	hkdf::InvalidLength => KeyDerivationFailed,
	hkdf::InvalidPrkLength => KeyDerivationFailed,
});

#[cfg(feature = "encryption")]
impl From<rand_core::OsError> for CryptoError {
	fn from(error: rand_core::OsError) -> Self {
		CryptoError::InternalError { message: error.to_string() }
	}
}

#[cfg(feature = "encryption")]
impl_variant_error_from!(CryptoError, {
	cbc::cipher::InvalidLength => InvalidKeySize,
	cbc::cipher::inout::PadError => DecryptionFailed,
	cbc::cipher::inout::NotEqualError => DecryptionFailed,
	cbc::cipher::block_padding::UnpadError => DecryptionFailed,
});

#[cfg(feature = "encryption")]
keetanetwork_utils::impl_error_from_with_fields!(CryptoError, {
	AeadError => InternalError { message: |error: AeadError| error.to_string() }
});

#[cfg(feature = "signature")]
impl_variant_error_from!(CryptoError, {
	crate::operations::SignatureError => SignatureError,
});

#[cfg(feature = "signature")]
impl From<CryptoError> for crate::operations::SignatureError {
	fn from(_: CryptoError) -> Self {
		crate::operations::SignatureError::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_utils::{test_error_from_conversions, test_error_variants};

	#[cfg(feature = "encryption")]
	use crate::algorithms::aes_cbc::Aes256Cbc;
	#[cfg(feature = "encryption")]
	use crate::operations::encryption::SymmetricEncryption;
	#[cfg(feature = "encryption")]
	use aes::Aes256;
	#[cfg(feature = "encryption")]
	use cbc::cipher::KeyIvInit;
	#[cfg(feature = "encryption")]
	use cbc::Encryptor;

	// Test all error variants for basic properties
	test_error_variants! {
		test_all_error_variants, [
			CryptoError::InvalidKeyMaterial,
			CryptoError::KeyDerivationFailed,
			CryptoError::InvalidPublicKey,
			CryptoError::InvalidPrivateKey,
			CryptoError::SignatureVerificationFailed,
			CryptoError::SignatureError,
			CryptoError::UnsupportedAlgorithm { algorithm: "test".to_string() },
			CryptoError::InternalError { message: "test".to_string() },
			CryptoError::InvalidLength { message: "test".to_string() },
			CryptoError::InvalidInput,
			CryptoError::EncryptionFailed,
			CryptoError::DecryptionFailed,
			CryptoError::InvalidOperation,
			CryptoError::InvalidKeySize,
			CryptoError::InvalidIvSize,
			CryptoError::EncryptionNotSupported,
		]
	}

	// Test From conversions for HKDF errors
	test_error_from_conversions! {
		test_hkdf_error_conversions, CryptoError, [
			hkdf::InvalidLength,
			hkdf::InvalidPrkLength,
		]
	}

	#[cfg(feature = "encryption")]
	// Test From conversions for CBC cipher errors
	test_error_from_conversions! {
		test_cbc_error_conversions, CryptoError, [
			cbc::cipher::inout::PadError,
			cbc::cipher::inout::NotEqualError,
			cbc::cipher::block_padding::UnpadError,
		]
	}

	#[cfg(feature = "encryption")]
	// Test From conversions for AEAD errors
	test_error_from_conversions! {
		test_aead_error_conversions, CryptoError, [
			AeadError,
		]
	}

	#[cfg(feature = "signature")]
	// Test From conversions for signature errors
	test_error_from_conversions! {
		test_signature_error_conversions, CryptoError, [
			crate::operations::SignatureError::new(),
		]
	}

	#[cfg(feature = "signature")]
	test_error_from_conversions! {
		test_crypto_error_to_signature_error, crate::operations::SignatureError, [
			CryptoError::SignatureError,
		]
	}

	// Business logic tests that demonstrate actual error scenarios
	#[cfg(feature = "encryption")]
	#[test]
	fn test_cbc_cipher_invalid_length_conversion() {
		// Create an InvalidLength error by trying to create a CBC cipher with wrong key size
		let wrong_key = [0u8; 16]; // AES-256 needs 32 bytes, not 16
		let iv = [0u8; 16]; // Valid IV size

		let result = Encryptor::<Aes256>::new_from_slices(&wrong_key, &iv);
		assert!(result.is_err());

		let cbc_error = result.unwrap_err();
		let crypto_error: CryptoError = cbc_error.into();
		assert_eq!(crypto_error, CryptoError::InvalidKeySize);
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_padding_errors_conversion() {
		let cipher = Aes256Cbc;
		let key = [0u8; 32]; // Valid key size
		let invalid_ciphertext = [0u8; 15]; // Invalid size (not multiple of 16)

		let result = cipher.decrypt(key, invalid_ciphertext);
		assert!(result.is_err());
		// This should result in a DecryptionFailed error
		assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
	}
}
