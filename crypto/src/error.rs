use snafu::Snafu;

#[cfg(feature = "x509")]
use crate::CertificateError;

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
	/// Unsupported algorithm
	#[snafu(display("Unsupported algorithm: {algorithm}"))]
	UnsupportedAlgorithm { algorithm: String },
	/// Internal cryptographic error
	#[snafu(display("Internal cryptographic error: {message}"))]
	InternalError { message: String },
	/// Invalid length specified
	#[snafu(display("Invalid length specified"))]
	InvalidLength,
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
	/// Certificate operation error
	#[cfg(feature = "x509")]
	#[snafu(display("Certificate error: {source}"))]
	CertificateError { source: CertificateError },
}

impl From<hkdf::InvalidLength> for CryptoError {
	fn from(_: hkdf::InvalidLength) -> Self {
		CryptoError::KeyDerivationFailed
	}
}

impl From<hkdf::InvalidPrkLength> for CryptoError {
	fn from(_: hkdf::InvalidPrkLength) -> Self {
		CryptoError::KeyDerivationFailed
	}
}

#[cfg(feature = "encryption")]
impl From<cbc::cipher::InvalidLength> for CryptoError {
	fn from(_: cbc::cipher::InvalidLength) -> Self {
		CryptoError::InvalidKeySize
	}
}

#[cfg(feature = "encryption")]
impl From<cbc::cipher::inout::PadError> for CryptoError {
	fn from(_: cbc::cipher::inout::PadError) -> Self {
		CryptoError::DecryptionFailed
	}
}

#[cfg(feature = "encryption")]
impl From<cbc::cipher::inout::NotEqualError> for CryptoError {
	fn from(_: cbc::cipher::inout::NotEqualError) -> Self {
		CryptoError::DecryptionFailed
	}
}

#[cfg(feature = "encryption")]
impl From<cbc::cipher::block_padding::UnpadError> for CryptoError {
	fn from(_: cbc::cipher::block_padding::UnpadError) -> Self {
		CryptoError::DecryptionFailed
	}
}

#[cfg(feature = "x509")]
impl From<crate::x509::error::CertificateError> for CryptoError {
	fn from(source: crate::x509::error::CertificateError) -> Self {
		CryptoError::CertificateError { source }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "encryption")]
	use crate::algorithms::aes_cbc::Aes256Cbc;
	#[cfg(feature = "encryption")]
	use crate::operations::encryption::SymmetricEncryption;
	#[cfg(feature = "x509")]
	use crate::x509::error::CertificateError;
	#[cfg(feature = "encryption")]
	use aes::Aes256;
	#[cfg(feature = "encryption")]
	use cbc::cipher::KeyIvInit;
	#[cfg(feature = "encryption")]
	use cbc::Encryptor;

	#[test]
	fn test_crypto_error_unsupported_algorithm() {
		let error = CryptoError::UnsupportedAlgorithm { algorithm: "test-algo".to_string() };
		assert_eq!(error.to_string(), "Unsupported algorithm: test-algo");
	}

	#[test]
	fn test_crypto_error_internal_error() {
		let error = CryptoError::InternalError { message: "test message".to_string() };
		assert_eq!(error.to_string(), "Internal cryptographic error: test message");
	}

	#[test]
	fn test_hkdf_invalid_length_conversion() {
		let hkdf_error = hkdf::InvalidLength;
		let crypto_error: CryptoError = hkdf_error.into();
		assert_eq!(crypto_error, CryptoError::KeyDerivationFailed);
	}

	#[test]
	fn test_hkdf_invalid_prk_length_conversion() {
		let hkdf_error = hkdf::InvalidPrkLength;
		let crypto_error: CryptoError = hkdf_error.into();
		assert_eq!(crypto_error, CryptoError::KeyDerivationFailed);
	}

	#[test]
	fn test_crypto_error_clone_and_partial_eq() {
		let error1 = CryptoError::InvalidKeySize;
		let error2 = error1.clone();
		assert_eq!(error1, error2);

		let error3 = CryptoError::DecryptionFailed;
		assert_ne!(error1, error3);
	}

	#[test]
	fn test_crypto_error_debug() {
		let error = CryptoError::InvalidKeySize;
		let debug_str = format!("{error:?}");
		assert!(debug_str.contains("InvalidKeySize"));
	}

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

		let result = cipher.decrypt(&key, &invalid_ciphertext);
		assert!(result.is_err());
		// This should result in a DecryptionFailed error
		assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
	}

	#[cfg(feature = "encryption")]
	#[test]
	fn test_cbc_error_conversions() {
		// Test PadError conversion
		let pad_error = cbc::cipher::inout::PadError;
		let crypto_error: CryptoError = pad_error.into();
		assert_eq!(crypto_error, CryptoError::DecryptionFailed);

		// Test NotEqualError conversion
		let not_equal_error = cbc::cipher::inout::NotEqualError;
		let crypto_error: CryptoError = not_equal_error.into();
		assert_eq!(crypto_error, CryptoError::DecryptionFailed);

		// Test UnpadError conversion
		let unpad_error = cbc::cipher::block_padding::UnpadError;
		let crypto_error: CryptoError = unpad_error.into();
		assert_eq!(crypto_error, CryptoError::DecryptionFailed);
	}

	#[cfg(feature = "x509")]
	#[test]
	fn test_certificate_error_conversion() {
		let cert_error = CertificateError::InvalidCertificate;
		let crypto_error: CryptoError = cert_error.clone().into();

		// Test that the conversion creates the correct variant
		assert_eq!(crypto_error, CryptoError::CertificateError { source: cert_error });
	}

	#[cfg(feature = "x509")]
	#[test]
	fn test_certificate_error_display() {
		let cert_error = CertificateError::ValidationFailed { reason: "expired".to_string() };
		assert_eq!(cert_error.to_string(), "Certificate validation failed: expired");

		let crypto_error: CryptoError = cert_error.into();
		assert!(crypto_error.to_string().contains("Certificate error:"));
		assert!(crypto_error.to_string().contains("Certificate validation failed: expired"));
	}
}
