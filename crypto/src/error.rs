use snafu::Snafu;

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

impl From<hkdf::InvalidLength> for CryptoError {
	fn from(_: hkdf::InvalidLength) -> Self {
		CryptoError::KeyDerivationFailed
	}
}
