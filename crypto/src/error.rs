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
}
