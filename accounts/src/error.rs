use hex::FromHexError;
use keetanet_error::KeetaNetError;
use snafu::Snafu;
use strum_macros::AsRefStr;

use crypto::CryptoError;

/// Account error types that match TypeScript AccountErrorCode format
#[derive(Debug, Snafu, AsRefStr, Clone, PartialEq, Eq)]
#[snafu(visibility(pub))]
pub enum AccountError {
	#[snafu(display("Invalid account prefix"))]
	#[strum(serialize = "INVALID_PREFIX")]
	InvalidPrefix,

	#[snafu(display("Invalid key type"))]
	#[strum(serialize = "INVALID_KEYTYPE")]
	InvalidKeyType,

	#[snafu(display("Invalid external key type"))]
	#[strum(serialize = "INVALID_KEYTYPE_EXTERNAL")]
	InvalidKeyTypeExternal,

	#[snafu(display("Invalid X.509 certificate"))]
	#[strum(serialize = "INVALID_X509_CERTIFICATE")]
	InvalidX509Certificate,

	#[snafu(display("Passphrase is too weak"))]
	#[strum(serialize = "PASSPHRASE_WEAK")]
	PassphraseWeak,

	#[snafu(display("Invalid construction parameters"))]
	#[strum(serialize = "INVALID_CONSTRUCTION")]
	InvalidConstruction,

	#[snafu(display("Identifier accounts cannot sign data"))]
	#[strum(serialize = "NO_IDENTIFIER_SIGN")]
	NoIdentifierSign,

	#[snafu(display("Identifier accounts cannot verify signatures"))]
	#[strum(serialize = "NO_IDENTIFIER_VERIFY")]
	NoIdentifierVerify,

	#[snafu(display("Identifier accounts cannot verify certificates"))]
	#[strum(serialize = "NO_IDENTIFIER_VERIFY_CERTIFICATE")]
	NoIdentifierVerifyCertificate,

	#[snafu(display("Invalid identifier construction"))]
	#[strum(serialize = "INVALID_IDENTIFIER_CONSTRUCTION")]
	InvalidIdentifierConstruction,

	#[snafu(display("Seed index is undefined"))]
	#[strum(serialize = "SEED_INDEX_UNDEFINED")]
	SeedIndexUndefined,

	#[snafu(display("Seed index cannot be negative"))]
	#[strum(serialize = "SEED_INDEX_NEGATIVE")]
	SeedIndexNegative,

	#[snafu(display("Seed index must be an integer"))]
	#[strum(serialize = "SEED_INDEX_NOT_INT")]
	SeedIndexNotInt,

	#[snafu(display("Seed index is too large"))]
	#[strum(serialize = "SEED_INDEX_TOO_LARGE")]
	SeedIndexTooLarge,

	#[snafu(display("Encryption is not supported for this key type"))]
	#[strum(serialize = "ENCRYPTION_NOT_SUPPORTED")]
	EncryptionNotSupported,
}

impl AccountError {
	/// Get the error code in TypeScript-compatible format (ACCOUNT_${variant})
	pub fn error_code(&self) -> String {
		format!("ACCOUNT_{}", self.as_ref())
	}
}

impl From<AccountError> for KeetaNetError {
	fn from(err: AccountError) -> Self {
		KeetaNetError::Code { code: err.error_code(), message: err.to_string() }
	}
}

impl From<FromHexError> for AccountError {
	fn from(_err: FromHexError) -> Self {
		AccountError::InvalidConstruction
	}
}

impl From<CryptoError> for AccountError {
	fn from(err: CryptoError) -> Self {
		match err {
			CryptoError::InvalidKeyMaterial => AccountError::InvalidConstruction,
			CryptoError::KeyDerivationFailed => AccountError::InvalidConstruction,
			CryptoError::InvalidPrivateKey => AccountError::InvalidConstruction,
			CryptoError::InvalidPublicKey => AccountError::InvalidPrefix,
			CryptoError::InvalidLength { .. } => AccountError::PassphraseWeak,
			CryptoError::InvalidInput => AccountError::PassphraseWeak,
			CryptoError::UnsupportedAlgorithm { .. } => AccountError::InvalidKeyType,
			CryptoError::SignatureVerificationFailed => AccountError::InvalidConstruction,
			CryptoError::SignatureError => AccountError::InvalidConstruction,
			CryptoError::EncryptionFailed => AccountError::InvalidConstruction,
			CryptoError::DecryptionFailed => AccountError::InvalidConstruction,
			CryptoError::InvalidOperation => AccountError::InvalidConstruction,
			CryptoError::EncryptionNotSupported => AccountError::EncryptionNotSupported,
			CryptoError::InternalError { .. } => AccountError::InvalidConstruction,
			CryptoError::InvalidKeySize => AccountError::InvalidKeyType,
			CryptoError::InvalidIvSize => AccountError::InvalidConstruction,
		}
	}
}

impl From<crypto::operations::SignatureError> for AccountError {
	fn from(_err: crypto::operations::SignatureError) -> Self {
		AccountError::InvalidConstruction
	}
}

impl From<AccountError> for crypto::operations::SignatureError {
	fn from(_err: AccountError) -> Self {
		crypto::operations::SignatureError::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_account_error_formatting() {
		let error = AccountError::InvalidPrefix;
		let display_string = format!("{error}");
		assert_eq!(display_string, "Invalid account prefix");

		// Test error code format (using strum AsRefStr)
		assert_eq!(error.error_code(), "ACCOUNT_INVALID_PREFIX");
		// Test strum serialization directly
		assert_eq!(error.as_ref(), "INVALID_PREFIX");
	}

	#[test]
	fn test_from_keeta_net_error() {
		// Test conversion from AccountError to KeetaNetError
		let account_error = AccountError::InvalidPrefix;
		let keeta_error: KeetaNetError = account_error.into();
		assert!(matches!(keeta_error, KeetaNetError::Code { 
			code,
			message: _
		} if code == "ACCOUNT_INVALID_PREFIX"));

		// Test another error type
		let account_error2 = AccountError::PassphraseWeak;
		let keeta_error2: KeetaNetError = account_error2.into();
		assert!(matches!(keeta_error2, KeetaNetError::Code { 
			code,
			message: _
		} if code == "ACCOUNT_PASSPHRASE_WEAK"));
	}

	#[test]
	fn test_signature_error_conversion() {
		let signature_error = crypto::operations::SignatureError::new();
		let account_error: AccountError = signature_error.into();
		assert_eq!(account_error, AccountError::InvalidConstruction);

		// Test opposite conversion
		let account_error = AccountError::InvalidConstruction;
		let _signature_error: crypto::operations::SignatureError = account_error.into();
		// SignatureError does not implement PartialEq
	}

	#[test]
	fn test_crypto_error_conversion() {
		let invalid_construction_variants = vec![
			CryptoError::InvalidKeyMaterial,
			CryptoError::KeyDerivationFailed,
			CryptoError::InvalidPrivateKey,
			CryptoError::SignatureVerificationFailed,
			CryptoError::SignatureError,
			CryptoError::EncryptionFailed,
			CryptoError::DecryptionFailed,
			CryptoError::InvalidOperation,
			CryptoError::InternalError { message: "test".to_string() },
			CryptoError::InvalidIvSize,
		];

		for crypto_error in invalid_construction_variants {
			let account_error: AccountError = crypto_error.into();
			assert_eq!(account_error, AccountError::InvalidConstruction);
		}

		// Test that InvalidLength maps to PassphraseWeak
		let passphrase_weak_error: AccountError = CryptoError::InvalidLength { message: "test".to_string() }.into();
		assert_eq!(passphrase_weak_error, AccountError::PassphraseWeak);
	}
}
