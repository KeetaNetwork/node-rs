use hex::FromHexError;
use keetanet_error::KeetaNetError;
use snafu::Snafu;
use strum_macros::AsRefStr;

use crypto::error::CryptoError;
use utils::impl_variant_error_from;

/// Account error types
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
	pub fn error_code(&self) -> String {
		format!("ACCOUNT_{}", self.as_ref())
	}
}

impl From<AccountError> for KeetaNetError {
	fn from(err: AccountError) -> Self {
		KeetaNetError::Code { code: err.error_code(), message: err.to_string() }
	}
}

impl_variant_error_from!(AccountError, {
	FromHexError => InvalidConstruction,
	crypto::operations::SignatureError => InvalidConstruction,
});

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

impl From<AccountError> for crypto::operations::SignatureError {
	fn from(_err: AccountError) -> Self {
		crypto::operations::SignatureError::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use utils::{test_error_from_conversions, test_error_variants};

	test_error_variants! {
		test_account_error_variants, [
			AccountError::InvalidPrefix,
			AccountError::InvalidKeyType,
			AccountError::PassphraseWeak,
			AccountError::InvalidConstruction,
			AccountError::EncryptionNotSupported,
		]
	}

	test_error_from_conversions! {
		test_all_from_implementations, AccountError, [
			// FromHexError conversion
			hex::FromHexError::InvalidHexCharacter { c: 'z', index: 0 },
			hex::FromHexError::OddLength,
			hex::FromHexError::InvalidStringLength,

			// SignatureError conversion
			crypto::operations::SignatureError::new(),

			// Sample CryptoError conversions
			CryptoError::InvalidKeyMaterial,
			CryptoError::InvalidPublicKey,
			CryptoError::InvalidLength { message: "test".to_string() },
			CryptoError::UnsupportedAlgorithm { algorithm: "test".to_string() },
			CryptoError::EncryptionNotSupported,
		]
	}

	#[test]
	fn test_error_code_format() {
		let error = AccountError::InvalidPrefix;
		// Test error code format (using strum AsRefStr)
		assert_eq!(error.error_code(), "ACCOUNT_INVALID_PREFIX");
		// Test strum serialization directly
		assert_eq!(error.as_ref(), "INVALID_PREFIX");
	}

	#[test]
	fn test_from_keeta_net_error() {
		let account_error = AccountError::InvalidPrefix;
		let keeta_error: KeetaNetError = account_error.into();
		assert!(matches!(keeta_error, KeetaNetError::Code { 
			code,
			message: _
		} if code == "ACCOUNT_INVALID_PREFIX"));

		let account_error2 = AccountError::PassphraseWeak;
		let keeta_error2: KeetaNetError = account_error2.into();
		assert!(matches!(keeta_error2, KeetaNetError::Code { 
			code,
			message: _
		} if code == "ACCOUNT_PASSPHRASE_WEAK"));
	}
}
