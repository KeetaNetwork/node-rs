use hex::FromHexError;
use keetanet_error::KeetaNetError;
use strum_macros::AsRefStr;

use crypto::CryptoError;

#[derive(Debug, AsRefStr, Clone, PartialEq, Eq)]
pub enum AccountError {
	#[strum(serialize = "INVALID_PREFIX")]
	InvalidPrefix,
	#[strum(serialize = "INVALID_KEYTYPE")]
	InvalidKeyType,
	#[strum(serialize = "INVALID_KEYTYPE_EXTERNAL")]
	InvalidKeyTypeExternal,
	#[strum(serialize = "INVALID_X509_CERTIFICATE")]
	InvalidX509Certificate,
	#[strum(serialize = "PASSPHRASE_WEAK")]
	PassphraseWeak,
	#[strum(serialize = "INVALID_CONSTRUCTION")]
	InvalidConstruction,
	#[strum(serialize = "NO_IDENTIFIER_SIGN")]
	NoIdentifierSign,
	#[strum(serialize = "NO_IDENTIFIER_VERIFY")]
	NoIdentifierVerify,
	#[strum(serialize = "NO_IDENTIFIER_VERIFY_CERTIFICATE")]
	NoIdentifierVerifyCertificate,
	#[strum(serialize = "INVALID_IDENTIFIER_CONSTRUCTION")]
	InvalidIdentifierConstruction,
	#[strum(serialize = "SEED_INDEX_UNDEFINED")]
	SeedIndexUndefined,
	#[strum(serialize = "SEED_INDEX_NEGATIVE")]
	SeedIndexNegative,
	#[strum(serialize = "SEED_INDEX_NOT_INT")]
	SeedIndexNotInt,
	#[strum(serialize = "SEED_INDEX_TOO_LARGE")]
	SeedIndexTooLarge,
	#[strum(serialize = "ENCRYPTION_NOT_SUPPORTED")]
	EncryptionNotSupported,
}

impl std::fmt::Display for AccountError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{self:?}")
	}
}

impl From<AccountError> for KeetaNetError {
	fn from(err: AccountError) -> Self {
		KeetaNetError::Code { code: err.as_ref().to_string(), message: format!("{err:?}") }
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
			CryptoError::InvalidLength => AccountError::InvalidConstruction,
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
		assert_eq!(display_string, "InvalidPrefix");
	}

	#[test]
	fn test_from_keeta_net_error() {
		// Test conversion from AccountError to KeetaNetError
		let account_error = AccountError::InvalidPrefix;
		let keeta_error: KeetaNetError = account_error.into();
		assert!(matches!(keeta_error, KeetaNetError::Code { 
			code, 
			message 
		} if code == "INVALID_PREFIX" && message == "InvalidPrefix"));

		// Test another error type
		let account_error2 = AccountError::PassphraseWeak;
		let keeta_error2: KeetaNetError = account_error2.into();
		assert!(matches!(keeta_error2, KeetaNetError::Code { 
			code, 
			message 
		} if code == "PASSPHRASE_WEAK" && message == "PassphraseWeak"));
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
			CryptoError::InvalidLength,
			CryptoError::SignatureVerificationFailed,
			CryptoError::SignatureError,
			CryptoError::EncryptionFailed,
			CryptoError::DecryptionFailed,
			CryptoError::InvalidOperation,
			CryptoError::InternalError { message: "test".to_string() },
			CryptoError::InvalidIvSize,
		];

		for crypto_error in invalid_construction_variants {
			assert_eq!(AccountError::from(crypto_error), AccountError::InvalidConstruction);
		}
	}
}
