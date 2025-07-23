use crypto::CryptoError;
use keetanet_error::KeetaNetError;
use strum_macros::AsRefStr;

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

impl From<AccountError> for KeetaNetError {
	fn from(err: AccountError) -> Self {
		KeetaNetError::Code { code: err.as_ref().to_string(), message: format!("{err:?}") }
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
			CryptoError::InternalError { .. } => AccountError::InvalidConstruction,
		}
	}
}
