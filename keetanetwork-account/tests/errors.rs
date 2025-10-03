use keetanetwork_account::AccountError;

// Test cases for error code compatibility with TypeScript
const ERROR_CODE_TEST_CASES: &[(AccountError, &str)] = &[
	(AccountError::InvalidPrefix, "ACCOUNT_INVALID_PREFIX"),
	(AccountError::InvalidKeyType, "ACCOUNT_INVALID_KEYTYPE"),
	(AccountError::InvalidKeyTypeExternal, "ACCOUNT_INVALID_KEYTYPE_EXTERNAL"),
	(AccountError::InvalidX509Certificate, "ACCOUNT_INVALID_X509_CERTIFICATE"),
	(AccountError::PassphraseWeak, "ACCOUNT_PASSPHRASE_WEAK"),
	(AccountError::InvalidConstruction, "ACCOUNT_INVALID_CONSTRUCTION"),
	(AccountError::NoIdentifierSign, "ACCOUNT_NO_IDENTIFIER_SIGN"),
	(AccountError::NoIdentifierVerify, "ACCOUNT_NO_IDENTIFIER_VERIFY"),
	(AccountError::NoIdentifierVerifyCertificate, "ACCOUNT_NO_IDENTIFIER_VERIFY_CERTIFICATE"),
	(AccountError::InvalidIdentifierConstruction, "ACCOUNT_INVALID_IDENTIFIER_CONSTRUCTION"),
	(AccountError::SeedIndexUndefined, "ACCOUNT_SEED_INDEX_UNDEFINED"),
	(AccountError::SeedIndexNegative, "ACCOUNT_SEED_INDEX_NEGATIVE"),
	(AccountError::SeedIndexNotInt, "ACCOUNT_SEED_INDEX_NOT_INT"),
	(AccountError::SeedIndexTooLarge, "ACCOUNT_SEED_INDEX_TOO_LARGE"),
	(AccountError::EncryptionNotSupported, "ACCOUNT_ENCRYPTION_NOT_SUPPORTED"),
];

#[test]
fn test_error_codes_compatibility() {
	for (error, expected_code) in ERROR_CODE_TEST_CASES {
		assert_eq!(error.error_code(), *expected_code);
	}
}
