//! Integration tests for account creation and public key parsing
use std::string::ToString;

use hex::{FromHex, ToHex};
use keetanetwork_account::{Account, GenericAccount, KeyPairType};
use keetanetwork_account::{Accountable, Keyable};
use keetanetwork_account::{KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
use keetanetwork_account::{KeyMULTISIG, KeyNETWORK, KeySTORAGE, KeyTOKEN};
use keetanetwork_crypto::prelude::IntoSecret;

mod common;
use common::*;

/// Invalid public keys for negative testing
const INVALID_PUBLIC_KEYS: &[&str] = &[
	// cspell:disable-next-line
	"keeta_cqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabibevehoy",
	// cspell:disable-next-line
	"keeta_aguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwuk",
	// cspell:disable-next-line
	"keeta_aguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwu",
	"A884D7FF138F2D9552F691280398B0EB65E0E518ECF871F06D57E5CA4EC50DA5",
];

/// Invalid prefix addresses for negative testing  
const INVALID_PREFIX_ADDRESSES: &[&str] = &[
	// cspell:disable-next-line
	"0xaguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwui",
	// cspell:disable-next-line
	"notkeeta_aguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwui",
];

// Test data for account parsing
struct AccountParsingTestCase {
	encoded_public_key: &'static str,
	expected_type: KeyPairType,
	is_identifier: bool,
}

const ACCOUNT_PARSING_TEST_CASES: &[AccountParsingTestCase] = &[
	AccountParsingTestCase {
		encoded_public_key: TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key,
		expected_type: KeyPairType::ECDSASECP256K1,
		is_identifier: false,
	},
	AccountParsingTestCase {
		encoded_public_key: TEST_PUBLIC_ACCOUNT.ecdsa_secp256r1.encoded_public_key,
		expected_type: KeyPairType::ECDSASECP256R1,
		is_identifier: false,
	},
	AccountParsingTestCase {
		encoded_public_key: TEST_PUBLIC_ACCOUNT.ed25519.encoded_public_key,
		expected_type: KeyPairType::ED25519,
		is_identifier: false,
	},
	AccountParsingTestCase {
		encoded_public_key: TEST_PUBLIC_ACCOUNT.network.encoded_public_key,
		expected_type: KeyPairType::NETWORK,
		is_identifier: true,
	},
	AccountParsingTestCase {
		encoded_public_key: TEST_PUBLIC_ACCOUNT.token.encoded_public_key,
		expected_type: KeyPairType::TOKEN,
		is_identifier: true,
	},
	AccountParsingTestCase {
		encoded_public_key: TEST_PUBLIC_ACCOUNT.storage.encoded_public_key,
		expected_type: KeyPairType::STORAGE,
		is_identifier: true,
	},
	AccountParsingTestCase {
		encoded_public_key: TEST_PUBLIC_ACCOUNT.multisig.encoded_public_key,
		expected_type: KeyPairType::MULTISIG,
		is_identifier: true,
	},
];

#[test]
fn test_account_from_public_key_parsing() {
	for test_case in ACCOUNT_PARSING_TEST_CASES {
		let account: GenericAccount = test_case.encoded_public_key.parse().unwrap();

		// Extract account properties and verify them
		let (actual_type, actual_is_identifier, actual_public_key) = match &account {
			GenericAccount::EcdsaSecp256k1(acc) => (KeyPairType::ECDSASECP256K1, false, acc.to_string()),
			GenericAccount::EcdsaSecp256r1(acc) => (KeyPairType::ECDSASECP256R1, false, acc.to_string()),
			GenericAccount::Ed25519(acc) => (KeyPairType::ED25519, false, acc.to_string()),
			GenericAccount::Network(acc) => (KeyPairType::NETWORK, true, acc.to_string()),
			GenericAccount::Token(acc) => (KeyPairType::TOKEN, true, acc.to_string()),
			GenericAccount::Storage(acc) => (KeyPairType::STORAGE, true, acc.to_string()),
			GenericAccount::Multisig(acc) => (KeyPairType::MULTISIG, true, acc.to_string()),
		};

		assert_eq!(actual_type, test_case.expected_type, "Key type mismatch for {}", test_case.encoded_public_key);
		assert_eq!(
			actual_is_identifier, test_case.is_identifier,
			"Identifier flag mismatch for {}",
			test_case.encoded_public_key
		);
		assert_eq!(actual_public_key, test_case.encoded_public_key, "Public key string mismatch");
	}
}

#[test]
fn test_invalid_public_key_parsing() {
	// Macro to test that a key fails to parse for a specific account type
	macro_rules! test_invalid_key {
		($invalid_key:expr, $account_type:ty) => {
			assert!(
				$invalid_key.parse::<Account<$account_type>>().is_err(),
				"Invalid key {} should not parse as {}",
				$invalid_key,
				stringify!($account_type)
			);
		};
	}

	for invalid_key in INVALID_PUBLIC_KEYS {
		test_invalid_key!(invalid_key, KeyECDSASECP256K1);
	}

	for invalid_prefix in INVALID_PREFIX_ADDRESSES {
		test_invalid_key!(invalid_prefix, KeyECDSASECP256K1);
	}
}

#[test]
fn test_account_from_seed_creation() {
	// Data-driven test configuration
	let seed_array = create_test_seed_array();

	// Macro to test account creation from seed and verify public key
	macro_rules! test_account_creation {
		($index:expr, $key_type:expr, $account_type:ty, $expected_pubkey:expr, $signature_size:expr, $supports_encryption:expr) => {{
			let seed = Keyable::Seed((seed_array.into_secret(), $index));
			let accountable = Accountable::KeyAndType(seed, $key_type);
			let account = Account::<$account_type>::try_from(accountable).unwrap();

			assert_eq!(account.to_keypair_type(), $key_type, "Keypair type mismatch");
			assert_eq!(account.to_string(), $expected_pubkey, "Public key string mismatch");
			assert_eq!(account.signature_size(), $signature_size, "Signature size mismatch");
			assert_eq!(account.supports_encryption(), $supports_encryption, "Encryption support mismatch");
			assert!(account.has_private_key(), "Account should have a private key");
			assert!(!account.is_identifier(), "Account should not be an identifier");
		}};
	}

	for (index_number, test_index) in TEST_PRIVATE_ACCOUNT.indexes.iter().enumerate() {
		let index = index_number as u32;

		test_account_creation!(
			index,
			KeyPairType::ECDSASECP256K1,
			KeyECDSASECP256K1,
			test_index.encoded_public_key_ecdsa_secp256k1,
			64,
			true
		);
		test_account_creation!(
			index,
			KeyPairType::ECDSASECP256R1,
			KeyECDSASECP256R1,
			test_index.encoded_public_key_ecdsa_secp256r1,
			64,
			true
		);
		test_account_creation!(
			index,
			KeyPairType::ED25519,
			KeyED25519,
			test_index.encoded_public_key_ed25519,
			64,
			true
		);
	}
}

#[test]
fn test_cross_platform_account_compatibility() {
	// Macro to test account creation from seed and verify public key
	macro_rules! test_seed_to_account {
		($seed_array:expr, $index:expr, $key_type:expr, $account_type:ty, $expected_pubkey:expr) => {{
			let account = Account::<$account_type>::try_from(Accountable::KeyAndType(
				Keyable::Seed(($seed_array.into_secret(), $index)),
				$key_type,
			))
			.unwrap();
			assert_eq!(account.to_string(), $expected_pubkey);
		}};
	}

	for (index_number, test_index) in TEST_PRIVATE_ACCOUNT.indexes.iter().enumerate() {
		let seed_array = create_test_seed_array();
		let index = index_number as u32;

		test_seed_to_account!(
			seed_array,
			index,
			KeyPairType::ECDSASECP256K1,
			KeyECDSASECP256K1,
			test_index.encoded_public_key_ecdsa_secp256k1
		);
		test_seed_to_account!(
			seed_array,
			index,
			KeyPairType::ECDSASECP256R1,
			KeyECDSASECP256R1,
			test_index.encoded_public_key_ecdsa_secp256r1
		);
		test_seed_to_account!(
			seed_array,
			index,
			KeyPairType::ED25519,
			KeyED25519,
			test_index.encoded_public_key_ed25519
		);
	}

	// Macro to test public key parsing
	macro_rules! test_public_key_parsing {
		($encoded_key:expr, $account_type:ty) => {
			assert!(
				$encoded_key.parse::<Account<$account_type>>().is_ok(),
				"Failed to parse public key for type: {}",
				stringify!($account_type)
			);
		};
	}

	test_public_key_parsing!(TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key, KeyECDSASECP256K1);
	test_public_key_parsing!(TEST_PUBLIC_ACCOUNT.ecdsa_secp256r1.encoded_public_key, KeyECDSASECP256R1);
	test_public_key_parsing!(TEST_PUBLIC_ACCOUNT.ed25519.encoded_public_key, KeyED25519);
	test_public_key_parsing!(TEST_PUBLIC_ACCOUNT.network.encoded_public_key, KeyNETWORK);
	test_public_key_parsing!(TEST_PUBLIC_ACCOUNT.token.encoded_public_key, KeyTOKEN);
	test_public_key_parsing!(TEST_PUBLIC_ACCOUNT.storage.encoded_public_key, KeySTORAGE);
	test_public_key_parsing!(TEST_PUBLIC_ACCOUNT.multisig.encoded_public_key, KeyMULTISIG);
}

#[test]
fn test_hex_format_functionality() {
	// Macro to test hex format round-trip for specific account types
	macro_rules! test_hex_round_trip {
		($encoded_key:expr, $account_type:ty, $expected_key_type:expr) => {{
			// Parse from keeta format
			let account: Account<$account_type> = $encoded_key.parse().unwrap();
			assert_eq!(account.to_keypair_type(), $expected_key_type);

			// Convert to hex format
			let hex_string: String = account.encode_hex();
			assert!(!hex_string.is_empty());

			// Parse back from hex
			let account_from_hex = Account::<$account_type>::from_hex(&hex_string).unwrap();
			assert_eq!(account_from_hex.to_string(), account.to_string());
			assert_eq!(account_from_hex.to_keypair_type(), $expected_key_type);
		}};
	}

	// Test cryptographic account types
	test_hex_round_trip!(
		TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key,
		KeyECDSASECP256K1,
		KeyPairType::ECDSASECP256K1
	);
	test_hex_round_trip!(
		TEST_PUBLIC_ACCOUNT.ecdsa_secp256r1.encoded_public_key,
		KeyECDSASECP256R1,
		KeyPairType::ECDSASECP256R1
	);
	test_hex_round_trip!(TEST_PUBLIC_ACCOUNT.ed25519.encoded_public_key, KeyED25519, KeyPairType::ED25519);

	// Test identifier account types
	test_hex_round_trip!(TEST_PUBLIC_ACCOUNT.network.encoded_public_key, KeyNETWORK, KeyPairType::NETWORK);
	test_hex_round_trip!(TEST_PUBLIC_ACCOUNT.token.encoded_public_key, KeyTOKEN, KeyPairType::TOKEN);
	test_hex_round_trip!(TEST_PUBLIC_ACCOUNT.storage.encoded_public_key, KeySTORAGE, KeyPairType::STORAGE);
	test_hex_round_trip!(TEST_PUBLIC_ACCOUNT.multisig.encoded_public_key, KeyMULTISIG, KeyPairType::MULTISIG);
}

#[test]
fn test_generic_account_hex_format() {
	for test_case in ACCOUNT_PARSING_TEST_CASES {
		// Parse as GenericAccount
		let generic_account: GenericAccount = test_case.encoded_public_key.parse().unwrap();
		assert_eq!(generic_account.to_keypair_type(), test_case.expected_type);

		// Convert to hex format
		let hex_string: String = generic_account.encode_hex();
		assert!(!hex_string.is_empty());

		// Verify the type byte is correct (first byte should match the key type)
		let hex_bytes = hex::decode(&hex_string).unwrap();
		assert_eq!(hex_bytes[0], test_case.expected_type as u8);

		// Parse back from hex
		let generic_from_hex = GenericAccount::from_hex(&hex_string).unwrap();
		assert_eq!(generic_from_hex.to_keypair_type(), test_case.expected_type);

		// Round-trip should preserve the original public key string
		assert_eq!(generic_from_hex.to_string(), test_case.encoded_public_key);
	}
}

#[test]
fn test_hex_format_invalid_cases() {
	let invalid_hex_cases = [
		"",                  // Empty string
		"1",                 // Too short
		"FF123456789ABCDEF", // Invalid key type (0xFF)
		"GG123456789ABCDEF", // Invalid hex characters
		"0123456789ABCDEF",  // Too short for actual key data
	];

	for invalid_hex in invalid_hex_cases {
		let result = GenericAccount::from_hex(invalid_hex);
		assert!(result.is_err(), "Expected error for invalid hex: {invalid_hex}");
	}
}
