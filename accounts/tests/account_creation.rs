//! Integration tests for account creation and public key parsing
use std::string::ToString;

use accounts::{Account, GenericAccount, KeyPairType};
use accounts::{Accountable, Keyable};
use accounts::{KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
use accounts::{KeyMULTISIG, KeyNETWORK, KeySTORAGE, KeyTOKEN};
use secrecy::SecretBox;

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

#[test]
fn test_account_from_public_key_parsing() {
	let check_passes = [
		(TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key, KeyPairType::ECDSASECP256K1, false),
		(TEST_PUBLIC_ACCOUNT.ecdsa_secp256r1.encoded_public_key, KeyPairType::ECDSASECP256R1, false),
		(TEST_PUBLIC_ACCOUNT.ed25519.encoded_public_key, KeyPairType::ED25519, false),
		(TEST_PUBLIC_ACCOUNT.network.encoded_public_key, KeyPairType::NETWORK, true),
		(TEST_PUBLIC_ACCOUNT.token.encoded_public_key, KeyPairType::TOKEN, true),
		(TEST_PUBLIC_ACCOUNT.storage.encoded_public_key, KeyPairType::STORAGE, true),
		(TEST_PUBLIC_ACCOUNT.multisig.encoded_public_key, KeyPairType::MULTISIG, true),
	];

	for (encoded_public_key, expected_type, is_identifier) in check_passes {
		let account: GenericAccount = encoded_public_key.parse().unwrap();

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

		assert_eq!(actual_type, expected_type, "Key type mismatch for {encoded_public_key}");
		assert_eq!(actual_is_identifier, is_identifier, "Identifier flag mismatch for {encoded_public_key}");
		assert_eq!(actual_public_key, encoded_public_key, "Public key string mismatch");
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
			let seed = Keyable::Seed((SecretBox::new(Box::new(seed_array)), $index));
			let accountable = Accountable::KeyAndType(seed, $key_type);
			let account = Account::<$account_type>::try_from(accountable).unwrap();

			assert_eq!(account.keypair_type(), $key_type, "Keypair type mismatch");
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
				Keyable::Seed((SecretBox::new(Box::new($seed_array)), $index)),
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
			assert!($encoded_key.parse::<Account<$account_type>>().is_ok(), "Failed to parse public key");
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
