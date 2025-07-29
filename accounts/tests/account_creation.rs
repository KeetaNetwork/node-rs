//! Integration tests for account creation and public key parsing

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
		let account = encoded_public_key.parse().unwrap();
		match &account {
			GenericAccount::EcdsaSecp256k1(acc) => {
				assert_eq!(acc.keypair_type(), KeyPairType::ECDSASECP256K1);
				assert!(!acc.is_identifier());
			}
			GenericAccount::EcdsaSecp256r1(acc) => {
				assert_eq!(acc.keypair_type(), KeyPairType::ECDSASECP256R1);
				assert!(!acc.is_identifier());
			}
			GenericAccount::Ed25519(acc) => {
				assert_eq!(acc.keypair_type(), KeyPairType::ED25519);
				assert!(!acc.is_identifier());
			}
			GenericAccount::Network(acc) => {
				assert_eq!(acc.keypair_type(), KeyPairType::NETWORK);
				assert!(acc.is_identifier());
			}
			GenericAccount::Token(acc) => {
				assert_eq!(acc.keypair_type(), KeyPairType::TOKEN);
				assert!(acc.is_identifier());
			}
			GenericAccount::Storage(acc) => {
				assert_eq!(acc.keypair_type(), KeyPairType::STORAGE);
				assert!(acc.is_identifier());
			}
			GenericAccount::Multisig(acc) => {
				assert_eq!(acc.keypair_type(), KeyPairType::MULTISIG);
				assert!(acc.is_identifier());
			}
		}

		// Verify the account has the expected properties
		match account {
			GenericAccount::EcdsaSecp256k1(acc) if expected_type == KeyPairType::ECDSASECP256K1 => {
				assert_eq!(acc.public_key_string(), encoded_public_key);
				assert_eq!(acc.is_identifier(), is_identifier);
			}
			GenericAccount::EcdsaSecp256r1(acc) if expected_type == KeyPairType::ECDSASECP256R1 => {
				assert_eq!(acc.public_key_string(), encoded_public_key);
				assert_eq!(acc.is_identifier(), is_identifier);
			}
			GenericAccount::Ed25519(acc) if expected_type == KeyPairType::ED25519 => {
				assert_eq!(acc.public_key_string(), encoded_public_key);
				assert_eq!(acc.is_identifier(), is_identifier);
			}
			GenericAccount::Network(acc) if expected_type == KeyPairType::NETWORK => {
				assert_eq!(acc.public_key_string(), encoded_public_key);
				assert_eq!(acc.is_identifier(), is_identifier);
			}
			GenericAccount::Token(acc) if expected_type == KeyPairType::TOKEN => {
				assert_eq!(acc.public_key_string(), encoded_public_key);
				assert_eq!(acc.is_identifier(), is_identifier);
			}
			GenericAccount::Storage(acc) if expected_type == KeyPairType::STORAGE => {
				assert_eq!(acc.public_key_string(), encoded_public_key);
				assert_eq!(acc.is_identifier(), is_identifier);
			}
			GenericAccount::Multisig(acc) if expected_type == KeyPairType::MULTISIG => {
				assert_eq!(acc.public_key_string(), encoded_public_key);
				assert_eq!(acc.is_identifier(), is_identifier);
			}
			_ => panic!("Account type mismatch for {encoded_public_key}"),
		}
	}
}

#[test]
fn test_invalid_public_key_parsing() {
	for invalid_key in INVALID_PUBLIC_KEYS {
		assert!(invalid_key.parse::<Account<KeyECDSASECP256K1>>().is_err());
	}

	for invalid_prefix in INVALID_PREFIX_ADDRESSES {
		assert!(invalid_prefix.parse::<Account<KeyECDSASECP256K1>>().is_err());
	}
}

#[test]
fn test_account_from_seed_creation() {
	let seed_array = create_test_seed_array();

	for (index_number, test_index) in TEST_PRIVATE_ACCOUNT.indexes.iter().enumerate() {
		let index = index_number as u32;

		let secp256k1_account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ECDSASECP256K1,
		))
		.unwrap();
		assert_eq!(secp256k1_account.keypair_type(), KeyPairType::ECDSASECP256K1);
		assert_eq!(secp256k1_account.public_key_string(), test_index.encoded_public_key_ecdsa_secp256k1);
		assert_eq!(secp256k1_account.signature_size(), 64); // ECDSA signatures are 64 bytes
		assert!(secp256k1_account.supports_encryption());
		assert!(secp256k1_account.has_private_key());
		assert!(!secp256k1_account.is_identifier());

		let secp256r1_account = Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ECDSASECP256R1,
		))
		.unwrap();
		assert_eq!(secp256r1_account.keypair_type(), KeyPairType::ECDSASECP256R1);
		assert_eq!(secp256r1_account.public_key_string(), test_index.encoded_public_key_ecdsa_secp256r1);
		assert_eq!(secp256r1_account.signature_size(), 64); // ECDSA signatures are 64 bytes
		assert!(!secp256r1_account.supports_encryption()); // Not yet implemented
		assert!(secp256r1_account.has_private_key());
		assert!(!secp256r1_account.is_identifier());

		let ed25519_account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ED25519,
		))
		.unwrap();
		assert_eq!(ed25519_account.keypair_type(), KeyPairType::ED25519);
		assert_eq!(ed25519_account.public_key_string(), test_index.encoded_public_key_ed25519);
		assert_eq!(ed25519_account.signature_size(), 64); // Ed25519 signatures are 64 bytes
		assert!(ed25519_account.supports_encryption());
		assert!(ed25519_account.has_private_key());
		assert!(!ed25519_account.is_identifier());
	}
}

#[test]
fn test_cross_platform_account_compatibility() {
	for (index_number, test_index) in TEST_PRIVATE_ACCOUNT.indexes.iter().enumerate() {
		let seed_array = create_test_seed_array();
		let index = index_number as u32;

		let secp256k1_account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ECDSASECP256K1,
		))
		.unwrap();
		assert_eq!(secp256k1_account.public_key_string(), test_index.encoded_public_key_ecdsa_secp256k1);

		let secp256r1_account = Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ECDSASECP256R1,
		))
		.unwrap();
		assert_eq!(secp256r1_account.public_key_string(), test_index.encoded_public_key_ecdsa_secp256r1);

		let ed25519_account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ED25519,
		))
		.unwrap();
		assert_eq!(ed25519_account.public_key_string(), test_index.encoded_public_key_ed25519);
	}

	assert!(TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key.parse::<Account<KeyECDSASECP256K1>>().is_ok());
	assert!(TEST_PUBLIC_ACCOUNT.ecdsa_secp256r1.encoded_public_key.parse::<Account<KeyECDSASECP256R1>>().is_ok());
	assert!(TEST_PUBLIC_ACCOUNT.ed25519.encoded_public_key.parse::<Account<KeyED25519>>().is_ok());
	assert!(TEST_PUBLIC_ACCOUNT.network.encoded_public_key.parse::<Account<KeyNETWORK>>().is_ok());
	assert!(TEST_PUBLIC_ACCOUNT.token.encoded_public_key.parse::<Account<KeyTOKEN>>().is_ok());
	assert!(TEST_PUBLIC_ACCOUNT.storage.encoded_public_key.parse::<Account<KeySTORAGE>>().is_ok());
	assert!(TEST_PUBLIC_ACCOUNT.multisig.encoded_public_key.parse::<Account<KeyMULTISIG>>().is_ok());
}
