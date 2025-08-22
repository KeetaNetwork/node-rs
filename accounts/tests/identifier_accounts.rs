//! Integration tests for identifier account generation functionality.

use accounts::{Account, GenericAccount, KeyPair, KeyPairType, KeyTOKEN};
use accounts::{Accountable, KeyECDSASECP256K1, KeyNETWORK, KeySTORAGE, Keyable};
use secrecy::SecretBox;

mod common;
use common::*;

// Test data for identifier generation consistency testing
const CONSISTENCY_TEST_NETWORK_IDS: &[u64] = &[0, 1, 2, 3, 4];

// Test data for network address verification
const NETWORK_VERIFICATION_CASES: &[(u64, &str)] = &[
	(1, "Network ID 1"),
	(2, "Network ID 2"),
	(12345, "Network ID 12345"),
	(54321, "Network ID 54321"),
	(999999, "Network ID 999999"),
];

// Helper function to create crypto account with test seed
fn create_test_crypto_account() -> Account<KeyECDSASECP256K1> {
	let seed_array = create_test_seed_array();
	Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256K1,
	))
	.unwrap()
}

// Helper function to verify network account properties
fn verify_network_account_properties(account: &Account<KeyNETWORK>) {
	assert_eq!(account.to_keypair_type(), KeyPairType::NETWORK);
	assert!(account.is_identifier());
	assert!(account.is_network());
	assert!(!account.has_private_key());
	assert!(!account.supports_encryption());
}

// Helper function to verify token identifier properties
fn verify_token_identifier_properties(account: &accounts::Account<accounts::KeyTOKEN>) {
	assert_eq!(account.to_keypair_type(), KeyPairType::TOKEN);
	assert!(account.is_identifier());
	assert!(!account.has_private_key());
}

// Helper function to verify storage identifier properties
fn verify_storage_identifier_properties(account: &accounts::Account<accounts::KeySTORAGE>) {
	assert_eq!(account.to_keypair_type(), KeyPairType::STORAGE);
	assert!(account.is_identifier());
	assert!(!account.has_private_key());
}

#[test]
fn test_network_address_deterministic_generation() {
	// Test deterministic generation with data-driven approach
	for (network_id, description) in NETWORK_VERIFICATION_CASES {
		// Same network ID should produce identical accounts
		let network_account1 = Account::<KeyNETWORK>::generate_network_address(*network_id).unwrap();
		let network_account2 = Account::<KeyNETWORK>::generate_network_address(*network_id).unwrap();
		assert_eq!(
			network_account1.to_string(),
			network_account2.to_string(),
			"Same network ID should produce identical accounts for {description}"
		);

		// Verify account properties
		verify_network_account_properties(&network_account1);
	}

	// Test that different network IDs produce different accounts
	let accounts: Vec<_> = NETWORK_VERIFICATION_CASES
		.iter()
		.map(|(network_id, _)| Account::<KeyNETWORK>::generate_network_address(*network_id).unwrap())
		.collect();

	for i in 0..accounts.len() {
		for j in (i + 1)..accounts.len() {
			assert_ne!(
				accounts[i].to_string(),
				accounts[j].to_string(),
				"Different network IDs should produce different accounts: {} vs {}",
				NETWORK_VERIFICATION_CASES[i].1,
				NETWORK_VERIFICATION_CASES[j].1
			);
		}
	}
}

#[test]
fn test_base_token_identifier_generation() {
	// Test base token generation from network addresses with data-driven approach
	for (network_id, description) in NETWORK_VERIFICATION_CASES {
		let network_address = Account::<KeyNETWORK>::generate_network_address(*network_id).unwrap();
		verify_network_account_properties(&network_address);

		// Generate base token identifier (using None for previous hash like Block.NO_PREVIOUS)
		let base_token_result = network_address.generate_identifier(KeyPairType::TOKEN, None, 0);
		assert!(base_token_result.is_ok(), "Failed to generate base token identifier for {description}");

		let base_token_generic = base_token_result.unwrap();
		assert!(matches!(base_token_generic, GenericAccount::Token(_)));

		let base_token_address = Account::<KeyTOKEN>::try_from(base_token_generic).unwrap();
		verify_token_identifier_properties(&base_token_address);
	}
}

#[test]
fn test_token_identifier_restrictions() {
	let network_address = Account::<KeyNETWORK>::generate_network_address(NETWORK_VERIFICATION_CASES[0].0).unwrap();
	let base_token_result = network_address.generate_identifier(KeyPairType::TOKEN, None, 0);
	assert!(base_token_result.is_ok());

	let base_token_address = Account::<KeyTOKEN>::try_from(base_token_result.unwrap()).unwrap();
	// Test that token identifiers cannot generate more token identifiers.
	let token_from_token_result = base_token_address.generate_identifier(KeyPairType::TOKEN, None, 0);
	assert!(
		token_from_token_result.is_err(),
		"Token identifiers should not be able to generate more token identifiers"
	);
}

#[test]
fn test_network_identifier_restrictions() {
	let network_address = Account::<KeyNETWORK>::generate_network_address(NETWORK_VERIFICATION_CASES[0].0).unwrap();
	// Network addresses should not be able to generate token identifiers with some previous hash
	// (only base tokens with None/NO_PREVIOUS should work)
	let fake_previous_hash = "fake_hash";
	let token_with_previous_result =
		network_address.generate_identifier(KeyPairType::TOKEN, Some(fake_previous_hash), 0);

	// This should fail
	assert!(
		token_with_previous_result.is_err(),
		"Network addresses should not generate token identifiers with previous hash"
	);
}

#[test]
fn test_storage_identifier_generation() {
	let crypto_account = create_test_crypto_account();

	let storage_result = crypto_account.generate_identifier(KeyPairType::STORAGE, None, 0);
	assert!(storage_result.is_ok(), "Failed to generate storage identifier");

	let storage_generic = storage_result.unwrap();
	assert!(matches!(storage_generic, GenericAccount::Storage(_)));

	let storage_identifier = Account::<KeySTORAGE>::try_from(storage_generic).unwrap();
	verify_storage_identifier_properties(&storage_identifier);
}

#[test]
fn test_identifier_generation_deterministic() {
	// Test that identifier generation is deterministic
	let account1 = create_test_crypto_account();
	let account2 = create_test_crypto_account();

	// Generate storage identifiers from both accounts
	let storage1 = account1
		.generate_identifier(KeyPairType::STORAGE, None, 0)
		.unwrap();
	let storage2 = account2
		.generate_identifier(KeyPairType::STORAGE, None, 0)
		.unwrap();

	let storage1 = Account::<KeySTORAGE>::try_from(storage1).unwrap();
	let storage2 = Account::<KeySTORAGE>::try_from(storage2).unwrap();
	assert_eq!(storage1.to_string(), storage2.to_string(), "Identifier generation should be deterministic");
}

#[test]
fn test_base_address_consistency() {
	for &network_id in CONSISTENCY_TEST_NETWORK_IDS {
		// Generate network and base token addresses
		let network_address = Account::<KeyNETWORK>::generate_network_address(network_id).unwrap();
		let base_token_result = network_address.generate_identifier(KeyPairType::TOKEN, None, 0);
		assert!(base_token_result.is_ok());

		// Generate them again to verify consistency
		let network_address_check = Account::<KeyNETWORK>::generate_network_address(network_id).unwrap();
		let base_token_check_result = network_address_check.generate_identifier(KeyPairType::TOKEN, None, 0);
		assert!(base_token_check_result.is_ok());

		// Compare network addresses
		assert_eq!(
			network_address.to_string(),
			network_address_check.to_string(),
			"Network addresses should be deterministic for network_id {network_id}"
		);

		let token1 = Account::<KeyTOKEN>::try_from(base_token_result.unwrap()).unwrap();
		let token2 = Account::<KeyTOKEN>::try_from(base_token_check_result.unwrap()).unwrap();
		assert_eq!(
			token1.keypair.to_public_key_string(),
			token2.keypair.to_public_key_string(),
			"Base token addresses should be deterministic for network_id {network_id}"
		);
	}
}

#[test]
fn test_account_comparison() {
	let account1 = TEST_PUBLIC_ACCOUNT
		.ecdsa_secp256k1
		.encoded_public_key
		.parse::<Account<KeyECDSASECP256K1>>()
		.unwrap();
	let account2 = TEST_PUBLIC_ACCOUNT
		.ecdsa_secp256k1
		.encoded_public_key
		.parse::<Account<KeyECDSASECP256K1>>()
		.unwrap();

	assert!(account1.compare_public_key(TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key));
	assert!(account1.compare_account(&account2)); // Same public keys
	assert!(!account1.compare_public_key(TEST_PUBLIC_ACCOUNT.ecdsa_secp256r1.encoded_public_key));
}

#[test]
fn test_identifier_account_error_handling() {
	let network_account = Account::<KeyNETWORK>::generate_network_address(12345).unwrap();

	// Test that identifier accounts cannot sign
	let sign_result = network_account.sign(b"test data", None);
	assert!(sign_result.is_err());

	// Test that identifier accounts cannot verify signatures
	let verify_result = network_account.verify(b"test data", [0u8; 64], None);
	assert!(verify_result.is_err());

	// Test encryption on unsupported accounts
	let encrypt_result = network_account.encrypt(b"test data");
	assert!(encrypt_result.is_err());

	let decrypt_result = network_account.decrypt([0u8; 64]);
	assert!(decrypt_result.is_err());

	// Test that token identifiers cannot generate storage identifiers
	let token_account = TEST_PUBLIC_ACCOUNT
		.token
		.encoded_public_key
		.parse::<GenericAccount>()
		.unwrap();
	let token_account = Account::<KeyTOKEN>::try_from(token_account).unwrap();
	let invalid_generation = token_account.generate_identifier(KeyPairType::STORAGE, None, 0);
	assert!(invalid_generation.is_err());
}
