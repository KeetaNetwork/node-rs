//! Integration tests for network addresses and identifier functionality.

use accounts::KeyECDSASECP256K1;
use accounts::{Account, GenericAccount, KeyPairType};
use accounts::{Accountable, KeyNETWORK, Keyable};

mod common;
use common::*;

#[test]
fn test_network_address_generation() {
	let network_id = 12345u64;

	let network_account = Account::<KeyNETWORK>::generate_network_address(network_id).unwrap();
	assert_eq!(network_account.keypair_type(), KeyPairType::NETWORK);
	assert_eq!(network_account.signature_size(), 0);
	assert!(network_account.is_identifier());
	assert!(network_account.is_network());
	assert!(!network_account.has_private_key());
	assert!(!network_account.supports_encryption());

	// Network addresses should be deterministic
	let network_account2 = Account::<KeyNETWORK>::generate_network_address(network_id).unwrap();
	assert_eq!(network_account.to_string(), network_account2.to_string());

	// Different network IDs should produce different addresses
	let different_network = Account::<KeyNETWORK>::generate_network_address(54321u64).unwrap();
	assert_ne!(network_account.to_string(), different_network.to_string());
}

#[test]
fn test_identifier_generation() {
	use accounts::KeyECDSASECP256K1;
	use secrecy::SecretBox;

	let seed_array = create_test_seed_array();
	let crypto_account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256K1,
	))
	.unwrap();

	let token_result = crypto_account.generate_identifier(KeyPairType::TOKEN, None, 0);
	assert!(token_result.is_ok());

	let result = token_result.unwrap();
	assert!(matches!(result, GenericAccount::Token(_)));

	if let GenericAccount::Token(token_account) = result {
		assert_eq!(token_account.keypair_type(), KeyPairType::TOKEN);
		assert!(token_account.is_identifier());
		assert!(token_account.is_token());
		assert!(!token_account.has_private_key());
		assert!(!token_account.supports_encryption());
		assert_eq!(token_account.signature_size(), 0);
	}

	let network_account = Account::<KeyNETWORK>::generate_network_address(12345).unwrap();
	let token_from_network = network_account.generate_identifier(KeyPairType::TOKEN, None, 0);
	assert!(token_from_network.is_ok());

	let storage_from_token = crypto_account.generate_identifier(KeyPairType::STORAGE, Some("0x123"), 5);
	assert!(storage_from_token.is_err());
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

	assert!(account1.compare_public_key(
		TEST_PUBLIC_ACCOUNT
			.ecdsa_secp256k1
			.encoded_public_key
	));
	assert!(account1.compare_account(&account2)); // Same public keys
	assert!(!account1.compare_public_key(
		TEST_PUBLIC_ACCOUNT
			.ecdsa_secp256r1
			.encoded_public_key
	));
}

#[test]
fn test_identifier_account_error_handling() {
	let network_account = Account::<KeyNETWORK>::generate_network_address(12345).unwrap();
	let sign_result = network_account.sign(b"test data", None);
	assert!(sign_result.is_err());

	let verify_result = network_account.verify(b"test data", &[0u8; 64], None);
	assert!(verify_result.is_err());

	// Test encryption on unsupported accounts
	let encrypt_result = network_account.encrypt(b"test data");
	assert!(encrypt_result.is_err());

	let decrypt_result = network_account.decrypt(&[0u8; 64]);
	assert!(decrypt_result.is_err());

	let token_account = // cspell:disable-next-line
		"keeta_anze4ny3srfer2k3shxalg34w4iq4wdgzjyhsfocq7cjzk43o5fpc2igkuifg".parse::<GenericAccount>().unwrap();
	if let GenericAccount::Token(token_acc) = token_account {
		let invalid_generation = token_acc.generate_identifier(KeyPairType::STORAGE, None, 0);
		assert!(invalid_generation.is_err());
	}
}
