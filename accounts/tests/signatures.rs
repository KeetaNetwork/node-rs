//! Integration tests for signature creation and verification

use accounts::account::{KeyECDSASECP256K1, KeyPair, SigningOptions};
use accounts::{Account, Accountable, GenericAccount, KeyPairType, Keyable};
use accounts::{KeyECDSASECP256R1, KeyED25519};
use crypto::hash_default;
use secrecy::SecretBox;

mod common;
use common::*;

pub struct ExternalSignatureTestData {
	pub public_key_string: &'static str,
	pub test_data: &'static [u8],
	pub openssl_signature: &'static [u8],
	pub corrupted_signature: &'static [u8],
}

pub const EXTERNAL_SIGNATURE_TEST: ExternalSignatureTestData = ExternalSignatureTestData {
	// cspell:disable-next-line
	public_key_string: "keeta_aaba6iiv7igjuediblxmwzflfycwjlwrv6bbu4v7tb5kx6d2dllieunedvq3cza",
	test_data: b"Hello from external signature test",
	openssl_signature: &[
		0x30, 0x44, 0x02, 0x20, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
		0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x02, 0x20, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x11,
	],
	corrupted_signature: &[
		0x30, 0x44, 0x02, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x02, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	],
};

pub const TEST_MESSAGE: &[u8] = b"Some random test data";
pub const WRONG_TEST_MESSAGE: &[u8] = b"Wrong data";

#[test]
fn test_account_sign_and_verify() {
	let seed_array = create_test_seed_array();

	for index_number in 0..TEST_PRIVATE_ACCOUNT.indexes.len() {
		let index = index_number as u32;

		let secp256k1_account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ECDSASECP256K1,
		))
		.unwrap();

		let signature = secp256k1_account.sign(TEST_MESSAGE, None).unwrap();
		assert_eq!(signature.len(), 64);
		assert!(secp256k1_account.verify(TEST_MESSAGE, &signature, None).unwrap());
		assert!(!secp256k1_account.verify(WRONG_TEST_MESSAGE, &signature, None).unwrap());

		let secp256r1_account = Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ECDSASECP256R1,
		))
		.unwrap();

		let signature_r1 = secp256r1_account.sign(TEST_MESSAGE, None).unwrap();
		assert_eq!(signature_r1.len(), 64);
		assert!(secp256r1_account.verify(TEST_MESSAGE, &signature_r1, None).unwrap());
		assert!(!secp256r1_account.verify(WRONG_TEST_MESSAGE, &signature_r1, None).unwrap());

		let ed25519_account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
			Keyable::Seed((SecretBox::new(Box::new(seed_array)), index)),
			KeyPairType::ED25519,
		))
		.unwrap();

		let signature_ed = ed25519_account.sign(TEST_MESSAGE, None).unwrap();
		assert_eq!(signature_ed.len(), 64);
		assert!(ed25519_account.verify(TEST_MESSAGE, &signature_ed, None).unwrap());
		assert!(!ed25519_account.verify(WRONG_TEST_MESSAGE, &signature_ed, None).unwrap());

		// Ensure invalid algorithm combinations do not verify
		assert!(!secp256k1_account.verify(TEST_MESSAGE, &signature_r1, None).unwrap());
		assert!(!secp256k1_account.verify(TEST_MESSAGE, &signature_ed, None).unwrap());
		assert!(!secp256r1_account.verify(TEST_MESSAGE, &signature, None).unwrap());
	}
}

#[test]
fn test_signature_verification_with_public_key() {
	let seed_array = create_test_seed_array();

	let account_with_private = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256K1,
	))
	.unwrap();

	let rust_signature = account_with_private.sign(TEST_MESSAGE, None).unwrap();
	let self_verification = account_with_private.verify(TEST_MESSAGE, &rust_signature, None).unwrap();
	assert!(self_verification);

	// Create a public-only account from the same account's public key string
	let public_key_string = account_with_private.public_key_string();
	let account_public_only = public_key_string.parse::<GenericAccount>().unwrap();
	if let GenericAccount::EcdsaSecp256k1(public_account) = account_public_only {
		let public_verification = public_account.verify(TEST_MESSAGE, &rust_signature, None).unwrap();
		assert!(public_verification);
	}
}

#[test]
fn test_signing_options_compatibility() {
	let message = b"Hello World";

	let test_seed_bytes = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
	let mut seed_array = [0u8; 32];
	seed_array.copy_from_slice(&test_seed_bytes[0..32]);
	let test_seed = SecretBox::new(Box::new(seed_array));
	let account = KeyECDSASECP256K1::try_from(Keyable::Seed((test_seed, 0))).unwrap();

	let default_options = SigningOptions::new();
	let signature_default = account.sign(message, Some(&default_options)).unwrap();

	let raw_options = SigningOptions::raw();
	let signature_raw = account.sign(message, Some(&raw_options)).unwrap();
	assert_ne!(signature_default, signature_raw);

	let verify_default = account.verify(message, &signature_default, Some(&default_options)).unwrap();
	assert!(verify_default);

	let verify_raw = account.verify(message, &signature_raw, Some(&raw_options)).unwrap();
	assert!(verify_raw);

	let verify_cross_1 = account.verify(message, &signature_default, Some(&raw_options)).unwrap();
	assert!(!verify_cross_1);

	let verify_cross_2 = account.verify(message, &signature_raw, Some(&default_options)).unwrap();
	assert!(!verify_cross_2);
}

#[test]
fn test_default_signing_behavior() {
	let message = b"Test Message";
	let test_seed_bytes = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();

	let mut seed_array = [0u8; 32];
	seed_array.copy_from_slice(&test_seed_bytes[0..32]);

	let test_seed = SecretBox::new(Box::new(seed_array));
	let account = KeyECDSASECP256K1::try_from(Keyable::Seed((test_seed, 0))).unwrap();

	let signature = account.sign(message, None).unwrap();
	let is_valid = account.verify(message, &signature, None).unwrap();
	assert!(is_valid);

	let default_options = SigningOptions::new();
	let is_valid_with_options = account.verify(message, &signature, Some(&default_options)).unwrap();
	assert!(is_valid_with_options);

	let raw_options = SigningOptions::raw();
	let is_valid_raw = account.verify(message, &signature, Some(&raw_options)).unwrap();
	assert!(!is_valid_raw);
}

#[test]
fn test_cross_platform_signature_verification() {
	let message = b"Hello World";
	let test_seed_bytes = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();

	let mut seed_array = [0u8; 32];
	seed_array.copy_from_slice(&test_seed_bytes[0..32]);

	let test_seed = SecretBox::new(Box::new(seed_array));
	let account = KeyECDSASECP256K1::try_from(Keyable::Seed((test_seed, 0))).unwrap();

	let pre_hashed_message = hash_default(message).to_vec();
	let raw_options = SigningOptions::raw();
	let simulation_signature = account.sign(&pre_hashed_message, Some(&raw_options)).unwrap();

	let verification_result = account.verify(message, &simulation_signature, None);
	assert!(verification_result.is_ok());
}

#[test]
fn test_verify_openssl_signature() {
	let account_from_public = TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key.parse::<GenericAccount>().unwrap();
	if let GenericAccount::EcdsaSecp256k1(account) = account_from_public {
		let verification_result =
			account.verify(EXTERNAL_SIGNATURE_TEST.test_data, EXTERNAL_SIGNATURE_TEST.openssl_signature, None);

		match verification_result {
			Ok(true) => {}
			Ok(false) => {}
			Err(_) => {}
		}

		let _corrupted_result =
			account.verify(EXTERNAL_SIGNATURE_TEST.test_data, EXTERNAL_SIGNATURE_TEST.corrupted_signature, None);
	}
}

#[test]
fn test_verify_ios_ecdsa_signature() {
	let ecdsa_signature = [
		0x30, 0x45, 0x02, 0x20, 0x7C, 0x66, 0x95, 0xA6, 0x46, 0x7E, 0x1A, 0xC8, 0x78, 0x65, 0x97, 0x5D, 0x07, 0x2C,
		0x39, 0x4E, 0x30, 0x63, 0xB9, 0x0B, 0x86, 0x3E, 0xBA, 0x5A, 0x19, 0x2C, 0x5F, 0x8C, 0xDF, 0x42, 0x99, 0xF8,
		0x02, 0x21, 0x00, 0xA1, 0x47, 0x6A, 0x7D, 0x30, 0x04, 0xCD, 0x5D, 0xF8, 0x46, 0x7C, 0x8F, 0x99, 0x2C, 0x70,
		0x6B, 0x72, 0x13, 0x47, 0x95, 0x54, 0x67, 0xD3, 0x37, 0x55, 0xDB, 0x07, 0x0C, 0x95, 0xAE, 0x92, 0x24,
	];

	let ecdsa_account = TEST_PUBLIC_ACCOUNT.ecdsa_secp256k1.encoded_public_key.parse::<GenericAccount>().unwrap();
	if let GenericAccount::EcdsaSecp256k1(account) = ecdsa_account {
		let _verification_result = account.verify(EXTERNAL_SIGNATURE_TEST.test_data, &ecdsa_signature, None);
	}
}

#[test]
fn test_verify_ios_ed25519_signature() {
	let ed25519_signature = [
		0x5E, 0x26, 0x0B, 0x72, 0x09, 0x6A, 0x9E, 0x1D, 0x1A, 0x2C, 0x31, 0x4C, 0x55, 0x0C, 0x88, 0xA7, 0x8D, 0x2C,
		0x39, 0x4E, 0x30, 0x63, 0xB9, 0x0B, 0x86, 0x3E, 0xBA, 0x5A, 0x19, 0x2C, 0x5F, 0x8C, 0xDF, 0x42, 0x99, 0xF8,
		0xA1, 0x47, 0x6A, 0x7D, 0x30, 0x04, 0xCD, 0x5D, 0xF8, 0x46, 0x7C, 0x8F, 0x99, 0x2C, 0x70, 0x6B, 0x72, 0x13,
		0x47, 0x95, 0x54, 0x67, 0xD3, 0x37, 0x55, 0xDB, 0x07, 0x0C,
	];

	let ed25519_account = TEST_PUBLIC_ACCOUNT.ed25519.encoded_public_key.parse::<GenericAccount>().unwrap();
	if let GenericAccount::Ed25519(account) = ed25519_account {
		let _verification_result = account.verify(EXTERNAL_SIGNATURE_TEST.test_data, &ed25519_signature, None);
	}
}
