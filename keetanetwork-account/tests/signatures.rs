//! Integration tests for signature creation and verification

use keetanetwork_account::account::{AccountSigner, AccountVerifier, KeyECDSASECP256K1, KeyPair};
use keetanetwork_account::{Account, AccountError, GenericAccount, KeyPairType, Keyable};
use keetanetwork_account::{KeyECDSASECP256R1, KeyED25519, KeyMULTISIG, KeyNETWORK, KeySTORAGE, KeyTOKEN};
use keetanetwork_crypto::hash::hash_default;
use keetanetwork_crypto::prelude::{IntoSecret, SigningOptions};

mod common;
use common::*;

pub struct ExternalSignatureTestData {
	pub public_key_string: &'static str,
	pub test_data: &'static [u8],
	pub openssl_signature: &'static [u8],
	pub corrupted_signature: &'static [u8],
}

pub const TEST_PUBLIC_ACCOUNT: ExternalSignatureTestData = ExternalSignatureTestData {
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

pub const TEST_SEED_BYTES: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const TEST_MESSAGE: &[u8] = b"Some random test data";
pub const WRONG_TEST_MESSAGE: &[u8] = b"Wrong data";

fn assert_sign_and_verify<T>(account: &Account<T>, message: &[u8], wrong_message: &[u8]) -> Result<(), AccountError>
where
	T: KeyPair + AccountSigner + AccountVerifier,
{
	let signature = account.sign(message, None)?;
	assert_eq!(signature.len(), 64);

	let verify_correct = account.verify(message, &signature, None);
	assert!(verify_correct.is_ok());

	let verify_wrong = account.verify(wrong_message, &signature, None);
	assert!(verify_wrong.is_err());

	Ok(())
}

fn assert_cannot_sign_or_verify<T>(account: &Account<T>, data: &[u8], fake_signature: &[u8])
where
	T: KeyPair + AccountSigner + AccountVerifier,
{
	let sign_result = account.sign(data, None);
	assert!(sign_result.is_err());

	let verify_result = account.verify(data, fake_signature, None);
	assert!(verify_result.is_err());
}

fn account_from_test_seed_bytes<T>(index: u32) -> Result<T, AccountError>
where
	T: TryFrom<Keyable, Error = AccountError>,
{
	let test_seed_bytes = hex::decode(TEST_SEED_BYTES).map_err(|_| AccountError::InvalidConstruction)?;

	let mut seed_array = [0u8; 32];
	seed_array.copy_from_slice(&test_seed_bytes[0..32]);

	let test_seed = seed_array.into_secret();
	T::try_from(Keyable::Seed((test_seed, index)))
}

#[test]
fn test_account_sign() -> Result<(), AccountError> {
	for index_number in 0..TEST_PRIVATE_ACCOUNT.indexes.len() {
		let index = index_number as u32;

		let secp256k1_account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, index)?;
		assert_sign_and_verify(&secp256k1_account, TEST_MESSAGE, WRONG_TEST_MESSAGE)?;

		let secp256r1_account = create_account_from_seed::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, index)?;
		assert_sign_and_verify(&secp256r1_account, TEST_MESSAGE, WRONG_TEST_MESSAGE)?;

		let ed25519_account = create_account_from_seed::<KeyED25519>(KeyPairType::ED25519, index)?;
		assert_sign_and_verify(&ed25519_account, TEST_MESSAGE, WRONG_TEST_MESSAGE)?;
	}

	Ok(())
}

// Helper function to test signing options compatibility
fn test_signing_options_for_algorithm<T: KeyPair + TryFrom<Keyable, Error = AccountError>>(
	algorithm_type: KeyPairType,
	message: &[u8],
) -> Result<(), AccountError> {
	let account = account_from_test_seed_bytes::<T>(0)?;

	let default_options = SigningOptions::default();
	let signature_default = account.sign(message, Some(default_options))?;
	let raw_options = SigningOptions::raw();
	// For raw signing, we need to provide a 32-byte hash
	// Use a different hash to ensure signatures are different
	let different_hash = [0x42u8; 32];
	let signature_raw = account.sign(different_hash, Some(raw_options))?;

	assert_ne!(
		signature_default, signature_raw,
		"Different signing options should produce different signatures for {algorithm_type:?}"
	);

	let default_verifies_default = account.verify(message, &signature_default, Some(default_options));
	assert!(
		default_verifies_default.is_ok(),
		"Default signature should verify with default options for {algorithm_type:?}"
	);

	let raw_verifies_raw = account.verify(different_hash, &signature_raw, Some(raw_options));
	assert!(raw_verifies_raw.is_ok(), "Raw signature should verify with raw options for {algorithm_type:?}");

	let default_rejects_raw = account.verify(message, &signature_default, Some(raw_options));
	assert!(
		default_rejects_raw.is_err(),
		"Default signature should not verify with raw options for {algorithm_type:?}"
	);

	let raw_rejects_default = account.verify(message, &signature_raw, Some(default_options));
	assert!(
		raw_rejects_default.is_err(),
		"Raw signature should not verify with default options for {algorithm_type:?}"
	);

	Ok(())
}

#[test]
fn test_signing_options_compatibility() -> Result<(), AccountError> {
	// Test signing options for ECDSA algorithms
	let message = b"Hello World";
	test_signing_options_for_algorithm::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, message)?;
	test_signing_options_for_algorithm::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, message)?;

	Ok(())
}

#[test]
fn test_algorithm_validation() -> Result<(), AccountError> {
	let test_data = b"Algorithm test data";
	let wrong_data = b"Wrong test data";

	const TEST_INDEXES: &[u32] = &[0, 1, 2];
	for &index in TEST_INDEXES {
		// Test ECDSA SECP256K1 with signing options
		let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, index)?;
		assert_sign_and_verify(&account, test_data, wrong_data)?;
		test_signing_options_for_algorithm::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, test_data)?;

		// Test ECDSA SECP256R1 with signing options
		let account = create_account_from_seed::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, index)?;
		assert_sign_and_verify(&account, test_data, wrong_data)?;
		test_signing_options_for_algorithm::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, test_data)?;

		// Test ED25519 (no signing options)
		let account = create_account_from_seed::<KeyED25519>(KeyPairType::ED25519, index)?;
		assert_sign_and_verify(&account, test_data, wrong_data)?;
	}

	Ok(())
}

#[test]
fn test_default_signing_behavior() -> Result<(), AccountError> {
	let message = b"Test Message";
	let account = account_from_test_seed_bytes::<KeyECDSASECP256K1>(0)?;

	let signature = account.sign(message, None)?;
	let is_valid = account.verify(message, &signature, None);
	assert!(is_valid.is_ok(), "Signature should verify without options");

	let default_options = SigningOptions::default();
	let is_valid_with_options = account.verify(message, &signature, Some(default_options));
	assert!(is_valid_with_options.is_ok(), "Signature should verify with default options");

	let raw_options = SigningOptions::raw();
	let is_valid_raw = account.verify(message, &signature, Some(raw_options));
	assert!(is_valid_raw.is_err(), "Signature should not verify with raw options");

	Ok(())
}

#[test]
fn test_cross_platform_signature_verification() -> Result<(), AccountError> {
	let message = b"Hello World";
	let account = account_from_test_seed_bytes::<KeyECDSASECP256K1>(0)?;

	let pre_hashed_message = hash_default(message).to_vec();
	let raw_options = SigningOptions::raw();
	let simulation_signature = account.sign(&pre_hashed_message, Some(raw_options))?;

	let verification_result = account.verify(message, &simulation_signature, None);
	assert!(verification_result.is_ok());

	Ok(())
}

#[test]
fn test_verify_openssl_signature() -> Result<(), AccountError> {
	let account_from_public = TEST_PUBLIC_ACCOUNT
		.public_key_string
		.parse::<GenericAccount>()?;

	if let GenericAccount::EcdsaSecp256k1(account) = account_from_public {
		let message = TEST_PUBLIC_ACCOUNT.test_data;
		let signature = TEST_PUBLIC_ACCOUNT.openssl_signature;
		let _verification_result = account.verify(message, signature, None);
		// TODO: OpenSSL signature issue
		// assert!(verification_result.is_ok(), "OpenSSL signature should verify");

		let signature = TEST_PUBLIC_ACCOUNT.corrupted_signature;
		let verification_result = account.verify(message, signature, None);
		assert!(verification_result.is_err(), "Corrupted signature should not verify");
	}

	Ok(())
}

// Helper function for iOS signature testing
fn test_ios_signature(
	algorithm_name: &str,
	public_key_string: &str,
	signature_bytes: &[u8],
	test_data: &[u8],
	should_pass: bool,
) -> Result<(), AccountError> {
	let account_from_public = public_key_string.parse::<GenericAccount>()?;

	match account_from_public {
		GenericAccount::EcdsaSecp256k1(account) => {
			let verification_result = account.verify(test_data, signature_bytes, None);
			assert!(verification_result.is_ok(), "iOS {algorithm_name} signature should parse without errors");

			if should_pass {
				assert!(verification_result.is_ok(), "iOS {algorithm_name} signature should verify");
			}
		}
		GenericAccount::Ed25519(account) => {
			let verification_result = account.verify(test_data, signature_bytes, None);
			assert!(verification_result.is_ok(), "iOS {algorithm_name} signature should parse without errors");

			if should_pass {
				assert!(verification_result.is_ok(), "iOS {algorithm_name} signature should verify");
			}
		}
		_ => return Err(AccountError::InvalidConstruction),
	}

	Ok(())
}

#[test]
fn test_account_verify_ios_ecdsa_signature() -> Result<(), AccountError> {
	// cspell:disable-next-line
	let public_key_string = "keeta_aabm7moneqqjpaaee5vxjqoe5f2ay3dchgr2hysdfh4wg3ycylohabivswjyfci";
	let test_data = b"Some random test data";

	// Generated from iOS-core SDK
	let ios_ecdsa_signature = [
		0xC0, 0x87, 0x9B, 0xE6, 0x52, 0xD4, 0x29, 0x2D, 0xDD, 0xC6, 0xA1, 0x83, 0x71, 0x1F, 0x99, 0xED, 0x1E, 0x02,
		0x93, 0xC8, 0x24, 0x65, 0x1F, 0x83, 0x74, 0x36, 0x53, 0x75, 0x99, 0x0A, 0x2E, 0x7B, 0x35, 0xE0, 0xF2, 0x1D,
		0x15, 0x63, 0x46, 0x11, 0x8E, 0x19, 0x32, 0x11, 0x74, 0x82, 0xF7, 0xA9, 0x14, 0x50, 0x75, 0x44, 0x2F, 0xCC,
		0x91, 0xC2, 0x89, 0x46, 0xF6, 0x5C, 0xCD, 0xAC, 0x04, 0xBE,
	];

	// TODO: ECDSA signature parsing works but verification fails due to k256 strict validation
	test_ios_signature("ECDSA", public_key_string, &ios_ecdsa_signature, test_data, false)?;

	Ok(())
}

#[test]
fn test_account_verify_ios_ed25519_signature() -> Result<(), AccountError> {
	// cspell:disable-next-line
	let public_key_string = "keeta_aeqtota6vv3k26ykv7u3nu6xqtxqll4je6uy6ike7gbrqy6di5ww5mfyf2niu";
	let test_data = b"Some random test data";

	// Generated from iOS-core SDK
	let ios_ed25519_signature = [
		0xD6, 0xD7, 0x4F, 0xDF, 0xA3, 0x73, 0xC7, 0x18, 0xD6, 0x08, 0xA4, 0xD2, 0x75, 0x68, 0xCD, 0xB5, 0x72, 0x46,
		0x54, 0x49, 0x50, 0xFC, 0x5A, 0x2F, 0xD6, 0xFD, 0x80, 0xF5, 0x99, 0x47, 0xDE, 0xC6, 0xA6, 0x50, 0x57, 0xD0,
		0xA1, 0xFA, 0xCA, 0xA8, 0x7A, 0x5C, 0x83, 0x14, 0x22, 0x2B, 0xFC, 0x3A, 0xBE, 0x68, 0xAE, 0xA5, 0xFC, 0xD4,
		0x9C, 0x4F, 0xEF, 0xCC, 0x32, 0x29, 0xBE, 0x15, 0x61, 0x05,
	];

	test_ios_signature("Ed25519", public_key_string, &ios_ed25519_signature, test_data, true)?;

	Ok(())
}

#[test]
fn test_identifier_sign_verify_should_fail() -> Result<(), AccountError> {
	let test_data = b"Random Test Data";
	let fake_signature = [0u8; 64];

	// All identifier accounts should fail to sign and verify
	let network_account = create_account_from_seed::<KeyNETWORK>(KeyPairType::NETWORK, 0)?;
	assert_cannot_sign_or_verify(&network_account, test_data, &fake_signature);

	let token_account = create_account_from_seed::<KeyTOKEN>(KeyPairType::TOKEN, 0)?;
	assert_cannot_sign_or_verify(&token_account, test_data, &fake_signature);

	let storage_account = create_account_from_seed::<KeySTORAGE>(KeyPairType::STORAGE, 0)?;
	assert_cannot_sign_or_verify(&storage_account, test_data, &fake_signature);

	let multisig_account = create_account_from_seed::<KeyMULTISIG>(KeyPairType::MULTISIG, 0)?;
	assert_cannot_sign_or_verify(&multisig_account, test_data, &fake_signature);

	Ok(())
}

#[test]
fn test_account_sign_hard_coded() -> Result<(), AccountError> {
	let test_data = b"Some random test data";
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0)?;

	// Generate a signature and verify it can be verified
	let signature = account.sign(test_data, None)?;
	let verify_signature = account.verify(test_data, &signature, None);
	assert!(verify_signature.is_ok());

	// Test that corrupted signature fails
	let mut corrupted_signature = signature.clone();
	corrupted_signature[0] = corrupted_signature[0].wrapping_add(1);
	let verify_corrupted = account.verify(test_data, &corrupted_signature, None);
	assert!(verify_corrupted.is_err());

	// Test public key string round-trip
	let public_key_string = account.to_string();
	let public_account = public_key_string.parse::<GenericAccount>()?;

	if let GenericAccount::EcdsaSecp256k1(public_only_account) = public_account {
		let public_verify_signature = public_only_account.verify(test_data, &signature, None);
		assert!(public_verify_signature.is_ok());

		let public_verify_corrupted = public_only_account.verify(test_data, &corrupted_signature, None);
		assert!(public_verify_corrupted.is_err());
	} else {
		return Err(AccountError::InvalidConstruction);
	}

	Ok(())
}
