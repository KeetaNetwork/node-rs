//! Account algorithm mapping, construction, and the account primitive
//! operations shared across every binding boundary.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_account::account::{AccountSigner, AccountVerifier};
use keetanetwork_account::{
	Account, AccountPublicKey, Accountable, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519,
	KeyPairType, Keyable,
};
use keetanetwork_block::AccountRef;
use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret};

use crate::error::CodedError;

/// The default signing algorithm, matching the browser binding.
pub const DEFAULT_ALGORITHM: &str = "ecdsa_secp256k1";

/// Canonical map from algorithm name to crypto key type.
pub const CRYPTO_ALGORITHMS: [(&str, KeyPairType); 3] = [
	("ed25519", KeyPairType::ED25519),
	("ecdsa_secp256k1", KeyPairType::ECDSASECP256K1),
	("ecdsa_secp256r1", KeyPairType::ECDSASECP256R1),
];

/// The algorithm name for `key_type`, or `"other"` for identifier accounts.
pub fn algorithm_name(key_type: KeyPairType) -> &'static str {
	CRYPTO_ALGORITHMS
		.iter()
		.find_map(|(name, candidate)| (*candidate == key_type).then_some(*name))
		.unwrap_or("other")
}

/// Construct a [`GenericAccount`] from `keyable` for the named `algorithm`.
pub fn from_keyable(keyable: Keyable, algorithm: &str) -> Result<GenericAccount, CodedError> {
	let account = match algorithm {
		"ed25519" => Account::<KeyED25519>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ED25519))
			.map(GenericAccount::Ed25519),
		"ecdsa_secp256k1" => {
			Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256K1))
				.map(GenericAccount::EcdsaSecp256k1)
		}
		"ecdsa_secp256r1" => {
			Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256R1))
				.map(GenericAccount::EcdsaSecp256r1)
		}
		_ => {
			let names: Vec<&str> = CRYPTO_ALGORITHMS.iter().map(|(name, _)| *name).collect();
			return Err(CodedError::new(
				"INVALID_ALGORITHM",
				format!("algorithm must be one of: {}", names.join(", ")),
			));
		}
	};

	account.map_err(|error| CodedError::new("ACCOUNT", error.as_ref()))
}

/// Generate a fresh random 32-byte seed as hex.
pub fn generate_seed() -> Result<String, CodedError> {
	let seed = Account::<KeyED25519>::generate_random_seed().map_err(|error| CodedError::new("RNG", error.as_ref()))?;
	Ok(hex::encode(seed.expose_secret()))
}

/// Generate a fresh BIP39 mnemonic.
pub fn generate_passphrase() -> Result<Vec<String>, CodedError> {
	let passphrase =
		Account::<KeyED25519>::generate_passphrase().map_err(|error| CodedError::new("RNG", error.as_ref()))?;
	Ok(passphrase.expose_secret().clone())
}

/// Derive an account from a 32-byte hex `seed` at derivation `index`.
pub fn account_from_seed(seed: &str, index: u32, algorithm: &str) -> Result<AccountRef, CodedError> {
	let mut bytes = [0u8; 32];
	hex::decode_to_slice(seed, &mut bytes).map_err(|_| CodedError::new("INVALID_SEED", "seed must be 32-byte hex"))?;
	keyable_account(Keyable::Seed((bytes.into_secret(), index)), algorithm)
}

/// Build an account from a hex-encoded private `key`.
pub fn account_from_private_key(key: &str, algorithm: &str) -> Result<AccountRef, CodedError> {
	let bytes = hex::decode(key).map_err(|_| CodedError::new("INVALID_PRIVATE_KEY", "private key must be hex"))?;
	keyable_account(Keyable::PrivateKey(bytes), algorithm)
}

/// Derive an account from a BIP39 mnemonic `words` at derivation `index`.
pub fn account_from_passphrase(words: Vec<String>, index: u32, algorithm: &str) -> Result<AccountRef, CodedError> {
	keyable_account(Keyable::from((words, index)), algorithm)
}

/// Build a read-only account from a hex-encoded public `key`.
pub fn account_from_public_key(key: &str, algorithm: &str) -> Result<AccountRef, CodedError> {
	let bytes = hex::decode(key).map_err(|_| CodedError::new("INVALID_PUBLIC_KEY", "public key must be hex"))?;
	keyable_account(Keyable::PublicKey(bytes), algorithm)
}

/// Build a read-only account from its textual `address`.
pub fn account_from_address(address: &str) -> Result<AccountRef, CodedError> {
	let account =
		GenericAccount::from_str(address).map_err(|_| CodedError::new("INVALID_ADDRESS", "invalid account address"))?;
	Ok(Arc::new(account))
}

/// The textual account address.
pub fn account_address(account: &AccountRef) -> String {
	account.to_string()
}

/// The signing algorithm name, or `"other"` for identifier accounts.
pub fn account_algorithm(account: &AccountRef) -> String {
	String::from(algorithm_name(account.to_keypair_type()))
}

/// The type-prefixed public key transport bytes, hex-encoded.
pub fn account_public_key(account: &AccountRef) -> String {
	hex::encode(account.to_public_key_with_type())
}

/// Sign `message`, returning the raw signature bytes.
pub fn account_sign(account: &AccountRef, message: &[u8]) -> Result<Vec<u8>, CodedError> {
	AccountSigner::sign(account.as_ref(), message, None).map_err(|error| CodedError::new("SIGN", error.as_ref()))
}

/// Whether `signature` is a valid signature of `message` by this account.
pub fn account_verify(account: &AccountRef, message: &[u8], signature: &[u8]) -> bool {
	account.verify(message, signature, None).is_ok()
}

/// Encrypt `plaintext` to the account's public key.
pub fn account_encrypt(account: &AccountRef, plaintext: &[u8]) -> Result<Vec<u8>, CodedError> {
	account
		.encrypt(plaintext)
		.map_err(|error| CodedError::new("ENCRYPT", error.as_ref()))
}

/// Decrypt `ciphertext` with the account's private key.
pub fn account_decrypt(account: &AccountRef, ciphertext: &[u8]) -> Result<Vec<u8>, CodedError> {
	account
		.decrypt(ciphertext)
		.map_err(|error| CodedError::new("DECRYPT", error.as_ref()))
}

fn keyable_account(keyable: Keyable, algorithm: &str) -> Result<AccountRef, CodedError> {
	let account = from_keyable(keyable, algorithm)?;
	Ok(Arc::new(account))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn algorithm_names_round_trip_every_crypto_type() {
		for (name, key_type) in CRYPTO_ALGORITHMS {
			assert_eq!(algorithm_name(key_type), name, "{name} must round-trip through KeyPairType");
		}
	}

	#[test]
	fn identifier_types_report_other() {
		assert_eq!(algorithm_name(KeyPairType::TOKEN), "other");
	}

	#[test]
	fn generated_seed_is_32_byte_hex() {
		let seed = generate_seed().expect("seed generation must succeed");
		assert_eq!(seed.len(), 64);
		assert!(hex::decode(&seed).is_ok());
	}

	#[test]
	fn account_round_trips_through_seed_and_address() {
		let seed = generate_seed().expect("seed generation must succeed");
		let account = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("account derivation must succeed");
		let address = account_address(&account);
		let reopened = account_from_address(&address).expect("address must parse");
		assert_eq!(account_address(&reopened), address);
		assert_eq!(account_algorithm(&account), DEFAULT_ALGORITHM);
	}

	#[test]
	fn signatures_verify_against_the_signing_account() {
		let seed = generate_seed().expect("seed generation must succeed");
		let account = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("account derivation must succeed");
		let message = b"keeta multisig";
		let signature = account_sign(&account, message).expect("signing must succeed");
		assert!(account_verify(&account, message, &signature));
		assert!(!account_verify(&account, b"tampered", &signature));
	}

	#[test]
	fn invalid_seed_is_rejected_with_a_stable_code() {
		let error = account_from_seed("not-hex", 0, DEFAULT_ALGORITHM).expect_err("invalid seed must fail");
		assert_eq!(error.code, "INVALID_SEED");
	}

	#[test]
	fn passphrase_account_derives_and_exposes_transport_public_key() {
		let words = generate_passphrase().expect("passphrase generation must succeed");
		let account = account_from_passphrase(words, 0, DEFAULT_ALGORITHM).expect("passphrase derivation must succeed");
		assert_eq!(account_algorithm(&account), DEFAULT_ALGORITHM);

		let public_key = account_public_key(&account);
		assert!(!public_key.is_empty());
		assert!(hex::decode(&public_key).is_ok());
	}

	#[test]
	fn encryption_round_trips_through_the_owning_account() {
		let seed = generate_seed().expect("seed generation must succeed");
		let account = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("derivation must succeed");

		let plaintext = b"keeta secret payload";
		let ciphertext = account_encrypt(&account, plaintext).expect("encryption must succeed");
		let recovered = account_decrypt(&account, &ciphertext).expect("decryption must succeed");
		assert_eq!(recovered, plaintext);
	}

	#[test]
	fn malformed_inputs_are_rejected_with_stable_codes() {
		assert_eq!(
			account_from_private_key("zz", DEFAULT_ALGORITHM)
				.expect_err("bad key must fail")
				.code,
			"INVALID_PRIVATE_KEY"
		);
		assert_eq!(
			account_from_public_key("zz", DEFAULT_ALGORITHM)
				.expect_err("bad key must fail")
				.code,
			"INVALID_PUBLIC_KEY"
		);
		assert_eq!(
			account_from_address("not-an-address")
				.expect_err("bad address must fail")
				.code,
			"INVALID_ADDRESS"
		);
	}
}
