//! Documentation utilities for accounts examples.
//!
//! This module provides helper functions that are only available during
//! documentation generation. These helpers reduce code duplication in
//! documentation examples and provide consistent test data.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use keetanetwork_crypto::algorithms::ed25519::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
use keetanetwork_crypto::algorithms::secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};
use keetanetwork_crypto::algorithms::secp256r1::{Secp256r1Derivation, Secp256r1PrivateKey, Secp256r1PublicKey};
use keetanetwork_crypto::prelude::{IntoSecret, KeyDerivation, PrivateKey};

use crate::{Account, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyNETWORK};

/// Standard test seed for consistent documentation examples.
pub const DOC_TEST_SEED: &[u8] = b"abandon abandon abandon abandon abandon abandon abandon abandon";

/// Macro to create test key functions for different cryptographic algorithms.
macro_rules! create_test_keys_fn {
	(
		$(#[$attr:meta])*
		$fn_name:ident,
		$derivation:ty,
		$private_key:ty,
		$public_key:ty,
		$account_type:ty,
		$algorithm:literal
	) => {
		$(#[$attr])*
		///
		/// Returns (private_key, public_key, account) tuple with all the cryptographic
		/// components needed for documentation examples.
		pub fn $fn_name(seed: Option<&[u8]>) -> ($private_key, $public_key, Account<$account_type>) {
			let seed = seed.unwrap_or(DOC_TEST_SEED);
			let private_key = <$derivation>::derive_from_seed(seed.to_vec().into_secret())
				.expect(&format!("Failed to derive {} test private key", $algorithm));
			let public_key = private_key.as_public_key();

			// Create a second private key for the account since From consumes the original
			let account_private_key = <$derivation>::derive_from_seed(seed.to_vec().into_secret())
				.expect(&format!("Failed to derive {} test private key for account", $algorithm));
			let account = Account::from(account_private_key);

			(private_key, public_key, account)
		}
	};
}

// Generate test key creation functions for each supported algorithm
create_test_keys_fn!(
	/// Create Ed25519 test keys for documentation examples.
	create_ed25519_test_keys,
	Ed25519Derivation,
	Ed25519PrivateKey,
	Ed25519PublicKey,
	KeyED25519,
	"Ed25519"
);

create_test_keys_fn!(
	/// Create secp256k1 test keys for documentation examples.
	create_secp256k1_test_keys,
	Secp256k1Derivation,
	Secp256k1PrivateKey,
	Secp256k1PublicKey,
	KeyECDSASECP256K1,
	"secp256k1"
);

create_test_keys_fn!(
	/// Create secp256r1 test keys for documentation examples.
	create_secp256r1_test_keys,
	Secp256r1Derivation,
	Secp256r1PrivateKey,
	Secp256r1PublicKey,
	KeyECDSASECP256R1,
	"secp256r1"
);

/// Create a network identifier account for documentation examples.
///
/// Returns a network identifier account with a deterministic address.
pub fn create_network_test_account(network_id: Option<u64>) -> Account<KeyNETWORK> {
	let id = network_id.unwrap_or(12345);
	Account::<KeyNETWORK>::generate_network_address(id).expect("Failed to generate network address")
}

/// Create a test passphrase for seed derivation examples.
///
/// Returns a standard BIP39-style test passphrase that can be used
/// consistently across documentation examples.
pub fn create_test_passphrase() -> Vec<String> {
	vec![
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"abandon".to_string(),
		"art".to_string(),
	]
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{KeyPair, KeyPairType};

	#[test]
	fn test_create_ed25519_test_keys() {
		let (private_key, public_key, account) = create_ed25519_test_keys(None);
		assert_eq!(public_key, private_key.as_public_key());
		assert_eq!(account.keypair.to_public_key(), public_key);
		assert_eq!(account.keypair.to_keypair_type(), KeyPairType::ED25519);
	}

	#[test]
	fn test_create_secp256k1_test_keys() {
		let (private_key, public_key, account) = create_secp256k1_test_keys(None);
		assert_eq!(public_key, private_key.as_public_key());
		assert_eq!(account.keypair.to_public_key(), public_key);
		assert_eq!(account.keypair.to_keypair_type(), KeyPairType::ECDSASECP256K1);
	}

	#[test]
	fn test_create_secp256r1_test_keys() {
		let (private_key, public_key, account) = create_secp256r1_test_keys(None);
		assert_eq!(public_key, private_key.as_public_key());
		assert_eq!(account.keypair.to_public_key(), public_key);
		assert_eq!(account.keypair.to_keypair_type(), KeyPairType::ECDSASECP256R1);
	}

	#[test]
	fn test_create_network_test_account() {
		let account = create_network_test_account(Some(5));
		assert_eq!(account.keypair.to_keypair_type(), KeyPairType::NETWORK);
		assert!(account.is_identifier());
	}

	#[test]
	fn test_create_test_passphrase() {
		let passphrase = create_test_passphrase();
		assert_eq!(passphrase.len(), 12);
		assert_eq!(passphrase[0], "abandon");
		assert_eq!(passphrase[11], "art");
	}
}
