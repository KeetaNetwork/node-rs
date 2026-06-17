//! Internal helpers for working with [`GenericAccount`] values.

use hex::FromHex;
use keetanetwork_account::{AccountError, GenericAccount};

use crate::error::BlockError;

/// Dispatch an expression across all [`GenericAccount`] variants.
macro_rules! with_account_variants {
	($account:expr, $inner:ident, $expr:expr) => {
		match $account {
			GenericAccount::EcdsaSecp256k1($inner) => $expr,
			GenericAccount::EcdsaSecp256r1($inner) => $expr,
			GenericAccount::Ed25519($inner) => $expr,
			GenericAccount::Network($inner) => $expr,
			GenericAccount::Token($inner) => $expr,
			GenericAccount::Storage($inner) => $expr,
			GenericAccount::Multisig($inner) => $expr,
		}
	};
}

/// Parse a `[key_type_byte || raw_public_key]` buffer into an account.
pub(crate) fn parse_account_with_type(bytes: &[u8]) -> Result<GenericAccount, BlockError> {
	Ok(GenericAccount::from_hex(hex::encode(bytes))?)
}

/// Verify a signature against a message for any account variant.
pub(crate) fn verify_account(account: &GenericAccount, message: &[u8], signature: &[u8]) -> Result<(), AccountError> {
	with_account_variants!(account, inner, inner.verify(message, signature, None))
}

/// Whether two accounts share the same public key and type.
pub(crate) fn accounts_equal(left: &GenericAccount, right: &GenericAccount) -> bool {
	left.to_public_key_with_type() == right.to_public_key_with_type()
}

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_account::account::AccountSigner;
	use keetanetwork_account::{Account, Accountable, KeyED25519, KeyPairType, Keyable};
	use keetanetwork_crypto::prelude::IntoSecret;

	fn test_account(seed_byte: u8) -> GenericAccount {
		let seed = [seed_byte; 32].into_secret();
		let account =
			Account::<KeyED25519>::try_from(Accountable::KeyAndType(Keyable::Seed((seed, 0)), KeyPairType::ED25519))
				.expect("test account construction must succeed");
		GenericAccount::Ed25519(account)
	}

	fn signed_message(account: &GenericAccount, message: [u8; 32]) -> Vec<u8> {
		account
			.sign(message, None)
			.expect("test signing must succeed")
	}

	#[test]
	fn test_account_roundtrip_through_transport_bytes() -> Result<(), BlockError> {
		let account = test_account(5);
		let bytes = account.to_public_key_with_type();
		let parsed = parse_account_with_type(&bytes)?;
		assert_eq!(parsed.to_string(), account.to_string());
		assert!(accounts_equal(&parsed, &account));
		Ok(())
	}

	#[test]
	fn test_parse_rejects_unknown_type_byte() {
		assert!(parse_account_with_type(&[5u8, 1, 2, 3]).is_err());
		assert!(parse_account_with_type(&[]).is_err());
	}

	#[test]
	fn test_verify_account_roundtrip() {
		let account = test_account(9);
		let message = [1u8; 32];
		let signature = signed_message(&account, message);

		assert!(verify_account(&account, &message, &signature).is_ok());
		assert!(verify_account(&account, &[2u8; 32], &signature).is_err());
	}
}
