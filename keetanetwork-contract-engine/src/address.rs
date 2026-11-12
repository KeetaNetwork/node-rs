//! Keeta addresses, as text and as contracts see them.
//!
//! The text form is the usual `keeta_…` string. Contracts see an
//! [`Address`]: the key type byte and public key, which is what the ledger
//! stores for an account.

use std::str::FromStr;

use hex::FromHex;
use keetanetwork_account::{AccountPublicKey, GenericAccount, KeyPairType};
use keetanetwork_contract_std::Address;

use crate::error::EngineError;

/// Parse an address, accepting only its canonical textual form so that each
/// account has exactly one valid spelling.
pub fn parse_account(address: &str) -> Result<GenericAccount, EngineError> {
	let account = GenericAccount::from_str(address)
		.map_err(|error| EngineError::InvalidAddress { address: address.to_string(), reason: error.to_string() })?;
	if account.to_string() != address {
		return Err(EngineError::InvalidAddress {
			address: address.to_string(),
			reason: "not in canonical form".into(),
		});
	}
	Ok(account)
}

/// Parse an address and require it to be of a given kind.
pub fn parse_account_of(address: &str, kind: KeyPairType) -> Result<GenericAccount, EngineError> {
	let account = parse_account(address)?;
	if account.to_keypair_type() != kind {
		return Err(EngineError::InvalidAddress {
			address: address.to_string(),
			reason: format!("expected a {kind:?} account"),
		});
	}
	Ok(account)
}

/// An address as contracts see it.
pub fn to_address(account: &str) -> Result<Address, EngineError> {
	let parsed = parse_account(account)?;
	Address::from_raw(&parsed.to_public_key_with_type()).ok_or_else(|| EngineError::InvalidAddress {
		address: account.to_string(),
		reason: "key type has no contract address form".into(),
	})
}

/// The text form of an address a contract gave.
pub fn from_address(address: &Address) -> Result<String, EngineError> {
	let invalid = |reason: String| EngineError::InvalidAddress { address: format!("{address:?}"), reason };
	let raw = address
		.to_raw()
		.ok_or_else(|| invalid("unknown key type or non-zero padding".into()))?;
	GenericAccount::from_hex(hex::encode(raw))
		.map(|account| account.to_string())
		.map_err(|error| invalid(error.to_string()))
}

#[cfg(test)]
mod tests {
	use keetanetwork_block::testing::generate_ed25519_ref;

	use super::*;

	#[test]
	fn round_trips_through_contract_form() {
		let address = generate_ed25519_ref(1).to_string();
		assert_eq!(from_address(&to_address(&address).unwrap()).unwrap(), address);
	}

	#[test]
	fn rejects_garbage_and_non_canonical_spellings() {
		assert!(parse_account("cosmos1abc").is_err());
		let address = generate_ed25519_ref(1).to_string();
		assert!(parse_account(&address).is_ok());
		assert!(parse_account(&address.to_uppercase()).is_err());
		assert!(from_address(&Address([0xff; 34])).is_err());
	}
}
