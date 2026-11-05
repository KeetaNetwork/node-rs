//! Keeta addresses as CosmWasm addresses.
//!
//! The human form is the usual `keeta_…` string; the canonical form is the
//! key-type byte followed by the public key, which is what the ledger
//! stores for an account.

use std::str::FromStr;

use cosmwasm_vm::{BackendApi, BackendError, BackendResult, GasInfo};
use hex::FromHex;
use keetanetwork_account::{AccountPublicKey, GenericAccount, KeyPairType};

use crate::error::EngineError;

/// Placeholder price of an address conversion, in CosmWasm gas.
const ADDRESS_GAS: u64 = 1_000_000;

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

/// Whether the account is an identifier (token, storage, …) rather than a
/// key pair, i.e. whether its blocks are signed by someone else.
pub fn is_identifier(address: &str) -> bool {
	parse_account(address)
		.map(|account| account.to_keypair_type().is_identifier())
		.unwrap_or(false)
}

/// The `addr_*` functions contracts reach through `deps.api`.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeetaApi;

impl BackendApi for KeetaApi {
	fn addr_validate(&self, input: &str) -> BackendResult<()> {
		let result = parse_account(input)
			.map(|_| ())
			.map_err(|error| BackendError::user_err(error.to_string()));
		(result, GasInfo::with_cost(ADDRESS_GAS))
	}

	fn addr_canonicalize(&self, human: &str) -> BackendResult<Vec<u8>> {
		let result = parse_account(human)
			.map(|account| account.to_public_key_with_type())
			.map_err(|error| BackendError::user_err(error.to_string()));
		(result, GasInfo::with_cost(ADDRESS_GAS))
	}

	fn addr_humanize(&self, canonical: &[u8]) -> BackendResult<String> {
		let result = GenericAccount::from_hex(hex::encode(canonical))
			.map(|account| account.to_string())
			.map_err(|error| BackendError::user_err(format!("invalid canonical address: {error}")));
		(result, GasInfo::with_cost(ADDRESS_GAS))
	}
}

#[cfg(test)]
mod tests {
	use keetanetwork_block::testing::generate_ed25519_ref;

	use super::*;

	#[test]
	fn round_trips_through_canonical_form() {
		let address = generate_ed25519_ref(1).to_string();
		let (canonical, _) = KeetaApi.addr_canonicalize(&address);
		let canonical = canonical.unwrap();
		let (human, _) = KeetaApi.addr_humanize(&canonical);
		assert_eq!(human.unwrap(), address);
	}

	#[test]
	fn rejects_garbage_and_non_canonical_spellings() {
		assert!(KeetaApi.addr_validate("cosmos1abc").0.is_err());
		let address = generate_ed25519_ref(1).to_string();
		assert!(KeetaApi.addr_validate(&address).0.is_ok());
		assert!(KeetaApi.addr_validate(&address.to_uppercase()).0.is_err());
	}
}
