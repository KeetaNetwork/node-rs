//! Account algorithm mapping and construction shared across binding boundaries.

use alloc::format;
use alloc::vec::Vec;

use keetanetwork_account::{
	Account, Accountable, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPairType, Keyable,
};

use crate::error::CodedError;

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
}
