//! Pure parsing and rendering between JS-facing strings and the core domain
//! types. Kept free of `wasm-bindgen` so it compiles and testing coverage
//! can be properly computed.

#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]

use alloc::string::{String, ToString};
use core::str::FromStr;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{AdjustMethod, Amount, BaseFlag, BlockPurpose};
use num_bigint::BigInt;

/// Canonical map from JS permission flag name to base flag.
pub const BASE_FLAGS: [(&str, BaseFlag); 15] = [
	("access", BaseFlag::Access),
	("owner", BaseFlag::Owner),
	("admin", BaseFlag::Admin),
	("update_info", BaseFlag::UpdateInfo),
	("send_on_behalf", BaseFlag::SendOnBehalf),
	("token_admin_create", BaseFlag::TokenAdminCreate),
	("token_admin_supply", BaseFlag::TokenAdminSupply),
	("token_admin_modify_balance", BaseFlag::TokenAdminModifyBalance),
	("storage_create", BaseFlag::StorageCreate),
	("storage_can_hold", BaseFlag::StorageCanHold),
	("storage_deposit", BaseFlag::StorageDeposit),
	("permission_delegate_add", BaseFlag::PermissionDelegateAdd),
	("permission_delegate_remove", BaseFlag::PermissionDelegateRemove),
	("manage_certificate", BaseFlag::ManageCertificate),
	("multisig_signer", BaseFlag::MultisigSigner),
];

/// A rejected JS input, identified by the stable error code surfaced to JS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
	Amount,
	AdjustMethod,
	Purpose,
	IdentifierType,
	PermissionFlag,
}

impl ParseError {
	/// The stable `error.code` value JS consumers branch on.
	pub fn code(self) -> &'static str {
		match self {
			ParseError::Amount => "INVALID_AMOUNT",
			ParseError::AdjustMethod => "INVALID_ADJUST_METHOD",
			ParseError::Purpose => "INVALID_PURPOSE",
			ParseError::IdentifierType => "INVALID_IDENTIFIER_TYPE",
			ParseError::PermissionFlag => "INVALID_PERMISSION_FLAG",
		}
	}

	/// A human-readable explanation of the rejection.
	pub fn message(self) -> &'static str {
		match self {
			ParseError::Amount => "amount must be a decimal integer",
			ParseError::AdjustMethod => "method must be add, subtract, or set",
			ParseError::Purpose => "purpose must be generic or fee",
			ParseError::IdentifierType => {
				"identifier type must be network, token, or storage (use the multisig path for multisig)"
			}
			ParseError::PermissionFlag => "unknown base permission flag",
		}
	}
}

/// Parse a decimal integer string into an [`Amount`].
pub fn amount(value: &str) -> Result<Amount, ParseError> {
	Amount::from_str(value).map_err(|_| ParseError::Amount)
}

/// Render an [`Amount`] as a decimal integer string.
pub fn amount_to_string(amount: Amount) -> String {
	BigInt::from(amount).to_string()
}

/// Parse a supply/balance adjustment method.
pub fn adjust_method(method: &str) -> Result<AdjustMethod, ParseError> {
	match method {
		"add" => Ok(AdjustMethod::Add),
		"subtract" => Ok(AdjustMethod::Subtract),
		"set" => Ok(AdjustMethod::Set),
		_ => Err(ParseError::AdjustMethod),
	}
}

/// Parse a block purpose.
pub fn purpose(purpose: &str) -> Result<BlockPurpose, ParseError> {
	match purpose {
		"generic" => Ok(BlockPurpose::Generic),
		"fee" => Ok(BlockPurpose::Fee),
		_ => Err(ParseError::Purpose),
	}
}

/// Parse an identifier key type by its kind. Multisig identifiers are created
/// through the dedicated multisig path, which supplies the required arguments.
pub fn identifier_type(kind: &str) -> Result<KeyPairType, ParseError> {
	match kind {
		"network" => Ok(KeyPairType::NETWORK),
		"token" => Ok(KeyPairType::TOKEN),
		"storage" => Ok(KeyPairType::STORAGE),
		_ => Err(ParseError::IdentifierType),
	}
}

/// Parse a base permission flag by its snake_case name.
pub fn base_flag(flag: &str) -> Result<BaseFlag, ParseError> {
	BASE_FLAGS
		.iter()
		.find_map(|(name, candidate)| (*name == flag).then_some(*candidate))
		.ok_or(ParseError::PermissionFlag)
}

/// Render a base flag as its snake_case JS name.
pub fn base_flag_name(flag: BaseFlag) -> &'static str {
	BASE_FLAGS
		.iter()
		.find_map(|(name, candidate)| (*candidate == flag).then_some(*name))
		.unwrap_or("unknown")
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
	use super::*;

	#[test]
	fn amount_round_trips_decimal_strings() {
		let cases = ["0", "1", "1000", "1000000000"];
		for value in cases {
			let parsed = amount(value).expect("a decimal string must parse");
			assert_eq!(amount_to_string(parsed), value, "{value} must round-trip through Amount");
		}
	}

	#[test]
	fn amount_rejects_non_decimal_input() {
		let cases = ["", "abc", "1.5", "12x", "1 000"];
		for value in cases {
			assert!(matches!(amount(value), Err(ParseError::Amount)), "{value} must be rejected");
		}
	}

	#[test]
	fn adjust_method_parses_known_methods() {
		assert!(matches!(adjust_method("add"), Ok(AdjustMethod::Add)));
		assert!(matches!(adjust_method("subtract"), Ok(AdjustMethod::Subtract)));
		assert!(matches!(adjust_method("set"), Ok(AdjustMethod::Set)));
	}

	#[test]
	fn adjust_method_rejects_unknown_method() {
		assert!(matches!(adjust_method("multiply"), Err(ParseError::AdjustMethod)));
	}

	#[test]
	fn purpose_parses_known_purposes() {
		assert!(matches!(purpose("generic"), Ok(BlockPurpose::Generic)));
		assert!(matches!(purpose("fee"), Ok(BlockPurpose::Fee)));
	}

	#[test]
	fn purpose_rejects_unknown_purpose() {
		assert!(matches!(purpose("vote"), Err(ParseError::Purpose)));
	}

	#[test]
	fn identifier_type_parses_known_kinds() {
		assert!(matches!(identifier_type("network"), Ok(KeyPairType::NETWORK)));
		assert!(matches!(identifier_type("token"), Ok(KeyPairType::TOKEN)));
		assert!(matches!(identifier_type("storage"), Ok(KeyPairType::STORAGE)));
	}

	#[test]
	fn identifier_type_rejects_multisig_and_unknown() {
		let cases = ["multisig", "wallet", ""];
		for kind in cases {
			assert!(matches!(identifier_type(kind), Err(ParseError::IdentifierType)), "{kind} must be rejected");
		}
	}

	#[test]
	fn base_flag_names_round_trip_every_known_flag() {
		for (name, _) in BASE_FLAGS {
			let parsed = base_flag(name).expect("a known flag name must parse");
			assert_eq!(base_flag_name(parsed), name, "{name} must round-trip through BaseFlag");
		}
	}

	#[test]
	fn base_flag_rejects_unknown_name() {
		assert!(matches!(base_flag("definitely_not_a_flag"), Err(ParseError::PermissionFlag)));
	}

	#[test]
	fn parse_error_codes_are_stable() {
		let cases = [
			(ParseError::Amount, "INVALID_AMOUNT"),
			(ParseError::AdjustMethod, "INVALID_ADJUST_METHOD"),
			(ParseError::Purpose, "INVALID_PURPOSE"),
			(ParseError::IdentifierType, "INVALID_IDENTIFIER_TYPE"),
			(ParseError::PermissionFlag, "INVALID_PERMISSION_FLAG"),
		];
		for (error, code) in cases {
			assert_eq!(error.code(), code, "the {error:?} code must stay stable for JS consumers");
		}
	}
}
