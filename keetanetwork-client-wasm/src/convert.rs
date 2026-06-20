//! Shared conversions between the core client types and the JS boundary.
//!
//! Errors cross the boundary as JavaScript `Error` objects carrying a stable
//! `code` property (`error.code`), so consumers can branch programmatically
//! instead of string-matching the message.

use alloc::string::String;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{AdjustMethod, Amount, BaseFlag, BlockPurpose};
use keetanetwork_client::{ClientError, LedgerSide};
use num_bigint::BigInt;
use wasm_bindgen::JsValue;

use crate::parse::{self, ParseError};

/// Result whose error is a coded JavaScript `Error` (see module docs).
pub type JsResult<T> = Result<T, JsValue>;

pub use crate::parse::{amount_to_string, base_flag_name};

/// Map a pure [`ParseError`] onto a coded JavaScript `Error`.
fn rejected(error: ParseError) -> JsValue {
	coded_error(error.code(), error.message())
}

/// Parse a decimal integer string into an [`Amount`].
pub fn parse_amount(amount: &str) -> JsResult<Amount> {
	parse::amount(amount).map_err(rejected)
}

/// Parse a 32-byte hex string into a fixed array.
pub fn parse_hash32(value: &str, label: &str) -> JsResult<[u8; 32]> {
	let mut bytes = [0u8; 32];
	hex::decode_to_slice(value, &mut bytes)
		.map(|()| bytes)
		.map_err(|_| coded_error("INVALID_HASH", &alloc::format!("{label} must be 32-byte hex")))
}

/// Parse a supply/balance/permission adjustment method.
pub fn parse_adjust_method(method: &str) -> JsResult<AdjustMethod> {
	parse::adjust_method(method).map_err(rejected)
}

/// Parse a ledger side selector, defaulting to the main ledger when absent.
pub fn parse_ledger_side(side: Option<String>) -> JsResult<Option<LedgerSide>> {
	match side.as_deref() {
		None => Ok(None),
		Some("main") => Ok(Some(LedgerSide::Main)),
		Some("side") => Ok(Some(LedgerSide::Side)),
		Some("both") => Ok(Some(LedgerSide::Both)),
		Some(_) => Err(coded_error("INVALID_LEDGER_SIDE", "side must be main, side, or both")),
	}
}

/// Parse a block purpose.
pub fn parse_purpose(purpose: &str) -> JsResult<BlockPurpose> {
	parse::purpose(purpose).map_err(rejected)
}

/// Parse an identifier key type by its kind. Multisig identifiers are created
/// through the dedicated multisig path, which supplies the required arguments.
pub fn parse_identifier_type(kind: &str) -> JsResult<KeyPairType> {
	parse::identifier_type(kind).map_err(rejected)
}

/// Parse a base permission flag by its snake_case name.
pub fn parse_base_flag(flag: &str) -> JsResult<BaseFlag> {
	parse::base_flag(flag).map_err(rejected)
}

/// Parse a `0x`-prefixed (or bare) hexadecimal string into a [`BigInt`].
pub fn parse_bigint_hex(value: &str, label: &str) -> JsResult<BigInt> {
	let digits = value.strip_prefix("0x").unwrap_or(value);
	BigInt::parse_bytes(digits.as_bytes(), 16)
		.ok_or_else(|| coded_error("INVALID_INTEGER", &alloc::format!("{label} must be 0x-hex")))
}

/// Build a JavaScript `Error` carrying a `code` property.
pub fn coded_error(code: &str, message: &str) -> JsValue {
	let error = js_sys::Error::new(message);
	let _ = js_sys::Reflect::set(&error, &JsValue::from_str("code"), &JsValue::from_str(code));
	error.into()
}

/// Convert a [`ClientError`] into a coded JavaScript `Error`. The message walks
/// the source chain; the `code` is [`ClientError::code`].
pub fn client_error(error: ClientError) -> JsValue {
	let mut message = error.to_string();
	let mut source = core::error::Error::source(&error);
	while let Some(inner) = source {
		message.push_str(": ");
		message.push_str(&inner.to_string());
		source = inner.source();
	}

	coded_error(error.code(), &message)
}

#[cfg(all(test, target_family = "wasm"))]
mod wasm_tests {
	use super::*;
	use wasm_bindgen_test::wasm_bindgen_test;

	#[wasm_bindgen_test]
	fn ledger_side_parses_each_known_side() {
		assert!(matches!(parse_ledger_side(None), Ok(None)));
		assert!(matches!(parse_ledger_side(Some(String::from("main"))), Ok(Some(LedgerSide::Main))));
		assert!(matches!(parse_ledger_side(Some(String::from("side"))), Ok(Some(LedgerSide::Side))));
		assert!(matches!(parse_ledger_side(Some(String::from("both"))), Ok(Some(LedgerSide::Both))));
	}

	#[wasm_bindgen_test]
	fn ledger_side_rejects_an_unknown_side() {
		let rejected = parse_ledger_side(Some(String::from("galaxy")));
		assert!(rejected.is_err());
	}

	#[wasm_bindgen_test]
	fn hash32_round_trips_valid_hex_and_rejects_bad_length() {
		let valid = parse_hash32(&"ab".repeat(32), "hash");
		assert!(matches!(valid, Ok(bytes) if bytes == [0xabu8; 32]));
		assert!(parse_hash32("zz", "hash").is_err());
	}

	#[wasm_bindgen_test]
	fn bigint_hex_parses_prefixed_and_bare_input() {
		let prefixed = parse_bigint_hex("0xff", "value").expect("prefixed hex must parse");
		let bare = parse_bigint_hex("ff", "value").expect("bare hex must parse");
		assert_eq!(prefixed, bare);
		assert_eq!(prefixed, BigInt::from(255u8));
		assert!(parse_bigint_hex("xy", "value").is_err());
	}

	#[wasm_bindgen_test]
	fn coded_error_attaches_the_stable_code_property() {
		let error = coded_error("INVALID_LEDGER_SIDE", "side must be main, side, or both");
		let code = js_sys::Reflect::get(&error, &JsValue::from_str("code")).expect("code property must be readable");
		assert_eq!(code.as_string().as_deref(), Some("INVALID_LEDGER_SIDE"));
	}
}
