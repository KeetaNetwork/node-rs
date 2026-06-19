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
