//! Boundary between the shared binding logic and the JS error carrier.

use alloc::string::String;

use keetanetwork_account::KeyPairType;
use keetanetwork_bindings::client as bindings_client;
use keetanetwork_bindings::error::CodedError;
use keetanetwork_bindings::parse;
use keetanetwork_block::{AdjustMethod, Amount, BaseFlag, BlockPurpose};
use keetanetwork_client::{ClientError, LedgerSide};
use num_bigint::BigInt;
use wasm_bindgen::JsValue;

/// Result whose error is a coded JavaScript `Error` (see module docs).
pub type JsResult<T> = Result<T, JsValue>;

pub use keetanetwork_bindings::parse::amount_to_string;

/// Parse a decimal integer string into an [`Amount`].
pub fn parse_amount(amount: &str) -> JsResult<Amount> {
	parse::amount(amount).map_err(rejected)
}

/// Parse a 32-byte hex string into a fixed array.
pub fn parse_hash32(value: &str, label: &str) -> JsResult<[u8; 32]> {
	parse::hash32(value, label).map_err(coded)
}

/// Parse a supply/balance/permission adjustment method.
pub fn parse_adjust_method(method: &str) -> JsResult<AdjustMethod> {
	parse::adjust_method(method).map_err(rejected)
}

/// Parse a ledger side selector, defaulting to the main ledger when absent.
pub fn parse_ledger_side(side: Option<String>) -> JsResult<Option<LedgerSide>> {
	bindings_client::ledger_side(side.as_deref()).map_err(coded)
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
	parse::bigint_hex(value, label).map_err(coded)
}

/// Build a JavaScript `Error` carrying a `code` property.
pub fn coded_error(code: &str, message: &str) -> JsValue {
	let error = js_sys::Error::new(message);
	let _ = js_sys::Reflect::set(&error, &JsValue::from_str("code"), &JsValue::from_str(code));
	error.into()
}

/// Project a shared [`CodedError`] onto a coded JavaScript `Error`.
pub fn coded(error: CodedError) -> JsValue {
	coded_error(&error.code, &error.message)
}

/// Convert a [`ClientError`] into a coded JavaScript `Error`.
pub fn client_error(error: ClientError) -> JsValue {
	coded(CodedError::from(error))
}

/// Project any shared parse failure onto a coded JavaScript `Error`.
fn rejected(error: parse::ParseError) -> JsValue {
	coded(CodedError::from(error))
}

#[cfg(all(test, target_family = "wasm"))]
mod wasm_tests {
	use super::*;
	use wasm_bindgen_test::wasm_bindgen_test;

	#[wasm_bindgen_test]
	fn coded_error_attaches_the_stable_code_property() {
		let error = coded_error("INVALID_LEDGER_SIDE", "side must be main, side, or both");
		let code = js_sys::Reflect::get(&error, &JsValue::from_str("code")).expect("code property must be readable");
		assert_eq!(code.as_string().as_deref(), Some("INVALID_LEDGER_SIDE"));
	}
}
