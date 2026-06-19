//! Shared conversions between the core client types and the JS boundary.
//!
//! Errors cross the boundary as JavaScript `Error` objects carrying a stable
//! `code` property (`error.code`), so consumers can branch programmatically
//! instead of string-matching the message.

use alloc::string::{String, ToString};
use core::str::FromStr;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{AdjustMethod, Amount, BaseFlag, BlockPurpose};
use keetanetwork_client::ClientError;
use num_bigint::BigInt;
use wasm_bindgen::JsValue;

/// Result whose error is a coded JavaScript `Error` (see module docs).
pub type JsResult<T> = Result<T, JsValue>;

/// Canonical map from JS permission flag name to base flag. Single source of
/// truth for both parsing names and rendering them.
const BASE_FLAGS: [(&str, BaseFlag); 15] = [
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

/// Parse a decimal integer string into an [`Amount`].
pub fn parse_amount(amount: &str) -> JsResult<Amount> {
	Amount::from_str(amount).map_err(|_| coded_error("INVALID_AMOUNT", "amount must be a decimal integer"))
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
	match method {
		"add" => Ok(AdjustMethod::Add),
		"subtract" => Ok(AdjustMethod::Subtract),
		"set" => Ok(AdjustMethod::Set),
		_ => Err(coded_error("INVALID_ADJUST_METHOD", "method must be add, subtract, or set")),
	}
}

/// Parse a block purpose.
pub fn parse_purpose(purpose: &str) -> JsResult<BlockPurpose> {
	match purpose {
		"generic" => Ok(BlockPurpose::Generic),
		"fee" => Ok(BlockPurpose::Fee),
		_ => Err(coded_error("INVALID_PURPOSE", "purpose must be generic or fee")),
	}
}

/// Parse an identifier key type by its kind. Multisig identifiers are created
/// through the dedicated multisig path, which supplies the required arguments.
pub fn parse_identifier_type(kind: &str) -> JsResult<KeyPairType> {
	match kind {
		"network" => Ok(KeyPairType::NETWORK),
		"token" => Ok(KeyPairType::TOKEN),
		"storage" => Ok(KeyPairType::STORAGE),
		_ => Err(coded_error(
			"INVALID_IDENTIFIER_TYPE",
			"identifier type must be network, token, or storage (use the multisig path for multisig)",
		)),
	}
}

/// Parse a base permission flag by its snake_case name.
pub fn parse_base_flag(flag: &str) -> JsResult<BaseFlag> {
	BASE_FLAGS
		.iter()
		.find_map(|(name, candidate)| (*name == flag).then_some(*candidate))
		.ok_or_else(|| coded_error("INVALID_PERMISSION_FLAG", "unknown base permission flag"))
}

/// Render a base flag as its snake_case JS name.
pub fn base_flag_name(flag: BaseFlag) -> &'static str {
	BASE_FLAGS
		.iter()
		.find_map(|(name, candidate)| (*candidate == flag).then_some(*name))
		.unwrap_or("unknown")
}

/// Parse a `0x`-prefixed (or bare) hexadecimal string into a [`BigInt`].
pub fn parse_bigint_hex(value: &str, label: &str) -> JsResult<BigInt> {
	let digits = value.strip_prefix("0x").unwrap_or(value);
	BigInt::parse_bytes(digits.as_bytes(), 16)
		.ok_or_else(|| coded_error("INVALID_INTEGER", &alloc::format!("{label} must be 0x-hex")))
}

/// Render an [`Amount`] as a decimal integer string.
pub fn amount_to_string(amount: Amount) -> String {
	BigInt::from(amount).to_string()
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
