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
use serde::Serialize;
use wasm_bindgen::JsValue;

/// Result whose error is a coded JavaScript `Error` (see module docs).
pub type JsResult<T> = Result<T, JsValue>;

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
	match flag {
		"access" => Ok(BaseFlag::Access),
		"owner" => Ok(BaseFlag::Owner),
		"admin" => Ok(BaseFlag::Admin),
		"update_info" => Ok(BaseFlag::UpdateInfo),
		"send_on_behalf" => Ok(BaseFlag::SendOnBehalf),
		"token_admin_create" => Ok(BaseFlag::TokenAdminCreate),
		"token_admin_supply" => Ok(BaseFlag::TokenAdminSupply),
		"token_admin_modify_balance" => Ok(BaseFlag::TokenAdminModifyBalance),
		"storage_create" => Ok(BaseFlag::StorageCreate),
		"storage_can_hold" => Ok(BaseFlag::StorageCanHold),
		"storage_deposit" => Ok(BaseFlag::StorageDeposit),
		"permission_delegate_add" => Ok(BaseFlag::PermissionDelegateAdd),
		"permission_delegate_remove" => Ok(BaseFlag::PermissionDelegateRemove),
		"manage_certificate" => Ok(BaseFlag::ManageCertificate),
		"multisig_signer" => Ok(BaseFlag::MultisigSigner),
		_ => Err(coded_error("INVALID_PERMISSION_FLAG", "unknown base permission flag")),
	}
}

/// Render an [`Amount`] as a decimal integer string.
pub fn amount_to_string(amount: Amount) -> String {
	BigInt::from(amount).to_string()
}

/// Serialize a value to a plain JS object.
pub fn to_js<T: Serialize>(value: &T) -> JsResult<JsValue> {
	serde_wasm_bindgen::to_value(value).map_err(|error| coded_error("SERIALIZE", &error.to_string()))
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
