//! Permission-set construction and projection shared across binding
//! boundaries.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use keetanetwork_block::{BaseFlag, Permissions};
use num_bigint::BigInt;

use crate::error::CodedError;
use crate::parse::base_flag_name;

/// Build a permission set from base `flags` and external bit `offsets`.
pub fn from_flags(flags: &[BaseFlag], offsets: &[u8]) -> Result<Permissions, CodedError> {
	Permissions::from_flags(flags, offsets).map_err(|error| CodedError::new("INVALID_PERMISSIONS", error.to_string()))
}

/// Decode a permission set from the on-chain `[base, external]` bitmaps.
pub fn from_bigints(base: BigInt, external: BigInt) -> Result<Permissions, CodedError> {
	Permissions::from_bigints(base, external).map_err(|error| CodedError::new("INVALID_PERMISSIONS", error.to_string()))
}

/// The base flag names present, after normalization.
pub fn flag_names(permissions: &Permissions) -> Vec<String> {
	permissions
		.base()
		.flags()
		.iter()
		.map(|flag| String::from(base_flag_name(*flag)))
		.collect()
}

/// The external bit offsets present, ascending.
pub fn offsets(permissions: &Permissions) -> Vec<u8> {
	let bits = permissions.external().as_bigint();
	(0..bits.bits())
		.filter(|offset| bits.bit(*offset))
		.map(|offset| offset as u8)
		.collect()
}

/// The `[base, external]` bitmaps as `0x`-prefixed hex.
pub fn bitmaps(permissions: &Permissions) -> Vec<String> {
	let base = permissions.base().as_bigint().to_str_radix(16);
	let external = permissions.external().as_bigint().to_str_radix(16);
	alloc::vec![format!("0x{base}"), format!("0x{external}")]
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parse::base_flag;

	#[test]
	fn empty_permissions_project_to_zero_bitmaps() {
		let permissions = from_flags(&[], &[]).expect("empty flags must build");
		assert_eq!(bitmaps(&permissions), alloc::vec![String::from("0x0"), String::from("0x0")]);
		assert!(flag_names(&permissions).is_empty());
		assert!(offsets(&permissions).is_empty());
	}

	#[test]
	fn a_known_flag_round_trips_through_projection() {
		let flag = base_flag("manage_certificate").expect("known flag must parse");
		let permissions = from_flags(&[flag], &[]).expect("flags must build");
		assert!(flag_names(&permissions)
			.iter()
			.any(|name| name == "manage_certificate"));
	}
}
