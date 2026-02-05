//! # Keetanetwork Permissions
//!
//! Permission bit definitions for the Keetanetwork blockchain.

#![no_std]

// Base permission bit constants
pub const ACCESS: u64 = 1 << 0;
pub const OWNER: u64 = 1 << 1;
pub const ADMIN: u64 = 1 << 2;
pub const UPDATE_INFO: u64 = 1 << 3;
pub const SEND_ON_BEHALF: u64 = 1 << 4;
pub const TOKEN_CREATE: u64 = 1 << 5;
pub const TOKEN_SUPPLY: u64 = 1 << 6;
pub const TOKEN_BALANCE: u64 = 1 << 7;
pub const STORAGE_CREATE: u64 = 1 << 8;
pub const STORAGE_HOLD: u64 = 1 << 9;
pub const STORAGE_DEPOSIT: u64 = 1 << 10;
pub const PERM_ADD: u64 = 1 << 11;
pub const PERM_REMOVE: u64 = 1 << 12;
pub const MANAGE_CERT: u64 = 1 << 13;
pub const MULTISIG_SIGNER: u64 = 1 << 14;

/// Lookup table mapping each base permission bit to its display name.
pub const BASE_PERMISSIONS: [(u64, &str); 15] = [
	(ACCESS, "ACCESS"),
	(OWNER, "OWNER"),
	(ADMIN, "ADMIN"),
	(UPDATE_INFO, "INFO"),
	(SEND_ON_BEHALF, "SEND"),
	(TOKEN_CREATE, "T_CREATE"),
	(TOKEN_SUPPLY, "T_SUPPLY"),
	(TOKEN_BALANCE, "T_BALANCE"),
	(STORAGE_CREATE, "S_CREATE"),
	(STORAGE_HOLD, "S_HOLD"),
	(STORAGE_DEPOSIT, "S_DEPOSIT"),
	(PERM_ADD, "P_ADD"),
	(PERM_REMOVE, "P_REMOVE"),
	(MANAGE_CERT, "CERT"),
	(MULTISIG_SIGNER, "MULTISIG"),
];

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn no_duplicate_bits() {
		let mut combined = 0u64;
		for &(mask, _) in &BASE_PERMISSIONS {
			assert_eq!(combined & mask, 0, "duplicate bit in BASE_PERMISSIONS");
			combined |= mask;
		}
	}

	#[test]
	fn all_bits_contiguous() {
		let mut combined = 0u64;
		for &(mask, _) in &BASE_PERMISSIONS {
			combined |= mask;
		}
		assert_eq!(combined, (1 << 15) - 1);
	}
}
