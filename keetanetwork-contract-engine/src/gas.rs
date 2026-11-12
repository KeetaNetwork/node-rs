//! Gas, in compute units.
//!
//! As on Solana, every sBPF instruction costs one unit, and host functions
//! charge for their work on top. The numbers follow Solana's schedule where
//! there is an equivalent (host function base cost, invocation, hashing,
//! memory operations); storage and ledger operations, which Solana prices
//! through rent and fees instead, are provisional.

/// Every host function call.
pub const SYSCALL: u64 = 100;

/// Bytes copied, compared or set per unit (memory host functions, return
/// data, instruction data).
pub const BYTES_PER_UNIT: u64 = 250;

/// Running a contract: each top-level call and each invocation.
pub const INVOKE: u64 = 1_000;

/// SHA-256, plus one unit per two bytes hashed.
pub const SHA256: u64 = 85;

/// Loading an account into an invocation, plus one unit per 32 bytes.
pub const ACCOUNT_LOAD: u64 = 100;

/// Writing a changed account, plus one unit per 8 bytes.
pub const ACCOUNT_WRITE: u64 = 1_000;

/// A ledger effect: `SEND` or `SET_INFO`.
pub const LEDGER: u64 = 1_000;

/// Gas for handling `bytes` bytes of memory.
pub fn bytes(bytes: usize) -> u64 {
	bytes as u64 / BYTES_PER_UNIT
}

/// Gas for hashing `bytes` bytes.
pub fn sha256(bytes: usize) -> u64 {
	SHA256 + bytes as u64 / 2
}

/// Gas for loading an account of `bytes` bytes.
pub fn account_load(bytes: usize) -> u64 {
	ACCOUNT_LOAD + bytes as u64 / 32
}

/// Gas for writing an account of `bytes` bytes.
pub fn account_write(bytes: usize) -> u64 {
	ACCOUNT_WRITE + bytes as u64 / 8
}
