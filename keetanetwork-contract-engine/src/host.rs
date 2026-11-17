//! What the engine needs from whoever runs it: a representative, reading
//! its ledger.
//!
//! The engine keeps no state of its own between calls. Everything it reads
//! comes through [`Host`], and everything a call changes comes back in its
//! [`LedgerOutcome`](crate::LedgerOutcome), for the host to apply once the
//! call's block is on the ledger.
//!
//! Within one call the engine caches every read, so the host sees each key
//! at most once and the call sees one consistent view. A call must not see
//! the host's state change underneath it.

use num_bigint::BigUint;
use snafu::Snafu;

/// A host could not answer. Aborts the whole call.
#[derive(Debug, Snafu)]
#[snafu(display("{message}"))]
pub struct HostError {
	/// What went wrong
	pub message: String,
}

impl HostError {
	/// An error with this message.
	pub fn new(message: impl Into<String>) -> Self {
		Self { message: message.into() }
	}
}

/// Result of a host read.
pub type HostResult<T> = Result<T, HostError>;

/// SHA-256 of a contract's code (its sBPF ELF file).
pub type CodeHash = [u8; 32];

/// An account's `SET_INFO` fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountInfo {
	/// Account name
	pub name: String,
	/// Account description
	pub description: String,
	/// Free-form metadata
	pub metadata: String,
}

/// A deployed contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractRecord {
	/// The code it runs
	pub code_hash: CodeHash,
	/// Its account's name, description and metadata
	pub info: AccountInfo,
}

/// Read access to the ledger.
pub trait Host: Send + Sync {
	/// ELF bytes by hash. Asked for when the engine has not loaded the code
	/// yet, e.g. after a restart.
	fn code_bytes(&self, hash: &CodeHash) -> HostResult<Option<Vec<u8>>>;

	/// The contract at `address`, or `None` if there is none.
	fn contract(&self, address: &str) -> HostResult<Option<ContractRecord>>;

	/// The data of one of `contract`'s accounts, keyed by its 32-byte id.
	/// `None` for an account that does not exist (has no data).
	fn storage_get(&self, contract: &str, key: &[u8]) -> HostResult<Option<Vec<u8>>>;

	/// An account's balance of a token.
	fn balance(&self, account: &str, token: &str) -> HostResult<BigUint>;

	/// A token's total supply, or `None` if the token does not exist.
	fn token_supply(&self, token: &str) -> HostResult<Option<BigUint>>;

	/// Why the ledger would refuse a `SEND` of `token` from `from` to `to`,
	/// or `None` if it would accept one. Keeta requires `ACCESS` on the token
	/// for both accounts and, when `to` is a storage account,
	/// `STORAGE_CAN_HOLD` for the token and `STORAGE_DEPOSIT` for `from`.
	///
	/// The engine asks before each `SEND` a contract makes, and fails the
	/// call on a refusal. Answer from the ledger as it is before the call.
	fn send_refusal(&self, from: &str, to: &str, token: &str) -> HostResult<Option<String>>;
}
