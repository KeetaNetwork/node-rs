#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use snafu::prelude::*;

/// The category of a node-emitted error, taken from the `type` field of the
/// error envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeErrorType {
	Account,
	Api,
	Block,
	Certificate,
	Client,
	Kv,
	Ledger,
	Permissions,
	Vote,
	/// Any type the node reports that this build does not recognize.
	#[default]
	Generic,
}

impl From<&str> for NodeErrorType {
	fn from(value: &str) -> Self {
		match value {
			"ACCOUNT" => Self::Account,
			"API" => Self::Api,
			"BLOCK" => Self::Block,
			"CERTIFICATE" => Self::Certificate,
			"CLIENT" => Self::Client,
			"KV" => Self::Kv,
			"LEDGER" => Self::Ledger,
			"PERMISSIONS" => Self::Permissions,
			"VOTE" => Self::Vote,
			_ => Self::Generic,
		}
	}
}

/// Full (`LEDGER_`-prefixed) codes that carry conflicting accounts.
const LEDGER_VOTE_CODES: [&str; 2] = ["LEDGER_NOT_SUCCESSOR", "LEDGER_NOT_OPENING"];

/// Full (`LEDGER_`-prefixed) codes that carry idempotent-key collision data.
const LEDGER_IDEMPOTENT_CODES: [&str; 1] = ["LEDGER_IDEMPOTENT_KEY_EXISTS"];

/// The fields decoded from a node error envelope, used to construct the typed
/// [`KeetaNetError`]. Only LEDGER errors populate the extras; other categories
/// collapse to a coded carrier, matching the reference.
#[derive(Debug, Default)]
pub struct NodeErrorParts {
	/// Error category from the `type` field.
	pub kind: NodeErrorType,
	/// Full error code (e.g. `LEDGER_SUCCESSOR_VOTE_EXISTS`).
	pub code: String,
	/// Human-readable message.
	pub message: String,
	/// Whether the operation may be retried (LEDGER base errors).
	pub should_retry: bool,
	/// Suggested retry delay in milliseconds, when retryable.
	pub retry_delay: Option<u64>,
	/// Accounts party to a vote conflict (LEDGER vote errors).
	pub accounts: Vec<String>,
	/// The block hash being published (LEDGER idempotent errors).
	pub blockhash: Option<String>,
	/// The pre-existing block hash for the idempotent key.
	pub existing_blockhash: Option<String>,
	/// The account the idempotent key belongs to.
	pub account: Option<String>,
	/// The idempotent key bytes.
	pub idempotent_key: Option<Vec<u8>>,
}

/// A unified error carrying either an internal failure or a node-emitted coded
/// error. Domain crates bridge their validation errors into [`Self::Code`].
#[derive(Debug, Snafu)]
pub enum KeetaNetError {
	/// An internal invariant was violated.
	#[snafu(display("internal error"))]
	Internal,
	/// An error with no recognized code.
	#[snafu(display("{msg}"))]
	Unknown {
		/// Description of the failure.
		msg: String,
	},
	/// The requested functionality is not implemented.
	#[snafu(display("not implemented"))]
	NotImplemented,
	/// A coded node error with no further structure.
	#[snafu(display("{code}: {message}"))]
	Code {
		/// Full error code.
		code: String,
		/// Human-readable message.
		message: String,
	},
	/// A ledger error that may be retryable.
	#[snafu(display("{code}: {message}"))]
	Ledger {
		/// Full error code.
		code: String,
		/// Human-readable message.
		message: String,
		/// Whether the operation may be retried.
		should_retry: bool,
		/// Suggested retry delay in milliseconds, when retryable.
		retry_delay: Option<u64>,
	},
	/// A ledger vote conflict naming the contended accounts.
	#[snafu(display("{code}: {message}"))]
	LedgerVote {
		/// Full error code.
		code: String,
		/// Human-readable message.
		message: String,
		/// Accounts party to the conflict.
		accounts: Vec<String>,
	},
	/// A ledger idempotent-key collision.
	#[snafu(display("{code}: {message}"))]
	LedgerIdempotent {
		/// Full error code.
		code: String,
		/// Human-readable message.
		message: String,
		/// The block hash being published.
		blockhash: String,
		/// The pre-existing block hash for the idempotent key.
		existing_blockhash: String,
		/// The account the idempotent key belongs to.
		account: Option<String>,
		/// The idempotent key bytes.
		idempotent_key: Option<Vec<u8>>,
	},
}

impl KeetaNetError {
	/// The category of this error, when it carries a node code.
	pub fn node_type(&self) -> Option<NodeErrorType> {
		let code = match self {
			Self::Code { code, .. }
			| Self::Ledger { code, .. }
			| Self::LedgerVote { code, .. }
			| Self::LedgerIdempotent { code, .. } => code,
			Self::Internal | Self::Unknown { .. } | Self::NotImplemented => return None,
		};

		let prefix = code.split('_').next().unwrap_or_default();

		Some(NodeErrorType::from(prefix))
	}

	/// The full error code, when this carries one.
	pub fn code(&self) -> Option<&str> {
		match self {
			Self::Code { code, .. }
			| Self::Ledger { code, .. }
			| Self::LedgerVote { code, .. }
			| Self::LedgerIdempotent { code, .. } => Some(code),
			Self::Internal | Self::Unknown { .. } | Self::NotImplemented => None,
		}
	}
}

impl From<NodeErrorParts> for KeetaNetError {
	fn from(parts: NodeErrorParts) -> Self {
		let NodeErrorParts {
			kind,
			code,
			message,
			should_retry,
			retry_delay,
			accounts,
			blockhash,
			existing_blockhash,
			account,
			idempotent_key,
		} = parts;

		if kind != NodeErrorType::Ledger {
			return Self::Code { code, message };
		}

		if LEDGER_IDEMPOTENT_CODES.contains(&code.as_str()) {
			if let (Some(blockhash), Some(existing_blockhash)) = (blockhash, existing_blockhash) {
				return Self::LedgerIdempotent {
					code,
					message,
					blockhash,
					existing_blockhash,
					account,
					idempotent_key,
				};
			}
		}

		if LEDGER_VOTE_CODES.contains(&code.as_str()) {
			return Self::LedgerVote { code, message, accounts };
		}

		Self::Ledger { code, message, should_retry, retry_delay }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::string::ToString;
	use alloc::vec;

	fn parts(kind: NodeErrorType, code: &str) -> NodeErrorParts {
		NodeErrorParts { kind, code: code.to_string(), message: "boom".to_string(), ..Default::default() }
	}

	#[test]
	fn non_ledger_collapses_to_code() {
		let error = KeetaNetError::from(parts(NodeErrorType::Api, "API_INVALID_SIDE"));
		assert!(matches!(error, KeetaNetError::Code { code, .. } if code == "API_INVALID_SIDE"));
	}

	#[test]
	fn ledger_base_carries_retry() {
		let mut input = parts(NodeErrorType::Ledger, "LEDGER_SUCCESSOR_VOTE_EXISTS");
		input.should_retry = true;
		input.retry_delay = Some(250);

		let error = KeetaNetError::from(input);
		assert!(matches!(error, KeetaNetError::Ledger { should_retry: true, retry_delay: Some(250), .. }));
	}

	#[test]
	fn ledger_vote_carries_accounts() {
		let mut input = parts(NodeErrorType::Ledger, "LEDGER_NOT_SUCCESSOR");
		input.accounts = vec!["keeta_a".to_string()];

		let error = KeetaNetError::from(input);
		assert!(matches!(error, KeetaNetError::LedgerVote { accounts, .. } if accounts == ["keeta_a"]));
	}

	#[test]
	fn ledger_idempotent_carries_hashes() {
		let mut input = parts(NodeErrorType::Ledger, "LEDGER_IDEMPOTENT_KEY_EXISTS");
		input.blockhash = Some("aa".to_string());
		input.existing_blockhash = Some("bb".to_string());

		let error = KeetaNetError::from(input);
		assert!(
			matches!(error, KeetaNetError::LedgerIdempotent { blockhash, existing_blockhash, .. } if blockhash == "aa" && existing_blockhash == "bb")
		);
	}

	#[test]
	fn idempotent_without_hashes_falls_back_to_base() {
		let error = KeetaNetError::from(parts(NodeErrorType::Ledger, "LEDGER_IDEMPOTENT_KEY_EXISTS"));
		assert!(matches!(error, KeetaNetError::Ledger { .. }));
	}

	#[test]
	fn node_type_recovers_category_from_code() {
		let error = KeetaNetError::from(parts(NodeErrorType::Ledger, "LEDGER_NOT_OPENING"));
		assert_eq!(error.node_type(), Some(NodeErrorType::Ledger));
	}
}
