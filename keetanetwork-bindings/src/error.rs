//! Boundary error shared by binding crates.

use alloc::string::{String, ToString};

use keetanetwork_block::BlockError;
use keetanetwork_vote::VoteError;

/// Code used when a core error exposes no stable code.
pub const UNKNOWN_CODE: &str = "UNKNOWN";

/// A core failure reduced to a stable code and a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedError {
	/// Stable, machine-readable code consumers branch on.
	pub code: String,
	/// Human-readable description.
	pub message: String,
}

impl CodedError {
	/// A coded error from a code and message.
	pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
		Self { code: code.into(), message: message.into() }
	}

	/// A coded error from an optional static code, falling back to
	/// [`UNKNOWN_CODE`] when absent.
	pub fn coded(code: Option<&str>, message: impl Into<String>) -> Self {
		Self::new(code.unwrap_or(UNKNOWN_CODE), message)
	}
}

/// Derive `From<$error> for CodedError` for core errors that expose an
/// optional stable `code()` and a `Display` message.
macro_rules! coded_from {
	($($error:ty),+ $(,)?) => {
		$(
			impl From<$error> for CodedError {
				fn from(error: $error) -> Self {
					Self::coded(error.code(), error.to_string())
				}
			}
		)+
	};
}

coded_from!(BlockError, VoteError);

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn maps_known_block_code() {
		let coded = CodedError::from(BlockError::InvalidVersion);
		assert_eq!(coded.code, "BLOCK_INVALID_VERSION");
	}

	#[test]
	fn non_coded_block_error_falls_back_to_unknown() {
		let coded = CodedError::from(BlockError::MalformedSigner);
		assert_eq!(coded.code, UNKNOWN_CODE);
	}

	#[test]
	fn coded_preserves_an_explicit_code() {
		let coded = CodedError::coded(Some("EXPLICIT"), "message");
		assert_eq!(coded.code, "EXPLICIT");
	}
}
