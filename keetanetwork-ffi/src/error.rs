//! Boundary error

use core::fmt::{Display, Formatter, Result as FmtResult};

use keetanetwork_block::BlockError;
use keetanetwork_vote::VoteError;

/// Code used when a core error exposes no stable code.
const UNKNOWN_CODE: &str = "UNKNOWN";

/// Error surfaced across the FFI boundary.
#[derive(Debug, uniffi::Error)]
pub enum FfiError {
	/// A KeetaNet operation failed.
	Keeta {
		/// Stable TS-compatible code, or `UNKNOWN` when none exists.
		code: String,
		/// Human-readable description.
		message: String,
	},
}

impl FfiError {
	/// Collapse a core error's optional code and message into the boundary form.
	fn coded(code: Option<&'static str>, message: String) -> Self {
		FfiError::Keeta { code: code.unwrap_or(UNKNOWN_CODE).into(), message }
	}

	/// Construct a boundary error from a fixed code and message, for failures
	/// that originate at the FFI layer rather than in a core crate.
	pub(crate) fn boundary(code: &'static str, message: impl Into<String>) -> Self {
		FfiError::Keeta { code: code.into(), message: message.into() }
	}
}

impl Display for FfiError {
	fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
		let FfiError::Keeta { code, message } = self;
		write!(formatter, "[{code}] {message}")
	}
}

impl core::error::Error for FfiError {}

impl From<BlockError> for FfiError {
	fn from(error: BlockError) -> Self {
		FfiError::coded(error.code(), error.to_string())
	}
}

impl From<VoteError> for FfiError {
	fn from(error: VoteError) -> Self {
		FfiError::coded(error.code(), error.to_string())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn maps_known_block_code() {
		let FfiError::Keeta { code, .. } = FfiError::from(BlockError::InvalidVersion);
		assert_eq!(code, "BLOCK_INVALID_VERSION");
	}

	#[test]
	fn non_coded_error_falls_back_to_unknown() {
		let FfiError::Keeta { code, .. } = FfiError::from(BlockError::MalformedSigner);
		assert_eq!(code, UNKNOWN_CODE);
	}
}
