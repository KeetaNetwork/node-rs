//! Helpers that require the orchestrator client crate: orchestrator-error
//! reduction and ledger-side parsing.

use alloc::string::ToString;

use keetanetwork_client::{ClientError, LedgerSide};

use crate::error::CodedError;

impl From<ClientError> for CodedError {
	fn from(error: ClientError) -> Self {
		let mut message = error.to_string();
		let mut source = core::error::Error::source(&error);
		while let Some(inner) = source {
			message.push_str(": ");
			message.push_str(&inner.to_string());
			source = inner.source();
		}

		CodedError::new(error.code(), message)
	}
}

/// Parse a ledger side selector, defaulting to the main ledger when absent.
pub fn ledger_side(side: Option<&str>) -> Result<Option<LedgerSide>, CodedError> {
	match side {
		None => Ok(None),
		Some("main") => Ok(Some(LedgerSide::Main)),
		Some("side") => Ok(Some(LedgerSide::Side)),
		Some("both") => Ok(Some(LedgerSide::Both)),
		Some(_) => Err(CodedError::new("INVALID_LEDGER_SIDE", "side must be main, side, or both")),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_each_known_side() {
		assert!(matches!(ledger_side(None), Ok(None)));
		assert!(matches!(ledger_side(Some("main")), Ok(Some(LedgerSide::Main))));
		assert!(matches!(ledger_side(Some("side")), Ok(Some(LedgerSide::Side))));
		assert!(matches!(ledger_side(Some("both")), Ok(Some(LedgerSide::Both))));
	}

	#[test]
	fn rejects_an_unknown_side() {
		assert!(matches!(ledger_side(Some("galaxy")), Err(error) if error.code == "INVALID_LEDGER_SIDE"));
	}
}
