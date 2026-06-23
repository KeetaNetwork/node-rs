//! Timestamp conversion shared across binding boundaries.

use alloc::format;

use chrono::{DateTime, Utc};

use crate::error::CodedError;

/// Convert a Unix-millisecond timestamp into a UTC instant. `label` names the
/// field for the rejection message when the value is out of range.
pub fn from_unix_millis(millis: i64, label: &str) -> Result<DateTime<Utc>, CodedError> {
	DateTime::from_timestamp_millis(millis)
		.ok_or_else(|| CodedError::new("INVALID_DATE", format!("{label} unix milliseconds out of range")))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn converts_the_unix_epoch() {
		let instant = from_unix_millis(0, "ts");
		assert!(matches!(instant, Ok(value) if value.timestamp_millis() == 0));
	}

	#[test]
	fn rejects_a_value_out_of_range() {
		let rejected = from_unix_millis(i64::MAX, "ts");
		assert!(matches!(rejected, Err(error) if error.code == "INVALID_DATE"));
	}
}
