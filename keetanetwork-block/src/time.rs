//! Block timestamp with TypeScript-compatible `GeneralizedTime` encoding.
//!
//! Block dates are encoded as ASN.1 `GeneralizedTime` with millisecond
//! precision: `YYYYMMDDHHMMSSZ` when the millisecond component is zero
//! and `YYYYMMDDHHMMSS.mmmZ` (always three fractional digits) otherwise.
//!
//! Transport-format encoding/decoding is delegated to
//! [`keetanetwork_asn1::Asn1Time`]; this type adds the millisecond-precision
//! convenience surface (`now`, `from_unix_millis`, `unix_millis`).

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Datelike, Timelike, Utc};
use keetanetwork_asn1::Asn1Time;

#[cfg(feature = "std")]
use chrono::SubsecRound;

/// A block timestamp with millisecond precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockTime(Asn1Time);

impl BlockTime {
	/// The current time, truncated to millisecond precision.
	#[cfg(feature = "std")]
	pub fn now() -> Self {
		Self(Asn1Time::new(Utc::now().trunc_subsecs(3)))
	}

	/// Construct from a Unix timestamp in milliseconds.
	pub fn from_unix_millis(millis: i64) -> Option<Self> {
		DateTime::from_timestamp_millis(millis).map(|value| Self(Asn1Time::new(value)))
	}

	/// The Unix timestamp in milliseconds.
	pub fn unix_millis(&self) -> i64 {
		self.0.as_datetime().timestamp_millis()
	}
}

impl Default for BlockTime {
	/// The Unix epoch, used as a panic-free fallback moment in `no_std`
	/// contexts that lack a clock.
	fn default() -> Self {
		Self::from(DateTime::<Utc>::UNIX_EPOCH)
	}
}

impl From<DateTime<Utc>> for BlockTime {
	fn from(value: DateTime<Utc>) -> Self {
		Self(Asn1Time::new(value))
	}
}

impl From<BlockTime> for DateTime<Utc> {
	fn from(value: BlockTime) -> Self {
		*value.0.as_datetime()
	}
}

impl From<Asn1Time> for BlockTime {
	fn from(value: Asn1Time) -> Self {
		Self(value)
	}
}

/// ISO 8601 with millisecond precision and a `Z` designator
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`), matching TypeScript's `Date.toISOString`.
impl fmt::Display for BlockTime {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let datetime = self.0.as_datetime();
		write!(
			formatter,
			"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
			datetime.year(),
			datetime.month(),
			datetime.day(),
			datetime.hour(),
			datetime.minute(),
			datetime.second(),
			datetime.timestamp_subsec_millis()
		)
	}
}

/// Parse an ISO 8601 / RFC 3339 moment, normalizing to UTC.
impl FromStr for BlockTime {
	type Err = chrono::ParseError;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		let parsed = DateTime::parse_from_rfc3339(value)?;
		Ok(Self::from(parsed.with_timezone(&Utc)))
	}
}

impl From<BlockTime> for Asn1Time {
	fn from(value: BlockTime) -> Self {
		value.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn time_from_str(text: &str) -> BlockTime {
		BlockTime::from(
			text.parse::<DateTime<Utc>>()
				.expect("test datetime string must parse"),
		)
	}

	fn unix_millis_time(millis: i64) -> BlockTime {
		BlockTime::from_unix_millis(millis).expect("test unix millis must map to block time")
	}

	#[test]
	fn test_unix_millis_round_trip() {
		let time = unix_millis_time(1735787045678);
		assert_eq!(time.unix_millis(), 1735787045678);
	}

	#[test]
	fn test_truncates_sub_millisecond_precision() {
		let time = time_from_str("2025-01-02T03:04:05.123456Z");
		let datetime: DateTime<Utc> = time.into();
		assert_eq!(datetime.timestamp_subsec_millis(), 123);
	}

	#[test]
	fn test_now_returns_recent() {
		let time = BlockTime::now();
		let now = Utc::now();
		let diff = (now.timestamp_millis() - time.unix_millis()).abs();
		assert!(diff < 5_000);
	}

	#[test]
	fn test_asn1_time_round_trip() {
		let time = time_from_str("2025-01-02T03:04:05.500Z");
		let asn1: Asn1Time = time.into();
		let restored: BlockTime = asn1.into();
		assert_eq!(time, restored);
	}

	#[test]
	fn test_display_matches_iso_millis() {
		let time = time_from_str("2025-01-02T03:04:05.123Z");
		assert_eq!(time.to_string(), "2025-01-02T03:04:05.123Z");
	}

	#[test]
	fn test_display_pads_zero_millis() {
		let time = time_from_str("2025-01-02T03:04:05Z");
		assert_eq!(time.to_string(), "2025-01-02T03:04:05.000Z");
	}

	#[test]
	fn test_from_str_round_trip() {
		let time = "2025-01-02T03:04:05.123Z"
			.parse::<BlockTime>()
			.expect("test moment must parse");
		assert_eq!(time.to_string(), "2025-01-02T03:04:05.123Z");
	}

	#[test]
	fn test_from_str_normalizes_offsets_to_utc() {
		let time = "2025-01-02T04:04:05.123+01:00"
			.parse::<BlockTime>()
			.expect("test moment must parse");
		assert_eq!(time.to_string(), "2025-01-02T03:04:05.123Z");
	}

	#[test]
	fn test_from_str_rejects_garbage() {
		assert!("not-a-moment".parse::<BlockTime>().is_err());
	}
}
