//! Block timestamp with TypeScript-compatible `GeneralizedTime` encoding.
//!
//! The reference implementation encodes block dates as ASN.1
//! `GeneralizedTime` with millisecond precision: `YYYYMMDDHHMMSSZ` when the
//! millisecond component is zero and `YYYYMMDDHHMMSS.mmmZ` (always three
//! fractional digits) otherwise.

use chrono::{DateTime, NaiveDateTime, SubsecRound, Utc};
use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};

/// Encoded length without a fractional component: `YYYYMMDDHHMMSSZ`.
const PLAIN_LENGTH: u16 = 15;
/// Encoded length with a fractional component: `YYYYMMDDHHMMSS.mmmZ`.
const FRACTIONAL_LENGTH: u16 = 19;

/// A block timestamp with millisecond precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockTime(DateTime<Utc>);

impl BlockTime {
	/// The current time, truncated to millisecond precision.
	pub fn now() -> Self {
		Self(Utc::now().trunc_subsecs(3))
	}

	/// Construct from a Unix timestamp in milliseconds.
	pub fn from_unix_millis(millis: i64) -> Option<Self> {
		DateTime::from_timestamp_millis(millis).map(Self)
	}

	/// The Unix timestamp in milliseconds.
	pub fn unix_millis(&self) -> i64 {
		self.0.timestamp_millis()
	}

	fn to_wire_string(self) -> String {
		if self.0.timestamp_subsec_millis() == 0 {
			self.0.format("%Y%m%d%H%M%SZ").to_string()
		} else {
			self.0.format("%Y%m%d%H%M%S%.3fZ").to_string()
		}
	}
}

impl From<DateTime<Utc>> for BlockTime {
	fn from(value: DateTime<Utc>) -> Self {
		Self(value.trunc_subsecs(3))
	}
}

impl From<BlockTime> for DateTime<Utc> {
	fn from(value: BlockTime) -> Self {
		value.0
	}
}

impl FixedTag for BlockTime {
	const TAG: Tag = Tag::GeneralizedTime;
}

impl EncodeValue for BlockTime {
	fn value_len(&self) -> der::Result<Length> {
		if self.0.timestamp_subsec_millis() == 0 {
			Ok(Length::new(PLAIN_LENGTH))
		} else {
			Ok(Length::new(FRACTIONAL_LENGTH))
		}
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		writer.write(self.to_wire_string().as_bytes())
	}
}

impl<'a> DecodeValue<'a> for BlockTime {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
		let length = u32::from(header.length);
		if length != u32::from(PLAIN_LENGTH) && length != u32::from(FRACTIONAL_LENGTH) {
			return Err(der::Error::new(der::ErrorKind::DateTime, reader.position()));
		}

		let mut bytes = [0u8; FRACTIONAL_LENGTH as usize];
		let buffer = &mut bytes[..length as usize];
		reader.read_into(buffer)?;

		let text =
			core::str::from_utf8(buffer).map_err(|_| der::Error::new(der::ErrorKind::DateTime, reader.position()))?;

		let format = if length == u32::from(PLAIN_LENGTH) {
			"%Y%m%d%H%M%SZ"
		} else {
			"%Y%m%d%H%M%S%.3fZ"
		};
		let parsed = NaiveDateTime::parse_from_str(text, format)
			.map_err(|_| der::Error::new(der::ErrorKind::DateTime, reader.position()))?;

		Ok(Self(parsed.and_utc()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use der::{Decode, Encode};

	fn time_from_str(text: &str) -> BlockTime {
		BlockTime::from(
			text.parse::<DateTime<Utc>>()
				.expect("test datetime string must parse"),
		)
	}

	fn hex_bytes(text: &str) -> Vec<u8> {
		hex::decode(text).expect("test hex literal must decode")
	}

	fn unix_millis_time(millis: i64) -> BlockTime {
		BlockTime::from_unix_millis(millis).expect("test unix millis must map to block time")
	}

	#[test]
	fn test_encode_without_milliseconds() -> der::Result<()> {
		let time = time_from_str("2025-01-02T03:04:05Z");
		let encoded = time.to_der()?;
		assert_eq!(encoded, hex_bytes("180f32303235303130323033303430355a"));
		Ok(())
	}

	#[test]
	fn test_encode_with_milliseconds() -> der::Result<()> {
		let time = time_from_str("2025-01-02T03:04:05.678Z");
		let encoded = time.to_der()?;
		assert_eq!(encoded, hex_bytes("181332303235303130323033303430352e3637385a"));
		Ok(())
	}

	#[test]
	fn test_encode_keeps_trailing_fraction_zeros() -> der::Result<()> {
		let time = time_from_str("2025-01-02T03:04:05.500Z");
		let encoded = time.to_der()?;
		assert_eq!(encoded, hex_bytes("181332303235303130323033303430352e3530305a"));
		Ok(())
	}

	#[test]
	fn test_roundtrip() -> der::Result<()> {
		let cases = ["2025-01-02T03:04:05Z", "2025-01-02T03:04:05.678Z", "2025-01-02T03:04:05.001Z"];
		for case in cases {
			let time = time_from_str(case);
			let encoded = time.to_der()?;
			let decoded = BlockTime::from_der(&encoded)?;
			assert_eq!(decoded, time);
		}
		Ok(())
	}

	#[test]
	fn test_decode_invalid_length() {
		let result = BlockTime::from_der(&hex_bytes("18023030"));
		assert!(result.is_err());
	}

	#[test]
	fn test_unix_millis_roundtrip() {
		let time = unix_millis_time(1735787045678);
		assert_eq!(time.unix_millis(), 1735787045678);
	}
}
