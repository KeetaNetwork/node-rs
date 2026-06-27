//! TypeScript reference-compatible ASN.1 `GeneralizedTime` wrapper.
//!
//! Both `rasn`'s built-in `GeneralizedTime` and `der::asn1::GeneralizedTime`
//! strip trailing zeros from the fractional-seconds component to produce
//! canonical DER. The reference TypeScript implementation does not strip
//! trailing zeros: a timestamp such as `20250102030405.500Z` keeps all three
//! digits on the transport. Transport-format byte compatibility with that
//! reference therefore requires a type whose encoder preserves the
//! millisecond precision.
//!
//! [`Asn1Time`] wraps a UTC `chrono::DateTime`, encodes as
//! `YYYYMMDDHHMMSSZ` (15 octets) when the millisecond component is zero and
//! `YYYYMMDDHHMMSS.mmmZ` (19 octets) otherwise, and decodes both forms. The
//! same byte-exact format is produced by the `rasn` and `der` backend impl
//! so consumers can switch backends without affecting the transport.

use alloc::string::{String, ToString};

use chrono::{DateTime, SubsecRound, Utc};

/// `GeneralizedTime` value with TypeScript-compatible transport encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn1Time(DateTime<Utc>);

impl Asn1Time {
	/// Wrap an existing UTC datetime, truncating sub-millisecond precision.
	pub fn new(value: DateTime<Utc>) -> Self {
		Self(value.trunc_subsecs(3))
	}

	/// Borrow the inner UTC datetime.
	pub fn as_datetime(&self) -> &DateTime<Utc> {
		&self.0
	}

	fn format_transport(&self) -> String {
		if self.0.timestamp_subsec_millis() == 0 {
			self.0.format("%Y%m%d%H%M%SZ").to_string()
		} else {
			self.0.format("%Y%m%d%H%M%S%.3fZ").to_string()
		}
	}

	#[cfg(feature = "der")]
	fn parse_transport(text: &str) -> Option<Self> {
		let format = match text.len() {
			TRANSPORT_LEN_PLAIN => "%Y%m%d%H%M%SZ",
			TRANSPORT_LEN_FRACTIONAL => "%Y%m%d%H%M%S%.3fZ",
			_ => return None,
		};
		chrono::NaiveDateTime::parse_from_str(text, format)
			.ok()
			.map(|naive| Self::new(naive.and_utc()))
	}
}

/// Encoded length without a fractional component: `YYYYMMDDHHMMSSZ`.
#[cfg(feature = "der")]
const TRANSPORT_LEN_PLAIN: usize = 15;
/// Encoded length with a fractional component: `YYYYMMDDHHMMSS.mmmZ`.
#[cfg(feature = "der")]
const TRANSPORT_LEN_FRACTIONAL: usize = 19;

impl From<DateTime<Utc>> for Asn1Time {
	fn from(value: DateTime<Utc>) -> Self {
		Self::new(value)
	}
}

impl From<Asn1Time> for DateTime<Utc> {
	fn from(value: Asn1Time) -> Self {
		value.0
	}
}

#[cfg(feature = "rasn")]
mod rasn_impls {
	use chrono::Utc;
	use rasn::types::{Constraints, GeneralizedTime, Identifier, Tag};
	use rasn::{AsnType, Decode, Decoder, Encode, Encoder};

	use super::Asn1Time;

	impl From<GeneralizedTime> for Asn1Time {
		fn from(value: GeneralizedTime) -> Self {
			Self::new(value.with_timezone(&Utc))
		}
	}

	impl From<Asn1Time> for GeneralizedTime {
		fn from(value: Asn1Time) -> Self {
			value.0.fixed_offset()
		}
	}

	impl AsnType for Asn1Time {
		const TAG: Tag = Tag::GENERALIZED_TIME;
		const IDENTIFIER: Identifier = Identifier::GENERALIZED_TIME;
	}

	impl Encode for Asn1Time {
		fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
			&self,
			encoder: &mut E,
			tag: Tag,
			constraints: Constraints,
			identifier: Identifier,
		) -> Result<(), E::Error> {
			let transport = self.format_transport();
			encoder
				.encode_octet_string(tag, constraints, transport.as_bytes(), identifier.or(Self::IDENTIFIER))
				.map(drop)
		}
	}

	impl Decode for Asn1Time {
		fn decode_with_tag_and_constraints<D: Decoder>(
			decoder: &mut D,
			tag: Tag,
			_: Constraints,
		) -> Result<Self, D::Error> {
			let parsed = decoder.decode_generalized_time(tag)?;
			Ok(Self::new(parsed.with_timezone(&Utc)))
		}
	}
}

#[cfg(feature = "der")]
mod der_impls {
	use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};

	use super::{Asn1Time, TRANSPORT_LEN_FRACTIONAL, TRANSPORT_LEN_PLAIN};

	impl FixedTag for Asn1Time {
		const TAG: Tag = Tag::GeneralizedTime;
	}

	impl EncodeValue for Asn1Time {
		fn value_len(&self) -> der::Result<Length> {
			let len = if self.0.timestamp_subsec_millis() == 0 {
				TRANSPORT_LEN_PLAIN as u16
			} else {
				TRANSPORT_LEN_FRACTIONAL as u16
			};
			Ok(Length::new(len))
		}

		fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
			writer.write(self.format_transport().as_bytes())
		}
	}

	impl<'a> DecodeValue<'a> for Asn1Time {
		fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
			let length = u32::from(header.length) as usize;
			if length != TRANSPORT_LEN_PLAIN && length != TRANSPORT_LEN_FRACTIONAL {
				return Err(der::Error::new(der::ErrorKind::DateTime, reader.position()));
			}

			let mut bytes = [0u8; TRANSPORT_LEN_FRACTIONAL];
			let buffer = &mut bytes[..length];
			reader.read_into(buffer)?;

			let text = core::str::from_utf8(buffer)
				.map_err(|_| der::Error::new(der::ErrorKind::DateTime, reader.position()))?;

			Self::parse_transport(text).ok_or_else(|| der::Error::new(der::ErrorKind::DateTime, reader.position()))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn datetime(text: &str) -> DateTime<Utc> {
		text.parse::<DateTime<Utc>>().expect("test datetime parses")
	}

	fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
		(0..hex_str.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("test hex digits parse"))
			.collect()
	}

	fn hex(bytes: &[u8]) -> String {
		bytes.iter().map(|b| format!("{b:02x}")).collect()
	}

	#[test]
	fn test_truncates_sub_millisecond_precision() {
		let micro = datetime("2025-01-02T03:04:05.123456Z");
		let value = Asn1Time::new(micro);
		assert_eq!(value.0.timestamp_subsec_millis(), 123);
	}

	#[test]
	fn test_format_transport_byte_strings() {
		let cases = [
			("2025-01-02T03:04:05Z", "20250102030405Z"),
			("2025-01-02T03:04:05.678Z", "20250102030405.678Z"),
			("2025-01-02T03:04:05.500Z", "20250102030405.500Z"),
			("2025-01-02T03:04:05.001Z", "20250102030405.001Z"),
		];
		for (input, expected) in cases {
			let value = Asn1Time::new(datetime(input));
			assert_eq!(value.format_transport(), expected);
		}
	}

	#[cfg(feature = "der")]
	#[test]
	fn test_parse_transport_round_trip() {
		let cases = ["2025-01-02T03:04:05Z", "2025-01-02T03:04:05.678Z", "2025-01-02T03:04:05.500Z"];
		for case in cases {
			let original = Asn1Time::new(datetime(case));
			let parsed = Asn1Time::parse_transport(&original.format_transport()).expect("parse_transport");
			assert_eq!(parsed, original);
		}
	}

	#[cfg(feature = "rasn")]
	mod rasn_backend {
		use super::*;

		#[test]
		fn test_encode_without_milliseconds() {
			let value = Asn1Time::new(datetime("2025-01-02T03:04:05Z"));
			let der = rasn::der::encode(&value).expect("Asn1Time encodes");
			assert_eq!(hex(&der), "180f32303235303130323033303430355a");
		}

		#[test]
		fn test_encode_with_milliseconds_keeps_trailing_zeros() {
			let cases = [
				("2025-01-02T03:04:05.678Z", "181332303235303130323033303430352e3637385a"),
				("2025-01-02T03:04:05.500Z", "181332303235303130323033303430352e3530305a"),
				("2025-01-02T03:04:05.001Z", "181332303235303130323033303430352e3030315a"),
				("2025-01-02T03:04:05.100Z", "181332303235303130323033303430352e3130305a"),
			];
			for (input, expected) in cases {
				let value = Asn1Time::new(datetime(input));
				let der = rasn::der::encode(&value).expect("Asn1Time encodes");
				assert_eq!(hex(&der), expected, "transport bytes for {input}");
			}
		}

		#[test]
		fn test_decode_round_trip_preserves_milliseconds() {
			let cases = [
				"2025-01-02T03:04:05Z",
				"2025-01-02T03:04:05.678Z",
				"2025-01-02T03:04:05.500Z",
				"2025-01-02T03:04:05.001Z",
			];
			for case in cases {
				let original = Asn1Time::new(datetime(case));
				let der = rasn::der::encode(&original).expect("encode round-trip");
				let decoded: Asn1Time = rasn::der::decode(&der).expect("decode round-trip");
				assert_eq!(decoded, original, "round-trip preserves {case}");
			}
		}

		#[test]
		fn test_decode_canonical_form_without_trailing_zeros() {
			let canonical_der = hex_to_bytes("181132303235303130323033303430352e355a");
			let decoded: Asn1Time = rasn::der::decode(&canonical_der).expect("decode canonical form");
			assert_eq!(decoded.0.timestamp_subsec_millis(), 500);
		}

		#[test]
		fn test_byte_compat_15_char_form() {
			let cases = [
				("2025-01-01T00:00:00Z", "180f32303235303130313030303030305a"),
				("1970-01-01T00:00:00Z", "180f31393730303130313030303030305a"),
				("2099-12-31T23:59:59Z", "180f32303939313233313233353935395a"),
			];
			for (input, expected) in cases {
				let value = Asn1Time::new(datetime(input));
				let der = rasn::der::encode(&value).expect("encode whole-second");
				assert_eq!(hex(&der), expected, "15-char transport for {input}");
			}
		}
	}

	#[cfg(feature = "der")]
	mod der_backend {
		use super::*;
		use der::{Decode as _, Encode as _};

		#[test]
		fn test_encode_without_milliseconds() {
			let value = Asn1Time::new(datetime("2025-01-02T03:04:05Z"));
			let bytes = value.to_der().expect("Asn1Time encodes via der");
			assert_eq!(hex(&bytes), "180f32303235303130323033303430355a");
		}

		#[test]
		fn test_encode_with_milliseconds_keeps_trailing_zeros() {
			let cases = [
				("2025-01-02T03:04:05.678Z", "181332303235303130323033303430352e3637385a"),
				("2025-01-02T03:04:05.500Z", "181332303235303130323033303430352e3530305a"),
				("2025-01-02T03:04:05.001Z", "181332303235303130323033303430352e3030315a"),
			];
			for (input, expected) in cases {
				let value = Asn1Time::new(datetime(input));
				let bytes = value.to_der().expect("Asn1Time encodes via der");
				assert_eq!(hex(&bytes), expected);
			}
		}

		#[test]
		fn test_round_trip_preserves_milliseconds() {
			let cases = ["2025-01-02T03:04:05Z", "2025-01-02T03:04:05.678Z", "2025-01-02T03:04:05.001Z"];
			for case in cases {
				let original = Asn1Time::new(datetime(case));
				let bytes = original.to_der().expect("encode");
				let decoded = Asn1Time::from_der(&bytes).expect("decode");
				assert_eq!(decoded, original);
			}
		}

		#[test]
		fn test_decode_invalid_length_rejected() {
			assert!(Asn1Time::from_der(&hex_to_bytes("18023030")).is_err());
		}
	}
}
