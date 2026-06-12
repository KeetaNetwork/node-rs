//! Arbitrary-precision amounts encoded as ASN.1 `INTEGER`.

use core::fmt::{Display, Formatter, Result as FmtResult};
use core::str::FromStr;

use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};
use num_bigint::{BigInt, ParseBigIntError, Sign};

/// An arbitrary-precision integer amount.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(BigInt);

impl Amount {
	/// Whether this amount is negative.
	pub fn is_negative(&self) -> bool {
		self.0.sign() == Sign::Minus
	}

	/// Borrow the inner big integer.
	pub fn as_bigint(&self) -> &BigInt {
		&self.0
	}
}

impl From<BigInt> for Amount {
	fn from(value: BigInt) -> Self {
		Self(value)
	}
}

impl From<Amount> for BigInt {
	fn from(value: Amount) -> Self {
		value.0
	}
}

impl From<u64> for Amount {
	fn from(value: u64) -> Self {
		Self(BigInt::from(value))
	}
}

impl From<i64> for Amount {
	fn from(value: i64) -> Self {
		Self(BigInt::from(value))
	}
}

impl From<u128> for Amount {
	fn from(value: u128) -> Self {
		Self(BigInt::from(value))
	}
}

impl Display for Amount {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		write!(f, "{}", self.0)
	}
}

impl FromStr for Amount {
	type Err = ParseBigIntError;

	/// Parse a decimal amount, or a hexadecimal one when prefixed with `0x`
	/// (TypeScript JSON serialization uses `0x`-prefixed hex strings).
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let (negative, magnitude) = if let Some(rest) = s.strip_prefix('-') {
			(true, rest)
		} else {
			(false, s)
		};

		let value = if let Some(hex_digits) = magnitude.strip_prefix("0x") {
			<BigInt as num_traits::Num>::from_str_radix(hex_digits, 16)?
		} else {
			magnitude.parse::<BigInt>()?
		};

		if negative {
			Ok(Self(-value))
		} else {
			Ok(Self(value))
		}
	}
}

impl FixedTag for Amount {
	const TAG: Tag = Tag::Integer;
}

impl EncodeValue for Amount {
	fn value_len(&self) -> der::Result<Length> {
		Length::try_from(self.0.to_signed_bytes_be().len())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		writer.write(&self.0.to_signed_bytes_be())
	}
}

impl<'a> DecodeValue<'a> for Amount {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
		let bytes = reader.read_vec(header.length)?;

		// Enforce DER minimal-octets INTEGER rules (X.690 8.3.2)
		let non_canonical = match bytes.as_slice() {
			[] => true,
			[0x00, second, ..] => second & 0x80 == 0,
			[0xFF, second, ..] => second & 0x80 != 0,
			_ => false,
		};
		if non_canonical {
			return Err(der::Error::new(der::ErrorKind::Noncanonical { tag: Tag::Integer }, reader.position()));
		}

		Ok(Self(BigInt::from_signed_bytes_be(&bytes)))
	}
}

#[cfg(test)]
mod tests {
	use der::{Decode, Encode};
	use num_bigint::ParseBigIntError;

	use super::*;

	fn large_amount() -> Amount {
		"99999999999999999999999999999999999999999999999999"
			.parse()
			.expect("test decimal parse must succeed")
	}

	#[test]
	fn test_encode_zero() -> der::Result<()> {
		let encoded = Amount::from(0u64).to_der()?;
		assert_eq!(encoded, [0x02, 0x01, 0x00]);
		Ok(())
	}

	#[test]
	fn test_encode_high_bit_padding() -> der::Result<()> {
		let encoded = Amount::from(0x80u64).to_der()?;
		assert_eq!(encoded, [0x02, 0x02, 0x00, 0x80]);
		Ok(())
	}

	#[test]
	fn test_encode_negative() -> der::Result<()> {
		let encoded = Amount::from(-129i64).to_der()?;
		assert_eq!(encoded, [0x02, 0x02, 0xFF, 0x7F]);
		Ok(())
	}

	#[test]
	fn test_roundtrip_large() -> der::Result<()> {
		let large = large_amount();
		let encoded = large.to_der()?;
		let decoded = Amount::from_der(&encoded)?;
		assert_eq!(decoded, large);
		Ok(())
	}

	#[test]
	fn test_decode_rejects_redundant_leading_zero() {
		let result = Amount::from_der(&[0x02, 0x02, 0x00, 0x01]);
		assert!(result.is_err());
	}

	#[test]
	fn test_decode_rejects_redundant_leading_ff() {
		let result = Amount::from_der(&[0x02, 0x02, 0xFF, 0xFF]);
		assert!(result.is_err());
	}

	#[test]
	fn test_decode_rejects_empty() {
		let result = Amount::from_der(&[0x02, 0x00]);
		assert!(result.is_err());
	}

	#[test]
	fn test_parse_hex_and_decimal() -> Result<(), ParseBigIntError> {
		let hex_amount: Amount = "0xff".parse()?;
		assert_eq!(hex_amount, Amount::from(255u64));

		let negative: Amount = "-42".parse()?;
		assert_eq!(negative, Amount::from(-42i64));
		assert!(negative.is_negative());
		Ok(())
	}
}
