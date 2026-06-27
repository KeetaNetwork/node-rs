//! Arbitrary-precision amounts encoded as ASN.1 `INTEGER`.
//!
//! On the transport `Amount` is just an ASN.1 `INTEGER`; the codec lives in
//! `keetanetwork-asn1`. This module provides the block crate's domain-level
//! type with sign predicates and human-friendly parsing.

use core::fmt::{Display, Formatter, Result as FmtResult};
use core::str::FromStr;

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

#[cfg(test)]
mod tests {
	use num_bigint::ParseBigIntError;

	use super::*;

	#[test]
	fn test_parse_hex_and_decimal() -> Result<(), ParseBigIntError> {
		let hex_amount: Amount = "0xff".parse()?;
		assert_eq!(hex_amount, Amount::from(255u64));

		let negative: Amount = "-42".parse()?;
		assert_eq!(negative, Amount::from(-42i64));
		assert!(negative.is_negative());
		Ok(())
	}

	#[test]
	fn test_bigint_round_trip() {
		let cases: [Amount; 4] = [
			Amount::from(0u64),
			Amount::from(0x80u64),
			Amount::from(-129i64),
			"99999999999999999999999999999999999999"
				.parse()
				.expect("test decimal must parse"),
		];

		for amount in cases {
			let bigint: BigInt = amount.clone().into();
			let round_trip = Amount::from(bigint);
			assert_eq!(round_trip, amount);
		}
	}

	#[test]
	fn test_default_is_zero() {
		let zero = Amount::default();
		assert_eq!(zero, Amount::from(0u64));
		assert!(!zero.is_negative());
	}
}
