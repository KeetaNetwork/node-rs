//! Error types for ASN.1 operations.

use snafu::Snafu;

/// Error type for ASN.1 operations
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum Asn1Error {
	#[snafu(display("DER encoding error: {source}"))]
	Der { source: der::Error },
	#[snafu(display("Invalid OID: {reason}"))]
	InvalidOid { reason: String },
	#[snafu(display("Invalid public key format"))]
	InvalidPublicKey,
}

impl From<der::Error> for Asn1Error {
	fn from(error: der::Error) -> Self {
		Asn1Error::Der { source: error }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	macro_rules! test_error_variants {
		($($error_name:ident: $error_expr:expr => $expected_display:expr),+ $(,)?) => {
			#[test]
			fn test_error_creation_and_display() {
				$(
					let error = $error_expr;
					let display_str = format!("{}", error);
					assert!(display_str.contains($expected_display));
				)+
			}
		};
	}

	test_error_variants! {
		invalid_oid: Asn1Error::InvalidOid { reason: "test.invalid.oid".to_string() } => "Invalid OID: test.invalid.oid",
		invalid_public_key: Asn1Error::InvalidPublicKey => "Invalid public key format",
		der_error: Asn1Error::Der { source: der::Error::from(der::ErrorKind::Failed) } => "DER encoding error:",
	}

	#[test]
	fn test_from_der_error() {
		let der_error_cases = [
			der::Error::from(der::ErrorKind::Failed),
			der::Error::from(der::ErrorKind::Length { tag: der::Tag::Null }),
			der::Error::from(der::ErrorKind::Value { tag: der::Tag::Null }),
		];

		for der_error in der_error_cases {
			let asn1_error: Asn1Error = der_error.into();
			let expected = Asn1Error::Der { source: der_error };
			assert_eq!(asn1_error, expected);
		}
	}

	#[test]
	fn test_error_equality() {
		let test_cases = [
			(
				Asn1Error::InvalidOid { reason: "same.oid".to_string() },
				Asn1Error::InvalidOid { reason: "same.oid".to_string() },
				true,
			),
			(
				Asn1Error::InvalidOid { reason: "different.oid".to_string() },
				Asn1Error::InvalidOid { reason: "other.oid".to_string() },
				false,
			),
			(Asn1Error::InvalidPublicKey, Asn1Error::InvalidPublicKey, true),
			(Asn1Error::InvalidPublicKey, Asn1Error::InvalidOid { reason: "test".to_string() }, false),
		];

		for (error1, error2, should_be_equal) in test_cases {
			assert_eq!(error1 == error2, should_be_equal);
		}
	}

	#[test]
	fn test_error_debug_format() {
		let test_cases = [
			Asn1Error::InvalidOid { reason: "debug.test".to_string() },
			Asn1Error::InvalidPublicKey,
			Asn1Error::Der { source: der::Error::from(der::ErrorKind::Failed) },
		];

		for error in test_cases {
			let debug_str = format!("{error:?}");
			assert!(!debug_str.is_empty());

			match error {
				Asn1Error::InvalidOid { reason } => {
					assert!(debug_str.contains(&reason));
				}
				Asn1Error::InvalidPublicKey => {
					assert!(debug_str.contains("InvalidPublicKey"));
				}
				Asn1Error::Der { .. } => {
					assert!(debug_str.contains("Der"));
				}
			}
		}
	}
}
