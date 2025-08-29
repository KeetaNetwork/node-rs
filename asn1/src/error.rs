//! Error types for ASN.1 operations.

use snafu::Snafu;

/// Error type for ASN.1 operations
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
pub enum Asn1Error {
	#[cfg(feature = "der")]
	#[snafu(display("DER encoding error: {source}"))]
	DerError { source: der::Error },

	#[cfg(feature = "rasn")]
	#[snafu(display("RASN error: {reason}"))]
	RasnError { reason: String },

	#[snafu(display("Invalid OID: {reason}"))]
	InvalidOid { reason: String },

	#[snafu(display("Invalid public key format"))]
	InvalidPublicKey,
}

// Use error macros to implement From conversions
#[cfg(feature = "der")]
utils::impl_source_error_from!(Asn1Error, {
	der::Error => DerError,
});

#[cfg(feature = "der")]
utils::impl_error_from_with_fields!(Asn1Error, {
	const_oid::Error => InvalidOid { reason: |e: const_oid::Error| format!("{e:?}") },
});

#[cfg(feature = "rasn")]
utils::impl_error_from_with_fields!(Asn1Error, {
	rasn::uper::de::DecodeError => RasnError { reason: |e: &rasn::uper::de::DecodeError| format!("decode error: {e}") },
	rasn::der::enc::EncodeError => RasnError { reason: |e: &rasn::der::enc::EncodeError| format!("encode error: {e}") },
});

// Add der::Error conversion when using rasn feature for interop
#[cfg(all(feature = "rasn", not(feature = "der")))]
impl From<der::Error> for Asn1Error {
	fn from(e: der::Error) -> Self {
		Asn1Error::RasnError { reason: format!("der error: {e}") }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use utils::{test_error_from_conversions, test_error_variants};

	test_error_variants! {
		test_asn1_error_variants, [
			Asn1Error::InvalidOid { reason: "test.oid".to_string() },
			Asn1Error::InvalidPublicKey,
			#[cfg(feature = "der")]
			Asn1Error::DerError { source: der::Error::from(der::ErrorKind::Failed) },
			#[cfg(feature = "rasn")]
			Asn1Error::RasnError { reason: "test error".to_string() },
		]
	}

	#[cfg(feature = "der")]
	test_error_from_conversions! {
		test_der_from_conversions, Asn1Error, [
			der::Error::from(der::ErrorKind::Failed),
			const_oid::Error::Empty,
		]
	}

	#[cfg(feature = "rasn")]
	test_error_from_conversions! {
		test_rasn_from_conversions, Asn1Error, [
			rasn::uper::de::DecodeError::type_not_extensible(rasn::Codec::Der),
			rasn::der::enc::EncodeError::length_exceeds_platform_size(rasn::Codec::Der),
		]
	}

	#[cfg(feature = "rasn")]
	#[test]
	fn test_rasn_error_display() {
		let error = Asn1Error::RasnError { reason: "test rasn error".to_string() };
		assert_eq!(error.to_string(), "RASN error: test rasn error");
	}
}
