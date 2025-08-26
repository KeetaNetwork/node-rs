//! Error types for ASN.1 operations.

use snafu::Snafu;
use utils::{impl_error_from_with_fields, impl_source_error_from};

/// Error type for ASN.1 operations
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
pub enum Asn1Error {
	#[snafu(display("DER encoding error: {source}"))]
	DerError { source: der::Error },

	#[snafu(display("Invalid OID: {reason}"))]
	InvalidOid { reason: String },

	#[snafu(display("Invalid public key format"))]
	InvalidPublicKey,
}

impl_source_error_from!(Asn1Error, {
	der::Error => DerError,
});

impl_error_from_with_fields!(Asn1Error, {
	const_oid::Error => InvalidOid { reason: |e| format!("{e:?}") },
});

#[cfg(test)]
mod tests {
	use super::*;
	use utils::{test_error_from_conversions, test_error_variants};

	test_error_variants! {
		test_asn1_error_variants, [
			Asn1Error::InvalidOid { reason: "test.oid".to_string() },
			Asn1Error::InvalidPublicKey,
			Asn1Error::DerError { source: der::Error::from(der::ErrorKind::Failed) },
		]
	}

	test_error_from_conversions! {
		test_from_conversions, Asn1Error, [
			der::Error::from(der::ErrorKind::Failed),
			const_oid::Error::Empty,
		]
	}
}
