mod common;

use keetanetwork_x509::certificates::Certificate;

use common::*;

#[test]
fn test_certificate_has_extensions() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	assert!(ca_cert.tbs_certificate.extensions.is_some());
	assert!(user_cert.tbs_certificate.extensions.is_some());
}

#[test]
fn test_extension_count() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_extensions = ca_cert
		.tbs_certificate
		.extensions
		.as_ref()
		.ok_or("CA cert should have extensions")?;
	let user_extensions = user_cert
		.tbs_certificate
		.extensions
		.as_ref()
		.ok_or("User cert should have extensions")?;
	assert!(!ca_extensions.is_empty());
	assert!(!user_extensions.is_empty());
	// Both certs should have extensions
	assert!(!ca_extensions.is_empty());
	assert!(!user_extensions.is_empty());

	Ok(())
}

#[test]
fn test_extensions_not_empty() {
	let ca_cert = ca_certificate();
	if let Some(extensions) = &ca_cert.tbs_certificate.extensions {
		for ext in extensions {
			assert!(!ext.extn_value.is_empty());
		}
	}
}

#[test]
fn test_extension_der_roundtrip() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let ca_der = ca_cert.to_der()?;
	let ca_from_der = Certificate::try_from(ca_der.as_slice())?;

	let original_extensions = &ca_cert.tbs_certificate.extensions;
	let decoded_extensions = &ca_from_der.tbs_certificate.extensions;
	assert_eq!(original_extensions.is_some(), decoded_extensions.is_some());

	if let (Some(orig), Some(decoded)) = (original_extensions, decoded_extensions) {
		assert_eq!(orig.len(), decoded.len());
	}

	Ok(())
}
