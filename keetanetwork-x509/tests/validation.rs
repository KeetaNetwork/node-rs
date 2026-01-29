mod common;

use keetanetwork_x509::certificates::Certificate;

use common::*;

#[test]
fn test_certificate_chain_validation() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let ca_subject = &ca_cert.tbs_certificate.subject;
	let user_issuer = &user_cert.tbs_certificate.issuer;
	assert_eq!(ca_subject, user_issuer);
}

#[test]
fn test_certificate_self_signed_validation() {
	let ca_cert = ca_certificate();
	let ca_subject = &ca_cert.tbs_certificate.subject;
	let ca_issuer = &ca_cert.tbs_certificate.issuer;
	assert_eq!(ca_subject, ca_issuer);
}

#[test]
fn test_certificate_validity_period() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	// Check that validity periods have both not_before and not_after
	let ca_validity = &ca_cert.tbs_certificate.validity;
	let user_validity = &user_cert.tbs_certificate.validity;
	assert!(ca_validity.not_before != ca_validity.not_after);
	assert!(user_validity.not_before != user_validity.not_after);
}

#[test]
fn test_certificate_public_key_extraction() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_public_key = &ca_cert.tbs_certificate.subject_public_key_info;
	let user_public_key = &user_cert.tbs_certificate.subject_public_key_info;
	assert!(!ca_public_key.subject_public_key.is_empty());
	assert!(!user_public_key.subject_public_key.is_empty());

	// Use backend-appropriate method for getting bytes
	#[cfg(feature = "der")]
	assert_ne!(ca_public_key.subject_public_key.as_bytes(), user_public_key.subject_public_key.as_bytes());
	#[cfg(all(feature = "rasn", not(feature = "der")))]
	assert_ne!(ca_public_key.subject_public_key.raw_bytes(), user_public_key.subject_public_key.raw_bytes());
}

#[test]
fn test_certificate_der_roundtrip() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_der = ca_cert.to_der()?;
	let user_der = user_cert.to_der()?;

	let ca_cert_from_der = Certificate::try_from(ca_der)?;
	let user_cert_from_der = Certificate::try_from(user_der)?;
	assert_eq!(ca_cert.tbs_certificate.subject, ca_cert_from_der.tbs_certificate.subject);
	assert_eq!(user_cert.tbs_certificate.subject, user_cert_from_der.tbs_certificate.subject);

	Ok(())
}

#[test]
fn test_certificate_algorithm_identifiers() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_algorithm = &ca_cert.signature_algorithm;
	let user_algorithm = &user_cert.signature_algorithm;
	// Both should have valid algorithm identifiers
	assert!(!ca_algorithm.oid.to_string().is_empty());
	assert!(!user_algorithm.oid.to_string().is_empty());
	// They should use the same signature algorithm
	assert_eq!(ca_algorithm.oid, user_algorithm.oid);
}

#[test]
fn test_certificate_serial_numbers() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	// Serial numbers should be different
	assert_ne!(ca_cert.tbs_certificate.serial_number, user_cert.tbs_certificate.serial_number);
	// Both should have valid serial numbers
	assert!(!ca_cert.tbs_certificate.serial_number.as_bytes().is_empty());
	assert!(!user_cert
		.tbs_certificate
		.serial_number
		.as_bytes()
		.is_empty());
}
