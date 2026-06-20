mod common;

#[cfg(feature = "serde")]
use std::collections::BTreeSet;

use keetanetwork_x509::certificates::Extension;
use keetanetwork_x509::oids;

#[cfg(feature = "serde")]
use keetanetwork_x509::certificates::{CertificateBundle, CertificateHash, CertificateOptions};

use common::*;

#[cfg(feature = "serde")]
#[test]
fn test_json_serialization() -> Result<(), Box<dyn core::error::Error>> {
	use serde_json;

	let cert = ca_certificate();
	let bundle = CertificateBundle {
		certificate: cert.clone(),
		options: CertificateOptions::default(),
		root: BTreeSet::new(),
		intermediate: BTreeSet::new(),
	};

	// Test that JSON contains hash field
	let json_value = serde_json::to_value(&bundle)?;
	let json_string = serde_json::to_string(&json_value)?;
	assert!(json_string.contains("\"hash\""));

	// Verify the certificate hash is present in the serialized JSON
	let cert_hash = json_value["certificate"]["hash"]
		.as_str()
		.ok_or("certificate hash not found")?;
	assert!(!cert_hash.is_empty());
	Ok(())
}

#[test]
fn test_extension_creation() -> Result<(), Box<dyn core::error::Error>> {
	// Test Extension::new functionality
	let ext = Extension::new("1.2.3.4", [0x01, 0x02], true)?;
	assert_eq!(ext.extn_id.to_string(), "1.2.3.4");
	assert!(ext.critical);
	assert_eq!(ext.extn_value.as_bytes(), &[0x01, 0x02]);

	let ext_non_critical = Extension::new("1.2.3.4.5", [0x03, 0x04, 0x05], false)?;
	assert_eq!(ext_non_critical.extn_id.to_string(), "1.2.3.4.5");
	assert!(!ext_non_critical.critical);
	assert_eq!(ext_non_critical.extn_value.as_bytes(), &[0x03, 0x04, 0x05]);

	Ok(())
}

#[test]
fn test_extension_lookup() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();

	// Test get_extension method
	let basic_constraints_ext = ca_cert
		.extension(oids::BASIC_CONSTRAINTS)
		.ok_or("basic constraints extension not found")?;
	assert!(basic_constraints_ext.critical);

	// Test non-existent extension
	let non_existent_ext = ca_cert.extension("1.2.3.4.999");
	assert!(non_existent_ext.is_none());

	Ok(())
}

#[test]
fn test_extension_listing() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	// Test extensions method - demonstrate natural iterator usage
	let ca_extension_count = ca_cert.extensions().count();
	let user_extension_count = user_cert.extensions().count();
	assert!(ca_extension_count > 0);
	assert!(user_extension_count > 0);

	// Test extension OIDs are accessible - demonstrate typical usage pattern
	let ca_extension_oids: Vec<String> = ca_cert
		.extensions()
		.map(|ext| ext.extn_id.to_string())
		.collect();
	assert!(ca_extension_oids.contains(&oids::BASIC_CONSTRAINTS.to_string()));
	assert!(ca_extension_oids.contains(&oids::KEY_USAGE.to_string()));

	// User cert should have different extension set (not CA)
	let user_extension_oids: Vec<String> = user_cert
		.extensions()
		.map(|ext| ext.extn_id.to_string())
		.collect();
	assert!(user_extension_oids.contains(&oids::KEY_USAGE.to_string()));
	assert!(user_extension_oids.contains(&oids::SUBJECT_KEY_IDENTIFIER.to_string()));
	assert!(user_extension_oids.contains(&oids::AUTHORITY_KEY_IDENTIFIER.to_string()));
}

#[test]
fn test_extension_criticality() {
	let ca_cert = ca_certificate();
	let extensions = ca_cert.extensions();

	// Test extension criticality verification
	for ext in extensions {
		match ext.extn_id.to_string().as_str() {
			x if x == oids::BASIC_CONSTRAINTS => assert!(ext.critical),
			x if x == oids::KEY_USAGE => assert!(ext.critical),
			x if x == oids::SUBJECT_KEY_IDENTIFIER => assert!(!ext.critical),
			x if x == oids::AUTHORITY_KEY_IDENTIFIER => assert!(!ext.critical),
			_ => {}
		}
	}
}

#[cfg(feature = "serde")]
#[test]
fn test_json_hash_consistency() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = CertificateHash::try_from(&ca_cert)?;
	let user_hash = CertificateHash::try_from(&user_cert)?;
	let ca_hash_hex = hex::encode(ca_hash.as_ref());
	let user_hash_hex = hex::encode(user_hash.as_ref());

	let ca_json = serde_json::to_value(&ca_cert)?;
	let user_json = serde_json::to_value(&user_cert)?;

	let ca_hash_field = ca_json["hash"].as_str().ok_or("ca hash not found")?;
	let user_hash_field = user_json["hash"].as_str().ok_or("user hash not found")?;
	assert_eq!(ca_hash_field, ca_hash_hex);
	assert_eq!(user_hash_field, user_hash_hex);
	assert_ne!(ca_hash_field, user_hash_field);

	Ok(())
}

#[test]
fn test_certificate_display_round_trip() -> Result<(), Box<dyn core::error::Error>> {
	use keetanetwork_x509::certificates::Certificate;

	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	// Test Display trait produces valid PEM
	let ca_pem_display = format!("{ca_cert}");
	let user_pem_display = format!("{user_cert}");

	// Test to_pem method produces same result as Display
	let ca_pem_method = ca_cert.to_pem()?;
	let user_pem_method = user_cert.to_pem()?;

	assert_eq!(ca_pem_display, ca_pem_method);
	assert_eq!(user_pem_display, user_pem_method);

	// Test round-trip: Certificate -> Display -> parse -> Certificate
	let ca_cert_roundtrip = ca_pem_display.parse::<Certificate>()?;
	let user_cert_roundtrip = user_pem_display.parse::<Certificate>()?;

	assert_eq!(ca_cert, ca_cert_roundtrip);
	assert_eq!(user_cert, user_cert_roundtrip);

	// Test that PEM format is correct
	assert!(ca_pem_display.starts_with("-----BEGIN CERTIFICATE-----"));
	assert!(ca_pem_display.ends_with("-----END CERTIFICATE-----\n"));
	assert!(user_pem_display.starts_with("-----BEGIN CERTIFICATE-----"));
	assert!(user_pem_display.ends_with("-----END CERTIFICATE-----\n"));

	Ok(())
}
