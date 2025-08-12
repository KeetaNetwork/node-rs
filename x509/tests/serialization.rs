mod common;

use std::collections::HashSet;
use x509::certificates::{CertificateBundle, CertificateHash, CertificateOptions, Extension};
use x509::oids;

use common::*;

#[cfg(feature = "serde")]
#[test]
fn test_json_serialization() {
	use serde_json;

	let cert = ca_certificate();
	let bundle = CertificateBundle {
		certificate: cert.clone(),
		options: CertificateOptions::default(),
		root: HashSet::new(),
		intermediate: HashSet::new(),
	};

	// Test that JSON contains hash field
	let json_struct = bundle.to_json(true).unwrap();
	let json_string = serde_json::to_string(&json_struct).unwrap();
	assert!(json_string.contains("\"$hash\""));
	assert!(!json_struct.hash_field.is_empty());
	assert!(json_struct.chain_field.is_none());
}

#[test]
fn test_extension_creation() {
	// Test Extension::new functionality
	let ext = Extension::new("1.2.3.4", &[0x01, 0x02], true).unwrap();
	assert_eq!(ext.oid.to_string(), "1.2.3.4");
	assert!(ext.critical);
	assert_eq!(ext.value.as_bytes(), &[0x01, 0x02]);

	let ext_non_critical = Extension::new("1.2.3.4.5", &[0x03, 0x04, 0x05], false).unwrap();
	assert_eq!(ext_non_critical.oid.to_string(), "1.2.3.4.5");
	assert!(!ext_non_critical.critical);
	assert_eq!(ext_non_critical.value.as_bytes(), &[0x03, 0x04, 0x05]);
}

#[test]
fn test_extension_lookup() {
	let ca_cert = ca_certificate();

	// Test get_extension method
	let basic_constraints_ext = ca_cert.get_extension(oids::BASIC_CONSTRAINTS);
	assert!(basic_constraints_ext.is_some());
	assert!(basic_constraints_ext.unwrap().critical);

	// Test non-existent extension
	let non_existent_ext = ca_cert.get_extension("1.2.3.4.999");
	assert!(non_existent_ext.is_none());
}

#[test]
fn test_extension_listing() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	// Test get_extensions method
	let ca_extensions = ca_cert.get_extensions();
	let user_extensions = user_cert.get_extensions();
	assert!(!ca_extensions.is_empty());
	assert!(!user_extensions.is_empty());

	// Test extension OIDs are accessible
	let ca_extension_oids: Vec<String> = ca_extensions
		.iter()
		.map(|ext| ext.oid.to_string())
		.collect();
	assert!(ca_extension_oids.contains(&oids::BASIC_CONSTRAINTS.to_string()));
	assert!(ca_extension_oids.contains(&oids::KEY_USAGE.to_string()));

	// User cert should have different extension set (not CA)
	let user_extension_oids: Vec<String> = user_extensions
		.iter()
		.map(|ext| ext.oid.to_string())
		.collect();
	assert!(user_extension_oids.contains(&oids::KEY_USAGE.to_string()));
	assert!(user_extension_oids.contains(&oids::SUBJECT_KEY_IDENTIFIER.to_string()));
	assert!(user_extension_oids.contains(&oids::AUTHORITY_KEY_IDENTIFIER.to_string()));
}

#[test]
fn test_extension_criticality() {
	let ca_cert = ca_certificate();
	let extensions = ca_cert.get_extensions();

	// Test extension criticality verification
	for ext in &extensions {
		match ext.oid.to_string().as_str() {
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
fn test_json_hash_consistency() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = CertificateHash::from(&ca_cert);
	let user_hash = CertificateHash::from(&user_cert);
	let ca_hash_hex = hex::encode(ca_hash.as_ref());
	let user_hash_hex = hex::encode(user_hash.as_ref());

	let ca_json = ca_cert.to_json(true).unwrap();
	let user_json = user_cert.to_json(true).unwrap();
	assert_eq!(ca_json.hash_field, ca_hash_hex);
	assert_eq!(user_json.hash_field, user_hash_hex);
	assert_ne!(ca_json.hash_field, user_json.hash_field);
}
