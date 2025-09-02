mod common;

#[cfg(feature = "serde")]
use std::collections::HashSet;

use keetanetwork_x509::certificates::{Certificate, CertificateHash};

#[cfg(feature = "serde")]
use keetanetwork_x509::certificates::{CertificateBundle, CertificateOptions};

use common::*;

#[test]
fn test_hash_uniqueness() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = CertificateHash::try_from(&ca_cert).unwrap();
	let user_hash = CertificateHash::try_from(&user_cert).unwrap();
	assert_ne!(ca_hash, user_hash);
	assert_eq!(ca_hash.len(), 20);
	assert_eq!(user_hash.len(), 20);
}

#[test]
fn test_hash_consistency() {
	let ca_cert = ca_certificate();
	let ca_cert_2 = ca_certificate();

	let ca_hash = CertificateHash::try_from(&ca_cert).unwrap();
	let ca_hash_2 = CertificateHash::try_from(&ca_cert_2).unwrap();
	assert_eq!(ca_hash, ca_hash_2);
}

#[test]
fn test_hash_hex_representation() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = CertificateHash::try_from(&ca_cert).unwrap();
	let user_hash = CertificateHash::try_from(&user_cert).unwrap();

	let ca_hash_hex = hex::encode(ca_hash.as_ref());
	let user_hash_hex = hex::encode(user_hash.as_ref());
	assert_ne!(ca_hash_hex, user_hash_hex);
	assert_eq!(ca_hash_hex.len(), 40); // 20 bytes * 2 hex chars
	assert_eq!(user_hash_hex.len(), 40);
}

#[test]
fn test_hash_der_consistency() {
	let ca_cert = ca_certificate();
	let ca_der = ca_cert.to_der().unwrap();
	let ca_from_der = Certificate::try_from(ca_der.as_slice()).unwrap();

	let ca_hash_from_der = CertificateHash::try_from(&ca_from_der).unwrap();
	let ca_hash_original = CertificateHash::try_from(&ca_cert).unwrap();
	assert_eq!(ca_hash_original, ca_hash_from_der);
}

#[cfg(feature = "serde")]
#[test]
fn test_hash_json_serialization() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = CertificateHash::try_from(&ca_cert).unwrap();
	let user_hash = CertificateHash::try_from(&user_cert).unwrap();
	let ca_hash_hex = hex::encode(ca_hash.as_ref());
	let user_hash_hex = hex::encode(user_hash.as_ref());

	let ca_bundle = CertificateBundle {
		certificate: ca_cert.clone(),
		options: CertificateOptions::default(),
		root: HashSet::new(),
		intermediate: HashSet::new(),
	};
	let user_bundle = CertificateBundle {
		certificate: user_cert.clone(),
		options: CertificateOptions::default(),
		root: HashSet::new(),
		intermediate: HashSet::new(),
	};

	// Serialize to JSON and verify hash consistency
	let ca_json = serde_json::to_value(&ca_bundle).unwrap();
	let user_json = serde_json::to_value(&user_bundle).unwrap();

	// Extract hash fields from JSON
	let ca_hash_field = ca_json["certificate"]["hash"].as_str().unwrap();
	let user_hash_field = user_json["certificate"]["hash"].as_str().unwrap();
	assert!(!ca_hash_field.is_empty());
	assert_eq!(ca_hash_field, ca_hash_hex);
	assert!(!user_hash_field.is_empty());
	assert_eq!(user_hash_field, user_hash_hex);
	assert_ne!(ca_hash_field, user_hash_field);
}
