mod common;

use x509::certificates::Certificate;

use common::*;

#[test]
fn test_hash_uniqueness() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = ca_cert.hash().unwrap();
	let user_hash = user_cert.hash().unwrap();
	assert_ne!(ca_hash, user_hash);
	assert_eq!(ca_hash.len(), 20);
	assert_eq!(user_hash.len(), 20);
}

#[test]
fn test_hash_consistency() {
	let ca_cert = ca_certificate();
	let ca_cert_2 = ca_certificate();

	let ca_hash = ca_cert.hash().unwrap();
	let ca_hash_2 = ca_cert_2.hash().unwrap();
	assert_eq!(ca_hash, ca_hash_2);
}

#[test]
fn test_hash_hex_representation() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = ca_cert.hash().unwrap();
	let user_hash = user_cert.hash().unwrap();

	let ca_hash_hex = hex::encode(ca_hash.as_bytes());
	let user_hash_hex = hex::encode(user_hash.as_bytes());
	assert_ne!(ca_hash_hex, user_hash_hex);
	assert_eq!(ca_hash_hex.len(), 40); // 20 bytes * 2 hex chars
	assert_eq!(user_hash_hex.len(), 40);
}

#[test]
fn test_hash_der_consistency() {
	let ca_cert = ca_certificate();
	let ca_der = ca_cert.to_der().unwrap();
	let ca_from_der = Certificate::from_der(&ca_der).unwrap();

	let ca_hash_from_der = ca_from_der.hash().unwrap();
	let ca_hash_original = ca_cert.hash().unwrap();
	assert_eq!(ca_hash_original, ca_hash_from_der);
}

#[cfg(feature = "serde")]
#[test]
fn test_hash_json_serialization() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = ca_cert.hash().unwrap();
	let user_hash = user_cert.hash().unwrap();
	let ca_hash_hex = hex::encode(ca_hash.as_bytes());
	let user_hash_hex = hex::encode(user_hash.as_bytes());

	let ca_json = ca_cert.to_json(true).unwrap();
	let user_json = user_cert.to_json(true).unwrap();
	assert!(!ca_json.hash_field.is_empty());
	assert_eq!(ca_json.hash_field, ca_hash_hex);
	assert!(!user_json.hash_field.is_empty());
	assert_eq!(user_json.hash_field, user_hash_hex);
	assert_ne!(ca_json.hash_field, user_json.hash_field);
}
