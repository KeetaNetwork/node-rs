mod common;

use keetanetwork_x509::certificates::{Certificate, CertificateHash};

#[cfg(feature = "serde")]
use keetanetwork_x509::certificates::CertificateBundle;

use common::*;

#[test]
fn test_hash_uniqueness() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let ca_hash = CertificateHash::try_from(&ca_cert)?;
	let user_hash = CertificateHash::try_from(&user_cert)?;
	assert_ne!(ca_hash, user_hash);
	assert_eq!(ca_hash.len(), 20);
	assert_eq!(user_hash.len(), 20);

	Ok(())
}

#[test]
fn test_hash_consistency() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let ca_cert_2 = ca_certificate();
	let ca_hash = CertificateHash::try_from(&ca_cert)?;
	let ca_hash_2 = CertificateHash::try_from(&ca_cert_2)?;
	assert_eq!(ca_hash, ca_hash_2);

	Ok(())
}

#[test]
fn test_hash_hex_representation() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = CertificateHash::try_from(&ca_cert)?;
	let user_hash = CertificateHash::try_from(&user_cert)?;

	let ca_hash_hex = hex::encode(ca_hash.as_ref());
	let user_hash_hex = hex::encode(user_hash.as_ref());
	assert_ne!(ca_hash_hex, user_hash_hex);
	assert_eq!(ca_hash_hex.len(), 40); // 20 bytes * 2 hex chars
	assert_eq!(user_hash_hex.len(), 40);

	Ok(())
}

#[test]
fn test_hash_der_consistency() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let ca_der = ca_cert.to_der()?;
	let ca_from_der = Certificate::try_from(ca_der.as_slice())?;

	let ca_hash_from_der = CertificateHash::try_from(&ca_from_der)?;
	let ca_hash_original = CertificateHash::try_from(&ca_cert)?;
	assert_eq!(ca_hash_original, ca_hash_from_der);

	Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn test_hash_json_serialization() -> Result<(), Box<dyn core::error::Error>> {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	let ca_hash = CertificateHash::try_from(&ca_cert)?;
	let user_hash = CertificateHash::try_from(&user_cert)?;
	let ca_hash_hex = hex::encode(ca_hash.as_ref());
	let user_hash_hex = hex::encode(user_hash.as_ref());

	let ca_bundle = CertificateBundle::try_from(vec![ca_cert.clone()])?;
	let user_bundle = CertificateBundle::try_from(vec![user_cert.clone()])?;

	// Serialize to JSON and verify hash consistency
	let ca_json = serde_json::to_value(&ca_bundle)?;
	let user_json = serde_json::to_value(&user_bundle)?;

	// Extract hash fields from JSON
	let ca_hash_field = ca_json["certificate"]["hash"]
		.as_str()
		.ok_or("ca hash not found")?;
	let user_hash_field = user_json["certificate"]["hash"]
		.as_str()
		.ok_or("user hash not found")?;
	assert!(!ca_hash_field.is_empty());
	assert_eq!(ca_hash_field, ca_hash_hex);
	assert!(!user_hash_field.is_empty());
	assert_eq!(user_hash_field, user_hash_hex);
	assert_ne!(ca_hash_field, user_hash_field);

	Ok(())
}
