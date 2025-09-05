mod common;

use keetanetwork_x509::certificates::*;

use common::*;

/// Helper to create a trusted CA bundle
fn create_trusted_ca_bundle() -> CertificateBundle {
	let ca_cert = ca_certificate();
	CertificateBundle::try_from(vec![ca_cert])
		.unwrap()
		.as_trusted()
}

/// Helper to create an untrusted user bundle
fn create_untrusted_user_bundle() -> CertificateBundle {
	let user_cert = user_certificate();
	CertificateBundle::try_from(vec![user_cert])
		.unwrap()
		.as_untrusted()
}

/// Helper to create user bundle with CA in root store
fn create_user_bundle_with_ca_store() -> CertificateBundle {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let chain = vec![user_cert, ca_cert];

	CertificateBundle::try_from(chain).unwrap().as_trusted()
}

#[test]
fn test_trusted_ca_certificate() {
	let ca_bundle = create_trusted_ca_bundle();
	assert!(ca_bundle.is_trusted());
	assert_eq!(ca_bundle.to_chain_length(), 1); // Self-signed cert
	assert!(ca_bundle.to_issuer_certificate().is_some()); // Self-signed cert is its own issuer
}

#[test]
fn test_untrusted_user_certificate() {
	let user_bundle = create_untrusted_user_bundle();
	assert!(!user_bundle.is_trusted());
	assert_eq!(user_bundle.to_chain_length(), 1); // No valid chain
	assert!(user_bundle.to_issuer_certificate().is_none()); // No issuer found
}

#[test]
fn test_user_certificate_with_ca_store() {
	let user_bundle = create_user_bundle_with_ca_store();
	// Marked as trusted in options
	assert!(user_bundle.is_trusted());
	// Note: These test certificates are not cryptographically valid,
	// so chain verification fails and length remains 1
	assert_eq!(user_bundle.to_chain_length(), 1);
	assert!(user_bundle.to_issuer_certificate().is_none());
	assert!(user_bundle.to_root_certificate().is_none());
}

#[test]
fn test_certificate_chain_verification() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	// Test direct chain verification (bypassing bundle)
	let chain = vec![user_cert.clone(), ca_cert.clone()];
	let verified_chain: Vec<_> = user_cert.verify_chain(chain).collect();
	// These test certificates are not cryptographically valid
	assert_eq!(verified_chain.len(), 1); // Only contains user cert, no valid chain to CA
}

#[test]
fn test_certificate_properties() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let cert_moment = test_moment();
	// Test validity checking
	assert!(ca_cert.is_valid_at(cert_moment).unwrap());
	assert!(user_cert.is_valid_at(cert_moment).unwrap());
	// Test CA vs non-CA certificates
	assert!(ca_cert.is_ca());
	assert!(!user_cert.is_ca());
}

#[test]
fn test_manual_bundle_construction() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	// Test bundle construction from Vec<Certificate>
	let untrusted_bundle = CertificateBundle::try_from(vec![user_cert.clone()]).unwrap();
	assert!(!untrusted_bundle.is_trusted());

	let chain = vec![user_cert.clone(), ca_cert];
	let trusted_bundle = CertificateBundle::try_from(chain).unwrap().as_trusted();
	assert!(trusted_bundle.is_trusted());
}
