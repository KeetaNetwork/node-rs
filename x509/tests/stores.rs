mod common;

use std::collections::HashSet;
use x509::certificates::*;

use common::*;

#[test]
fn test_certificate_stores_basic() {
	let cert_moment = test_moment();
	let ca_cert_trusted = CertificateBundle::new(
		CA_CERT_PEM,
		Some(CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(true) }),
		None,
		None,
	)
	.unwrap();
	assert!(ca_cert_trusted.is_trusted());
	// The CA certificate has chain length 0 when it's a trusted root
	assert_eq!(ca_cert_trusted.chain_length(), 1);
	assert!(ca_cert_trusted.get_issuer_certificate().is_some()); // Self-signed cert is its own issuer
}

#[test]
fn test_certificate_stores_untrusted() {
	let cert_moment = test_moment();
	let user_cert_without_chain = CertificateBundle::new(
		USER_CERT_PEM,
		Some(CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(false) }),
		None,
		None,
	)
	.unwrap();
	assert!(!user_cert_without_chain.is_trusted());
	assert_eq!(user_cert_without_chain.chain_length(), 1);
	assert!(user_cert_without_chain.get_issuer_certificate().is_none());
}

#[test]
fn test_certificate_chain_verification() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	// Test 3: verify_chain() with root store
	let mut root_store = HashSet::new();
	root_store.insert(ca_cert.clone());
	let intermediate_store = HashSet::new();

	let verified_chain: Vec<_> = user_cert
		.verify_chain(&root_store, &intermediate_store)
		.collect();
	assert_eq!(verified_chain.len(), 2); // Should find chain: user cert -> CA certificate
}

#[test]
fn test_certificate_stores_with_chain() {
	let cert_moment = test_moment();
	let ca_cert = ca_certificate();

	let mut root_store = HashSet::new();
	root_store.insert(ca_cert.clone());

	let user_cert_with_store = CertificateBundle::new(
		USER_CERT_PEM,
		Some(CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(true) }),
		Some(root_store.clone()),
		None,
	)
	.unwrap();
	assert!(user_cert_with_store.is_trusted());
	assert_eq!(user_cert_with_store.chain_length(), 2);
	assert!(user_cert_with_store.get_issuer_certificate().is_some());
	assert_eq!(
		user_cert_with_store
			.get_issuer_certificate()
			.unwrap()
			.subject(),
		ca_cert.subject()
	);
}

#[test]
fn test_certificate_root_retrieval() {
	let cert_moment = test_moment();
	let ca_cert = ca_certificate();

	let mut root_store = HashSet::new();
	root_store.insert(ca_cert.clone());

	let user_cert_with_store = CertificateBundle::new(
		USER_CERT_PEM,
		Some(CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(true) }),
		Some(root_store.clone()),
		None,
	)
	.unwrap();

	// Test get_root_certificate functionality
	let root = user_cert_with_store.get_root_certificate();
	assert!(root.is_some());
	assert_eq!(root.unwrap().subject(), ca_cert.subject());
}

#[test]
fn test_certificate_validity_checking() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let cert_moment = test_moment();

	// Test certificate validity checking
	assert!(ca_cert.is_valid_at(cert_moment).unwrap());
	assert!(user_cert.is_valid_at(cert_moment).unwrap());
	// Test CA vs non-CA certificates
	assert!(ca_cert.is_ca());
	assert!(!user_cert.is_ca());
}

#[test]
fn test_certificate_chain_operations() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let cert_moment = test_moment();

	// Test certificate chain operations
	let root_store = HashSet::from([ca_cert.clone()]);
	let intermediate_store = HashSet::new();

	let verified_chain: Vec<_> = user_cert
		.verify_chain(&root_store, &intermediate_store)
		.collect();
	assert_eq!(verified_chain.len(), 2);

	let user_with_no_chain = CertificateBundle {
		certificate: user_cert.clone(),
		options: CertificateOptions { moment: Some(cert_moment), ..Default::default() },
		root: HashSet::new(),
		intermediate: HashSet::new(),
	};
	assert!(!user_with_no_chain.is_trusted());
	assert_eq!(user_with_no_chain.chain_length(), 1);
	assert!(user_with_no_chain.get_issuer_certificate().is_none());

	let user_cert_with_chain = CertificateBundle {
		certificate: user_cert.clone(),
		options: CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(true) },
		root: root_store.clone(),
		intermediate: intermediate_store.clone(),
	};

	assert!(user_cert_with_chain.is_trusted());
	assert_eq!(user_cert_with_chain.chain_length(), 2);

	let issuer = user_cert_with_chain.get_issuer_certificate();
	assert!(issuer.is_some());
	assert_eq!(issuer.unwrap().subject(), ca_cert.subject());

	let root = user_cert_with_chain.get_root_certificate();
	assert!(root.is_some());
	assert_eq!(root.unwrap().subject(), ca_cert.subject());
}
