mod common;

use std::collections::HashSet;
use x509::certificates::*;

use common::*;

#[test]
fn test_certificate_bundle_creation() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();

	// Test basic bundle properties
	let bundle = CertificateBundle::try_from(vec![ca_cert.clone(), user_cert.clone()]).unwrap();
	assert_eq!(bundle.clone().into_iter().count(), 1); // Only returns valid chains

	// Test that we can access all certificates through stores
	let all_certificates = {
		let mut all_certs = vec![bundle.certificate.clone()];
		all_certs.extend(bundle.root.iter().cloned());
		all_certs.extend(bundle.intermediate.iter().cloned());
		all_certs
	};
	assert!(!all_certificates.is_empty());
}

#[test]
fn test_certificate_bundle_with_chain() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let cert_moment = test_moment();

	// Test bundle can find chains properly
	let mut root_store = HashSet::new();
	root_store.insert(ca_cert.clone());

	// This should find a chain from user cert to CA
	let user_bundle = CertificateBundle {
		certificate: user_cert.clone(),
		options: CertificateOptions { moment: Some(cert_moment), ..Default::default() },
		root: root_store.clone(),
		intermediate: HashSet::new(),
	};
	assert_eq!(user_bundle.to_chain_length(), 2);

	// Test trusted bundle
	let trusted_user_bundle = CertificateBundle {
		certificate: user_cert.clone(),
		options: CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(true) },
		root: root_store.clone(),
		intermediate: HashSet::new(),
	};
	assert!(trusted_user_bundle.is_trusted());
}

#[test]
fn test_certificate_bundle_operations() {
	let ca_cert = ca_certificate();

	// Test DER encoding/decoding round trip
	let bundle = CertificateBundle::try_from(vec![ca_cert.clone()]).unwrap();
	let der_buffer: Vec<u8> = (&bundle).try_into().unwrap();
	assert!(!der_buffer.is_empty());

	// Test reconstruction from DER
	let reconstructed_bundle = CertificateBundle::try_from(der_buffer.as_slice()).unwrap();
	assert_eq!(reconstructed_bundle.into_iter().count(), 1);
}

#[test]
fn test_certificate_bundle_stores() {
	let ca_cert = ca_certificate();
	let user_cert = user_certificate();
	let cert_moment = test_moment();

	// Test certificate store operations
	let mut root_certs = HashSet::new();
	root_certs.insert(ca_cert.clone());
	let mut intermediate_certs = HashSet::new();
	intermediate_certs.insert(user_cert.clone());

	// Test that certificate with stores but no trusted root option is not trusted by default
	let cert_with_options = CertificateBundle {
		certificate: ca_cert.clone(),
		options: CertificateOptions::default(),
		root: root_certs.clone(),
		intermediate: intermediate_certs.clone(),
	};
	assert!(!cert_with_options.is_trusted());

	// Test trusted certificate creation
	let options_trusted = CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(true) };
	let ca_pem = ca_cert.to_pem().unwrap();
	let trusted_cert = CertificateBundle::new(&ca_pem, Some(options_trusted), None, None).unwrap();
	assert!(trusted_cert.is_trusted());
}

#[test]
fn test_certificate_bundle_constructor() {
	let cert_moment = test_moment();

	// Test CertificateBundle constructor variants
	let cert_with_opts = CertificateBundle::new(CA_CERT_PEM, None, None, None).unwrap();
	assert!(!cert_with_opts.is_trusted());
	assert_eq!(cert_with_opts.to_chain_length(), 1);

	// Test with trusted root option
	let trusted_opts = CertificateOptions { moment: Some(cert_moment), is_trusted_root: Some(true) };
	let trusted_bundle = CertificateBundle::new(CA_CERT_PEM, Some(trusted_opts), None, None).unwrap();
	assert!(trusted_bundle.is_trusted());
}
