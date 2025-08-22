//! Documentation utilities for X.509 examples.
//!
//! This module provides helper functions that are only available during
//! documentation generation. These helpers reduce code duplication in
//! documentation examples and provide consistent test data.

use accounts::{Account, KeyED25519, KeyPair};
use crypto::algorithms::{Ed25519Derivation, Ed25519PrivateKey, Ed25519PublicKey};
use crypto::bigint::U256;
use crypto::prelude::{KeyDerivation, PrivateKey};

use crate::builder::CertificateBuilder;
use crate::certificates::Certificate;
use crate::{oids, utils};

/// Standard test seed for consistent documentation examples.
pub const DOC_TEST_SEED: &[u8] = b"abandon abandon abandon abandon abandon abandon ";

/// Create a complete key set (private key, public key, and account) for documentation examples.
///
/// Returns (private_key, public_key, account) tuple with all the cryptographic
/// components needed for certificate examples.
pub fn create_test_keys(seed: Option<&[u8]>) -> (Ed25519PrivateKey, Ed25519PublicKey, Account<KeyED25519>) {
	let seed = seed.unwrap_or(DOC_TEST_SEED);
	let private_key = Ed25519Derivation::derive_from_seed(seed).expect("Failed to derive test private key");
	let public_key = private_key.as_public_key();
	let account = Account::from(private_key.clone());

	(private_key, public_key, account)
}

/// Create a single test certificate.
///
/// Creates a self-signed CA certificate using test keys. If signer is provided,
/// uses the custom signer for certificate signing.
///
/// # Panics
///
/// Panics if certificate creation fails.
pub fn create_test_certificate(subject_name: &str, signer: Option<Account<KeyED25519>>) -> Certificate {
	let (_, _, account) = create_test_keys(None);
	let public_key_info = account.keypair.to_public_key().into();

	// Create a distinguished name
	let subject_dn = utils::create_dn(&[(oids::CN, subject_name)]).expect("Failed to create subject DN");

	let builder = CertificateBuilder::new()
		.with_subject_public_key(public_key_info)
		.with_subject_dn(subject_dn.clone())
		.with_issuer_dn(subject_dn) // Self-signed
		.with_serial_number(U256::from(1u128))
		.with_validity_days(365)
		.with_basic_constraints(true, None); // CA certificate

	match signer {
		Some(custom_signer) => builder.build(&custom_signer),
		None => builder.build(&account),
	}
	.expect("Failed to create test certificate")
}

/// Create a certificate chain (root CA, intermediate CA, client certificate).
///
/// Returns (client_cert, intermediate_cert, root_cert) for documentation examples
/// that need to demonstrate full certificate chain validation. If signer is provided,
/// uses the custom signer for all certificates in the chain.
///
/// # Panics
///
/// Panics if certificate chain creation fails.
pub fn create_test_certificate_chain(signer: Option<&Account<KeyED25519>>) -> (Certificate, Certificate, Certificate) {
	// Create different keys for each certificate
	let (_, _, root_account) = create_test_keys(Some(b"root_seed_32_bytes_exactly!!!!"));
	let (_, _, intermediate_account) = create_test_keys(Some(b"intermediate_seed_32_bytes_ex"));
	let (_, _, client_account) = create_test_keys(Some(b"client_seed_32_bytes_exactly!"));

	// Helper function to create certificates using the same signing approach
	let create_cert = |builder: CertificateBuilder, account: &Account<KeyED25519>| -> Certificate {
		match signer {
			Some(custom_signer) => builder.build(custom_signer),
			None => builder.build(account),
		}
		.expect("Failed to build certificate")
	};

	// Create root CA
	let root_public_key_info = root_account.keypair.to_public_key().into();
	let root_dn = utils::create_dn(&[(oids::CN, "Test Root CA")]).expect("Failed to create root DN");

	let root_cert = create_cert(
		CertificateBuilder::new()
			.with_subject_public_key(root_public_key_info)
			.with_subject_dn(root_dn.clone())
			.with_issuer_dn(root_dn) // Self-signed
			.with_validity_days(3650)
			.with_serial_number(U256::from(1u128))
			.with_basic_constraints(true, None), // CA certificate
		&root_account,
	);

	// Create intermediate CA signed by root
	let intermediate_public_key_info = intermediate_account.keypair.to_public_key().into();
	let intermediate_dn =
		utils::create_dn(&[(oids::CN, "Test Intermediate CA")]).expect("Failed to create intermediate DN");
	let root_dn = utils::create_dn(&[(oids::CN, "Test Root CA")]).expect("Failed to create root DN");

	let intermediate_cert = create_cert(
		CertificateBuilder::new()
			.with_subject_public_key(intermediate_public_key_info)
			.with_subject_dn(intermediate_dn)
			.with_issuer_dn(root_dn)
			.with_validity_days(1825)
			.with_serial_number(U256::from(2u128))
			.with_basic_constraints(true, None), // CA certificate
		&intermediate_account,
	);

	// Create client certificate signed by intermediate
	let client_public_key_info = client_account.keypair.to_public_key().into();
	let client_dn = utils::create_dn(&[(oids::CN, "Test Client")]).expect("Failed to create client DN");
	let intermediate_dn =
		utils::create_dn(&[(oids::CN, "Test Intermediate CA")]).expect("Failed to create intermediate DN");

	let client_cert = create_cert(
		CertificateBuilder::new()
			.with_subject_public_key(client_public_key_info)
			.with_subject_dn(client_dn)
			.with_issuer_dn(intermediate_dn)
			.with_validity_days(365)
			.with_serial_number(U256::from(3u128))
			.with_basic_constraints(false, None), // Not a CA certificate
		&client_account,
	);

	(client_cert, intermediate_cert, root_cert)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_create_test_keys() {
		// Verify the key pair is correctly related
		let (private_key, public_key, account) = create_test_keys(None);
		assert_eq!(public_key, private_key.as_public_key());

		// Verify account was created from the private key
		let account_public_key = account.keypair.to_public_key();
		assert_eq!(account_public_key, public_key);
	}

	#[test]
	fn test_create_test_certificate() {
		// Verify basic certificate properties
		let cert = create_test_certificate("Test CA", None);
		assert!(cert.to_subject().contains("Test CA"));
		assert!(cert.to_issuer().contains("Test CA")); // Self-signed
	}

	#[test]
	fn test_create_test_certificate_chain() {
		let (client_cert, intermediate_cert, root_cert) = create_test_certificate_chain(None);

		// Verify certificate names
		assert!(root_cert.to_subject().contains("Test Root CA"));
		assert!(intermediate_cert
			.to_subject()
			.contains("Test Intermediate CA"));
		assert!(client_cert.to_subject().contains("Test Client"));

		// Verify chain relationships
		assert_eq!(root_cert.tbs_certificate.issuer, root_cert.tbs_certificate.subject); // Root is self-signed
		assert_eq!(intermediate_cert.tbs_certificate.issuer, root_cert.tbs_certificate.subject); // Intermediate signed by root
		assert_eq!(client_cert.tbs_certificate.issuer, intermediate_cert.tbs_certificate.subject);
	}
}
