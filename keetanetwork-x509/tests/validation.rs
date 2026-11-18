mod common;

use keetanetwork_account::{Account, KeyED25519, KeyPair};
use keetanetwork_x509::builder::{CertificateBuilder, ExtensionBuilder};
use keetanetwork_x509::certificates::{Certificate, Extension};
use keetanetwork_x509::doc_utils::create_test_keys;
use keetanetwork_x509::{oids, utils, SerialNumber};

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
	{
		let ca_public_key_bytes = ca_public_key.subject_public_key.as_bytes();
		let user_public_key_bytes = user_public_key.subject_public_key.as_bytes();
		assert_ne!(ca_public_key_bytes, user_public_key_bytes);
	}
	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		let ca_public_key_bytes = ca_public_key.subject_public_key.raw_bytes();
		let user_public_key_bytes = user_public_key.subject_public_key.raw_bytes();
		assert_ne!(ca_public_key_bytes, user_public_key_bytes);
	}
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
	let ca_oid = ca_algorithm.oid.to_string();
	let user_oid = user_algorithm.oid.to_string();
	assert!(!ca_oid.is_empty());
	assert!(!user_oid.is_empty());
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
	let ca_serial_bytes = ca_cert.tbs_certificate.serial_number.as_bytes();
	let user_serial_bytes = user_cert.tbs_certificate.serial_number.as_bytes();
	assert!(!ca_serial_bytes.is_empty());
	assert!(!user_serial_bytes.is_empty());
}

/// Starts a certificate for `subject_cn` issued by `issuer_cn`, ready for extensions and signing.
fn certificate_builder(
	subject: &Account<KeyED25519>,
	subject_cn: &str,
	issuer_cn: &str,
	serial: u64,
) -> CertificateBuilder {
	let subject_dn = utils::create_dn(&[(oids::CN, subject_cn)]).expect("subject DN");
	let issuer_dn = utils::create_dn(&[(oids::CN, issuer_cn)]).expect("issuer DN");

	CertificateBuilder::new()
		.with_subject_public_key(subject.keypair.to_public_key().into())
		.with_subject_dn(subject_dn)
		.with_issuer_dn(issuer_dn)
		.with_validity_days(365)
		.with_serial_number(SerialNumber::from(serial))
}

/// Signing accounts for test chains: a root, two intermediate CAs, and a leaf.
struct ChainAccounts {
	root: Account<KeyED25519>,
	upper: Account<KeyED25519>,
	lower: Account<KeyED25519>,
	leaf: Account<KeyED25519>,
}

impl ChainAccounts {
	fn new() -> Self {
		let account = |seed: &[u8]| create_test_keys(Some(seed)).2;
		Self {
			root: account(b"root_seed_32_bytes_exactly!!!!"),
			upper: account(b"upper_seed_32_bytes_exactly!!"),
			lower: account(b"lower_seed_32_bytes_exactly!!"),
			leaf: account(b"leaf_seed_32_bytes_exactly!!!"),
		}
	}

	/// Self-signed root CA named "Root".
	fn root_certificate(&self, path_len: Option<u8>) -> Certificate {
		certificate_builder(&self.root, "Root", "Root", 1)
			.with_basic_constraints(true, path_len)
			.build(&self.root)
			.expect("root certificate")
	}

	/// Leaf certificate issued by `issuer_cn` and signed by `signer`.
	fn leaf_certificate(&self, issuer_cn: &str, signer: &Account<KeyED25519>) -> Certificate {
		certificate_builder(&self.leaf, "Leaf", issuer_cn, 4)
			.with_basic_constraints(false, None)
			.build(signer)
			.expect("leaf certificate")
	}
}

/// Asserts path validation and chain building agree on whether `path` (leaf first, root last) is valid.
fn assert_path_accepted(case: &str, path: &[Certificate], accepted: bool) -> Result<(), Box<dyn core::error::Error>> {
	let leaf = &path[0];
	assert_eq!(leaf.validate_certificate_path(path)?, accepted, "validate_certificate_path, case: {case}");

	let chain: Vec<Certificate> = leaf.verify_chain(path.to_vec()).collect();
	assert_eq!(chain.len() == path.len(), accepted, "verify_chain, case: {case}");

	Ok(())
}

/// Asserts the single-issuer entry points agree on whether `issuer` may issue `leaf` under `root`.
fn assert_issuer_accepted(
	case: &str,
	leaf: Certificate,
	issuer: Certificate,
	root: &Certificate,
	accepted: bool,
) -> Result<(), Box<dyn core::error::Error>> {
	assert_eq!(issuer.can_sign_certificates(), accepted, "can_sign_certificates, case: {case}");
	assert_eq!(leaf.is_issued_by(&issuer), accepted, "is_issued_by, case: {case}");
	assert_eq!(leaf.is_valid_issuer_subject_pair(&issuer)?, accepted, "is_valid_issuer_subject_pair, case: {case}");
	assert_eq!(leaf.is_trusted([issuer.clone(), root.clone()], None), accepted, "is_trusted, case: {case}");

	assert_path_accepted(case, &[leaf, issuer, root.clone()], accepted)
}

#[test]
fn test_chain_requires_ca_issuer() -> Result<(), Box<dyn core::error::Error>> {
	let accounts = ChainAccounts::new();
	let root = accounts.root_certificate(None);

	let cases = [("CA issuer", true, true), ("non-CA issuer", false, false)];
	for (case, issuer_is_ca, accepted) in cases {
		let issuer = certificate_builder(&accounts.upper, "Issuer", "Root", 2)
			.with_basic_constraints(issuer_is_ca, None)
			.build(&accounts.root)?;

		let leaf = accounts.leaf_certificate("Issuer", &accounts.upper);
		assert_issuer_accepted(case, leaf, issuer, &root, accepted)?;
	}

	Ok(())
}

#[test]
fn test_chain_requires_key_cert_sign() -> Result<(), Box<dyn core::error::Error>> {
	const DIGITAL_SIGNATURE: u16 = 0x80;
	const KEY_CERT_SIGN: u16 = 0x04;
	const CRL_SIGN: u16 = 0x02;
	// An OCTET STRING where Key Usage requires a BIT STRING
	const MALFORMED_KEY_USAGE: &[u8] = b"\x04\x01\x06";

	let accounts = ChainAccounts::new();
	let root = accounts.root_certificate(None);
	let cases = [
		("no Key Usage", vec![], true),
		("keyCertSign set", vec![ExtensionBuilder::for_key_usage(KEY_CERT_SIGN | CRL_SIGN)], true),
		("keyCertSign clear", vec![ExtensionBuilder::for_key_usage(DIGITAL_SIGNATURE | CRL_SIGN)], false),
		("malformed Key Usage", vec![Extension::new(oids::KEY_USAGE, MALFORMED_KEY_USAGE, true)?], false),
	];

	for (case, issuer_extensions, accepted) in cases {
		let issuer = certificate_builder(&accounts.upper, "Issuer", "Root", 2)
			.with_basic_constraints(true, None)
			.with_extensions(issuer_extensions)
			.build(&accounts.root)?;

		let leaf = accounts.leaf_certificate("Issuer", &accounts.upper);
		assert_issuer_accepted(case, leaf, issuer, &root, accepted)?;
	}

	Ok(())
}

#[test]
fn test_chain_enforces_path_len_constraint() -> Result<(), Box<dyn core::error::Error>> {
	let accounts = ChainAccounts::new();

	// Path: leaf, lower CA, upper CA, root. Root and upper CA each have intermediates below them.
	let cases = [
		("no constraints", None, None, true),
		("constraints at limit", Some(2), Some(1), true),
		("upper CA allows none", None, Some(0), false),
		("root allows one", Some(1), None, false),
	];
	for (case, root_path_len, upper_path_len, accepted) in cases {
		let root = accounts.root_certificate(root_path_len);
		let upper = certificate_builder(&accounts.upper, "Upper", "Root", 2)
			.with_basic_constraints(true, upper_path_len)
			.build(&accounts.root)?;
		let lower = certificate_builder(&accounts.lower, "Lower", "Upper", 3)
			.with_basic_constraints(true, Some(0))
			.build(&accounts.upper)?;

		let leaf = accounts.leaf_certificate("Lower", &accounts.lower);
		assert_path_accepted(case, &[leaf, lower, upper, root], accepted)?;
	}

	Ok(())
}

#[test]
fn test_path_len_constraint_skips_self_issued_intermediate() -> Result<(), Box<dyn core::error::Error>> {
	let accounts = ChainAccounts::new();

	// Path: leaf, lower CA, root key rollover (self-issued, new key), root.
	// Only the lower CA counts against the root's pathLenConstraint.
	let cases = [("rollover not counted", Some(1), true), ("lower CA still counted", Some(0), false)];
	for (case, root_path_len, accepted) in cases {
		let root = accounts.root_certificate(root_path_len);
		// The builder derives a self-issued certificate's AKI from its own key, so name the signing root key.
		let root_key_id = utils::generate_key_identifier(
			root.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;
		let rollover = certificate_builder(&accounts.upper, "Root", "Root", 2)
			.with_basic_constraints(true, None)
			.with_extension(ExtensionBuilder::for_authority_key_identifier(&root_key_id))
			.build(&accounts.root)?;
		let lower = certificate_builder(&accounts.lower, "Lower", "Root", 3)
			.with_basic_constraints(true, None)
			.build(&accounts.upper)?;

		let leaf = accounts.leaf_certificate("Lower", &accounts.lower);
		let path = [leaf.clone(), lower, rollover, root];
		assert_eq!(leaf.validate_certificate_path(&path)?, accepted, "case: {case}");
	}

	Ok(())
}

#[test]
fn test_verify_chain_stops_on_issuer_cycle() -> Result<(), Box<dyn core::error::Error>> {
	let accounts = ChainAccounts::new();

	// "Upper" and "Lower" each issue the other, so neither chain reaches a root.
	let upper = certificate_builder(&accounts.upper, "Upper", "Lower", 2)
		.with_basic_constraints(true, None)
		.build(&accounts.lower)?;
	let lower = certificate_builder(&accounts.lower, "Lower", "Upper", 3)
		.with_basic_constraints(true, None)
		.build(&accounts.upper)?;

	let leaf = accounts.leaf_certificate("Upper", &accounts.upper);
	let chain: Vec<Certificate> = leaf.verify_chain([upper.clone(), lower.clone()]).collect();
	assert_eq!(chain, [leaf, upper, lower]);

	Ok(())
}
