//! Regression: path validation / is_trusted must reject non-CA issuers.
//!
//! RFC 5280 §6.1.4(k) requires intermediate certificates to assert cA=TRUE.
//! A compromised end-entity key must not be able to mint child certificates
//! that this library treats as trusted.

use chrono::Utc;
use keetanetwork_account::{Account, KeyED25519, KeyPair};
use keetanetwork_crypto::algorithms::ed25519::Ed25519Derivation;
use keetanetwork_crypto::algorithms::KeyDerivation;
use keetanetwork_crypto::prelude::IntoSecret;
use keetanetwork_x509::builder::CertificateBuilder;
use keetanetwork_x509::certificates::Certificate;
use keetanetwork_x509::{oids, utils};
use x509_cert::serial_number::SerialNumber;

fn account_from_seed(seed: &[u8]) -> Account<KeyED25519> {
	let private_key = Ed25519Derivation::derive_from_seed(seed.to_vec().into_secret())
		.expect("deterministic test seed must derive");
	Account::from(private_key)
}

fn build_self_signed_end_entity(account: &Account<KeyED25519>, cn: &str) -> Certificate {
	let dn = utils::create_dn(&[(oids::CN, cn)]).expect("DN");
	CertificateBuilder::new()
		.with_subject_public_key(account.keypair.to_public_key().into())
		.with_subject_dn(dn.clone())
		.with_issuer_dn(dn)
		.with_serial_number(SerialNumber::from(1u64))
		.with_validity_days(365)
		.with_basic_constraints(false, None) // NOT a CA
		.build(account)
		.expect("self-signed EE must build")
}

fn build_child_signed_by_ee(
	issuer_account: &Account<KeyED25519>,
	issuer_cn: &str,
	child_account: &Account<KeyED25519>,
	child_cn: &str,
) -> Certificate {
	let issuer_dn = utils::create_dn(&[(oids::CN, issuer_cn)]).expect("issuer DN");
	let child_dn = utils::create_dn(&[(oids::CN, child_cn)]).expect("child DN");
	CertificateBuilder::new()
		.with_subject_public_key(child_account.keypair.to_public_key().into())
		.with_subject_dn(child_dn)
		.with_issuer_dn(issuer_dn)
		.with_serial_number(SerialNumber::from(2u64))
		.with_validity_days(30)
		.with_basic_constraints(false, None)
		.build(issuer_account)
		.expect("child signed by EE must build")
}

#[test]
fn test_validate_path_rejects_non_ca_issuer() {
	let ee = account_from_seed(b"audit-ee-seed-32-bytes-padded!!!");
	let child = account_from_seed(b"audit-child-seed-32-bytes-pad!!");

	let ee_cert = build_self_signed_end_entity(&ee, "Compromised EE");
	assert!(!ee_cert.is_ca(), "fixture must be a non-CA end entity");

	let forged = build_child_signed_by_ee(&ee, "Compromised EE", &child, "Attacker Forged");

	assert!(!forged
		.is_valid_issuer_subject_pair(&ee_cert)
		.expect("pair check"));

	let path = vec![forged.clone(), ee_cert.clone()];
	let accepted = forged
		.validate_certificate_path(&path)
		.expect("path validation should not error");
	assert!(!accepted, "non-CA end-entity must not be accepted as a path issuer");
}

#[test]
fn test_is_trusted_rejects_cert_minted_by_non_ca() {
	let ee = account_from_seed(b"audit-ee-seed-32-bytes-padded!!!");
	let child = account_from_seed(b"audit-child-seed-32-bytes-pad!!");

	let ee_cert = build_self_signed_end_entity(&ee, "Compromised EE");
	let forged = build_child_signed_by_ee(&ee, "Compromised EE", &child, "Attacker Forged");

	let trusted = forged.is_trusted([ee_cert], Some(Utc::now()));
	assert!(
		!trusted,
		"is_trusted must not accept a certificate minted by a non-CA end-entity"
	);
}
