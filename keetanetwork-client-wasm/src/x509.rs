//! JS `X509CertificateBuilder`: assemble and sign X.509 certificates whose
//! DER bytes feed directly into [`ManageCertificate.add`](crate::certificate).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use keetanetwork_account::GenericAccount;
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_x509::builder::CertificateBuilder;
use keetanetwork_x509::certificates::{Certificate, CertificateBundle};
use keetanetwork_x509::error::CertificateError;
use keetanetwork_x509::{oids, utils, SerialNumber};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::account::Account;
use crate::convert::{coded_error, JsResult};

/// Fluent X.509 certificate builder. Set the subject key and naming, then
/// `build` with a signing account to obtain the signed certificate as hex DER.
#[wasm_bindgen]
#[derive(Default)]
pub struct X509CertificateBuilder {
	inner: CertificateBuilder,
}

#[wasm_bindgen]
impl X509CertificateBuilder {
	/// A builder with the default profile (common extensions included).
	#[wasm_bindgen(constructor)]
	pub fn new() -> Self {
		Self::default()
	}

	/// A CA profile: basic constraints `cA: true` and certificate-signing usage.
	#[wasm_bindgen(js_name = forCa)]
	pub fn for_ca() -> Self {
		Self { inner: CertificateBuilder::for_ca() }
	}

	/// An end-entity profile: leaf basic constraints and signing usage.
	#[wasm_bindgen(js_name = forEndEntity)]
	pub fn for_end_entity() -> Self {
		Self { inner: CertificateBuilder::for_end_entity() }
	}

	/// A TLS server profile: end-entity usage plus `serverAuth` EKU.
	#[wasm_bindgen(js_name = forServer)]
	pub fn for_server() -> Self {
		Self { inner: CertificateBuilder::for_server() }
	}

	/// A TLS client profile: end-entity usage plus `clientAuth` EKU.
	#[wasm_bindgen(js_name = forClient)]
	pub fn for_client() -> Self {
		Self { inner: CertificateBuilder::for_client() }
	}

	/// Set the subject distinguished name to a single common name.
	#[wasm_bindgen(js_name = withSubjectCommonName)]
	pub fn with_subject_common_name(&mut self, common_name: String) -> JsResult<()> {
		let dn = utils::create_dn(&[(oids::CN, common_name.as_str())]).map_err(certificate_error)?;
		self.apply(|builder| builder.with_subject_dn(dn));
		Ok(())
	}

	/// Set the issuer distinguished name to a single common name.
	#[wasm_bindgen(js_name = withIssuerCommonName)]
	pub fn with_issuer_common_name(&mut self, common_name: String) -> JsResult<()> {
		let dn = utils::create_dn(&[(oids::CN, common_name.as_str())]).map_err(certificate_error)?;
		self.apply(|builder| builder.with_issuer_dn(dn));
		Ok(())
	}

	/// Certify `account`'s public key as the subject public key.
	#[wasm_bindgen(js_name = withSubjectPublicKeyFromAccount)]
	pub fn with_subject_public_key_from_account(&mut self, account: &Account) -> JsResult<()> {
		let public_key = subject_public_key(account)?;
		self.apply(|builder| builder.with_subject_public_key(public_key));
		Ok(())
	}

	/// Set the certificate serial number.
	#[wasm_bindgen(js_name = withSerialNumber)]
	pub fn with_serial_number(&mut self, serial: u64) {
		self.apply(|builder| builder.with_serial_number(SerialNumber::from(serial)));
	}

	/// Set validity to `days` starting now.
	#[wasm_bindgen(js_name = withValidityDays)]
	pub fn with_validity_days(&mut self, days: u32) {
		self.apply(|builder| builder.with_validity_days(u64::from(days)));
	}

	/// Set explicit validity bounds from Unix-millisecond timestamps.
	#[wasm_bindgen(js_name = withValidity)]
	pub fn with_validity(&mut self, not_before_millis: f64, not_after_millis: f64) -> JsResult<()> {
		let not_before = timestamp(not_before_millis, "notBefore")?;
		let not_after = timestamp(not_after_millis, "notAfter")?;
		self.apply(|builder| builder.with_validity(not_before, not_after));
		Ok(())
	}

	/// Mark the subject and issuer as identical for a self-signed certificate.
	#[wasm_bindgen(js_name = asSelfSigned)]
	pub fn as_self_signed(&mut self) {
		self.apply(CertificateBuilder::as_self_signed);
	}

	/// Add a basic constraints extension with the given CA flag and optional
	/// path length constraint.
	#[wasm_bindgen(js_name = withBasicConstraints)]
	pub fn with_basic_constraints(&mut self, is_ca: bool, path_length: Option<u8>) {
		self.apply(|builder| builder.with_basic_constraints(is_ca, path_length));
	}

	/// Add a key usage extension from the raw RFC 5280 bit field.
	#[wasm_bindgen(js_name = withKeyUsage)]
	pub fn with_key_usage(&mut self, bits: u16) {
		self.apply(|builder| builder.with_key_usage(bits));
	}

	/// Add an extended key usage extension from a list of purpose OIDs.
	#[wasm_bindgen(js_name = withExtendedKeyUsage)]
	pub fn with_extended_key_usage(&mut self, purpose_oids: Vec<String>) {
		self.apply(|builder| builder.with_extended_key_usage(purpose_oids));
	}

	/// Add a subject alternative name extension from a list of entries (DNS
	/// names, IP addresses, email addresses, or URIs).
	#[wasm_bindgen(js_name = withSubjectAltName)]
	pub fn with_subject_alt_name(&mut self, entries: Vec<String>) {
		self.apply(|builder| builder.with_subject_alt_name(entries));
	}

	/// Add an arbitrary extension by OID with a DER-encoded `value`.
	#[wasm_bindgen(js_name = withCustomExtension)]
	pub fn with_custom_extension(&mut self, oid: String, value: Vec<u8>, critical: bool) {
		self.apply(|builder| builder.with_custom_extension(oid, value, critical));
	}

	/// Sign the certificate with `signer` and return the DER bytes as hex,
	/// ready for [`ManageCertificate.add`](crate::certificate).
	pub fn build(&self, signer: &Account) -> JsResult<String> {
		let certificate = match &*signer.inner() {
			GenericAccount::Ed25519(account) => self.inner.build(account),
			GenericAccount::EcdsaSecp256k1(account) => self.inner.build(account),
			GenericAccount::EcdsaSecp256r1(account) => self.inner.build(account),
			_ => return Err(coded_error("UNSUPPORTED_KEY_TYPE", "certificate signing requires a signing account")),
		}
		.map_err(certificate_error)?;

		let der = Vec::<u8>::try_from(&certificate).map_err(certificate_error)?;
		Ok(hex::encode(der))
	}
}

impl X509CertificateBuilder {
	fn apply<F: FnOnce(CertificateBuilder) -> CertificateBuilder>(&mut self, transform: F) {
		let current = core::mem::take(&mut self.inner);
		self.inner = transform(current);
	}
}

/// Derive the subject public key info from a signing account, dispatching over
/// the concrete key type since the conversion is per-algorithm.
fn subject_public_key(account: &Account) -> JsResult<SubjectPublicKeyInfo> {
	match &*account.inner() {
		GenericAccount::Ed25519(inner) => SubjectPublicKeyInfo::try_from(inner),
		GenericAccount::EcdsaSecp256k1(inner) => SubjectPublicKeyInfo::try_from(inner),
		GenericAccount::EcdsaSecp256r1(inner) => SubjectPublicKeyInfo::try_from(inner),
		_ => return Err(coded_error("UNSUPPORTED_KEY_TYPE", "certificate subject key requires a signing account")),
	}
	.map_err(|error| coded_error("PUBLIC_KEY", error.as_ref()))
}

/// Convert a Unix-millisecond timestamp into a UTC instant.
fn timestamp(millis: f64, label: &str) -> JsResult<DateTime<Utc>> {
	if !millis.is_finite() {
		return Err(coded_error("INVALID_DATE", &alloc::format!("{label} unix milliseconds must be finite")));
	}

	let millis_i64 = millis as i64;
	if millis_i64 as f64 != millis {
		return Err(coded_error(
			"INVALID_DATE",
			&alloc::format!("{label} unix milliseconds must be an integer within i64 range"),
		));
	}

	DateTime::from_timestamp_millis(millis_i64)
		.ok_or_else(|| coded_error("INVALID_DATE", &alloc::format!("{label} unix milliseconds out of range")))
}

/// A parsed view of an X.509 certificate's core fields. When produced from a
/// chain, `chainLength` reports the number of certificates linked from the leaf.
#[wasm_bindgen]
pub struct X509Certificate {
	subject: String,
	issuer: String,
	serial_number: String,
	not_before_millis: f64,
	not_after_millis: f64,
	chain_length: usize,
}

impl X509Certificate {
	/// Project a parsed certificate's core fields into the JS view, recording
	/// the verified chain length the leaf belongs to.
	fn from_leaf(parsed: &Certificate, chain_length: usize) -> Self {
		Self {
			subject: parsed.to_subject(),
			issuer: parsed.to_issuer(),
			serial_number: hex::encode(parsed.tbs_certificate.serial_number.as_bytes()),
			not_before_millis: parsed.to_not_before().timestamp_millis() as f64,
			not_after_millis: parsed.to_not_after().timestamp_millis() as f64,
			chain_length,
		}
	}
}

#[wasm_bindgen]
impl X509Certificate {
	/// Parse a hex-DER X.509 `certificate` into its subject, issuer, serial
	/// number (hex), and validity window (Unix milliseconds).
	pub fn parse(certificate: String) -> JsResult<X509Certificate> {
		let der =
			hex::decode(&certificate).map_err(|_| coded_error("INVALID_CERTIFICATE", "certificate must be hex DER"))?;
		let parsed = Certificate::try_from(der.as_slice()).map_err(certificate_error)?;
		Ok(Self::from_leaf(&parsed, 1))
	}

	/// Parse a leaf `certificate` (hex DER) together with its `intermediates`
	/// (hex DER), returning the leaf's fields and the verified `chainLength`
	/// reachable from the leaf through the supplied certificates.
	#[wasm_bindgen(js_name = parseChain)]
	pub fn parse_chain(certificate: String, intermediates: Vec<String>) -> JsResult<X509Certificate> {
		let leaf_der =
			hex::decode(&certificate).map_err(|_| coded_error("INVALID_CERTIFICATE", "certificate must be hex DER"))?;
		let mut bundle = CertificateBundle::try_from(leaf_der.as_slice()).map_err(certificate_error)?;
		for intermediate in &intermediates {
			let der = hex::decode(intermediate)
				.map_err(|_| coded_error("INVALID_CERTIFICATE", "intermediate must be hex DER"))?;
			let cert = Certificate::try_from(der.as_slice()).map_err(certificate_error)?;
			bundle.add_intermediate(cert);
		}
		let chain_length = bundle.to_chain_length();
		Ok(Self::from_leaf(bundle.to_certificate(), chain_length))
	}

	/// The subject distinguished name, rendered as a string.
	#[wasm_bindgen(getter)]
	pub fn subject(&self) -> String {
		self.subject.clone()
	}

	/// The issuer distinguished name, rendered as a string.
	#[wasm_bindgen(getter)]
	pub fn issuer(&self) -> String {
		self.issuer.clone()
	}

	/// The serial number as a hex string.
	#[wasm_bindgen(getter, js_name = serialNumber)]
	pub fn serial_number(&self) -> String {
		self.serial_number.clone()
	}

	/// The `notBefore` validity bound in Unix milliseconds.
	#[wasm_bindgen(getter, js_name = notBeforeMilliseconds)]
	pub fn not_before_millis(&self) -> f64 {
		self.not_before_millis
	}

	/// The `notAfter` validity bound in Unix milliseconds.
	#[wasm_bindgen(getter, js_name = notAfterMilliseconds)]
	pub fn not_after_millis(&self) -> f64 {
		self.not_after_millis
	}

	/// The number of certificates linked from the leaf, including the leaf.
	#[wasm_bindgen(getter, js_name = chainLength)]
	pub fn chain_length(&self) -> usize {
		self.chain_length
	}
}

#[cfg(all(test, target_family = "wasm"))]
mod wasm_tests {
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::*;
	use crate::certificate::ManageCertificate;

	fn signing_account() -> Account {
		let seed = Account::generate_seed().expect("seed generation must succeed");
		Account::from_seed(seed, 0, Some(String::from("ed25519"))).expect("seeded account must derive")
	}

	#[wasm_bindgen_test]
	fn self_signed_server_preset_builds_to_compliant_der() {
		let account = signing_account();
		let mut builder = X509CertificateBuilder::for_server();
		builder
			.with_subject_common_name(String::from("example.com"))
			.expect("subject common name must set");
		builder.as_self_signed();
		builder
			.with_subject_public_key_from_account(&account)
			.expect("subject key must derive from a signing account");
		builder.with_serial_number(1);

		let der_hex = builder
			.build(&account)
			.expect("self-signed certificate must build");
		let der = hex::decode(&der_hex).expect("built certificate must be hex");
		assert!(Certificate::try_from(der).is_ok());
		assert!(ManageCertificate::add(der_hex).is_ok());
	}

	#[wasm_bindgen_test]
	fn build_requires_a_subject_public_key() {
		let account = signing_account();
		let mut builder = X509CertificateBuilder::new();
		builder
			.with_subject_common_name(String::from("example.com"))
			.expect("subject common name must set");
		builder.as_self_signed();
		builder.with_serial_number(1);
		builder.with_validity_days(365);
		assert!(builder.build(&account).is_err());
	}

	#[wasm_bindgen_test]
	fn parse_recovers_the_subject_issuer_and_serial() {
		let account = signing_account();
		let mut builder = X509CertificateBuilder::for_client();
		builder
			.with_subject_common_name(String::from("leaf.example"))
			.expect("subject common name must set");
		builder
			.with_issuer_common_name(String::from("issuer.example"))
			.expect("issuer common name must set");
		builder
			.with_subject_public_key_from_account(&account)
			.expect("subject key must derive from a signing account");
		builder.with_serial_number(7);

		let der_hex = builder.build(&account).expect("certificate must build");
		let parsed = X509Certificate::parse(der_hex).expect("built certificate must parse");
		assert!(parsed.subject().contains("leaf.example"));
		assert!(parsed.issuer().contains("issuer.example"));
		assert_eq!(parsed.serial_number(), "07");
		assert!(parsed.not_after_millis() > parsed.not_before_millis());
	}

	#[wasm_bindgen_test]
	fn change_hash_matches_the_der_digest() {
		let account = signing_account();
		let mut builder = X509CertificateBuilder::for_client();
		builder
			.with_subject_common_name(String::from("leaf.example"))
			.expect("subject common name must set");
		builder.as_self_signed();
		builder
			.with_subject_public_key_from_account(&account)
			.expect("subject key must derive from a signing account");
		builder.with_serial_number(1);

		let der_hex = builder.build(&account).expect("certificate must build");
		let add = ManageCertificate::add(der_hex).expect("add change must assemble");
		let remove = ManageCertificate::remove(add.hash()).expect("remove change must accept the add hash");
		assert_eq!(add.hash().len(), 64);
		assert_eq!(add.hash(), remove.hash());
	}

	#[wasm_bindgen_test]
	fn parse_chain_links_the_leaf_to_its_issuer() {
		let ca = signing_account();
		let leaf = signing_account();

		let mut ca_builder = X509CertificateBuilder::for_ca();
		ca_builder
			.with_subject_common_name(String::from("Test CA"))
			.expect("ca subject common name must set");
		ca_builder.as_self_signed();
		ca_builder
			.with_subject_public_key_from_account(&ca)
			.expect("ca subject key must derive");
		ca_builder.with_serial_number(1);
		let ca_der = ca_builder.build(&ca).expect("ca certificate must build");

		let mut leaf_builder = X509CertificateBuilder::for_client();
		leaf_builder
			.with_subject_common_name(String::from("leaf.example"))
			.expect("leaf subject common name must set");
		leaf_builder
			.with_issuer_common_name(String::from("Test CA"))
			.expect("leaf issuer common name must set");
		leaf_builder
			.with_subject_public_key_from_account(&leaf)
			.expect("leaf subject key must derive");
		leaf_builder.with_serial_number(2);
		let leaf_der = leaf_builder
			.build(&ca)
			.expect("leaf certificate must build");

		let chain = X509Certificate::parse_chain(leaf_der, alloc::vec![ca_der]).expect("chain must parse");
		assert_eq!(chain.chain_length(), 2);
		assert!(chain.subject().contains("leaf.example"));
		assert!(chain.issuer().contains("Test CA"));
	}

	#[wasm_bindgen_test]
	fn parse_chain_of_a_lone_leaf_has_unit_length() {
		let account = signing_account();
		let mut builder = X509CertificateBuilder::for_client();
		builder
			.with_subject_common_name(String::from("leaf.example"))
			.expect("subject common name must set");
		builder.as_self_signed();
		builder
			.with_subject_public_key_from_account(&account)
			.expect("subject key must derive");
		builder.with_serial_number(1);

		let der_hex = builder.build(&account).expect("certificate must build");
		let chain = X509Certificate::parse_chain(der_hex, alloc::vec![]).expect("chain must parse");
		assert_eq!(chain.chain_length(), 1);
	}
}

/// Map a [`CertificateError`] onto a coded JavaScript `Error`.
fn certificate_error(error: CertificateError) -> JsValue {
	let code = match error {
		CertificateError::InvalidCertificate => "INVALID_CERTIFICATE",
		CertificateError::ValidationFailed { .. } => "VALIDATION_FAILED",
		CertificateError::Expired => "CERTIFICATE_EXPIRED",
		CertificateError::NotYetValid => "CERTIFICATE_NOT_YET_VALID",
		CertificateError::Asn1ParseError { .. } => "ASN1_PARSE_ERROR",
		CertificateError::MissingField { .. } => "MISSING_FIELD",
		CertificateError::InvalidExtension { .. } => "INVALID_EXTENSION",
		CertificateError::ChainValidationFailed { .. } => "CHAIN_VALIDATION_FAILED",
		CertificateError::UnsupportedVersion { .. } => "UNSUPPORTED_VERSION",
		CertificateError::CertificateSignatureVerificationFailed => "SIGNATURE_VERIFICATION_FAILED",
		CertificateError::CertificateDuplicateIncluded => "CERTIFICATE_DUPLICATE",
		CertificateError::CertificateOrphanFound => "CERTIFICATE_ORPHAN",
		CertificateError::CertificateCycleFound => "CERTIFICATE_CYCLE",
	};
	coded_error(code, &error.to_string())
}
