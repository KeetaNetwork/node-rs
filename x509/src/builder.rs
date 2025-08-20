//! X.509 certificate and extension builders.
//!
//! This module provides builder patterns for creating X.509 certificates and extensions.

use asn1::Encode;
use asn1::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use asn1::{BitString, ObjectIdentifier, Uint};
use chrono::{DateTime, Duration, Utc};
use crypto::bigint::U256;
use crypto::prelude::{Algorithm, CryptoSignerWithOptions, SignatureEncoding, SigningOptions};

use crate::certificates::{Certificate, Extension, TbsCertificate, Validity};
use crate::error::CertificateError;
use crate::oids;
use crate::utils::generate_key_identifier;
use crate::DistinguishedName;

/// Builder for creating X.509 certificate extensions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ExtensionBuilder {
	oid: Option<String>,
	critical: bool,
	value: Option<Vec<u8>>,
}

impl ExtensionBuilder {
	/// Create a new extension builder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Create a basic constraints extension according to RFC 5280 Section 4.2.1.9.
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9>
	///
	/// BasicConstraints ::= SEQUENCE {
	///     cA                      BOOLEAN DEFAULT FALSE,
	///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
	/// }
	pub fn for_basic_constraints(is_ca: bool, path_length: Option<u8>) -> Self {
		Self::new()
			.with_oid(oids::BASIC_CONSTRAINTS)
			.with_critical(true)
			.with_basic_constraints_value(is_ca, path_length)
	}

	/// Create a key usage extension according to RFC 5280 Section 4.2.1.3.
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3>
	///
	/// KeyUsage ::= BIT STRING {
	///     digitalSignature        (0),
	///     nonRepudiation          (1),
	///     keyEncipherment         (2),
	///     dataEncipherment        (3),
	///     keyAgreement            (4),
	///     keyCertSign             (5),
	///     cRLSign                 (6),
	///     encipherOnly            (7),
	///     decipherOnly            (8)
	/// }
	pub fn for_key_usage(key_usage_bits: u16) -> Self {
		Self::new()
			.with_oid(oids::KEY_USAGE)
			.with_key_usage_value(key_usage_bits)
			.as_critical()
	}

	/// Create an extended key usage extension according to RFC 5280 Section 4.2.1.12.
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12>
	///
	/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
	/// KeyPurposeId ::= OBJECT IDENTIFIER
	pub fn for_extended_key_usage<I, S>(ext_key_use: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		Self::new()
			.with_oid(oids::EXTENDED_KEY_USAGE)
			.with_extended_key_usage_value(ext_key_use)
			.as_non_critical()
	}

	/// Create a subject alternative name according to RFC 5280 Section 4.2.1.6.
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6>
	///
	/// GeneralName ::= CHOICE {
	///     otherName                       \[0\] OtherName,
	///     rfc822Name                      \[1\] IA5String,
	///     dNSName                         \[2\] IA5String,
	///     x400Address                     \[3\] ORAddress,
	///     directoryName                   \[4\] Name,
	///     ediPartyName                    \[5\] EDIPartyName,
	///     uniformResourceIdentifier       \[6\] IA5String,
	///     iPAddress                       \[7\] OCTET STRING,
	///     registeredID                    \[8\] OBJECT IDENTIFIER
	/// }
	pub fn for_subject_alt_name<I, S>(san_entries: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		Self::new()
			.with_oid(oids::SUBJECT_ALT_NAME)
			.with_subject_alt_name_value(san_entries)
			.as_non_critical()
	}

	/// Create a subject key identifier extension according to RFC 5280 Section 4.2.1.2.
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2>
	///
	/// SubjectKeyIdentifier ::= KeyIdentifier
	/// KeyIdentifier ::= OCTET STRING
	pub fn for_subject_key_identifier<T: AsRef<[u8]>>(key_id: T) -> Self {
		Self::new()
			.with_oid(oids::SUBJECT_KEY_IDENTIFIER)
			.with_value(key_id)
			.as_non_critical()
	}

	/// Create an authority key identifier extension according to RFC 5280 Section 4.2.1.1.
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1>
	///
	/// AuthorityKeyIdentifier ::= SEQUENCE {
	///     keyIdentifier             \[0\] KeyIdentifier           OPTIONAL,
	///     authorityCertIssuer       \[1\] GeneralNames            OPTIONAL,
	///     authorityCertSerialNumber \[2\] CertificateSerialNumber OPTIONAL
	/// }
	/// KeyIdentifier ::= OCTET STRING
	pub fn for_authority_key_identifier<T: AsRef<[u8]>>(key_id: T) -> Self {
		Self::new()
			.with_oid(oids::AUTHORITY_KEY_IDENTIFIER)
			.with_authority_key_identifier_value(key_id)
			.as_non_critical()
	}

	/// Set the extension OID.
	pub fn with_oid<S: AsRef<str>>(mut self, oid: S) -> Self {
		self.oid = Some(oid.as_ref().to_string());
		self
	}

	/// Mark the extension as critical.
	pub fn as_critical(mut self) -> Self {
		self.critical = true;
		self
	}

	/// Mark the extension as non-critical (default).
	pub fn as_non_critical(mut self) -> Self {
		self.critical = false;
		self
	}

	/// Set whether the extension is critical.
	pub fn with_critical(mut self, critical: bool) -> Self {
		self.critical = critical;
		self
	}

	/// Set the extension value directly.
	pub fn with_value<T: AsRef<[u8]>>(mut self, value: T) -> Self {
		self.value = Some(value.as_ref().to_vec());
		self
	}

	/// Set basic constraints extension value.
	fn with_basic_constraints_value(mut self, is_ca: bool, path_length: Option<u8>) -> Self {
		let mut value = vec![0x30]; // SEQUENCE
		if is_ca {
			if let Some(path_len) = path_length {
				let content = vec![0x01, 0x01, 0xFF, 0x02, 0x01, path_len];
				value.push(content.len() as u8);
				value.extend_from_slice(&content);
			} else {
				let content = vec![0x01, 0x01, 0xFF];
				value.push(content.len() as u8);
				value.extend_from_slice(&content);
			}
		} else {
			value.push(0x00);
		}

		self.value = Some(value);
		self
	}

	/// Set key usage extension value.
	fn with_key_usage_value(mut self, key_usage_bits: u16) -> Self {
		let bytes = key_usage_bits.to_be_bytes();
		let value = vec![0x03, 0x02, 0x00, bytes[1]];

		self.value = Some(value);
		self
	}

	/// Set extended key usage extension value.
	fn with_extended_key_usage_value<I, S>(mut self, ext_key_use: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let mut value = vec![0x30]; // SEQUENCE
		let mut content = Vec::new();

		for eku_oid in ext_key_use {
			if let Ok(oid) = ObjectIdentifier::new(eku_oid.as_ref()) {
				if let Ok(oid_der) = oid.to_der() {
					content.extend_from_slice(&oid_der);
				}
			}
		}

		value.push(content.len() as u8);
		value.extend_from_slice(&content);

		self.value = Some(value);
		self
	}

	/// Set subject alternative name extension value.
	fn with_subject_alt_name_value<I, S>(mut self, san_entries: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let general_names: Vec<Vec<u8>> = san_entries
			.into_iter()
			.map(|san_entry| {
				let san_entry = san_entry.as_ref();
				if san_entry.contains('@') {
					let mut name = vec![0x81]; // [1] IMPLICIT
					name.push(san_entry.len() as u8);
					name.extend_from_slice(san_entry.as_bytes());
					name
				} else if san_entry.parse::<core::net::IpAddr>().is_ok() {
					let ip_bytes = if let Ok(ip) = san_entry.parse::<core::net::Ipv4Addr>() {
						ip.octets().to_vec()
					} else if let Ok(ip) = san_entry.parse::<core::net::Ipv6Addr>() {
						ip.octets().to_vec()
					} else {
						san_entry.as_bytes().to_vec()
					};

					let mut name = vec![0x87]; // [7] IMPLICIT
					name.push(ip_bytes.len() as u8);
					name.extend_from_slice(&ip_bytes);
					name
				} else if san_entry.starts_with("http://") || san_entry.starts_with("https://") {
					let mut name = vec![0x86]; // [6] IMPLICIT
					name.push(san_entry.len() as u8);
					name.extend_from_slice(san_entry.as_bytes());
					name
				} else {
					// Default to DNS Name
					// TODO Should we care about other types?
					// DNS Name [2] IMPLICIT UTF8String (default)
					let mut name = vec![0x82]; // [2] IMPLICIT (DNS Name)
					name.push(san_entry.len() as u8);
					name.extend_from_slice(san_entry.as_bytes());
					name
				}
			})
			.collect();

		let content: Vec<u8> = general_names.into_iter().flatten().collect();
		let mut value = vec![0x30]; // SEQUENCE
		value.push(content.len() as u8);
		value.extend_from_slice(&content);

		self.value = Some(value);
		self
	}

	/// Set authority key identifier extension value.
	fn with_authority_key_identifier_value<T: AsRef<[u8]>>(mut self, key_id: T) -> Self {
		let key_id = key_id.as_ref();
		let mut auth_key_id_der = vec![0x30]; // SEQUENCE
		let key_id_with_tag = [&[0x80], key_id].concat(); // [0] IMPLICIT

		auth_key_id_der.push(key_id_with_tag.len() as u8);
		auth_key_id_der.extend_from_slice(&key_id_with_tag);

		self.value = Some(auth_key_id_der);
		self
	}

	/// Build the extension.
	pub fn build(self) -> Result<Extension, CertificateError> {
		let oid = self
			.oid
			.ok_or(CertificateError::MissingField { field: "oid".to_string() })?;
		let value = self
			.value
			.ok_or(CertificateError::MissingField { field: "value".to_string() })?;

		Extension::new(&oid, &value, self.critical)
	}
}

/// Certificate builder for creating new certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBuilder {
	pub subject_public_key: Option<SubjectPublicKeyInfo>,
	pub subject_dn: Option<DistinguishedName>,
	pub issuer_dn: Option<DistinguishedName>,
	pub valid_from: Option<DateTime<Utc>>,
	pub valid_to: Option<DateTime<Utc>>,
	pub serial: Option<U256>,
	pub is_ca: Option<bool>,
	pub include_common_exts: bool,
	pub extensions: Vec<Extension>,
}

impl Default for CertificateBuilder {
	fn default() -> Self {
		Self {
			subject_public_key: None,
			subject_dn: None,
			issuer_dn: None,
			valid_from: None,
			valid_to: None,
			serial: None,
			is_ca: None,
			include_common_exts: true,
			extensions: Vec::new(),
		}
	}
}

impl CertificateBuilder {
	/// Create a new certificate builder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the subject public key.
	pub fn with_subject_public_key(mut self, public_key: SubjectPublicKeyInfo) -> Self {
		self.subject_public_key = Some(public_key);
		self
	}

	/// Set the subject distinguished name.
	pub fn with_subject_dn(mut self, dn: DistinguishedName) -> Self {
		self.subject_dn = Some(dn);
		self
	}

	/// Set the issuer distinguished name.  
	pub fn with_issuer_dn(mut self, dn: DistinguishedName) -> Self {
		self.issuer_dn = Some(dn);
		self
	}

	/// Set the validity period.
	pub fn with_validity(mut self, not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
		self.valid_from = Some(not_before);
		self.valid_to = Some(not_after);
		self
	}

	/// Set the serial number (up to 256-bit integer).
	pub fn with_serial_number(mut self, serial: U256) -> Self {
		self.serial = Some(serial);
		self
	}

	/// Add an extension.
	pub fn with_extension(mut self, extension: Extension) -> Self {
		self.extensions.push(extension);
		self
	}

	/// Add a basic constraints extension.
	pub fn with_basic_constraints(mut self, is_ca: bool, path_length: Option<u8>) -> Self {
		if let Ok(extension) = ExtensionBuilder::for_basic_constraints(is_ca, path_length).build() {
			self.extensions.push(extension);
		}

		self
	}

	/// Add a key usage extension.
	pub fn with_key_usage(mut self, key_usage_bits: u16) -> Self {
		if let Ok(extension) = ExtensionBuilder::for_key_usage(key_usage_bits).build() {
			self.extensions.push(extension);
		}

		self
	}

	/// Add an extended key usage extension.
	pub fn with_extended_key_usage<I, S>(mut self, ext_key_use: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		// Convert the input into a vector of strings
		let ext_key_use_strings: Vec<String> = ext_key_use
			.into_iter()
			.map(|s| s.as_ref().to_string())
			.collect();

		let ext_key_use_vec: Vec<&str> = ext_key_use_strings.iter().map(|s| s.as_str()).collect();
		if let Ok(extension) = ExtensionBuilder::for_extended_key_usage(ext_key_use_vec).build() {
			self.extensions.push(extension);
		}

		self
	}

	/// Add a subject alternative name extension.
	pub fn with_subject_alt_name<I, S>(mut self, san_entries: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		// Convert the input into a vector of strings
		let san_entries_strings: Vec<String> = san_entries
			.into_iter()
			.map(|s| s.as_ref().to_string())
			.collect();

		let san_entries_vec: Vec<&str> = san_entries_strings.iter().map(|s| s.as_str()).collect();
		if let Ok(extension) = ExtensionBuilder::for_subject_alt_name(san_entries_vec).build() {
			self.extensions.push(extension);
		}

		self
	}

	/// Add a custom extension by OID.
	pub fn with_custom_extension<S: AsRef<str>, T: AsRef<[u8]>>(mut self, oid: S, value: T, critical: bool) -> Self {
		if let Ok(extension) = Extension::new(oid, value, critical) {
			self.extensions.push(extension);
		}

		self
	}

	/// Set validity in days from now.
	pub fn with_validity_days(mut self, days: u64) -> Self {
		let now = Utc::now();
		let expiry = now + Duration::days(days as i64);
		self.valid_from = Some(now);
		self.valid_to = Some(expiry);

		self
	}

	/// Disable automatic common extensions.
	pub fn without_common_extensions(mut self) -> Self {
		self.include_common_exts = false;
		self
	}

	/// Enable automatic common extensions (default).
	pub fn with_common_extensions(mut self) -> Self {
		self.include_common_exts = true;
		self
	}

	/// Set whether this is a CA certificate.
	pub fn with_is_ca(mut self, is_ca: bool) -> Self {
		self.is_ca = Some(is_ca);
		self
	}

	/// Mark the certificate as a CA certificate.
	pub fn as_ca(self) -> Self {
		self.with_is_ca(true)
	}

	/// Create a self-signed certificate (issuer = subject).
	pub fn as_self_signed(mut self) -> Self {
		if let Some(ref subject) = self.subject_dn.clone() {
			self.issuer_dn = Some(subject.clone());
		}

		self
	}

	/// Add multiple extensions at once.
	pub fn with_extensions<I>(mut self, extensions: I) -> Self
	where
		I: IntoIterator<Item = Extension>,
	{
		self.extensions.extend(extensions);
		self
	}

	/// Create a preset CA certificate builder.
	pub fn for_ca() -> Self {
		Self::new()
			.with_is_ca(true)
			.with_key_usage(0x06) // keyCertSign + cRLSign
			.with_validity_days(365 * 10) // 10 years
	}

	/// Create a preset end-entity certificate builder.
	pub fn for_end_entity() -> Self {
		Self::new()
			.with_is_ca(false)
			.with_key_usage(0xC0) // digitalSignature + nonRepudiation
			.with_validity_days(365) // 1 year
	}

	/// Create a preset server certificate builder
	pub fn for_server() -> Self {
		Self::for_end_entity().with_extended_key_usage(vec![oids::SERVER_AUTH])
	}

	/// Create a preset client certificate builder
	pub fn for_client() -> Self {
		Self::for_end_entity().with_extended_key_usage(vec![oids::CLIENT_AUTH])
	}

	/// Build the TBS certificate (to be signed).
	pub fn build_tbs(&self) -> Result<TbsCertificate, CertificateError> {
		let subject_public_key = self
			.subject_public_key
			.as_ref()
			.ok_or(CertificateError::MissingField { field: "subject_public_key".to_string() })?;
		let subject_dn = self
			.subject_dn
			.as_ref()
			.ok_or(CertificateError::MissingField { field: "subject_dn".to_string() })?;
		let issuer_dn = self
			.issuer_dn
			.as_ref()
			.ok_or(CertificateError::MissingField { field: "issuer_dn".to_string() })?;
		let valid_from = self
			.valid_from
			.ok_or(CertificateError::MissingField { field: "valid_from".to_string() })?;
		let valid_to = self
			.valid_to
			.ok_or(CertificateError::MissingField { field: "valid_to".to_string() })?;
		let serial = self
			.serial
			.as_ref()
			.ok_or(CertificateError::MissingField { field: "serial".to_string() })?;

		let mut extensions = self.extensions.clone();

		// Add common extensions if requested
		if self.include_common_exts {
			extensions.extend(self.create_common_extensions()?);
		}

		let extensions_option = if extensions.is_empty() {
			None
		} else {
			Some(extensions)
		};

		Ok(TbsCertificate {
			version: Some(2), // X.509 v3
			serial_number: Uint::new(&serial.to_be_bytes())?,
			signature_algorithm: AlgorithmIdentifier {
				algorithm: ObjectIdentifier::new(oids::SHA256_WITH_RSA)?, // SHA256withRSA
				parameters: None,
			},
			issuer: issuer_dn.clone(),
			validity: Validity { not_before: valid_from.try_into()?, not_after: valid_to.try_into()? },
			subject: subject_dn.clone(),
			subject_public_key_info: subject_public_key.clone(),
			issuer_unique_id: None,
			subject_unique_id: None,
			extensions: extensions_option,
		})
	}

	/// Build a test certificate without signing.
	///
	/// This method is useful for testing purposes and is not available outside
	/// of unit testing.
	#[cfg(test)]
	pub fn build_test(&self) -> Result<Certificate, CertificateError> {
		// First build the TBS certificate
		let tbs = self.build_tbs()?;
		// Dummy signature
		let signature_bytes = vec![0u8; 64];

		Ok(Certificate {
			tbs_certificate: tbs,
			signature_algorithm: oids::SHA256_WITH_RSA.parse()?,
			signature: BitString::from_bytes(&signature_bytes)?,
		})
	}

	/// Build and sign a certificate with any signer that implements CryptoSignerWithOptions.
	///
	/// This method is generic and works with any type that can sign, including
	/// Account types, raw private keys, or other signing implementations.
	pub fn build<T, S>(&self, signer: &T) -> Result<Certificate, CertificateError>
	where
		T: CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// Determine signature algorithm OID based on the algorithm
		// Get the algorithm from the signer
		let algorithm = signer.get_algorithm();
		let signature_algorithm_oid = match algorithm {
			Algorithm::Ed25519 => oids::ED25519,
			Algorithm::Secp256k1 => oids::ECDSA_WITH_SHA256,
			Algorithm::Secp256r1 => oids::ECDSA_WITH_SHA256,
		};

		// Build the TBS certificate with the correct signature algorithm
		let mut tbs_certificate = self.build_tbs()?;
		tbs_certificate.signature_algorithm =
			AlgorithmIdentifier { algorithm: ObjectIdentifier::new(signature_algorithm_oid)?, parameters: None };

		// Serialize the TBS certificate for signing
		let tbs_der = tbs_certificate.to_der()?;

		// Determine signing options based on algorithm
		let signing_options = match algorithm {
			Algorithm::Ed25519 => SigningOptions::raw(),
			Algorithm::Secp256k1 | Algorithm::Secp256r1 => SigningOptions::for_cert(),
		};

		// Sign the TBS certificate
		let signature = signer
			.sign_with_options(&tbs_der, signing_options)
			.map_err(|_| CertificateError::CertificateSignatureVerificationFailed)?;

		// Convert signature to bytes
		let signature_bytes = signature.to_bytes();
		let signature_bit_string = BitString::from_bytes(signature_bytes.as_ref())?;

		// Create the final certificate
		let cert = Certificate {
			tbs_certificate,
			signature_algorithm: AlgorithmIdentifier {
				algorithm: ObjectIdentifier::new(signature_algorithm_oid)?,
				parameters: None,
			},
			signature: signature_bit_string,
		};

		Ok(cert)
	}

	/// Create common certificate extensions
	fn create_common_extensions(&self) -> Result<Vec<Extension>, CertificateError> {
		let mut extensions = Vec::new();

		// Basic Constraints extension
		if let Some(is_ca) = self.is_ca {
			extensions.push(ExtensionBuilder::for_basic_constraints(is_ca, None).build()?);
		}

		// Key Usage extension
		if let Some(is_ca) = self.is_ca {
			let key_usage_bits = if is_ca {
				// CA certificates: keyCertSign (bit 5) + cRLSign (bit 6)
				0x06 // Bits 5,6 (keyCertSign, cRLSign)
			} else {
				// End entity certificates: digitalSignature (bit 0) + nonRepudiation (bit 1)
				0xC0 // Bits 0,1 (digitalSignature, nonRepudiation)
			};

			extensions.push(ExtensionBuilder::for_key_usage(key_usage_bits).build()?);
		}

		// Subject Key Identifier extension
		if let Some(subject_public_key) = &self.subject_public_key {
			let subject_key_id = generate_key_identifier(&subject_public_key.subject_public_key)?;
			extensions.push(ExtensionBuilder::for_subject_key_identifier(&subject_key_id).build()?);
		}

		// Authority Key Identifier extension (for self-signed certificates)
		if let (Some(issuer_dn), Some(subject_dn), Some(subject_public_key)) =
			(&self.issuer_dn, &self.subject_dn, &self.subject_public_key)
		{
			if issuer_dn == subject_dn {
				let authority_key_id = generate_key_identifier(&subject_public_key.subject_public_key)?;
				extensions.push(ExtensionBuilder::for_authority_key_identifier(&authority_key_id).build()?);
			}
		}

		Ok(extensions)
	}
}

#[cfg(test)]
mod tests {
	use accounts::{Account, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
	use asn1::{AlgorithmIdentifier, BitString, ObjectIdentifier, Uint};
	use chrono::Utc;
	use crypto::operations::encryption::KeyGeneration;
	use crypto::prelude::{AnyPrivateKey, Ed25519Derivation, KeyDerivation, Secp256k1PrivateKey, Secp256r1PrivateKey};
	use der::Decode;

	use super::*;
	use crate::certificates::{Certificate, TbsCertificate};
	use crate::oids;
	use crate::testing::{TEST_CERTIFICATE_SETS, TEST_SEED};
	use crate::utils;

	macro_rules! test_certificate_builder {
		($algorithm:expr, $is_ca:expr, $subject_cn:expr, $issuer_cn:expr) => {
			// Find the test set for this algorithm
			let test_set = TEST_CERTIFICATE_SETS
				.iter()
				.find(|set| set.algorithm == $algorithm)
				.expect("Test set not found for algorithm");

			let algorithm_oid = test_set.oid;
			let public_key_bytes = test_set
				.key_data
				.as_ref()
				.expect("Key data not found for algorithm")
				.public_key;

			let subject_cn_value = $subject_cn.split('=').nth(1).unwrap();
			let issuer_cn_value = $issuer_cn.split('=').nth(1).unwrap();
			let subject_dn = utils::create_dn(&[(oids::CN, subject_cn_value)]).unwrap();
			let issuer_dn = utils::create_dn(&[(oids::CN, issuer_cn_value)]).unwrap();

			let public_key_info = SubjectPublicKeyInfo {
				algorithm: AlgorithmIdentifier {
					algorithm: ObjectIdentifier::new(algorithm_oid).unwrap(),
					parameters: None,
				},
				subject_public_key: BitString::from_bytes(public_key_bytes).unwrap(),
			};

			let serial = 1u128;
			let not_before = Utc::now();
			let not_after = not_before + chrono::Duration::days(365);

			let builder = CertificateBuilder::new()
				.with_subject_public_key(public_key_info.clone())
				.with_subject_dn(subject_dn.clone())
				.with_issuer_dn(issuer_dn.clone())
				.with_validity(not_before, not_after)
				.with_serial_number(U256::from(serial))
				.with_is_ca($is_ca);

			let tbs = builder.build_tbs().unwrap();

			let expected_serial = Uint::new(&serial.to_be_bytes()).unwrap();
			assert_eq!(tbs.serial_number, expected_serial);
			assert_eq!(tbs.subject, subject_dn);
			assert_eq!(tbs.issuer, issuer_dn);
			assert_eq!(tbs.subject_public_key_info, public_key_info);
			assert_eq!(tbs.version, Some(2));
			assert!(tbs.extensions.is_some());

			if let Some(extensions) = &tbs.extensions {
				let extension_oids: Vec<String> = extensions.iter().map(|ext| ext.oid.to_string()).collect();
				assert!(extension_oids.contains(&oids::BASIC_CONSTRAINTS.to_string()));
				assert!(extension_oids.contains(&oids::KEY_USAGE.to_string()));
				assert!(extension_oids.contains(&oids::SUBJECT_KEY_IDENTIFIER.to_string()));

				if subject_dn == issuer_dn {
					assert!(extension_oids.contains(&oids::AUTHORITY_KEY_IDENTIFIER.to_string()));
				}
			}

			let tbs_der = tbs.to_der().unwrap();
			assert!(!tbs_der.is_empty());

			let tbs_re_parsed = TbsCertificate::from_der(&tbs_der).unwrap();
			assert_eq!(tbs, tbs_re_parsed);
		};
	}

	#[test]
	fn test_certificate_builder_basic() {
		// Test each algorithm in our test certificate sets
		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let algorithm_name = test_set.algorithm.to_string();
			let ca_name = format!("CN={} CA", &algorithm_name);
			let user_name = format!("CN={} User", &algorithm_name);

			// Test CA certificate
			test_certificate_builder!(test_set.algorithm, true, &ca_name, &ca_name);
			// Test end-entity certificate
			test_certificate_builder!(test_set.algorithm, false, &user_name, &ca_name);
		}
	}

	#[test]
	fn test_certificate_builder_extension_methods() {
		let subject_dn = utils::create_dn(&[(oids::CN, "Test Cert")]).unwrap();
		let issuer_dn = utils::create_dn(&[(oids::CN, "Test CA")]).unwrap();
		let key_usage_ext = ExtensionBuilder::for_key_usage(0x0080).build();

		let builder = CertificateBuilder::new()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(issuer_dn.clone())
			.with_serial_number(U256::from(12345u128))
			.with_validity_days(365)
			.with_extension(key_usage_ext.unwrap())
			.with_basic_constraints(false, None)
			.with_key_usage(0x0080)
			.with_extended_key_usage(vec![oids::CLIENT_AUTH])
			.with_subject_alt_name(vec!["test.example.com"])
			.with_custom_extension("1.2.3.4.5", [0x01, 0x02], false)
			.with_extensions(vec![Extension::new("1.2.3.4.6", [0x03, 0x04], false).unwrap()])
			.without_common_extensions()
			.with_common_extensions()
			.as_ca()
			.as_self_signed();

		// Test that the builder accumulated the extensions correctly
		assert!(builder.extensions.len() >= 5); // At least the ones we added manually

		// Test preset builders
		let ca_builder = CertificateBuilder::for_ca();
		assert_eq!(ca_builder.is_ca, Some(true));

		let ee_builder = CertificateBuilder::for_end_entity();
		assert_eq!(ee_builder.is_ca, Some(false));

		let server_builder = CertificateBuilder::for_server();
		assert_eq!(server_builder.is_ca, Some(false));

		let client_builder = CertificateBuilder::for_client();
		assert_eq!(client_builder.is_ca, Some(false));
	}

	#[test]
	fn test_certificate_builder_build_functionality() {
		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let subject_dn = utils::create_dn(&[(oids::CN, "Test Certificate")]).unwrap();
			let issuer_dn = utils::create_dn(&[(oids::CN, "Test CA")]).unwrap();

			let algorithm_oid = test_set.oid;
			let public_key_bytes = test_set
				.key_data
				.as_ref()
				.expect("Key data not found for algorithm")
				.public_key;
			let algorithm =
				AlgorithmIdentifier { algorithm: ObjectIdentifier::new(algorithm_oid).unwrap(), parameters: None };
			let subject_public_key = BitString::from_bytes(public_key_bytes).unwrap();
			let public_key_info = SubjectPublicKeyInfo { algorithm, subject_public_key };

			let builder = CertificateBuilder::new()
				.with_subject_public_key(public_key_info)
				.with_subject_dn(subject_dn)
				.with_issuer_dn(issuer_dn)
				.with_serial_number(U256::from(12345u128))
				.with_validity_days(365)
				.with_is_ca(false);

			let result = builder.build_test();
			assert!(result.is_ok());
		}
	}

	#[test]
	fn test_certificate_builder_api() {
		const TEST_CERTIFICATE_SETS: &[fn() -> AnyPrivateKey] = &[
			|| AnyPrivateKey::Ed25519(Ed25519Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap()),
			|| AnyPrivateKey::Secp256k1(Secp256k1PrivateKey::generate_random().unwrap()),
			|| AnyPrivateKey::Secp256r1(Secp256r1PrivateKey::generate_random().unwrap()),
		];

		for generate_key in TEST_CERTIFICATE_SETS {
			let private_key = generate_key();
			let public_key = private_key.derive_public_key();

			let serial = 1u64;
			let now = chrono::Utc::now();
			let valid_from = now - chrono::Duration::hours(1); // Start 1 hour before now
			let valid_to = now + chrono::Duration::days(365);
			let subject_dn = utils::create_dn(&[(oids::CN, "Test Subject")]).unwrap();
			let issuer_dn = subject_dn.clone();

			// Create a certificate builder and build a certificate
			let builder = CertificateBuilder::new()
				.with_subject_dn(subject_dn.clone())
				.with_issuer_dn(issuer_dn.clone())
				.with_serial_number(U256::from(serial))
				.with_validity(valid_from, valid_to)
				.with_subject_public_key(public_key.into())
				.with_is_ca(false);

			// Use direct key build first
			let result = match &private_key {
				AnyPrivateKey::Ed25519(key) => builder.build(key),
				AnyPrivateKey::Secp256k1(key) => builder.build(key),
				AnyPrivateKey::Secp256r1(key) => builder.build(key),
			};
			assert!(result.is_ok());

			// Use account to build
			let result = match private_key {
				AnyPrivateKey::Ed25519(key) => {
					let account = Account::<KeyED25519>::from(key);
					builder.build(&account)
				}
				AnyPrivateKey::Secp256k1(key) => {
					let account = Account::<KeyECDSASECP256K1>::from(key);
					builder.build(&account)
				}
				AnyPrivateKey::Secp256r1(key) => {
					let account = Account::<KeyECDSASECP256R1>::from(key);
					builder.build(&account)
				}
			};
			assert!(result.is_ok());

			// Verify the certificate structure
			let certificate = result.unwrap();
			assert_eq!(certificate.tbs_certificate.subject, subject_dn);
			assert_eq!(certificate.tbs_certificate.issuer, issuer_dn);
			assert_eq!(certificate.tbs_certificate.serial_number, asn1::Uint::new(&serial.to_be_bytes()).unwrap());
			assert!(!certificate.signature.raw_bytes().is_empty());

			// Verify the certificate is self-signed and can be verified with its own public key
			let subject_public_key = &certificate.tbs_certificate.subject_public_key_info;
			let signature_verification = certificate.verify_signature(subject_public_key);
			assert!(signature_verification.is_ok());
			assert!(signature_verification.unwrap());

			// Verify the certificate is currently valid
			assert!(certificate.is_currently_valid().unwrap());
			// Verify basic certificate properties
			assert!(certificate.is_self_signed());
			assert_eq!(certificate.to_subject(), certificate.to_issuer());

			// Test PEM/DER roundtrip to ensure the certificate is well-formed
			let pem_output = certificate.to_pem();
			assert!(pem_output.is_ok());

			let der_output = certificate.to_der();
			assert!(der_output.is_ok());

			// Verify we can parse the certificate back from PEM
			let re_parsed_cert = pem_output.unwrap().parse::<Certificate>();
			assert!(re_parsed_cert.is_ok());

			let re_parsed_cert = re_parsed_cert.unwrap();
			assert_eq!(certificate.to_der().unwrap(), re_parsed_cert.to_der().unwrap());
		}
	}

	#[test]
	fn test_extension_builder() {
		struct ExtensionTestCase {
			builder_fn: Box<dyn Fn() -> ExtensionBuilder>,
			expected_oid: &'static str,
			expected_critical: bool,
			validation_fn: Box<dyn Fn(&Extension) -> bool>,
		}

		let test_cases = vec![
			ExtensionTestCase {
				builder_fn: Box::new(|| ExtensionBuilder::for_basic_constraints(true, Some(5))),
				expected_oid: oids::BASIC_CONSTRAINTS,
				expected_critical: true,
				validation_fn: Box::new(|ext| {
					// Check that the value contains the expected SEQUENCE structure for CA=true, pathLen=5
					let value = ext.value.as_bytes();
					!value.is_empty() && value[0] == 0x30 // SEQUENCE tag
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| ExtensionBuilder::for_basic_constraints(false, None)),
				expected_oid: oids::BASIC_CONSTRAINTS,
				expected_critical: true,
				validation_fn: Box::new(|ext| {
					let value = ext.value.as_bytes();
					value.len() >= 2 && value[0] == 0x30 && value[1] == 0x00 // Empty SEQUENCE
				}),
			},
			ExtensionTestCase {
				// digitalSignature + keyCertSign + cRLSign
				builder_fn: Box::new(|| ExtensionBuilder::for_key_usage(0x0186)),
				expected_oid: oids::KEY_USAGE,
				expected_critical: true,
				validation_fn: Box::new(|ext| {
					let value = ext.value.as_bytes();
					value.len() == 4 && value[0] == 0x03 && value[1] == 0x02 // BIT STRING with length 2
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| {
					ExtensionBuilder::for_extended_key_usage(vec![oids::SERVER_AUTH, oids::CLIENT_AUTH])
				}),
				expected_oid: oids::EXTENDED_KEY_USAGE,
				expected_critical: false,
				validation_fn: Box::new(|ext| {
					let value = ext.value.as_bytes();
					!value.is_empty() && value[0] == 0x30 // SEQUENCE tag
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| {
					ExtensionBuilder::for_subject_alt_name(vec![
						"example.com",
						"192.168.1.1",
						"::1", // IPv6 loopback address
						"user@example.com",
						"https://example.com",
					])
				}),
				expected_oid: oids::SUBJECT_ALT_NAME,
				expected_critical: false,
				validation_fn: Box::new(|ext| {
					let value = ext.value.as_bytes();
					!value.is_empty() && value[0] == 0x30 // SEQUENCE tag
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| ExtensionBuilder::for_subject_key_identifier([0x01, 0x02, 0x03, 0x04])),
				expected_oid: oids::SUBJECT_KEY_IDENTIFIER,
				expected_critical: false,
				validation_fn: Box::new(|ext| {
					let value = ext.value.as_bytes();
					value == [0x01, 0x02, 0x03, 0x04]
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| ExtensionBuilder::for_authority_key_identifier([0x05, 0x06, 0x07, 0x08])),
				expected_oid: oids::AUTHORITY_KEY_IDENTIFIER,
				expected_critical: false,
				validation_fn: Box::new(|ext| {
					let value = ext.value.as_bytes();
					!value.is_empty() && value[0] == 0x30 // SEQUENCE tag
				}),
			},
		];

		// Test all extension types
		for test_case in test_cases {
			// Build the extension
			let extension = (test_case.builder_fn)().build();
			assert!(extension.is_ok());

			let extension = extension.unwrap();
			// Verify OID
			assert_eq!(extension.oid.to_string(), test_case.expected_oid);
			// Verify critical flag
			assert_eq!(extension.critical, test_case.expected_critical);
			// Run custom validation
			assert!((test_case.validation_fn)(&extension));
		}

		// Test fluent API customization
		let custom_basic_constraints = ExtensionBuilder::for_basic_constraints(true, None)
			.as_non_critical()
			.build()
			.unwrap();
		assert_eq!(custom_basic_constraints.oid.to_string(), oids::BASIC_CONSTRAINTS);
		assert!(!custom_basic_constraints.critical);

		// Test custom extension with fluent API
		let custom_extension = ExtensionBuilder::new()
			.with_oid("1.2.3.4.5.6")
			.with_value([0xDE, 0xAD, 0xBE, 0xEF])
			.as_critical()
			.build()
			.unwrap();
		assert_eq!(custom_extension.oid.to_string(), "1.2.3.4.5.6");
		assert!(custom_extension.critical);
		assert_eq!(custom_extension.value.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);

		// Test error cases
		let invalid_oid_result = ExtensionBuilder::new()
			.with_oid("invalid.oid")
			.with_value([0x01])
			.build();
		assert!(invalid_oid_result.is_err());

		let missing_oid_result = ExtensionBuilder::new().with_value([0x01]).build();
		assert!(missing_oid_result.is_err());

		let missing_value_result = ExtensionBuilder::new().with_oid("1.2.3.4").build();
		assert!(missing_value_result.is_err());
	}
}
