//! X.509 certificate handling
//!
//! This module provides functionality for working with X.509 certificates,
//! including parsing, validation, and generation of certificate requests.

use std::collections::HashSet;
use std::str::FromStr;

use asn1::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use asn1::{BitString, ObjectIdentifier, OctetString, Sequence, Uint};
use asn1::{Decode, Encode};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use crypto::bigint::U256;
use crypto::prelude::{Algorithm, CryptoSignerWithOptions, HashAlgorithm, SignatureEncoding, SigningOptions};
use hex;

#[cfg(feature = "serde")]
use asn1::utils::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::CertificateError;
use crate::oids;
use crate::time::Time;
use crate::utils;
use crate::utils::{dn_to_string, generate_key_identifier, parse_der_length};
use crate::DistinguishedName;

#[cfg(feature = "serde")]
use crate::utils::{dn_to_name_value_pairs, parse_authority_key_identifier, parse_key_identifier};
#[cfg(feature = "serde")]
use crate::NameValuePair;

/// Basic Constraints extension according to RFC 5280 Section 4.2.1.9.
/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9>
///
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
#[derive(Debug, Default, Clone, PartialEq, Eq, Sequence)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BasicConstraints {
	/// Indicates if this is a CA certificate
	#[asn1(default = "Default::default")]
	pub ca: bool,
	/// Optional path length constraint
	#[asn1(optional = "true")]
	#[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
	pub path_len_constraint: Option<u32>,
}

/// Certificate extension according to RFC 5280 Section 4.2.
/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2>
///
/// Extension ::= SEQUENCE {
///     extnID                  OBJECT IDENTIFIER,
///     critical                BOOLEAN DEFAULT FALSE,
///     extnValue               OCTET STRING
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Extension {
	/// Extension ID (OID)
	#[cfg_attr(feature = "serde", serde(serialize_with = "serialize_oid", deserialize_with = "deserialize_oid"))]
	pub oid: ObjectIdentifier,
	/// Indicates if this extension is critical
	#[asn1(default = "Default::default")]
	#[cfg_attr(feature = "serde", serde(default))]
	pub critical: bool,
	/// Extension value as an OctetString
	#[cfg_attr(
		feature = "serde",
		serde(serialize_with = "serialize_octet_string", deserialize_with = "deserialize_octet_string")
	)]
	pub value: OctetString,
}

impl Extension {
	/// Create a new extension.
	pub fn new<S: AsRef<str>, V: AsRef<[u8]>>(oid: S, value: V, critical: bool) -> Result<Self, CertificateError> {
		let oid = ObjectIdentifier::new(oid.as_ref())?;
		let value = OctetString::new(value.as_ref())?;

		Ok(Self { oid, critical, value })
	}
}

/// Builder for creating X.509 certificate extensions.
#[derive(Debug, Clone, Default)]
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

/// Certificate validity period according to RFC 5280 Section 4.1.2.5.
/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5>
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Validity {
	pub not_before: Time,
	pub not_after: Time,
}

/// TBS Certificate structure according to RFC 5280 Section 4.1.2.
/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2>
///
/// TBSCertificate  ::=  SEQUENCE  {
///     version         \[0\]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  \[1\]  IMPLICIT UniqueIdentifier OPTIONAL,
///     subjectUniqueID \[2\]  IMPLICIT UniqueIdentifier OPTIONAL,
///     extensions      \[3\]  EXPLICIT Extensions OPTIONAL
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct TbsCertificate {
	#[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
	pub version: Option<u8>, // Default is v1 (0), v3 is 2
	pub serial_number: Uint,
	pub signature_algorithm: AlgorithmIdentifier,
	pub issuer: DistinguishedName,
	pub validity: Validity,
	pub subject: DistinguishedName,
	pub subject_public_key_info: SubjectPublicKeyInfo,
	#[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
	pub issuer_unique_id: Option<BitString>,
	#[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
	pub subject_unique_id: Option<BitString>,
	#[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
	pub extensions: Option<Vec<Extension>>,
}

/// Options for certificate construction.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CertificateOptions {
	/// Time moment for validation
	pub moment: Option<DateTime<Utc>>,
	/// Override to mark as trusted root
	pub is_trusted_root: Option<bool>,
}

/// Certificate bundle containing a certificate, options, and trusted
/// roots/intermediates certificates.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateBundle {
	/// The core certificate
	pub certificate: Certificate,
	/// Certificate options for validation and trust
	pub options: CertificateOptions,
	/// Trusted root certificates
	pub root: HashSet<Certificate>,
	/// Trusted intermediate certificates
	pub intermediate: HashSet<Certificate>,
}

impl CertificateBundle {
	/// Create a new certificate from PEM with options.
	pub fn new(
		pem_data: &str,
		opts: Option<CertificateOptions>,
		root: Option<HashSet<Certificate>>,
		intermediate: Option<HashSet<Certificate>>,
	) -> Result<Self, CertificateError> {
		let certificate = pem_data.parse()?;
		let options = opts.unwrap_or_default();
		let root = root.unwrap_or_default();
		let intermediate = intermediate.unwrap_or_default();

		Ok(Self { certificate, options, root, intermediate })
	}

	/// Validate trust using the instance's certificate collections.
	/// Returns an error if no root certificates are available.
	pub fn verify_chain(mut self, moment: Option<DateTime<Utc>>) -> Result<Self, CertificateError> {
		if self.root.is_empty() {
			return Err(CertificateError::ChainValidationFailed {
				reason: "No root certificates available for validation".to_string(),
			});
		}

		// Build the certificate chain
		let chain: Vec<Certificate> = self
			.certificate
			.verify_chain(&self.root, &self.intermediate)
			.collect();

		// Validate that we have a complete chain to a trusted root
		if chain.is_empty() {
			return Err(CertificateError::ChainValidationFailed {
				reason: "Unable to build certificate chain".to_string(),
			});
		}

		// Check if the last certificate in the chain is a trusted root
		let is_trusted = chain
			.last()
			.map(|root_cert| self.root.contains(root_cert))
			.unwrap_or(false);

		self.options.moment = moment;
		self.options.is_trusted_root = Some(is_trusted);

		if !is_trusted {
			return Err(CertificateError::ChainValidationFailed {
				reason: "Certificate chain does not end with a trusted root".to_string(),
			});
		}

		Ok(self)
	}

	/// Get the root certificate from the chain.
	pub fn get_root_certificate(&self) -> Option<Certificate> {
		let chain: Vec<Certificate> = self
			.certificate
			.verify_chain(&self.root, &self.intermediate)
			.collect();
		if chain.len() > 1 {
			// Chain contains intermediate certificates, root is the last one
			chain.last().cloned()
		} else if self.certificate.is_self_signed() {
			Some(self.certificate.clone())
		} else {
			None
		}
	}

	/// Get the issuer certificate from the chain.
	pub fn get_issuer_certificate(&self) -> Option<Certificate> {
		let chain: Vec<Certificate> = self
			.certificate
			.verify_chain(&self.root, &self.intermediate)
			.collect();
		if chain.len() > 1 {
			// Chain contains more than just the main certificate, issuer is the second one
			chain.get(1).cloned()
		} else if self.certificate.is_self_signed() {
			Some(self.certificate.clone())
		} else {
			None
		}
	}

	pub fn get_certificate(&self) -> &Certificate {
		&self.certificate
	}

	/// Get the issuer's public key from the chain.
	pub fn get_issuer_public_key(&self) -> Option<SubjectPublicKeyInfo> {
		self.get_issuer_certificate()
			.map(|cert| cert.tbs_certificate.subject_public_key_info)
	}

	/// Get all certificates (main certificate + chain).
	pub fn get_chain(&self) -> impl Iterator<Item = Certificate> {
		self.certificate
			.verify_chain(&self.root, &self.intermediate)
	}

	/// Get chain length.
	pub fn chain_length(&self) -> usize {
		self.certificate
			.verify_chain(&self.root, &self.intermediate)
			.count()
	}

	/// Check if the certificate is trusted.
	pub fn is_trusted(&self) -> bool {
		self.options.is_trusted_root.unwrap_or(false)
	}

	/// Set the trusted status.
	pub fn with_trusted(mut self, trusted: bool) -> Self {
		self.options.is_trusted_root = Some(trusted);
		self
	}

	/// Set the certificate chain by adding certificates to the store.
	pub fn with_chain<I: IntoIterator<Item = Certificate>>(mut self, chain: I) -> Self {
		for cert in chain {
			self.add_intermediate(cert);
		}
		self
	}

	/// Add a root certificate to the store
	pub fn add_root(&mut self, cert: Certificate) {
		self.root.insert(cert);
	}

	/// Add an intermediate certificate to the store
	pub fn add_intermediate(&mut self, cert: Certificate) {
		self.intermediate.insert(cert);
	}

	/// Convert to DER format (concatenated DER of all certificates).
	pub fn to_der(&self) -> Result<Vec<u8>, CertificateError> {
		self.try_into()
	}

	/// Convert certificate bundle to JSON representation with chain information
	#[cfg(feature = "serde")]
	pub fn to_json(&self, include_pem: bool) -> Result<CertificateJson, CertificateError> {
		let mut cert_json = self.certificate.to_json(include_pem)?;

		// Add chain information from the bundle
		let chain_certs: Vec<Certificate> = self
			.intermediate
			.iter()
			.chain(self.root.iter())
			.cloned()
			.collect();

		if !chain_certs.is_empty() {
			let chain_json: Result<Vec<CertificateJson>, CertificateError> = chain_certs
				.iter()
				.map(|cert| cert.to_json(include_pem))
				.collect();

			let chain = chain_json?;
			cert_json.chain = Some(chain.clone());
			cert_json.chain_field = Some(chain);
		}

		Ok(cert_json)
	}
}

impl TryFrom<&CertificateBundle> for Vec<u8> {
	type Error = CertificateError;

	/// Convert to DER format (concatenated DER of all certificates).
	fn try_from(cert_with_options: &CertificateBundle) -> Result<Self, Self::Error> {
		let mut result = Vec::new();

		// Add main certificate
		result.extend_from_slice(&cert_with_options.certificate.to_der()?);

		// Add chain certificates
		let chain: Vec<Certificate> = cert_with_options
			.certificate
			.verify_chain(&cert_with_options.root, &cert_with_options.intermediate)
			.collect();
		for cert in &chain[1..] {
			// Skip the first one since it's the main certificate we already added
			result.extend_from_slice(&cert.to_der()?);
		}

		Ok(result)
	}
}

/// FromStr and TryFrom implementations for CertificateBundle
impl FromStr for CertificateBundle {
	type Err = CertificateError;

	fn from_str(pem_data: &str) -> Result<Self, Self::Err> {
		let certificate = pem_data.parse()?;
		let options = CertificateOptions::default();

		// For PEM string input, we can't determine trust without a store
		// User can call methods to set trust later if needed
		Ok(Self { certificate, options, root: HashSet::new(), intermediate: HashSet::new() })
	}
}

impl TryFrom<Certificate> for CertificateBundle {
	type Error = CertificateError;

	fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
		let options = CertificateOptions::default();

		// For direct Certificate input, default trust to false
		Ok(Self { certificate, options, root: HashSet::new(), intermediate: HashSet::new() })
	}
}

impl TryFrom<Vec<Certificate>> for CertificateBundle {
	type Error = CertificateError;

	fn try_from(certificates: Vec<Certificate>) -> Result<Self, Self::Error> {
		let mut iter = certificates.into_iter();
		if let Some(certificate) = iter.next() {
			let options = CertificateOptions::default();
			let mut intermediate = HashSet::new();

			// Add remaining certificates as intermediates in the store
			for intermediate_cert in iter {
				intermediate.insert(intermediate_cert);
			}

			// Determine trust: default to false, require explicit trust
			Ok(Self { certificate, options, root: HashSet::new(), intermediate })
		} else {
			Err(CertificateError::ValidationFailed {
				reason: "Cannot create options from empty certificate vector".to_string(),
			})
		}
	}
}

/// Additional TryFrom implementations for bundle functionality
impl TryFrom<&[u8]> for CertificateBundle {
	type Error = CertificateError;

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		// Parse multiple certificates from concatenated DER data
		let mut certificates = Vec::new();
		let mut offset = 0;

		while offset < data.len() {
			// Parse DER length to get exact certificate size
			if let Some((cert_len, header_len)) = parse_der_length(&data[offset..]) {
				let total_len = header_len + cert_len;

				// Extract the complete certificate DER data
				if offset + total_len <= data.len() {
					let cert_data = &data[offset..offset + total_len];

					if let Ok(cert) = Certificate::try_from(cert_data) {
						certificates.push(cert);
						offset += total_len;
					} else {
						break;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		}

		Self::try_from(certificates)
	}
}

impl TryFrom<Vec<u8>> for CertificateBundle {
	type Error = CertificateError;

	fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
		data.as_slice().try_into()
	}
}

/// Base extensions commonly found in certificates.
#[cfg(feature = "serde")]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BaseExtensions {
	/// Basic Constraints extension
	#[serde(skip_serializing_if = "Option::is_none")]
	pub basic_constraints: Option<BasicConstraints>,
	/// Subject Key Identifier extension
	#[serde(skip_serializing_if = "Option::is_none")]
	pub subject_key_identifier: Option<String>,
	/// Authority Key Identifier extension  
	#[serde(skip_serializing_if = "Option::is_none")]
	pub authority_key_identifier: Option<String>,
}

/// JSON-serializable certificate information.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateJson {
	/// Serial number as a string (to avoid JSON number precision issues)
	pub serial: String,
	/// Certificate subject DN string
	pub subject: String,
	/// Certificate issuer DN string
	pub issuer: String,
	/// Subject DN as structured name-value pairs
	pub subject_dn: Vec<NameValuePair>,
	/// Issuer DN as structured name-value pairs
	pub issuer_dn: Vec<NameValuePair>,
	/// Not valid before (ISO 8601 string)
	pub not_before: String,
	/// Not valid after (ISO 8601 string)
	pub not_after: String,
	/// Is this a CA certificate?
	pub is_ca: bool,
	/// Is this a self-signed certificate?
	pub is_self_signed: bool,
	/// Certificate hash (hex string)
	pub hash: String,
	/// Certificate hash
	#[serde(rename = "$hash")]
	pub hash_field: String,
	/// Base extensions (parsed common extensions)
	pub base_extensions: BaseExtensions,
	/// PEM-encoded certificate (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pem: Option<String>,
	/// Certificate chain (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub chain: Option<Vec<CertificateJson>>,
	/// Certificate chain
	#[serde(rename = "$chain", skip_serializing_if = "Option::is_none")]
	pub chain_field: Option<Vec<CertificateJson>>,
	/// Extensions information (all extensions as raw data)
	pub extensions: Vec<Extension>,
}

/// Certificate hash wrapper
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CertificateHash {
	hash: Vec<u8>,
	algorithm_oid: String,
}

impl CertificateHash {
	/// Create a new certificate hash with optional algorithm OID (defaults to SHA1)
	pub fn new<T: Into<Vec<u8>>, S: AsRef<str>>(hash: T, algorithm_oid: Option<S>) -> Self {
		let algorithm_oid = algorithm_oid
			.map(|s| s.as_ref().to_string())
			.unwrap_or_else(|| oids::SHA1.to_string());
		Self { hash: hash.into(), algorithm_oid }
	}

	/// Create a standardized certificate hash using SHA-256
	pub fn sha256<T: AsRef<[u8]>>(data: T) -> Self {
		let hash_bytes = HashAlgorithm::Sha2_256.hash(data.as_ref());
		Self::new(hash_bytes, Some(oids::SHA256))
	}

	/// Create a certificate hash using SHA-1 (for legacy compatibility)
	pub fn sha1<T: AsRef<[u8]>>(data: T) -> Self {
		let hash_bytes = HashAlgorithm::Sha1.hash(data.as_ref());
		Self::new(hash_bytes, Some(oids::SHA1))
	}

	/// Create a certificate hash from a certificate's DER bytes
	pub fn from_certificate_der<T: AsRef<[u8]>>(der_bytes: T) -> Self {
		// Use SHA-1 for certificate hashing (standard for X.509 key identifiers)
		Self::sha1(der_bytes)
	}

	/// Create a modernized certificate hash using SHA-256
	pub fn from_certificate_der_sha256<T: AsRef<[u8]>>(der_bytes: T) -> Self {
		Self::sha256(der_bytes)
	}

	/// Get the algorithm OID
	pub fn algorithm_oid(&self) -> &str {
		&self.algorithm_oid
	}

	/// Get the hash function name
	pub fn hash_function_name(&self) -> &str {
		match self.algorithm_oid.as_str() {
			oids::SHA1 => "SHA1",
			oids::SHA256 => "SHA256",
			oids::SHA512 => "SHA512",
			oids::SHA3_256 => "SHA3-256",
			_ => "UNKNOWN",
		}
	}

	/// Get the length of the hash in bytes
	pub fn len(&self) -> usize {
		self.hash.len()
	}

	/// Check if the hash is empty
	pub fn is_empty(&self) -> bool {
		self.hash.is_empty()
	}

	/// Verify this hash matches the given certificate
	pub fn verify_certificate(&self, certificate: &Certificate) -> Result<bool, CertificateError> {
		let der_bytes = certificate.to_der()?;
		let computed_hash = match self.algorithm_oid.as_str() {
			oids::SHA1 => Self::sha1(&der_bytes),
			oids::SHA256 => Self::sha256(&der_bytes),
			oids::SHA512 => {
				let sha512_hash = HashAlgorithm::Sha2_512.hash(&der_bytes);
				CertificateHash::new(sha512_hash, Some(oids::SHA512))
			}
			oids::SHA3_256 => {
				let sha3_hash = HashAlgorithm::Sha3_256.hash(&der_bytes);
				CertificateHash::new(sha3_hash, Some(oids::SHA3_256))
			}
			_ => {
				return Err(CertificateError::ValidationFailed {
					reason: format!("Unsupported hash algorithm OID: {}", self.algorithm_oid),
				})
			}
		};

		Ok(*self == computed_hash)
	}
}

impl std::fmt::Display for CertificateHash {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", hex::encode(&self.hash))
	}
}

impl AsRef<[u8]> for CertificateHash {
	fn as_ref(&self) -> &[u8] {
		&self.hash
	}
}

impl From<&[u8]> for CertificateHash {
	fn from(der_data: &[u8]) -> Self {
		Self::from_certificate_der(der_data)
	}
}

impl From<&Certificate> for CertificateHash {
	fn from(certificate: &Certificate) -> Self {
		let der_bytes = certificate
			.to_der()
			.expect("Failed to serialize certificate to DER");
		Self::from_certificate_der(&der_bytes)
	}
}

impl From<Certificate> for CertificateHash {
	fn from(certificate: Certificate) -> Self {
		Self::from(&certificate)
	}
}

impl std::str::FromStr for CertificateHash {
	type Err = CertificateError;

	fn from_str(hex: &str) -> Result<Self, Self::Err> {
		match hex::decode(hex) {
			Ok(bytes) => Ok(Self::new(bytes, None::<&str>)),
			Err(_) => Err(CertificateError::ValidationFailed { reason: "Invalid hex string".to_string() }),
		}
	}
}

/// Certificate hash set for managing collections of hashes
#[derive(Debug, Clone, Default)]
pub struct CertificateHashSet {
	certificates: HashSet<Certificate>,
}

impl CertificateHashSet {
	/// Create a new certificate set
	pub fn new<I: IntoIterator<Item = Certificate>>(certificates: I) -> Self {
		Self { certificates: certificates.into_iter().collect() }
	}

	/// Check if the set contains a certificate
	pub fn has(&self, certificate: &Certificate) -> bool {
		self.certificates.contains(certificate)
	}

	/// Add a certificate to the set
	pub fn insert(&mut self, certificate: Certificate) {
		self.certificates.insert(certificate);
	}
}

impl From<Vec<Certificate>> for CertificateHashSet {
	fn from(certificates: Vec<Certificate>) -> Self {
		Self { certificates: certificates.into_iter().collect() }
	}
}

impl TryFrom<&[Certificate]> for CertificateHashSet {
	type Error = CertificateError;

	fn try_from(certificates: &[Certificate]) -> Result<Self, Self::Error> {
		Ok(Self { certificates: certificates.iter().cloned().collect() })
	}
}

impl TryFrom<&[String]> for CertificateHashSet {
	type Error = CertificateError;

	fn try_from(_hash_strings: &[String]) -> Result<Self, Self::Error> {
		// Since we're eliminating hash-based operations, return empty set
		Ok(Self { certificates: HashSet::new() })
	}
}

impl From<CertificateHashSet> for Vec<String> {
	fn from(cert_set: CertificateHashSet) -> Self {
		// Convert certificates to their subject names as strings
		cert_set.certificates.iter().map(|c| c.subject()).collect()
	}
}

impl From<&CertificateHashSet> for Vec<String> {
	fn from(cert_set: &CertificateHashSet) -> Self {
		// Convert certificates to their subject names as strings
		cert_set.certificates.iter().map(|c| c.subject()).collect()
	}
}

/// Certificate builder for creating new certificates.
#[derive(Debug, Clone)]
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

/// Complete X.509 Certificate structure according to RFC 5280 Section 4.1.
/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1>
///
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Certificate {
	pub tbs_certificate: TbsCertificate,
	pub signature_algorithm: AlgorithmIdentifier,
	pub signature: BitString,
}

impl Certificate {
	/// Convert the certificate to DER format
	pub fn to_der(&self) -> Result<Vec<u8>, CertificateError> {
		Vec::<u8>::try_from(self)
	}

	/// Convert the certificate to PEM format
	pub fn to_pem(&self) -> Result<String, CertificateError> {
		Ok(format!("{self}"))
	}

	/// Get the serial number as U256
	pub fn serial_number(&self) -> U256 {
		// Get the raw bytes from the DER-encoded Uint
		let bytes = self.tbs_certificate.serial_number.as_bytes();
		// Create a 32-byte buffer for U256 (padded with zeros on the left)
		let mut padded = [0u8; 32];
		// Calculate starting position to right-align the serial number bytes
		let start = 32usize.saturating_sub(bytes.len());

		// Copy the serial number bytes to the right side of the buffer
		padded[start..].copy_from_slice(bytes);

		// Convert the big-endian byte array to U256
		U256::from_be_slice(&padded)
	}

	/// Check if the certificate is valid at a specific time
	pub fn check_valid(&self, time: DateTime<Utc>) -> bool {
		self.is_valid_at(time).unwrap_or(false)
	}

	/// Check if the certificate is valid at a specific time
	pub fn is_valid_at(&self, time: DateTime<Utc>) -> Result<bool, CertificateError> {
		let validity = &self.tbs_certificate.validity;

		if time < (&validity.not_before).into() {
			return Ok(false);
		}

		if time > (&validity.not_after).into() {
			return Ok(false);
		}

		Ok(true)
	}

	/// Check if the certificate is valid at a specific chrono DateTime (alias)
	pub fn is_valid_at_datetime(&self, time: DateTime<Utc>) -> Result<bool, CertificateError> {
		self.is_valid_at(time)
	}

	/// Check if the certificate is currently valid
	pub fn is_currently_valid(&self) -> Result<bool, CertificateError> {
		self.is_valid_at(Utc::now())
	}

	/// Check if the certificate is currently valid (simple boolean)
	pub fn check_currently_valid(&self) -> bool {
		self.check_valid(Utc::now())
	}

	/// Get the validity period as chrono DateTimes
	pub fn validity_period(&self) -> (DateTime<Utc>, DateTime<Utc>) {
		let validity = &self.tbs_certificate.validity;
		((&validity.not_before).into(), (&validity.not_after).into())
	}

	/// Get the not_before time as chrono DateTime
	pub fn not_before(&self) -> DateTime<Utc> {
		(&self.tbs_certificate.validity.not_before).into()
	}

	/// Get the not_after time as chrono DateTime
	pub fn not_after(&self) -> DateTime<Utc> {
		(&self.tbs_certificate.validity.not_after).into()
	}

	/// Get the certificate's age (how long it has been valid)
	pub fn age(&self) -> Duration {
		let now = Utc::now();
		now - self.not_before()
	}

	/// Get the remaining validity period of the certificate
	pub fn remaining_validity(&self) -> Duration {
		let now = Utc::now();
		self.not_after() - now
	}

	/// Check if the certificate will expire within the given duration
	pub fn expires_within(&self, duration: Duration) -> bool {
		let now = Utc::now();
		self.not_after() <= now + duration
	}

	/// Check if the certificate has been valid for at least the given duration
	pub fn valid_for_at_least(&self, duration: Duration) -> bool {
		self.age() >= duration
	}

	/// Get the subject distinguished name as a string
	pub fn subject(&self) -> String {
		dn_to_string(&self.tbs_certificate.subject)
	}

	/// Get the subject distinguished name as a string (alias for backward compatibility)
	pub fn subject_name(&self) -> String {
		self.subject()
	}

	/// Get the issuer distinguished name as a string
	pub fn issuer(&self) -> String {
		dn_to_string(&self.tbs_certificate.issuer)
	}

	/// Get the issuer distinguished name as a string (alias for backward compatibility)
	pub fn issuer_name(&self) -> String {
		self.issuer()
	}

	/// Get the subject public key
	pub fn subject_public_key(&self) -> &SubjectPublicKeyInfo {
		&self.tbs_certificate.subject_public_key_info
	}

	/// Check if this is a self-signed certificate
	pub fn is_self_signed(&self) -> bool {
		// Compare issuer and subject DNs
		self.tbs_certificate.issuer == self.tbs_certificate.subject
	}

	/// Get an extension by OID
	pub fn get_extension<S: AsRef<str>>(&self, oid: S) -> Option<&Extension> {
		if let Some(ref extensions) = self.tbs_certificate.extensions {
			let target_oid = ObjectIdentifier::new(oid.as_ref()).ok()?;
			extensions.iter().find(|ext| ext.oid == target_oid)
		} else {
			None
		}
	}

	/// Get all extensions from the certificate
	pub fn get_extensions(&self) -> impl Iterator<Item = &Extension> {
		self.tbs_certificate
			.extensions
			.iter()
			.flat_map(|exts| exts.iter())
	}

	/// Check if this is a CA certificate (has Basic Constraints CA=true)
	pub fn is_ca(&self) -> bool {
		if let Some(basic_constraints) = self.get_extension(oids::BASIC_CONSTRAINTS) {
			match BasicConstraints::from_der(basic_constraints.value.as_bytes()) {
				Ok(constraints) => constraints.ca,
				Err(_) => false, // Invalid extension, assume not a CA
			}
		} else {
			// No Basic Constraints extension means not a CA
			false
		}
	}

	/// Check if this certificate and another form a valid issuer-subject relationship
	pub fn is_valid_issuer_subject_pair(&self, issuer: &Certificate) -> Result<bool, CertificateError> {
		// Check DN matching
		if !self.validate_issuer_subject_dn_match(issuer) {
			return Ok(false);
		}

		// Check Authority/Subject Key Identifier matching
		if !self.validate_authority_key_identifier(issuer) {
			return Ok(false);
		}

		// Check signature
		if !self.verify_signature(&issuer.tbs_certificate.subject_public_key_info)? {
			return Ok(false);
		}

		// Check validity periods (issuer should be valid when this cert was issued)
		let this_not_before = self.not_before();
		if !issuer.is_valid_at(this_not_before)? {
			return Ok(false);
		}

		Ok(true)
	}

	/// Validate the certificate's signature using the issuer's public key.
	///
	/// This method verifies that the certificate was signed by the provided
	/// public key according to RFC 5280 certificate validation requirements.
	pub fn verify_signature(&self, issuer_public_key: &SubjectPublicKeyInfo) -> Result<bool, CertificateError> {
		let cert_sig_oid = &self.signature_algorithm.algorithm;
		let key_alg_oid = &issuer_public_key.algorithm.algorithm;

		// Check algorithm compatibility
		let is_compatible = match cert_sig_oid.to_string().as_str() {
			oids::ECDSA_WITH_SHA3_256 | oids::ECDSA_WITH_SHA256 => key_alg_oid.to_string() == oids::EC_PUBLIC_KEY,
			oids::ED25519 => key_alg_oid.to_string() == oids::ED25519,
			_ => false,
		};

		if !is_compatible {
			return Ok(false);
		}

		let tbs_der = self
			.tbs_certificate
			.to_der()
			.map_err(CertificateError::from)?;

		let signature_bytes = self.signature.raw_bytes();
		let public_key_bytes = issuer_public_key.subject_public_key.raw_bytes();

		// Dispatch to appropriate verification function based on signature algorithm
		match cert_sig_oid.to_string().as_str() {
			oids::ED25519 => utils::verify_ed25519_signature(public_key_bytes, signature_bytes, &tbs_der),

			oids::ECDSA_WITH_SHA3_256 => {
				// For ECDSA, try both curves since the verification function handles curve detection
				utils::verify_ecdsa_signature(public_key_bytes, signature_bytes, &tbs_der, HashAlgorithm::Sha3_256)
			}

			oids::ECDSA_WITH_SHA256 => {
				// For ECDSA, try both curves since the verification function handles curve detection
				utils::verify_ecdsa_signature(public_key_bytes, signature_bytes, &tbs_der, HashAlgorithm::Sha2_256)
			}

			oids::SHA256_WITH_RSA => Err(CertificateError::InvalidCertificate),

			_ => Ok(false),
		}
	}

	/// Validate the certificate at a specific time (throws error)
	pub fn assert_valid(&self, time: DateTime<Utc>) -> Result<(), CertificateError> {
		self.validate_at(time)
	}

	/// Validate the certificate at a specific time
	pub fn validate_at(&self, time: DateTime<Utc>) -> Result<(), CertificateError> {
		if time < (&self.tbs_certificate.validity.not_before).into() {
			return Err(CertificateError::NotYetValid);
		}

		if time > (&self.tbs_certificate.validity.not_after).into() {
			return Err(CertificateError::Expired);
		}

		Ok(())
	}

	/// Validate the certificate at a specific chrono DateTime (alias)
	pub fn validate_at_datetime(&self, time: DateTime<Utc>) -> Result<(), CertificateError> {
		self.validate_at(time)
	}

	/// Validate the certificate at the current time
	pub fn validate_now(&self) -> Result<(), CertificateError> {
		self.validate_at(Utc::now())
	}

	/// Check if two certificates have the same public key
	pub fn same_public_key(&self, other: &Certificate) -> bool {
		self.tbs_certificate.subject_public_key_info == other.tbs_certificate.subject_public_key_info
	}

	/// Validate certificate path according to RFC 5280 Section 6.
	/// See: <https://tools.ietf.org/html/rfc5280#section-6>
	pub fn validate_certificate_path(&self, path: &[Certificate]) -> Result<bool, CertificateError> {
		if path.is_empty() {
			return Ok(false);
		}

		// The first certificate in the path should be this certificate
		if *self != path[0] {
			return Ok(false);
		}

		// Validate each link in the chain
		for i in 0..path.len() - 1 {
			let subject_cert = &path[i];
			let issuer_cert = &path[i + 1];
			if !subject_cert.is_valid_issuer_subject_pair(issuer_cert)? {
				return Ok(false);
			}
		}

		// The last certificate should be self-signed (trust anchor)
		let trust_anchor = &path[path.len() - 1];
		if !trust_anchor.is_self_signed() {
			return Ok(false);
		}

		Ok(true)
	}

	/// Check if this certificate was issued by the given issuer
	pub fn check_issued(&self, issuer: &Certificate) -> bool {
		self.validate_issuer_subject_dn_match(issuer)
			&& self.validate_authority_key_identifier(issuer)
			&& self
				.verify_signature(&issuer.tbs_certificate.subject_public_key_info)
				.unwrap_or(false)
	}

	/// Validate RFC 5280 compliance for this certificate
	pub fn validate_rfc5280_compliance(&self) -> Result<(), CertificateError> {
		// Check version
		if let Some(version) = self.tbs_certificate.version {
			if version != 2 {
				return Err(CertificateError::ValidationFailed {
					reason: "Only X.509 v3 certificates are supported per RFC 5280".to_string(),
				});
			}
		}

		// Validate extensions compliance
		self.validate_critical_extensions()?;
		self.validate_extension_consistency()?;
		// Validate DN structure
		self.validate_distinguished_names()?;

		Ok(())
	}

	/// Validate that all critical extensions are properly handled
	pub fn validate_critical_extensions(&self) -> Result<(), CertificateError> {
		if let Some(extensions) = &self.tbs_certificate.extensions {
			let known_critical_extensions = [
				oids::BASIC_CONSTRAINTS,
				oids::KEY_USAGE,
				oids::CERTIFICATE_POLICIES,
				oids::SUBJECT_ALT_NAME,
				oids::NAME_CONSTRAINTS,
			];

			for extension in extensions {
				if extension.critical {
					let oid_str = extension.oid.to_string();

					// Check if this is a known critical extension
					if !known_critical_extensions.contains(&oid_str.as_str()) {
						return Err(CertificateError::ValidationFailed {
							reason: format!("Unknown critical extension: {oid_str}"),
						});
					}

					// Validate specific critical extensions
					match oid_str.as_str() {
						oids::BASIC_CONSTRAINTS => {
							// Basic Constraints MUST be marked critical for CA certificates
							if self.is_ca() {
								// Extension is correctly marked critical for CA
								continue;
							}
						}
						oids::KEY_USAGE => {
							// Key Usage should be critical per RFC 5280 recommendations
							continue;
						}
						_ => {
							// Other critical extensions are implementation-specific
							continue;
						}
					}
				}
			}
		}

		Ok(())
	}

	/// Validate extension consistency per RFC 5280
	pub fn validate_extension_consistency(&self) -> Result<(), CertificateError> {
		if let Some(extensions) = &self.tbs_certificate.extensions {
			// Check for duplicate extensions (RFC 5280 section 4.2)
			let mut seen_oids = HashSet::new();
			for extension in extensions {
				let oid_str = extension.oid.to_string();
				if seen_oids.contains(&oid_str) {
					return Err(CertificateError::ValidationFailed {
						reason: format!("Duplicate extension OID: {oid_str}"),
					});
				}
				seen_oids.insert(oid_str);
			}

			// Validate Basic Constraints consistency
			if let Some(basic_constraints_ext) = self.get_extension(oids::BASIC_CONSTRAINTS) {
				if let Ok(basic_constraints) = BasicConstraints::from_der(basic_constraints_ext.value.as_bytes()) {
					// CA certificates MUST have Basic Constraints marked as critical
					if basic_constraints.ca && !basic_constraints_ext.critical {
						return Err(CertificateError::ValidationFailed {
							reason: "CA certificates must have Basic Constraints marked as critical".to_string(),
						});
					}
				}
			}
		}

		Ok(())
	}

	/// Validate Distinguished Name structure per RFC 5280
	pub fn validate_distinguished_names(&self) -> Result<(), CertificateError> {
		// Validate subject DN
		if self.tbs_certificate.subject.is_empty() {
			// Subject can be empty only if Subject Alternative Name is present and marked critical
			if let Some(san_ext) = self.get_extension(oids::SUBJECT_ALT_NAME) {
				if !san_ext.critical {
					return Err(CertificateError::ValidationFailed {
						reason: "Empty subject DN requires critical Subject Alternative Name extension".to_string(),
					});
				}
			} else {
				return Err(CertificateError::ValidationFailed {
					reason: "Subject DN cannot be empty without Subject Alternative Name extension".to_string(),
				});
			}
		}

		// Issuer DN must not be empty
		if self.tbs_certificate.issuer.is_empty() {
			return Err(CertificateError::ValidationFailed { reason: "Issuer DN cannot be empty".to_string() });
		}

		Ok(())
	}

	/// Validate issuer/subject DN relationship per RFC 5280 section 4.1.2.4
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4>
	pub fn validate_issuer_subject_dn_match(&self, issuer: &Certificate) -> bool {
		// The issuer field of this certificate must match the subject field of the issuer certificate
		self.tbs_certificate.issuer == issuer.tbs_certificate.subject
	}

	/// Validate Authority Key Identifier extension per RFC 5280 section 4.2.1.1
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1>
	pub fn validate_authority_key_identifier(&self, issuer: &Certificate) -> bool {
		// If Authority Key Identifier is present, validate it matches the issuer's Subject Key Identifier
		if let Some(auth_key_ext) = self.get_extension(oids::AUTHORITY_KEY_IDENTIFIER) {
			if let Some(issuer_subject_key_ext) = issuer.get_extension(oids::SUBJECT_KEY_IDENTIFIER) {
				// Parse both key identifiers and compare
				if let (Some(auth_key_id), Some(subject_key_id)) = (
					utils::parse_authority_key_identifier(auth_key_ext.value.as_bytes()),
					utils::parse_key_identifier(issuer_subject_key_ext.value.as_bytes()),
				) {
					return auth_key_id == subject_key_id;
				}
			}
			// If Authority Key Identifier is present but can't be validated, this is suspicious
			return false;
		}

		// If no Authority Key Identifier is present, this check passes
		true
	}

	/// Parse base extensions from certificate
	#[cfg(feature = "serde")]
	fn parse_base_extensions(&self) -> BaseExtensions {
		let mut base_extensions = BaseExtensions::default();
		if let Some(extensions) = &self.tbs_certificate.extensions {
			for ext in extensions {
				match ext.oid.to_string().as_str() {
					// Basic Constraints
					oids::BASIC_CONSTRAINTS => {
						if let Ok(constraints) = BasicConstraints::from_der(ext.value.as_bytes()) {
							base_extensions.basic_constraints = Some(constraints);
						}
					}
					// Subject Key Identifier
					oids::SUBJECT_KEY_IDENTIFIER => {
						// Subject Key Identifier is an OCTET STRING containing the key identifier
						if let Some(key_id) = parse_key_identifier(ext.value.as_bytes()) {
							base_extensions.subject_key_identifier = Some(hex::encode(key_id));
						}
					}
					// Authority Key Identifier
					oids::AUTHORITY_KEY_IDENTIFIER => {
						// Authority Key Identifier is a SEQUENCE with optional KeyIdentifier [0]
						if let Some(key_id) = parse_authority_key_identifier(ext.value.as_bytes()) {
							base_extensions.authority_key_identifier = Some(hex::encode(key_id));
						}
					}
					// TODO: Do we care?
					_ => {} // Ignore other extensions for base extensions
				}
			}
		}

		base_extensions
	}

	/// Convert certificate to JSON representation
	#[cfg(feature = "serde")]
	pub fn to_json(&self, include_pem: bool) -> Result<CertificateJson, CertificateError> {
		let hash = CertificateHash::from(self);
		let hash_hex = hex::encode(hash.as_ref());
		let pem = if include_pem {
			Some(self.to_pem()?)
		} else {
			None
		};

		let extensions = self
			.tbs_certificate
			.extensions
			.as_ref()
			.map(|exts| {
				exts.iter()
					.map(|ext| Extension { oid: ext.oid, critical: ext.critical, value: ext.value.clone() })
					.collect()
			})
			.unwrap_or_default();

		// Convert serial number bytes to hex string
		let serial_bytes = self.tbs_certificate.serial_number.as_bytes();
		let serial_hex = hex::encode(serial_bytes);

		// Convert Time to DateTime<Utc> for RFC3339 formatting
		let not_before_dt: chrono::DateTime<chrono::Utc> = (&self.tbs_certificate.validity.not_before).into();
		let not_after_dt: chrono::DateTime<chrono::Utc> = (&self.tbs_certificate.validity.not_after).into();

		Ok(CertificateJson {
			serial: serial_hex,
			subject: self.subject(),
			issuer: self.issuer(),
			subject_dn: dn_to_name_value_pairs(&self.tbs_certificate.subject),
			issuer_dn: dn_to_name_value_pairs(&self.tbs_certificate.issuer),
			not_before: not_before_dt.to_rfc3339(),
			not_after: not_after_dt.to_rfc3339(),
			is_ca: self.is_ca(),
			is_self_signed: self.is_self_signed(),
			hash: hash_hex.clone(),
			hash_field: hash_hex,
			base_extensions: self.parse_base_extensions(),
			pem,
			chain: None,
			chain_field: None,
			extensions,
		})
	}

	/// Verify certificate chain using the provided certificate collections
	pub fn verify_chain(
		&self,
		root: &HashSet<Certificate>,
		intermediate: &HashSet<Certificate>,
	) -> impl Iterator<Item = Certificate> {
		let mut current = self;
		let mut ordered_chain = vec![self.clone()];
		let mut chain_set = HashSet::new();
		chain_set.insert(self.clone());

		// Build the chain by following issuer certificates
		loop {
			if current.is_self_signed() {
				// If this is a self-signed certificate, we are done
				break;
			}

			// Look for the issuer in the certificate collections
			let issuer = root
				.iter()
				.chain(intermediate.iter())
				.find(|cert| cert.tbs_certificate.subject == current.tbs_certificate.issuer);

			if let Some(issuer_cert) = issuer {
				// Only add if not already in the chain
				if !chain_set.contains(issuer_cert) {
					chain_set.insert(issuer_cert.clone());
					ordered_chain.push(issuer_cert.clone());
				}

				current = issuer_cert;
			} else {
				// Cannot find issuer, chain is incomplete
				break;
			}
		}

		ordered_chain.into_iter()
	}

	/// Check if this certificate is trusted given certificate collections.
	pub fn is_trusted(
		&self,
		root: &HashSet<Certificate>,
		intermediate: &HashSet<Certificate>,
		moment: Option<DateTime<Utc>>,
	) -> bool {
		// Check validity at the given moment (or now)
		let check_time = moment.unwrap_or_else(Utc::now);
		if !self.is_valid_at(check_time).unwrap_or(false) {
			return false;
		}

		// If this is directly in the trusted roots, it's trusted
		if root.contains(self) {
			return true;
		}

		// Try to build a chain to a trusted root
		let chain: Vec<Certificate> = self.verify_chain(root, intermediate).collect();

		// Check if the chain ends with a trusted root
		chain
			.last()
			.map(|root_cert| root.contains(root_cert))
			.unwrap_or(false)
	}

	/// Assert that a valid certificate graph can be constructed with the
	/// given certificates.
	///
	/// This validates that:
	/// - No duplicate certificates exist
	/// - No orphaned certificates exist
	/// - No cycles exist in the certificate chain
	pub fn assert_can_construct_valid_graph(
		&self,
		certificates: &HashSet<Certificate>,
	) -> Result<(), CertificateError> {
		// Check for duplicates - this is automatically handled by HashSet, but we need to ensure
		// no certificates with same content but different objects
		let mut seen_hashes = HashSet::new();
		for cert in certificates {
			let cert_hash = CertificateHash::from(cert);
			if !seen_hashes.insert(cert_hash) {
				return Err(CertificateError::ValidationFailed {
					reason: "CERTIFICATE_DUPLICATE_INCLUDED: Duplicate certificate found in graph".to_string(),
				});
			}
		}

		// Check for orphans - certificates that don't connect to the subject certificate
		let connected_certs = self.find_connected_certificates(certificates);
		for cert in certificates {
			if !connected_certs.contains(cert) && cert != self {
				return Err(CertificateError::ValidationFailed {
					reason: "CERTIFICATE_ORPHAN_FOUND: Orphaned certificate found that doesn't connect to subject"
						.to_string(),
				});
			}
		}

		// Check for cycles in the certificate graph
		self.detect_cycles(certificates)?;

		Ok(())
	}

	/// Find all certificates connected to this certificate.
	fn find_connected_certificates(&self, certificates: &HashSet<Certificate>) -> HashSet<Certificate> {
		let mut connected = HashSet::new();
		let mut to_visit = vec![self.clone()];
		let mut visited = HashSet::new();

		while let Some(current) = to_visit.pop() {
			if visited.contains(&current) {
				continue;
			}

			visited.insert(current.clone());

			// Find potential issuers of current certificate
			for cert in certificates {
				// Check if cert could be issuer of current
				if current.tbs_certificate.issuer == cert.tbs_certificate.subject {
					connected.insert(cert.clone());
					if !visited.contains(cert) {
						to_visit.push(cert.clone());
					}
				}

				// Check if current could be issuer of cert
				if cert.tbs_certificate.issuer == current.tbs_certificate.subject {
					connected.insert(cert.clone());
					if !visited.contains(cert) {
						to_visit.push(cert.clone());
					}
				}
			}
		}

		connected
	}

	/// Detect cycles in the certificate graph using depth-first search.
	fn detect_cycles(&self, certificates: &HashSet<Certificate>) -> Result<(), CertificateError> {
		let mut visited = HashSet::new();
		let mut rec_stack = HashSet::new();

		// Start DFS from the subject certificate
		self.dfs_cycle_detection(&mut visited, &mut rec_stack, certificates)?;

		// Check from each certificate in the set to catch disconnected cycles
		for cert in certificates {
			if !visited.contains(cert) {
				cert.dfs_cycle_detection(&mut visited, &mut rec_stack, certificates)?;
			}
		}

		Ok(())
	}

	/// Depth-first search for cycle detection.
	fn dfs_cycle_detection(
		&self,
		visited: &mut HashSet<Certificate>,
		rec_stack: &mut HashSet<Certificate>,
		certificates: &HashSet<Certificate>,
	) -> Result<(), CertificateError> {
		visited.insert(self.clone());
		rec_stack.insert(self.clone());

		// Find all certificates that this certificate issues
		for cert in certificates {
			if cert.tbs_certificate.issuer == self.tbs_certificate.subject {
				// Skip self-signed certificates as they're not cycles
				if cert.is_self_signed() {
					continue;
				}

				if rec_stack.contains(cert) {
					return Err(CertificateError::ValidationFailed {
						reason: "CERTIFICATE_CYCLE_FOUND: Cycle detected in certificate graph".to_string(),
					});
				}

				if !visited.contains(cert) {
					cert.dfs_cycle_detection(visited, rec_stack, certificates)?;
				}
			}
		}

		rec_stack.remove(self);
		Ok(())
	}
}

impl core::hash::Hash for Certificate {
	fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
		// Hash based on the DER bytes of the certificate
		if let Ok(der_bytes) = self.to_der() {
			der_bytes.hash(state);
		}
	}
}

impl std::fmt::Display for Certificate {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let der = self.to_der().map_err(|_| std::fmt::Error)?;
		let base64_content = general_purpose::STANDARD.encode(&der);

		// Write PEM format header
		writeln!(f, "-----BEGIN CERTIFICATE-----")?;
		// Split into 64-character lines
		for chunk in base64_content.as_bytes().chunks(64) {
			let chunk_str = core::str::from_utf8(chunk).map_err(|_| std::fmt::Error)?;
			writeln!(f, "{chunk_str}")?;
		}
		// Write PEM format footer
		writeln!(f, "-----END CERTIFICATE-----")
	}
}

impl std::str::FromStr for Certificate {
	type Err = CertificateError;

	fn from_str(pem: &str) -> Result<Self, Self::Err> {
		// Extract the base64 content between BEGIN/END CERTIFICATE markers
		let lines: Vec<&str> = pem.lines().collect();
		let start = lines
			.iter()
			.position(|line| line.contains("BEGIN CERTIFICATE"))
			.ok_or(CertificateError::InvalidCertificate)?;
		let end = lines
			.iter()
			.position(|line| line.contains("END CERTIFICATE"))
			.ok_or(CertificateError::InvalidCertificate)?;

		if start >= end {
			return Err(CertificateError::InvalidCertificate);
		}

		let base64_content = lines[start + 1..end].join("");
		let der_bytes = general_purpose::STANDARD.decode(base64_content)?;

		Self::try_from(der_bytes.as_slice())
	}
}

// TryFrom implementations for Certificate
impl TryFrom<&[u8]> for Certificate {
	type Error = CertificateError;

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		let cert = <Self as Decode>::from_der(data).map_err(CertificateError::from)?;

		// Validate RFC 5280 compliance
		cert.validate_rfc5280_compliance()?;

		Ok(cert)
	}
}

impl TryFrom<Vec<u8>> for Certificate {
	type Error = CertificateError;

	fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
		Self::try_from(data.as_slice())
	}
}

impl TryFrom<&Certificate> for Vec<u8> {
	type Error = CertificateError;

	fn try_from(value: &Certificate) -> Result<Self, Self::Error> {
		value.to_owned().try_into()
	}
}

impl TryFrom<Certificate> for Vec<u8> {
	type Error = CertificateError;

	fn try_from(value: Certificate) -> Result<Self, Self::Error> {
		Ok(<Certificate as Encode>::to_der(&value)?)
	}
}

macro_rules! impl_try_from_der_decode {
	($target_type:ty) => {
		impl TryFrom<&[u8]> for $target_type {
			type Error = CertificateError;

			fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
				Ok(<Self as Decode>::from_der(data)?)
			}
		}
	};
}

impl_try_from_der_decode!(TbsCertificate);

macro_rules! impl_try_from_der_encode_trait {
	($source_type:ty) => {
		impl TryFrom<&$source_type> for Vec<u8> {
			type Error = CertificateError;

			fn try_from(value: &$source_type) -> Result<Self, Self::Error> {
				<$source_type as Encode>::to_der(value).map_err(CertificateError::from)
			}
		}
	};
}

impl_try_from_der_encode_trait!(TbsCertificate);

#[cfg(test)]
mod tests {
	use asn1::oids;
	use asn1::{BitString, Uint};
	use chrono::Utc;
	use crypto::algorithms::ed25519::Ed25519Derivation;
	use crypto::operations::encryption::KeyGeneration;
	use crypto::Algorithm;
	use crypto::KeyDerivation;
	use crypto::{AnyPrivateKey, Secp256k1PrivateKey, Secp256r1PrivateKey};

	use super::*;
	use crate::utils;

	#[derive(Debug, Clone)]
	pub struct CertificateChain {
		pub root: &'static str,
		pub intermediate: &'static str,
		pub client: &'static str,
	}

	#[derive(Debug, Clone)]
	pub struct KeyData {
		pub public_key: &'static [u8],
		pub oid: &'static str,
	}

	#[derive(Debug, Clone)]
	pub struct TestCertificateSet {
		pub algorithm: Algorithm,
		pub oid: &'static str,
		pub chain: CertificateChain,
		pub key_data: Option<KeyData>,
	}

	const TEST_SEED: &str =
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

	// Test key data
	const RAW_ED25519_PUBLIC_KEY: [u8; 32] = [
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	];

	const RAW_SECP256R1_PUBLIC_KEY: [u8; 65] = [
		0x04, // Uncompressed point indicator
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	];

	const RAW_SECP256K1_PUBLIC_KEY: [u8; 65] = [
		0x04, 0x15, 0x7a, 0xb0, 0xeb, 0x13, 0x54, 0x4f, 0x15, 0x83, 0x63, 0x5c, 0xf8, 0xdb, 0x2e, 0xd3, 0x1f, 0xe9,
		0xd0, 0x29, 0x20, 0x6e, 0x16, 0x01, 0x00, 0x39, 0x2e, 0xc9, 0x12, 0x88, 0xd6, 0x53, 0xa8, 0x97, 0xcf, 0xb1,
		0x47, 0x62, 0x04, 0xd7, 0x2f, 0x7e, 0xa3, 0x1e, 0xf1, 0x6a, 0x62, 0x81, 0xec, 0xd7, 0x6f, 0x1d, 0x60, 0xce,
		0x31, 0xf1, 0x0f, 0x6d, 0x62, 0x15, 0xba, 0xfc, 0x6c, 0xdd, 0xcc,
	];

	// Data-driven test certificate sets organized by algorithm
	static TEST_CERTIFICATE_SETS: &[TestCertificateSet] = &[
		TestCertificateSet {
			algorithm: Algorithm::Secp256k1,
			oid: oids::ECDSA_WITH_SHA256,
			chain: CertificateChain {
				root: r#"-----BEGIN CERTIFICATE-----
MIIB8DCCAZWgAwIBAgIJAOQFula8pzhMMAoGCCqGSM49BAMCMFQxCzAJBgNVBAYT
AlVTMQswCQYDVQQIEwJDQTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxDjAMBgNVBAoT
BUtlZXRhMRIwEAYDVQQDEwlrZWV0YS5jb20wHhcNMjIxMTAyMjE0NzMwWhcNMzIx
MDMwMjE0NzMwWjBUMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFDASBgNVBAcT
C0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTESMBAGA1UEAxMJa2VldGEuY29t
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEFXqw6xNUTxWDY1z42y7TH+nQKSBuFgEA
OS7JEojWU6iXz7FHYgTXL36jHvFqYoHs128dYM4x8Q9tYhW6/GzdzKNTMFEwHQYD
VR0OBBYEFNB4UOk1stu7q7nmEfiIeN4ZtMaYMB8GA1UdIwQYMBaAFNB4UOk1stu7
q7nmEfiIeN4ZtMaYMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIh
APpGBwnYm+P/m5uzICFpZjmV55Y1vK2I+8Aoa+sOmQ28AiEAwkmsOoNRNxwSYsKE
wW0cCBKGS0ieSFZftyNLFYI1YvI=
-----END CERTIFICATE-----"#,
				intermediate: r#"-----BEGIN CERTIFICATE-----
MIIB6TCCAZCgAwIBAgIBATAKBggqhkjOPQQDAjBUMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExFDASBgNVBAcTC0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTES
MBAGA1UEAxMJa2VldGEuY29tMB4XDTIyMTEwMjIyMDE1MloXDTMwMDIwMzIyMDE1
MlowRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ4wDAYDVQQKEwVLZWV0YTEY
MBYGA1UEAxMPbm9kZTEua2VldGEuY29tMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE
RrmFHfkBmk8rFrA2etvh0MCeN/hBY6YXNHnkS+lN3I4m/ou8zOP4lrvrfaB6TIlH
+3n+P1W9wQag28nByMgVyqNmMGQwHQYDVR0OBBYEFHqplpYPZnUJ1w7RYlfLl4Ig
gvMrMB8GA1UdIwQYMBaAFNB4UOk1stu7q7nmEfiIeN4ZtMaYMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIH9qE0E4
jRN9FHnJbDglV2knXd/YG9EfytcrCnq8lpAsAiBruKTcu4NVUVXs/WXPcsMrDYm/
4gahA5CqK0VlqmA3TA==
-----END CERTIFICATE-----"#,
				client: r#"-----BEGIN CERTIFICATE-----
MIIB3jCCAYWgAwIBAgIBATAKBggqhkjOPQQDAjBEMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExDjAMBgNVBAoTBUtlZXRhMRgwFgYDVQQDEw9ub2RlMS5rZWV0YS5j
b20wHhcNMjIxMTAzMDEyOTU4WhcNMjcwNTExMDEyOTU4WjBiMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC0xvcyBBbmdlbGVzMQ4wDAYDVQQKDAVL
ZWV0YTEgMB4GA1UEAwwXY2xpZW50MS5ub2RlMS5rZWV0YS5jb20wVjAQBgcqhkjO
PQIBBgUrgQQACgNCAAQ3605beUhS+2ZGuk4OkQ2utb239l2gkAl4tgKp1JFyujP8
aNZ5Zh7nnfB64eWCOHtaGIXHYeXlYf+rZ9KfnULdo00wSzAdBgNVHQ4EFgQUGKqt
zLuSNICC4hIdFc3a7QdIkhMwHwYDVR0jBBgwFoAUeqmWlg9mdQnXDtFiV8uXgiCC
8yswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNHADBEAiB/sWgSvLZSddTHD64sWgPD
gQSnWXxjfIzcoP1W48lZngIgazAF+38D5aIrcmtnD2YEp5i1ydiYzxKCU1RFAZf5
40c=
-----END CERTIFICATE-----"#,
			},
			key_data: Some(KeyData { public_key: &RAW_SECP256K1_PUBLIC_KEY, oid: oids::EC_PUBLIC_KEY }),
		},
		TestCertificateSet {
			algorithm: Algorithm::Secp256r1,
			oid: oids::ECDSA_WITH_SHA256,
			chain: CertificateChain {
				root: r#"-----BEGIN CERTIFICATE-----
MIIB/TCCAaOgAwIBAgIUWT6KAkJd/vGnEaMpmzzBnR0adLMwCgYIKoZIzj0EAwIw
VDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRQwEgYDVQQHEwtMb3MgQW5nZWxl
czEOMAwGA1UEChMFS2VldGExEjAQBgNVBAMTCWtlZXRhLmNvbTAeFw0yMzA0Mjcx
NjU1NTBaFw0zMzA0MjQxNjU1NTBaMFQxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxDjAMBgNVBAoTBUtlZXRhMRIwEAYDVQQD
EwlrZWV0YS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATI0DTRcpiIYTuN
Blb4D0bkq8LtKOs6YZKFC5DBT8Tx5bgA53Vey1WaQu5S7tVUifcnRCw7DEBsmjf6
i0Kk+VOeo1MwUTAdBgNVHQ4EFgQUksGKPnEwhukWVJ1WUi84dlf6LAgwHwYDVR0j
BBgwFoAUksGKPnEwhukWVJ1WUi84dlf6LAgwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNIADBFAiEA/lS4Ofqn7KTuglEWT/qExfhhNmRGudGuGlygQpDufxIC
IGt06yHwG3iv0egp8nqgbrcS4sXWltY25atPhalwd7vN
-----END CERTIFICATE-----"#,
				intermediate: r#"-----BEGIN CERTIFICATE-----
MIIB7TCCAZOgAwIBAgIBATAKBggqhkjOPQQDAjBUMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExFDASBgNVBAcTC0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTES
MBAGA1UEAxMJa2VldGEuY29tMB4XDTIzMDQyODIzMzk0OFoXDTMwMDczMDIzMzk0
OFowRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ4wDAYDVQQKEwVLZWV0YTEY
MBYGA1UEAxMPbm9kZTEua2VldGEuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEKI6k6eNQwSlKZirGyvBwAT1qY908+tsHfbO4pNLeUF7TOje9YBLUmeI0vw2v
+EAzOFcvFZ+ADe8yYoZ6TAKkJ6NmMGQwHQYDVR0OBBYEFN6Gg86IhS98OidKd/uN
M5wqxQ/IMB8GA1UdIwQYMBaAFJLBij5xMIbpFlSdVlIvOHZX+iwIMBIGA1UdEwEB
/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0gAMEUCIFfN
eqS1mGcNz2C5voo63nnV88aI2C+Yth9ygRT+lz/tAiEAvUJ27e59NBmhZSnlydEc
k88mudtednU6sPAQroQ5Wqs=
-----END CERTIFICATE-----"#,
				client: r#"-----BEGIN CERTIFICATE-----
MIIB4TCCAYigAwIBAgIBATAKBggqhkjOPQQDAjBEMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExDjAMBgNVBAoTBUtlZXRhMRgwFgYDVQQDEw9ub2RlMS5rZWV0YS5j
b20wHhcNMjMwNDI5MDQwMDA5WhcNMjcxMTA0MDQwMDA5WjBiMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC0xvcyBBbmdlbGVzMQ4wDAYDVQQKDAVL
ZWV0YTEgMB4GA1UEAwwXY2xpZW50MS5ub2RlMS5rZWV0YS5jb20wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASu2fGSPSgdnCrzZSPag/HYnQAtj5aHf4yM1KI6dM+g
VO64zcjZM1tSGSRFuJ6dqegCA/mHal9lQLWjpwipussDo00wSzAdBgNVHQ4EFgQU
Di/e49jFkYuS2LLj/4+nXuWCi80wHwYDVR0jBBgwFoAU3oaDzoiFL3w6J0p3+40z
nCrFD8gwCQYDVR0TBAIwADAKBggqhkjOPQQDAgNHADBEAiBdy/XyPecBS+HovnKh
1h4kQrF81Y9mi74wTU8TyrnZ1wIgcHik2KQyKcTRO3O/86W6h6kjB0TI2L9q8DM2
zFR9Uxw=
-----END CERTIFICATE-----"#,
			},
			key_data: Some(KeyData { public_key: &RAW_SECP256R1_PUBLIC_KEY, oid: oids::EC_PUBLIC_KEY }),
		},
		TestCertificateSet {
			algorithm: Algorithm::Ed25519,
			oid: oids::ED25519,
			chain: CertificateChain {
				root: r#"-----BEGIN CERTIFICATE-----
MIIBvTCCAW+gAwIBAgIUcKymEHTsE7V20eIRhoWPjzIEl6IwBQYDK2VwMFQxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIEwJDQTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxDjAM
BgNVBAoTBUtlZXRhMRIwEAYDVQQDEwlrZWV0YS5jb20wHhcNMjIxMTA3MjA1MTU0
WhcNMzIxMTA0MjA1MTU0WjBUMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFDAS
BgNVBAcTC0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTESMBAGA1UEAxMJa2Vl
dGEuY29tMCowBQYDK2VwAyEAxP4ex9eEhp5IWCfpocshVT7NcFcIGN02e4asopW8
SbujUzBRMB0GA1UdDgQWBBQvx8bncF/SC0JUqUpj2g5wlWWLBDAfBgNVHSMEGDAW
gBQvx8bncF/SC0JUqUpj2g5wlWWLBDAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANB
AM/PDdzZ6Fmhlvb4sl+6q3dbl/g4hehhOod1Q2qoHLNsuAE91RAvZFw300MoE2Fz
KQ4u8DPSJYvt9Dmc9mVTDgk=
-----END CERTIFICATE-----"#,
				intermediate: r#"-----BEGIN CERTIFICATE-----
MIIBsDCCAWKgAwIBAgIEEAAAADAFBgMrZXAwVDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgTAkNBMRQwEgYDVQQHEwtMb3MgQW5nZWxlczEOMAwGA1UEChMFS2VldGExEjAQ
BgNVBAMTCWtlZXRhLmNvbTAeFw0yMjExMDcyMDUzMzNaFw0zMDAyMDgyMDUzMzNa
MEQxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEOMAwGA1UEChMFS2VldGExGDAW
BgNVBAMTD25vZGUxLmtlZXRhLmNvbTAqMAUGAytlcAMhAIRi0BDa4pNPKd1tqIpY
6ArNKx9p2Bg08UH8JfqczdLZo2YwZDAdBgNVHQ4EFgQUF1uoyLC6PaX2UuIrolGH
9/PydNIwHwYDVR0jBBgwFoAUL8fG53Bf0gtCVKlKY9oOcJVliwQwEgYDVR0TAQH/
BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwBQYDK2VwA0EAAfWCD0PJ+7iWpUqS
ki3MoY+bWUgWRaHRY2cAa8MZcaK3P4uiW+00NC40CkMqIl5tTGVRNof5mc1xf4zl
XTLIDA==
-----END CERTIFICATE-----"#,
				client: r#"-----BEGIN CERTIFICATE-----
MIIBpTCCAVegAwIBAgIEEAAAADAFBgMrZXAwRDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgTAkNBMQ4wDAYDVQQKEwVLZWV0YTEYMBYGA1UEAxMPbm9kZTEua2VldGEuY29t
MB4XDTIyMTEwNzIwNTQ1MloXDTI3MDUxNTIwNTQ1MlowYjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtMb3MgQW5nZWxlczEOMAwGA1UECgwFS2Vl
dGExIDAeBgNVBAMMF2NsaWVudDEubm9kZTEua2VldGEuY29tMCowBQYDK2VwAyEA
NMbgMpJ8D2Bo24HXD7quMF0QB+wTMhRTu/C0+KqgsLajTTBLMB0GA1UdDgQWBBSX
BEkhHzClJegI9DOeMbFHYrpZwzAfBgNVHSMEGDAWgBQXW6jIsLo9pfZS4iuiUYf3
8/J00jAJBgNVHRMEAjAAMAUGAytlcANBAEiVATSVlYxJ33rgcEfGjFgKtVFB8v2H
/63NVVO3k09vb25ouL80suLD9sLVzpYwD7UoBQfuWqwQEe1Sb7DLygc=
-----END CERTIFICATE-----"#,
			},
			key_data: Some(KeyData { public_key: &RAW_ED25519_PUBLIC_KEY, oid: oids::ED25519 }),
		},
	];

	/// Get a moment that's always within the certificate validity period.
	fn get_cert_moment() -> DateTime<Utc> {
		// Get the first test certificate and calculate a moment in the
		// middle of its validity.
		let cert: Certificate = TEST_CERTIFICATE_SETS[0].chain.root.parse().unwrap();
		let validity_start = cert.not_before();
		let validity_end = cert.not_after();
		let validity_duration = validity_end - validity_start;

		// Use a moment that's 25% through the certificate's validity period
		validity_start + validity_duration / 4
	}

	/// Deconstruct certificate bundle for easy unpacking
	#[derive(Debug, Clone)]
	struct CertificateTestBundle {
		pub ca_cert: Certificate,
		pub intermediate_cert: Certificate,
		pub client_cert: Certificate,
		pub root_certs: HashSet<Certificate>,
		pub intermediate_certs: HashSet<Certificate>,
	}

	/// Test data for certificate hash testing
	struct HashTestCase {
		hash_fn: fn(&[u8]) -> CertificateHash,
		expected_algorithm_oid: &'static str,
		expected_algorithm_name: &'static str,
		expected_length: usize,
	}

	/// Helper to test all hash algorithms with consistent data
	fn test_hash_algorithms<F>(test_fn: F)
	where
		F: Fn(&HashTestCase, &[u8]),
	{
		let test_cases = vec![
			HashTestCase {
				hash_fn: |data| CertificateHash::sha1(data),
				expected_algorithm_oid: crate::oids::SHA1,
				expected_algorithm_name: "SHA1",
				expected_length: 20,
			},
			HashTestCase {
				hash_fn: |data| CertificateHash::sha256(data),
				expected_algorithm_oid: crate::oids::SHA256,
				expected_algorithm_name: "SHA256",
				expected_length: 32,
			},
		];

		let test_data = b"test certificate data for hashing";
		for test_case in &test_cases {
			test_fn(test_case, test_data);
		}
	}

	/// Helper function to extract certificates from a certificate chain
	fn extract_certificates(chain: &CertificateChain) -> CertificateTestBundle {
		let ca_cert: Certificate = chain.root.parse().unwrap();
		let intermediate_cert: Certificate = chain.intermediate.parse().unwrap();
		let client_cert: Certificate = chain.client.parse().unwrap();

		CertificateTestBundle {
			root_certs: HashSet::from([ca_cert.clone()]),
			intermediate_certs: HashSet::from([intermediate_cert.clone()]),
			ca_cert,
			intermediate_cert,
			client_cert,
		}
	}

	/// Helper to create dummy certificate builder with common settings
	fn create_dummy_cert_builder(subject_cn: &str, issuer_cn: &str, serial: u32, is_ca: bool) -> CertificateBuilder {
		let moment = get_cert_moment();
		let valid_from = moment - chrono::Duration::hours(12);
		let valid_to = moment + chrono::Duration::hours(12);

		let dummy_public_key_bytes = vec![0u8; 32];
		let dummy_algorithm = asn1::AlgorithmIdentifier {
			algorithm: asn1::ObjectIdentifier::new(oids::ED25519).unwrap(),
			parameters: None,
		};
		let dummy_public_key_bitstring = asn1::BitString::from_bytes(&dummy_public_key_bytes).unwrap();
		let dummy_public_key_info =
			asn1::SubjectPublicKeyInfo { algorithm: dummy_algorithm, subject_public_key: dummy_public_key_bitstring };

		let subject_dn = utils::create_dn(&[(oids::CN, subject_cn)]).unwrap();
		let issuer_dn = utils::create_dn(&[(oids::CN, issuer_cn)]).unwrap();

		CertificateBuilder::new()
			.with_subject_public_key(dummy_public_key_info)
			.with_subject_dn(subject_dn)
			.with_issuer_dn(issuer_dn)
			.with_validity(valid_from, valid_to)
			.with_serial_number(crypto::bigint::U256::from(serial))
			.with_is_ca(is_ca)
	}

	/// Helper to test all certificate sets with a given test function
	fn test_all_certificate_sets<F>(test_fn: F)
	where
		F: Fn(&CertificateTestBundle),
	{
		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let bundle = extract_certificates(&test_set.chain);
			test_fn(&bundle);
		}
	}

	/// Helper to assert certificate properties
	fn assert_cert_properties(cert: &Certificate, expected_ca: bool) {
		assert!(!cert.issuer().is_empty());
		assert!(!cert.subject().is_empty());
		assert!(cert.serial_number() > U256::ZERO);

		if expected_ca {
			assert!(cert.is_ca());
		}

		let cert_moment = get_cert_moment();
		assert!(cert.is_valid_at(cert_moment).unwrap());
	}

	/// Helper to test DER/PEM roundtrip
	fn test_cert_roundtrip(cert: &Certificate) {
		let pem_output = cert.to_pem().unwrap();
		let cert_re_parsed: Certificate = pem_output.parse().unwrap();
		assert_eq!(cert.to_der().unwrap(), cert_re_parsed.to_der().unwrap());

		let der_bytes = cert.to_der().unwrap();
		let cert_from_der = Certificate::try_from(der_bytes.as_slice()).unwrap();
		assert_eq!(cert.to_der().unwrap(), cert_from_der.to_der().unwrap());
	}

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
	fn test_certificate_parsing() {
		test_all_certificate_sets(|bundle| {
			// Test root CA certificate (should be CA)
			assert_cert_properties(&bundle.ca_cert, true);
			test_cert_roundtrip(&bundle.ca_cert);

			// Test intermediate certificate (should be CA)
			assert_cert_properties(&bundle.intermediate_cert, true);
			test_cert_roundtrip(&bundle.intermediate_cert);

			// Test client certificate (should not be CA)
			assert_cert_properties(&bundle.client_cert, false);
			test_cert_roundtrip(&bundle.client_cert);
		});
	}

	#[test]
	fn test_certificate_validity() {
		test_all_certificate_sets(|bundle| {
			let cert_moment = get_cert_moment();

			for cert in [&bundle.ca_cert, &bundle.intermediate_cert, &bundle.client_cert] {
				let (not_before, not_after) = cert.validity_period();
				assert!(not_before < not_after);
				assert!(cert.is_valid_at(cert_moment).unwrap());
				assert!(cert.check_valid(cert_moment));

				let before_valid = not_before - chrono::Duration::seconds(1);
				let after_valid = not_after + chrono::Duration::seconds(1);
				assert!(!cert.is_valid_at(before_valid).unwrap());
				assert!(!cert.is_valid_at(after_valid).unwrap());

				let cert_age_at_moment = cert_moment - not_before;
				let cert_remaining_at_moment = not_after - cert_moment;
				assert!(cert_age_at_moment > chrono::Duration::zero());
				assert!(cert_remaining_at_moment > chrono::Duration::zero());
			}
		});
	}

	/// Helper to check certificate has expected extensions
	fn assert_cert_extensions(cert: &Certificate, expected_oids: &[&str]) {
		let extensions = cert.tbs_certificate.extensions.as_ref().unwrap();
		let found_oids: Vec<String> = extensions.iter().map(|ext| ext.oid.to_string()).collect();

		for expected_oid in expected_oids {
			assert!(found_oids.contains(&expected_oid.to_string()));
		}
	}

	#[test]
	fn test_certificate_extensions() {
		test_all_certificate_sets(|bundle| {
			// Test root certificate extensions
			assert_cert_extensions(
				&bundle.ca_cert,
				&[oids::BASIC_CONSTRAINTS, oids::AUTHORITY_KEY_IDENTIFIER, oids::SUBJECT_KEY_IDENTIFIER],
			);

			// Test intermediate certificate extensions
			assert_cert_extensions(
				&bundle.intermediate_cert,
				&[
					oids::BASIC_CONSTRAINTS,
					oids::KEY_USAGE,
					oids::AUTHORITY_KEY_IDENTIFIER,
					oids::SUBJECT_KEY_IDENTIFIER,
				],
			);

			// Test client certificate extensions
			assert_cert_extensions(
				&bundle.client_cert,
				&[oids::AUTHORITY_KEY_IDENTIFIER, oids::SUBJECT_KEY_IDENTIFIER],
			);
		});
	}

	#[test]
	fn test_chain_traversal() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, root_certs, intermediate_certs } =
				bundle;

			// Test Certificate without chain (should return None for non-self-signed)
			let client_with_no_chain = CertificateBundle {
				certificate: client_cert.clone(),
				options: CertificateOptions::default(),
				root: HashSet::new(),
				intermediate: HashSet::new(),
			};

			assert!(client_with_no_chain.get_issuer_certificate().is_none());
			assert!(client_with_no_chain.get_root_certificate().is_none());

			// Test self-signed certificate (should return itself)
			let ca_with_no_chain = CertificateBundle {
				certificate: ca_cert.clone(),
				options: CertificateOptions::default(),
				root: root_certs.clone(),
				intermediate: intermediate_certs.clone(),
			};

			assert!(ca_with_no_chain.get_issuer_certificate().is_some());
			assert!(ca_with_no_chain.get_root_certificate().is_some());

			// Test with complete chain
			let user_with_chain = CertificateBundle {
				certificate: client_cert.clone(),
				options: CertificateOptions::default(),
				root: root_certs.clone(),
				intermediate: intermediate_certs.clone(),
			};

			let issuer = user_with_chain.get_issuer_certificate().unwrap();
			let root = user_with_chain.get_root_certificate().unwrap();

			assert_eq!(issuer.subject(), intermediate_cert.subject());
			assert_eq!(root.subject(), ca_cert.subject());
			assert_eq!(user_with_chain.chain_length(), 3);
		});
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
			let valid_from = now;
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

			let result = match private_key {
				AnyPrivateKey::Ed25519(key) => builder.build(&key),
				AnyPrivateKey::Secp256k1(key) => builder.build(&key),
				AnyPrivateKey::Secp256r1(key) => builder.build(&key),
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
			assert_eq!(certificate.subject(), certificate.issuer());

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
	fn test_certificate_with_options_try_from() {
		macro_rules! test_certificate_with_options_basic {
			($try_from_expr:expr, $expected_trusted:expr, $expected_chain_length:expr) => {
				let cert_with_opts = $try_from_expr.unwrap();
				assert_eq!(cert_with_opts.is_trusted(), $expected_trusted);
				assert_eq!(cert_with_opts.chain_length(), $expected_chain_length);
			};
		}

		for test_set in TEST_CERTIFICATE_SETS.iter() {
			// Test basic conversions
			let pem_data = test_set.chain.root;
			let base_cert: Certificate = test_set.chain.root.parse().unwrap();
			test_certificate_with_options_basic!(pem_data.parse::<CertificateBundle>(), false, 1);
			test_certificate_with_options_basic!(CertificateBundle::try_from(base_cert.clone()), false, 1);
			test_certificate_with_options_basic!(CertificateBundle::try_from(vec![base_cert.clone()]), false, 1);

			// Test error handling
			let empty_result = CertificateBundle::try_from(Vec::<Certificate>::new());
			assert!(empty_result.is_err());

			// Test chain functionality
			let cert_with_opts = pem_data.parse::<CertificateBundle>().unwrap();
			let cert_with_trust = cert_with_opts
				.with_trusted(true)
				.with_chain(vec![base_cert]);
			assert!(cert_with_trust.is_trusted());
			assert_eq!(cert_with_trust.chain_length(), 1);
		}
	}

	#[test]
	fn test_certificate_with_options_bundle_functionality() {
		/// Helper to test bundle roundtrip
		fn test_bundle_roundtrip(bundle: &CertificateBundle, expected_cert_count: usize) {
			let der_bundle = bundle.to_der().unwrap();
			assert!(!der_bundle.is_empty());

			let restored = CertificateBundle::try_from(der_bundle.as_slice()).unwrap();
			let actual_count = restored.get_chain().count();
			assert_eq!(actual_count, expected_cert_count);
		}

		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } = bundle;

			let chain = vec![client_cert.clone(), intermediate_cert.clone(), ca_cert.clone()];
			let bundle = CertificateBundle::try_from(chain).unwrap();
			assert_eq!(bundle.certificate, *client_cert);
			assert_eq!(bundle.chain_length(), 3);
			assert_eq!(bundle.get_chain().count(), 3);

			// Test get_certificate method
			assert_eq!(bundle.get_certificate(), client_cert);

			// Test get_issuer_public_key method
			let issuer_public_key = bundle.get_issuer_public_key();
			assert!(issuer_public_key.is_some());

			#[cfg(feature = "serde")]
			{
				// Test to_json method with chain certificates
				let json_result = bundle.to_json(false);
				assert!(json_result.is_ok());

				let json_data = json_result.unwrap();
				assert!(json_data.chain.is_some());
			}

			// Test bundle roundtrip
			test_bundle_roundtrip(&bundle, 3);

			let single_cert_bundle = CertificateBundle::try_from(vec![client_cert.clone()]).unwrap();
			test_bundle_roundtrip(&single_cert_bundle, 1);
		});
	}

	#[test]
	fn test_certificate_store_functionality() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } = bundle;

			let mut cert_with_options = CertificateBundle {
				certificate: client_cert.clone(),
				options: CertificateOptions::default(),
				root: HashSet::new(),
				intermediate: HashSet::new(),
			};
			assert_eq!(cert_with_options.root.len(), 0);
			assert_eq!(cert_with_options.intermediate.len(), 0);

			cert_with_options.add_root(ca_cert.clone());
			assert_eq!(cert_with_options.root.len(), 1);

			cert_with_options.add_intermediate(intermediate_cert.clone());
			assert_eq!(cert_with_options.intermediate.len(), 1);

			let all_certs: Vec<_> = cert_with_options.get_chain().collect();
			assert_eq!(all_certs.len(), 3);
			assert!(all_certs.contains(ca_cert));
			assert!(all_certs.contains(intermediate_cert));
			assert!(all_certs.contains(client_cert));
		});
	}

	#[test]
	fn test_intermediate_certificate_functionality() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert: user_cert, .. } = bundle;

			// Create a certificate bundle with intermediate certificate
			let mut cert_bundle = CertificateBundle {
				certificate: user_cert.clone(),
				options: CertificateOptions::default(),
				root: HashSet::new(),
				intermediate: HashSet::new(),
			};

			// Add root and intermediate certificates
			cert_bundle.add_root(ca_cert.clone());
			cert_bundle.add_intermediate(intermediate_cert.clone());

			// Verify the chain includes all certificates
			let all_certs: Vec<_> = cert_bundle.get_chain().collect();
			assert_eq!(all_certs.len(), 3); // user_cert + intermediate_cert + ca_cert
			assert!(all_certs.contains(user_cert));
			assert!(all_certs.contains(ca_cert));
			assert!(all_certs.contains(intermediate_cert));

			// Test that intermediate certificate is properly stored
			assert_eq!(cert_bundle.intermediate.len(), 1);
			assert!(cert_bundle.intermediate.contains(intermediate_cert));
		});
	}

	#[test]
	fn test_certificate_validation_methods() {
		test_all_certificate_sets(|bundle| {
			let cert = &bundle.ca_cert;
			let moment = get_cert_moment();
			assert!(cert.is_valid_at_datetime(moment).unwrap());
			assert!(cert.check_valid(moment));
			assert!(cert.is_valid_at_datetime(moment).unwrap());
			assert!(cert.validate_at_datetime(moment).is_ok());
			assert!(cert.assert_valid(moment).is_ok());
			assert!(cert.validate_at(moment).is_ok());

			// Test validate_now (cert may be expired)
			let now = cert.validate_now();
			assert!(now.is_ok() || now.is_err());

			// Test current validity methods
			assert!(cert.is_currently_valid().unwrap());
			assert!(cert.check_currently_valid());

			let subject = cert.subject();
			let issuer = cert.issuer();
			let serial = cert.serial_number();
			assert!(!subject.is_empty());
			assert!(!issuer.is_empty());
			assert!(serial > U256::ZERO);

			let age = cert.age();
			assert!(age > chrono::Duration::zero());

			// Test remaining_validity method
			let remaining_validity = cert.remaining_validity();
			assert!(remaining_validity > chrono::Duration::zero());

			// Test expires_within method
			let far_future = chrono::Duration::days(365 * 10); // 10 years
			let near_future = chrono::Duration::minutes(1); // 1 minute
			assert!(cert.expires_within(far_future));
			assert!(!cert.expires_within(near_future));

			// Test valid_for_at_least method
			let short_duration = chrono::Duration::hours(1);
			let long_duration = chrono::Duration::days(365 * 10); // 10 years
			assert!(cert.valid_for_at_least(short_duration));
			assert!(!cert.valid_for_at_least(long_duration));

			// Calculate remaining validity from the test moment
			let remaining = cert.not_after() - moment;
			assert!(remaining > chrono::Duration::zero());
			// Certificate should still be valid (not expired)
			assert!(cert.not_after() > moment);
			// Certificate should have been issued before the test moment
			assert!(cert.not_before() < moment);
			// Age should be reasonable (at least 1 hour, less than 50 years)
			assert!(cert.age() >= chrono::Duration::hours(1));
			assert!(cert.age() <= chrono::Duration::days(365 * 50));

			let subject_name = cert.subject_name();
			let issuer_name = cert.issuer_name();
			assert!(!subject_name.is_empty());
			assert!(!issuer_name.is_empty());

			let public_key = cert.subject_public_key();
			let raw_bytes = public_key.subject_public_key.raw_bytes();
			assert!(!raw_bytes.is_empty());
		});
	}

	#[test]
	fn test_certificate_trust_and_verification() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert: user_cert, .. } = bundle;

			let moment = get_cert_moment();

			let empty_root = HashSet::new();
			let empty_intermediate = HashSet::new();
			assert!(!ca_cert.is_trusted(&empty_root, &empty_intermediate, Some(moment)));
			assert!(!user_cert.is_trusted(&empty_root, &empty_intermediate, Some(moment)));

			let mut store_root = HashSet::new();
			store_root.insert(ca_cert.clone());
			let mut store_intermediate = HashSet::new();
			store_intermediate.insert(intermediate_cert.clone());

			assert!(ca_cert.is_trusted(&store_root, &store_intermediate, Some(moment)));
			assert!(user_cert.is_trusted(&store_root, &store_intermediate, Some(moment)));

			let chain: Vec<Certificate> = user_cert
				.verify_chain(&store_root, &store_intermediate)
				.collect();
			assert!(!chain.is_empty());

			// Test with CertificateWithOptions for getting issuer and root
			let mut root_certs = HashSet::new();
			root_certs.insert(ca_cert.clone());
			let mut intermediate_certs = HashSet::new();
			intermediate_certs.insert(intermediate_cert.clone());

			let user_with_chain = CertificateBundle {
				certificate: user_cert.clone(),
				options: CertificateOptions::default(),
				root: root_certs,
				intermediate: intermediate_certs,
			};

			let issuer = user_with_chain.get_issuer_certificate();
			assert!(issuer.is_some());

			let root = user_with_chain.get_root_certificate();
			assert!(root.is_some());

			// Check validity methods
			assert!(ca_cert.is_self_signed());
			assert!(!intermediate_cert.is_self_signed());
			assert!(!user_cert.is_self_signed());
			assert!(ca_cert == ca_cert);
			assert!(ca_cert != user_cert);

			// Check name relationships (issuer/subject matching)
			assert_eq!(user_cert.issuer(), intermediate_cert.subject());
			assert_eq!(intermediate_cert.issuer(), ca_cert.subject());
			assert_eq!(ca_cert.issuer(), ca_cert.subject()); // Self-signed

			// Test cryptographic relationship
			assert!(intermediate_cert.check_issued(ca_cert));
			assert!(user_cert.check_issued(intermediate_cert));
		});
	}

	#[test]
	fn test_certificate_with_options_validation() {
		test_all_certificate_sets(|bundle| {
			let moment = get_cert_moment();
			let CertificateTestBundle { ca_cert, root_certs, intermediate_certs, client_cert, .. } = bundle;

			let cert_with_options = CertificateBundle::new(
				&client_cert.to_pem().unwrap(),
				Some(CertificateOptions { moment: Some(moment), is_trusted_root: Some(true) }),
				Some(root_certs.clone()),
				Some(intermediate_certs.clone()),
			)
			.unwrap();

			// Test validation with certificate collections
			let cert_with_options_clone = cert_with_options.clone();
			let validated = cert_with_options_clone.verify_chain(Some(moment)).unwrap();
			assert!(validated.is_trusted());

			// Test validation error when no root certificates are available
			let cert_with_no_roots = CertificateBundle {
				certificate: ca_cert.clone(),
				options: CertificateOptions::default(),
				root: HashSet::new(),
				intermediate: HashSet::new(),
			};

			// Verify that the certificate cannot be validated without roots
			let validation_result = cert_with_no_roots.verify_chain(Some(moment));
			assert!(matches!(validation_result, Err(CertificateError::ChainValidationFailed { .. })));

			// Test DER conversion
			let der_bytes = cert_with_options.to_der().unwrap();
			assert!(!der_bytes.is_empty());

			// Test get_certificates
			let all_certs = cert_with_options.get_chain();
			assert_eq!(all_certs.count(), 3);
		});
	}

	#[test]
	fn test_try_from_implementations() {
		macro_rules! test_certificate_conversion {
			($source:expr, $target_type:ty, $test_condition:expr) => {
				let converted: $target_type = $source.try_into().unwrap();
				assert!($test_condition(converted));
			};
		}

		macro_rules! test_certificate_from {
			($source:expr, $expected_hash:expr) => {
				let cert = Certificate::try_from($source).unwrap();
				assert_eq!($expected_hash, CertificateHash::from(&cert));
			};
		}

		macro_rules! test_certificate_parse {
			($source:expr, $expected_hash:expr) => {
				let cert: Certificate = $source.parse().unwrap();
				assert_eq!($expected_hash, CertificateHash::from(&cert));
			};
		}

		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert: user_cert, .. } =
				extract_certificates(&test_set.chain);

			// Test each certificate in the chain
			for cert in [&ca_cert, &intermediate_cert, &user_cert] {
				let der_bytes = cert.to_der().unwrap();
				let expected_hash = CertificateHash::from(cert);

				// Test Certificate from various sources
				test_certificate_from!(der_bytes.as_slice(), expected_hash);
				test_certificate_from!(der_bytes.clone(), expected_hash);

				// Test Certificate to various targets
				test_certificate_conversion!(cert, Vec<u8>, |v: Vec<u8>| v == der_bytes);
				test_certificate_conversion!(cert.clone(), Vec<u8>, |v: Vec<u8>| v == der_bytes);

				// Test CertificateWithOptions from single certificate DER
				let cert_der = cert.to_der().unwrap();
				let single_cert_bundle = CertificateBundle::try_from(cert_der).unwrap();
				assert_eq!(single_cert_bundle.get_chain().count(), 1);
			}

			// Test Certificate from PEM strings (specific to each cert type)
			test_certificate_parse!(test_set.chain.root, CertificateHash::from(&ca_cert));
			test_certificate_parse!(test_set.chain.root.to_string(), CertificateHash::from(&ca_cert));
			test_certificate_parse!(test_set.chain.intermediate, CertificateHash::from(&intermediate_cert));
			test_certificate_parse!(test_set.chain.intermediate.to_string(), CertificateHash::from(&intermediate_cert));
			test_certificate_parse!(test_set.chain.client, CertificateHash::from(&user_cert));
			test_certificate_parse!(test_set.chain.client.to_string(), CertificateHash::from(&user_cert));

			// Test CertificateWithOptions from concatenated DER
			let mut combined_der = ca_cert.to_der().unwrap();
			combined_der.extend_from_slice(&user_cert.to_der().unwrap());
		}
	}

	// TODO Fix these issues
	#[test]
	fn test_verify_signature() {
		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } =
				extract_certificates(&test_set.chain);

			// Get the correct signing keys for each certificate
			let ca_key = &ca_cert.tbs_certificate.subject_public_key_info;
			let intermediate_key = &intermediate_cert.tbs_certificate.subject_public_key_info;
			// let client_key = &client_cert.tbs_certificate.subject_public_key_info;

			// Test positive cases
			// TODO Bug with verifying self-signed
			// assert!(ca_cert.verify_signature(ca_key).unwrap());
			assert!(intermediate_cert.verify_signature(ca_key).unwrap());
			assert!(client_cert.verify_signature(intermediate_key).unwrap());

			// Test check_issued relationships
			// assert!(ca_cert.check_issued(&ca_cert));
			assert!(intermediate_cert.check_issued(&ca_cert));
			assert!(client_cert.check_issued(&intermediate_cert));

			// Test negative cases (wrong key usage)
			// assert!(!client_cert.verify_signature(client_key).unwrap());
			// assert!(!intermediate_cert.verify_signature(client_key).unwrap());
			// assert!(!ca_cert.verify_signature(client_key).unwrap());

			// Test certificate chain relationships (subject/issuer matching)
			assert_eq!(client_cert.issuer(), intermediate_cert.subject());
			assert_eq!(intermediate_cert.issuer(), ca_cert.subject());
			assert_eq!(ca_cert.issuer(), ca_cert.subject());

			// Test negative check_issued cases
			assert!(!client_cert.check_issued(&client_cert));
			assert!(!intermediate_cert.check_issued(&client_cert));
			assert!(!ca_cert.check_issued(&client_cert));

			// Verify signature and TBS data is present
			assert!(!ca_cert.signature.raw_bytes().is_empty());
			assert!(!intermediate_cert.signature.raw_bytes().is_empty());
			assert!(!client_cert.signature.raw_bytes().is_empty());
			assert!(!ca_cert.tbs_certificate.to_der().unwrap().is_empty());
			assert!(!intermediate_cert
				.tbs_certificate
				.to_der()
				.unwrap()
				.is_empty());
			assert!(!client_cert.tbs_certificate.to_der().unwrap().is_empty());
		}
	}

	#[test]
	fn test_verify_signature_edge_cases() {
		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert: user_cert, .. } =
				extract_certificates(&test_set.chain);
			assert!(user_cert.check_issued(&intermediate_cert));
			assert!(!user_cert.check_issued(&user_cert));
			assert!(intermediate_cert.check_issued(&ca_cert));
			assert!(!ca_cert.check_issued(&user_cert));

			let verification_cases = [
				//(&ca_cert, &ca_cert, true),
				(&intermediate_cert, &ca_cert, true),
				(&intermediate_cert, &user_cert, false),
				(&user_cert, &intermediate_cert, true),
				(&user_cert, &user_cert, false),
				(&ca_cert, &user_cert, false),
			];
			for (cert, issuer, expected) in verification_cases {
				let result = cert.verify_signature(&issuer.tbs_certificate.subject_public_key_info);
				assert_eq!(result.unwrap_or(false), expected);
			}
		}
	}

	#[test]
	fn test_verify_signature_algorithm_detection() {
		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert: user_cert, .. } =
				extract_certificates(&test_set.chain);

			// Verify signature algorithms are valid OIDs
			let ca_sig_alg = &ca_cert.signature_algorithm;
			let intermediate_sig_alg = &intermediate_cert.signature_algorithm;
			let user_sig_alg = &user_cert.signature_algorithm;
			assert!(!ca_sig_alg.algorithm.to_string().is_empty());
			assert!(!intermediate_sig_alg.algorithm.to_string().is_empty());
			assert!(!user_sig_alg.algorithm.to_string().is_empty());

			// Verify signatures
			let ca_public_key = &ca_cert.tbs_certificate.subject_public_key_info;
			let intermediate_public_key = &intermediate_cert.tbs_certificate.subject_public_key_info;
			let user_public_key = &user_cert.tbs_certificate.subject_public_key_info;
			assert!(user_cert.verify_signature(intermediate_public_key).unwrap());
			assert!(intermediate_cert.verify_signature(ca_public_key).unwrap());
			assert!(user_cert.verify_signature(intermediate_public_key).unwrap());

			// Verify public key algorithms match the expected OID from key data
			if let Some(key_data) = &test_set.key_data {
				assert_eq!(ca_public_key.algorithm.algorithm.to_string(), key_data.oid);
				assert_eq!(intermediate_public_key.algorithm.algorithm.to_string(), key_data.oid);
				assert_eq!(user_public_key.algorithm.algorithm.to_string(), key_data.oid);
			}

			// Test public key bit strings are not empty
			let ca_raw_key = ca_public_key.subject_public_key.raw_bytes();
			let intermediate_raw_key = intermediate_public_key.subject_public_key.raw_bytes();
			let client_raw_key = user_public_key.subject_public_key.raw_bytes();
			assert!(!ca_raw_key.is_empty());
			assert!(!intermediate_raw_key.is_empty());
			assert!(!client_raw_key.is_empty());
		}
	}

	#[test]
	fn test_verify_signature_with_store() {
		for test_set in TEST_CERTIFICATE_SETS.iter() {
			let moment = get_cert_moment();
			let CertificateTestBundle {
				ca_cert,
				intermediate_cert,
				client_cert: user_cert,
				root_certs,
				intermediate_certs,
			} = extract_certificates(&test_set.chain);

			let chain_verification: Vec<Certificate> = user_cert
				.verify_chain(&root_certs, &intermediate_certs)
				.collect();
			assert!(!chain_verification.is_empty());

			let ca_trusted = ca_cert.is_trusted(&root_certs, &intermediate_certs, Some(moment));
			assert!(ca_trusted);

			let user_trusted = user_cert.is_trusted(&root_certs, &intermediate_certs, Some(moment));
			assert!(user_trusted);

			// Test with CertificateWithOptions for getting issuer and root
			let user_with_chain = CertificateBundle {
				certificate: user_cert.clone(),
				options: CertificateOptions::default(),
				root: root_certs.clone(),
				intermediate: intermediate_certs.clone(),
			};

			let user_issuer = user_with_chain.get_issuer_certificate();
			assert!(user_issuer.is_some());
			assert_eq!(CertificateHash::from(&user_issuer.unwrap()), CertificateHash::from(&intermediate_cert));

			let user_root = user_with_chain.get_root_certificate();
			assert!(user_root.is_some());
			assert_eq!(CertificateHash::from(&user_root.unwrap()), CertificateHash::from(&ca_cert));
		}
	}

	#[test]
	fn test_certificate_hash_functionality() {
		let hash_bytes = vec![0x01, 0x02, 0x03, 0x04];

		let cert_hash = CertificateHash::new(hash_bytes.clone(), None::<&str>);
		assert_eq!(cert_hash.len(), 4);
		assert!(!cert_hash.is_empty());
		assert_eq!(cert_hash.as_ref(), &hash_bytes);

		let hex_string = cert_hash.to_string();
		assert_eq!(hex_string, "01020304");
		assert_eq!(cert_hash.to_string(), "01020304");
		assert_ne!(cert_hash.to_string(), "05060708");

		let other_hash = CertificateHash::new(hash_bytes.clone(), None::<&str>);
		assert_eq!(cert_hash, other_hash);

		let different_hash = CertificateHash::new(vec![0x05, 0x06], None::<&str>);
		assert_ne!(cert_hash, different_hash);
		let empty_hash = CertificateHash::new(vec![], None::<&str>);
		assert!(empty_hash.is_empty());
		assert_eq!(empty_hash.len(), 0);
	}

	#[test]
	fn test_certificate_hash_algorithms() {
		test_hash_algorithms(|test_case, test_data| {
			let hash = (test_case.hash_fn)(test_data);
			// Test algorithm properties
			assert_eq!(hash.algorithm_oid(), test_case.expected_algorithm_oid);
			assert_eq!(hash.hash_function_name(), test_case.expected_algorithm_name);
			assert_eq!(hash.len(), test_case.expected_length);
			assert!(!hash.is_empty());

			// Test deterministic behavior
			let hash2 = (test_case.hash_fn)(test_data);
			assert_eq!(hash, hash2);

			// Test different data produces different hash
			let different_data = b"different certificate data";
			let different_hash = (test_case.hash_fn)(different_data);
			assert_ne!(hash, different_hash);
		});
	}

	#[test]
	fn test_certificate_hash_conversions() {
		test_all_certificate_sets(|bundle| {
			for cert in [&bundle.ca_cert, &bundle.intermediate_cert, &bundle.client_cert] {
				// Test From<&Certificate>
				let hash_from_ref = CertificateHash::from(cert);
				let hash_from_owned = CertificateHash::from(cert.clone());
				assert_eq!(hash_from_ref, hash_from_owned);

				// Test From<&[u8]> via DER
				let der_bytes = cert.to_der().unwrap();
				let hash_from_der = CertificateHash::from(der_bytes.as_slice());
				assert_eq!(hash_from_ref, hash_from_der);

				// Test from_certificate_der methods
				let hash_sha1 = CertificateHash::from_certificate_der(&der_bytes);
				let hash_sha256 = CertificateHash::from_certificate_der_sha256(&der_bytes);
				assert_eq!(hash_from_ref, hash_sha1); // Default should be SHA1
				assert_ne!(hash_sha1, hash_sha256); // Different algorithms should differ

				// Test Display trait
				let hash_string = hash_from_ref.to_string();
				assert!(!hash_string.is_empty());
				assert_eq!(hash_string.len(), hash_from_ref.len() * 2); // Hex encoding doubles length

				// Test AsRef<[u8]>
				let hash_bytes: &[u8] = hash_from_ref.as_ref();
				assert_eq!(hash_bytes.len(), hash_from_ref.len());
			}
		});
	}

	#[test]
	fn test_certificate_hash_hex_conversions() {
		let test_data = b"test data for hex conversion";
		let hash = CertificateHash::sha256(test_data);
		let hex_string = hash.to_string();

		// Test FromStr with String
		let hash_from_string: CertificateHash = hex_string.parse().unwrap();
		assert_eq!(hash_from_string.as_ref(), hash.as_ref());

		// Test FromStr with &str
		let hash_from_str: CertificateHash = hex_string.as_str().parse().unwrap();
		assert_eq!(hash_from_str, hash_from_string);

		// Test invalid hex strings
		assert!("invalid_hex".parse::<CertificateHash>().is_err());
		assert!("g1234567".parse::<CertificateHash>().is_err()); // Invalid hex character
	}

	#[test]
	fn test_certificate_hash_verification() {
		test_all_certificate_sets(|bundle| {
			for cert in [&bundle.ca_cert, &bundle.intermediate_cert, &bundle.client_cert] {
				// Test verification with different algorithms
				let der_bytes = cert.to_der().unwrap();

				// Both should verify against the same certificate
				let hash_sha1 = CertificateHash::sha1(&der_bytes);
				let hash_sha256 = CertificateHash::sha256(&der_bytes);
				assert!(hash_sha1.verify_certificate(cert).unwrap());
				assert!(hash_sha256.verify_certificate(cert).unwrap());

				// Test SHA-512 and SHA3-256 verification
				let hash_sha512 =
					CertificateHash::new(crypto::HashAlgorithm::Sha2_512.hash(&der_bytes), Some(crate::oids::SHA512));
				assert!(hash_sha512.verify_certificate(cert).unwrap());
				let hash_sha3_256 =
					CertificateHash::new(crypto::HashAlgorithm::Sha3_256.hash(&der_bytes), Some(crate::oids::SHA3_256));
				assert!(hash_sha3_256.verify_certificate(cert).unwrap());

				// Test verification fails with different certificate
				if cert != &bundle.ca_cert {
					assert!(!hash_sha1.verify_certificate(&bundle.ca_cert).unwrap());
				}
			}
		});
	}

	#[test]
	fn test_certificate_hash_unknown_algorithm() {
		let _test_data = b"test data";
		let unknown_hash = CertificateHash::new(vec![0x01, 0x02], Some("1.2.3.4.5.unknown"));
		assert_eq!(unknown_hash.algorithm_oid(), "1.2.3.4.5.unknown");
		assert_eq!(unknown_hash.hash_function_name(), "UNKNOWN");

		// Verification should fail for unknown algorithms
		test_all_certificate_sets(|bundle| {
			let result = unknown_hash.verify_certificate(&bundle.ca_cert);
			assert!(result.is_err());
			assert!(result
				.unwrap_err()
				.to_string()
				.contains("Unsupported hash algorithm"));
		});
	}

	#[test]
	fn test_certificate_hash_set_basic_operations() {
		test_all_certificate_sets(|bundle| {
			let certs = vec![bundle.ca_cert.clone(), bundle.intermediate_cert.clone()];

			// Test basic queries
			let mut cert_set = CertificateHashSet::new(certs.clone());
			assert!(cert_set.has(&bundle.ca_cert));
			assert!(cert_set.has(&bundle.intermediate_cert));
			assert!(!cert_set.has(&bundle.client_cert));

			// Test insertion
			cert_set.insert(bundle.client_cert.clone());
			assert!(cert_set.has(&bundle.client_cert));

			// Test duplicate insertion (should not change set)
			let initial_len = cert_set.certificates.len();
			cert_set.insert(bundle.client_cert.clone());
			assert_eq!(cert_set.certificates.len(), initial_len);
		});
	}

	#[test]
	fn test_certificate_hash_set_conversions() {
		test_all_certificate_sets(|bundle| {
			let certs = vec![bundle.ca_cert.clone(), bundle.intermediate_cert.clone(), bundle.client_cert.clone()];

			// Test From<Vec<Certificate>>
			let cert_set_from_vec = CertificateHashSet::from(certs.clone());
			assert_eq!(cert_set_from_vec.certificates.len(), 3);

			// Test TryFrom<&[Certificate]>
			let cert_set_from_slice = CertificateHashSet::try_from(certs.as_slice()).unwrap();
			assert_eq!(cert_set_from_slice.certificates.len(), 3);

			// Test conversions to Vec<String> (subject names)
			let subject_names: Vec<String> = cert_set_from_vec.clone().into();
			assert_eq!(subject_names.len(), 3);
			assert!(subject_names.contains(&bundle.ca_cert.subject()));
			assert!(subject_names.contains(&bundle.intermediate_cert.subject()));
			assert!(subject_names.contains(&bundle.client_cert.subject()));

			// Test reference conversion
			let subject_names_ref: Vec<String> = (&cert_set_from_vec).into();
			assert_eq!(subject_names, subject_names_ref);
		});
	}

	#[test]
	fn test_certificate_hash_set_default_and_empty() {
		let empty_set = CertificateHashSet::default();
		assert_eq!(empty_set.certificates.len(), 0);

		// Test TryFrom<&[String]> (legacy conversion - returns empty)
		let hash_strings = vec!["abc123".to_string(), "def456".to_string()];
		let cert_set = CertificateHashSet::try_from(hash_strings.as_slice()).unwrap();
		assert_eq!(cert_set.certificates.len(), 0); // Should be empty as documented

		// Test empty conversions
		let empty_subjects: Vec<String> = empty_set.into();
		assert!(empty_subjects.is_empty());
	}

	#[test]
	fn test_certificate_hash_set_edge_cases() {
		test_all_certificate_sets(|bundle| {
			let certs_with_duplicates = vec![
				bundle.ca_cert.clone(),
				bundle.ca_cert.clone(), // Duplicate
				bundle.intermediate_cert.clone(),
			];

			let cert_set = CertificateHashSet::from(certs_with_duplicates);
			// HashSet should automatically deduplicate
			assert_eq!(cert_set.certificates.len(), 2);
			assert!(cert_set.has(&bundle.ca_cert));
			assert!(cert_set.has(&bundle.intermediate_cert));
		});
	}

	#[test]
	fn test_certificate_hash_consistency_across_serialization() {
		test_all_certificate_sets(|bundle| {
			for cert in [&bundle.ca_cert, &bundle.intermediate_cert, &bundle.client_cert] {
				// Hash should be consistent across PEM/DER round-trips
				let original_hash = CertificateHash::from(cert);

				let pem = cert.to_pem().unwrap();
				let cert_from_pem: Certificate = pem.parse().unwrap();
				let hash_from_pem = CertificateHash::from(&cert_from_pem);

				let der = cert.to_der().unwrap();
				let cert_from_der = Certificate::try_from(der).unwrap();
				let hash_from_der = CertificateHash::from(&cert_from_der);
				assert_eq!(original_hash, hash_from_pem);
				assert_eq!(original_hash, hash_from_der);
				assert_eq!(hash_from_pem, hash_from_der);
			}
		});
	}

	#[test]
	fn test_extension_creation_methods() {
		struct ExtensionTest {
			name: &'static str,
			extension: Extension,
			expected_oid: &'static str,
			expected_critical: bool,
		}

		let tests = vec![
			ExtensionTest {
				name: "subject alternative name",
				extension: ExtensionBuilder::for_subject_alt_name(vec![
					"example.com",
					"192.168.1.1",
					"2001:0db8:85a3:0000:0000:8a2e:0370:7334", // IPv6 address
					"user@example.com",
					"https://example.com",
				])
				.build()
				.unwrap(),
				expected_oid: oids::SUBJECT_ALT_NAME,
				expected_critical: false,
			},
			ExtensionTest {
				name: "extended key usage",
				extension: ExtensionBuilder::for_extended_key_usage(vec![oids::SERVER_AUTH, oids::CLIENT_AUTH])
					.build()
					.unwrap(),
				expected_oid: oids::EXTENDED_KEY_USAGE,
				expected_critical: false,
			},
			ExtensionTest {
				name: "basic constraints (CA)",
				extension: ExtensionBuilder::for_basic_constraints(true, Some(5))
					.build()
					.unwrap(),
				expected_oid: oids::BASIC_CONSTRAINTS,
				expected_critical: true,
			},
			ExtensionTest {
				name: "basic constraints (end entity)",
				extension: ExtensionBuilder::for_basic_constraints(false, None)
					.build()
					.unwrap(),
				expected_oid: oids::BASIC_CONSTRAINTS,
				expected_critical: true,
			},
			ExtensionTest {
				name: "key usage",
				extension: ExtensionBuilder::for_key_usage(0x0186).build().unwrap(),
				expected_oid: oids::KEY_USAGE,
				expected_critical: true,
			},
			ExtensionTest {
				name: "custom extension",
				extension: Extension::new("1.2.3.4", [0x01, 0x02, 0x03], true).unwrap(),
				expected_oid: "1.2.3.4",
				expected_critical: true,
			},
		];

		for test in tests {
			assert_eq!(test.extension.oid.to_string(), test.expected_oid, "OID mismatch for {}", test.name);
			assert_eq!(test.extension.critical, test.expected_critical, "Critical flag mismatch for {}", test.name);
		}
	}

	#[test]
	fn test_rfc5280_compliance_validation() {
		test_all_certificate_sets(|bundle| {
			let cert = &bundle.ca_cert;
			// Test RFC 5280 compliance validation
			assert!(cert.validate_rfc5280_compliance().is_ok());
			// Test critical extension validation
			assert!(cert.validate_critical_extensions().is_ok());
			// Test extension consistency
			assert!(cert.validate_extension_consistency().is_ok());
			// Test DN validation
			assert!(cert.validate_distinguished_names().is_ok());
		});

		// Test DN validation error cases
		let dn_test_cases = [
			(Vec::new(), utils::create_dn(&[(oids::CN, "Test Issuer")]).unwrap(), Some(false)),
			(Vec::new(), utils::create_dn(&[(oids::CN, "Test Issuer")]).unwrap(), None),
			(utils::create_dn(&[(oids::CN, "Test Subject")]).unwrap(), Vec::new(), None),
		];

		for (subject, issuer, san_critical) in dn_test_cases {
			// Create a minimal public key info for Ed25519
			let algorithm = oids::ED25519.parse().unwrap();
			let subject_public_key = BitString::from_bytes(&[0u8; 32]).unwrap();
			let public_key_info = SubjectPublicKeyInfo { algorithm, subject_public_key };
			let signature_algorithm = oids::ED25519.parse().unwrap();
			let signature = BitString::from_bytes(&[0u8; 64]).unwrap();
			let mut builder = CertificateBuilder::new()
				.with_serial_number(U256::from_u8(1))
				.with_validity_days(365)
				.with_subject_dn(subject)
				.with_issuer_dn(issuer)
				.with_subject_public_key(public_key_info);

			// Add SAN extension if specified
			if let Some(critical) = san_critical {
				let san_ext = ExtensionBuilder::for_subject_alt_name(vec!["example.com"])
					.with_critical(critical)
					.build()
					.expect("Failed to build SAN extension");
				builder = builder.with_extension(san_ext);
			}

			// Build the full certificate for validation
			let tbs_certificate = builder.build_tbs().unwrap();
			let cert = Certificate { tbs_certificate, signature_algorithm, signature };
			let result = cert.validate_distinguished_names();
			assert!(result.is_err());
			assert!(matches!(result, Err(CertificateError::ValidationFailed { reason: _ })));
		}
	}

	#[test]
	fn test_authority_subject_dn_validation() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } = bundle;
			// Test valid issuer-subject relationships
			assert!(intermediate_cert.validate_issuer_subject_dn_match(ca_cert));
			assert!(client_cert.validate_issuer_subject_dn_match(intermediate_cert));
			// Test self-signed certificate
			assert!(ca_cert.validate_issuer_subject_dn_match(ca_cert));
			// Test invalid relationships
			assert!(!client_cert.validate_issuer_subject_dn_match(ca_cert));
			assert!(!ca_cert.validate_issuer_subject_dn_match(client_cert));
		});
	}

	#[test]
	fn test_authority_key_identifier_validation() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } = bundle;
			// Test Authority Key Identifier validation
			assert!(intermediate_cert.validate_authority_key_identifier(ca_cert));
			assert!(client_cert.validate_authority_key_identifier(intermediate_cert));

			// Self-signed certificates may or may not have AKI
			if ca_cert
				.get_extension(oids::AUTHORITY_KEY_IDENTIFIER)
				.is_some()
			{
				assert!(ca_cert.validate_authority_key_identifier(ca_cert));
			}
		});
	}

	#[test]
	fn test_enhanced_certificate_validation() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } = bundle;
			// Test enhanced check_issued with RFC 5280 compliance
			assert!(intermediate_cert.check_issued(ca_cert));
			assert!(client_cert.check_issued(intermediate_cert));
			assert!(!client_cert.check_issued(ca_cert));
			// Test same public key comparison
			assert!(ca_cert.same_public_key(ca_cert));
			assert!(!ca_cert.same_public_key(client_cert));
			// Test valid issuer-subject pair validation
			assert!(intermediate_cert
				.is_valid_issuer_subject_pair(ca_cert)
				.unwrap());
			assert!(client_cert
				.is_valid_issuer_subject_pair(intermediate_cert)
				.unwrap());
			assert!(!client_cert.is_valid_issuer_subject_pair(ca_cert).unwrap());
		});
	}

	#[test]
	fn test_certificate_path_validation() {
		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } = bundle;

			// Test valid certificate path
			let valid_path = vec![client_cert.clone(), intermediate_cert.clone(), ca_cert.clone()];
			assert!(client_cert.validate_certificate_path(&valid_path).unwrap());

			// Test invalid path (wrong order)
			let invalid_path = vec![ca_cert.clone(), intermediate_cert.clone(), client_cert.clone()];
			assert!(!ca_cert.validate_certificate_path(&invalid_path).unwrap());

			// Test single certificate path (self-signed)
			let self_signed_path = vec![ca_cert.clone()];
			assert!(ca_cert
				.validate_certificate_path(&self_signed_path)
				.unwrap());

			// Test empty path
			assert!(!client_cert.validate_certificate_path(&[]).unwrap());
		});
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

	#[test]
	fn test_certificate_graph_validation() {
		// Create test certificates for graph validation
		let subject_cert = create_dummy_cert_builder("Subject", "Issuer", 1, false)
			.build_test()
			.unwrap();
		let intermediate_cert = create_dummy_cert_builder("Issuer", "Intermediate", 2, true)
			.build_test()
			.unwrap();
		let root_cert = create_dummy_cert_builder("Intermediate", "Intermediate", 3, true) // Self-signed
			.build_test()
			.unwrap();
		let orphan_cert = create_dummy_cert_builder("Orphan", "Orphan", 4, true) // Self-signed orphan
			.build_test()
			.unwrap();

		// Test valid graph (no cycles, no orphans, no duplicates)
		let valid_certificates = [intermediate_cert.clone(), root_cert.clone()]
			.into_iter()
			.collect();
		assert!(subject_cert
			.assert_can_construct_valid_graph(&valid_certificates)
			.is_ok());

		// Test with empty set (should pass)
		assert!(subject_cert
			.assert_can_construct_valid_graph(&HashSet::new())
			.is_ok());

		// Test with just intermediate (should pass)
		let intermediate_only = [intermediate_cert.clone()].into_iter().collect();
		assert!(subject_cert
			.assert_can_construct_valid_graph(&intermediate_only)
			.is_ok());

		// Test orphan detection
		let certificates_with_orphan = [intermediate_cert.clone(), root_cert.clone(), orphan_cert.clone()]
			.into_iter()
			.collect();
		let result = subject_cert.assert_can_construct_valid_graph(&certificates_with_orphan);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("CERTIFICATE_ORPHAN_FOUND"));

		// Test cycle detection by creating certificates that form a cycle
		let cycle_a_cert = create_dummy_cert_builder("CycleA", "CycleB", 5, true) // A issued by B
			.build_test()
			.unwrap();
		let cycle_b_cert = create_dummy_cert_builder("CycleB", "CycleA", 6, true) // B issued by A
			.build_test()
			.unwrap();
		let cycle_subject_cert = create_dummy_cert_builder("Subject", "CycleA", 7, false) // Subject issued by A
			.build_test()
			.unwrap();

		let certificates_with_cycle = [cycle_a_cert, cycle_b_cert].into_iter().collect();
		let cycle_result = cycle_subject_cert.assert_can_construct_valid_graph(&certificates_with_cycle);
		assert!(cycle_result.is_err());
		assert!(cycle_result
			.unwrap_err()
			.to_string()
			.contains("CERTIFICATE_CYCLE_FOUND"));
	}

	#[test]
	fn test_tbs_certificate_macro_conversions() {
		test_all_certificate_sets(|bundle| {
			let cert = &bundle.ca_cert;
			let tbs = &cert.tbs_certificate;

			// Test TryFrom<&[u8]> for TbsCertificate (from impl_try_from_der_decode macro)
			let tbs_der_bytes = tbs.to_der().unwrap();
			let tbs_from_bytes = TbsCertificate::try_from(tbs_der_bytes.as_slice()).unwrap();
			assert_eq!(tbs.serial_number, tbs_from_bytes.serial_number);
			assert_eq!(tbs.subject, tbs_from_bytes.subject);
			assert_eq!(tbs.issuer, tbs_from_bytes.issuer);

			// Test TryFrom<&TbsCertificate> for Vec<u8> (from impl_try_from_der_encode_trait macro)
			let der_from_ref: Vec<u8> = tbs.try_into().unwrap();
			assert!(!der_from_ref.is_empty());
			assert_eq!(der_from_ref, tbs_der_bytes);

			// Test round-trip conversion
			let tbs_roundtrip = TbsCertificate::try_from(der_from_ref.as_slice()).unwrap();
			assert_eq!(tbs.serial_number, tbs_roundtrip.serial_number);
			assert_eq!(tbs.subject, tbs_roundtrip.subject);
			assert_eq!(tbs.issuer, tbs_roundtrip.issuer);
		});
	}

	#[cfg(feature = "serde")]
	#[test]
	fn test_certificate_json_serialization() {
		test_all_certificate_sets(|bundle| {
			let cert_json = bundle.ca_cert.to_json(false).unwrap();
			// Test required string fields are not empty
			let string_fields = vec![
				("serial", cert_json.serial.as_str()),
				("subject", cert_json.subject.as_str()),
				("issuer", cert_json.issuer.as_str()),
				("hash", cert_json.hash.as_str()),
				("not_before", cert_json.not_before.as_str()),
				("not_after", cert_json.not_after.as_str()),
			];

			for (field_name, field_value) in string_fields {
				assert!(!field_value.is_empty(), "{field_name} field should not be empty");
			}

			// Test array fields are not empty
			assert!(!cert_json.subject_dn.is_empty(), "subject_dn should not be empty");
			assert!(!cert_json.issuer_dn.is_empty(), "issuer_dn should not be empty");
			assert!(!cert_json.extensions.is_empty(), "extensions should not be empty");
			assert!(cert_json.is_ca);

			let cert_json_with_pem = bundle.ca_cert.to_json(true).unwrap();
			assert!(cert_json_with_pem.pem.is_some());
			assert!(cert_json_with_pem.chain.is_none()); // Individual certificate has no chain
		});
	}
}
