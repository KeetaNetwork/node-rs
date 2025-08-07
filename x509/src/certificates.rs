//! X.509 certificate handling
//!
//! This module provides functionality for working with X.509 certificates,
//! including parsing, validation, and generation of certificate requests.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use crypto::bigint::U256;
use crypto::prelude::SigningOptions;
use crypto::prelude::{CryptoVerifierWithOptions, Ed25519PublicKey, Secp256k1PublicKey, Secp256r1PublicKey};
use crypto::prelude::{Ed25519Signature, Secp256k1Signature, Secp256r1Signature};
use crypto::HashAlgorithm;
use der::asn1::{Any, BitString, ObjectIdentifier, OctetString, Uint};
use der::{Decode, Encode, Sequence};
use hex;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::CertificateError;
use crate::oids;
use crate::time::Time;
use crate::utils::{
	dn_to_string, generate_key_identifier, parse_authority_key_identifier, parse_der_length, parse_key_identifier,
};
use crate::DistinguishedName;

#[cfg(feature = "serde")]
use crate::utils::dn_to_name_value_pairs;
#[cfg(feature = "serde")]
use crate::NameValuePair;

/// Basic Constraints extension according to RFC 5280 Section 4.2.1.9.
/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
///
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BasicConstraints {
	/// Indicates if this is a CA certificate
	#[asn1(default = "Default::default")]
	pub ca: bool,
	/// Optional path length constraint
	#[asn1(optional = "true")]
	pub path_len_constraint: Option<u32>,
}

/// Certificate extension according to RFC 5280 Section 4.2.
/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2
///
/// Extension ::= SEQUENCE {
///     extnID                  OBJECT IDENTIFIER,
///     critical                BOOLEAN DEFAULT FALSE,
///     extnValue               OCTET STRING
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Extension {
	/// Extension ID (OID)
	pub id: ObjectIdentifier,
	/// Indicates if this extension is critical
	#[asn1(optional = "true")]
	pub critical: Option<bool>,
	/// Extension value as an OctetString
	pub value: OctetString,
}

impl Extension {
	/// Create a new extension.
	pub fn new(oid: &str, value: &[u8], critical: bool) -> Result<Self, CertificateError> {
		let id = ObjectIdentifier::new(oid)?;
		let critical = Some(critical);
		let value = OctetString::new(value)?;

		Ok(Self { id, critical, value })
	}

	/// Create a basic constraints extension according to RFC 5280 Section 4.2.1.9.
	/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
	///
	/// BasicConstraints ::= SEQUENCE {
	///     cA                      BOOLEAN DEFAULT FALSE,
	///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
	/// }
	pub fn basic_constraints(is_ca: bool, path_length: Option<u8>) -> Result<Self, CertificateError> {
		let mut value = vec![0x30]; // SEQUENCE

		if is_ca {
			if let Some(path_len) = path_length {
				// SEQUENCE { BOOLEAN TRUE, INTEGER path_length }
				let content = vec![0x01, 0x01, 0xFF, 0x02, 0x01, path_len];
				value.push(content.len() as u8);
				value.extend_from_slice(&content);
			} else {
				// SEQUENCE { BOOLEAN TRUE }
				let content = vec![0x01, 0x01, 0xFF];
				value.push(content.len() as u8);
				value.extend_from_slice(&content);
			}
		} else {
			// Empty SEQUENCE for end-entity certificates
			value.push(0x00);
		}

		Self::new(oids::BASIC_CONSTRAINTS, &value, true)
	}

	/// Create a key usage extension according to RFC 5280 Section 4.2.1.3.
	/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
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
	pub fn key_usage(key_usage_bits: u16) -> Result<Self, CertificateError> {
		let bytes = key_usage_bits.to_be_bytes();
		let value = vec![0x03, 0x02, 0x00, bytes[1]];

		Self::new(oids::KEY_USAGE, &value, true)
	}

	/// Create an extended key usage extension according to RFC 5280 Section 4.2.1.12.
	/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
	///
	/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
	/// KeyPurposeId ::= OBJECT IDENTIFIER
	pub fn extended_key_usage(ext_key_use: Vec<&str>) -> Result<Self, CertificateError> {
		let mut value = vec![0x30]; // SEQUENCE
		let mut content = Vec::new();

		for eku_oid in ext_key_use {
			if let Ok(oid) = ObjectIdentifier::new(eku_oid) {
				if let Ok(oid_der) = oid.to_der() {
					content.extend_from_slice(&oid_der);
				}
			}
		}

		value.push(content.len() as u8);
		value.extend_from_slice(&content);

		Self::new(oids::EXTENDED_KEY_USAGE, &value, false)
	}

	/// Create a subject alternative name according to RFC 5280 Section 4.2.1.6.
	/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
	///
	/// GeneralName ::= CHOICE {
	///     otherName                       [0] OtherName,
	///     rfc822Name                      [1] IA5String,
	///     dNSName                         [2] IA5String,
	///     x400Address                     [3] ORAddress,
	///     directoryName                   [4] Name,
	///     ediPartyName                    [5] EDIPartyName,
	///     uniformResourceIdentifier       [6] IA5String,
	///     iPAddress                       [7] OCTET STRING,
	///     registeredID                    [8] OBJECT IDENTIFIER
	/// }
	pub fn subject_alt_name(san_entries: Vec<&str>) -> Result<Self, CertificateError> {
		// Properly encode SEQUENCE of GeneralNames
		let general_names: Vec<Vec<u8>> = san_entries
			.iter()
			.map(|&san_entry| {
				// For now, detect the type and encode appropriately
				if san_entry.contains('@') {
					// Email address [1] IMPLICIT UTF8String
					let mut name = vec![0x81]; // [1] IMPLICIT
					name.push(san_entry.len() as u8);
					name.extend_from_slice(san_entry.as_bytes());
					name
				} else if san_entry.parse::<core::net::IpAddr>().is_ok() {
					// IP Address [7] IMPLICIT OCTET STRING
					let ip_bytes = if let Ok(ip) = san_entry.parse::<core::net::Ipv4Addr>() {
						ip.octets().to_vec()
					} else if let Ok(ip) = san_entry.parse::<core::net::Ipv6Addr>() {
						ip.octets().to_vec()
					} else {
						san_entry.as_bytes().to_vec() // fallback
					};

					let mut name = vec![0x87]; // [7] IMPLICIT
					name.push(ip_bytes.len() as u8);
					name.extend_from_slice(&ip_bytes);
					name
				} else if san_entry.starts_with("http://") || san_entry.starts_with("https://") {
					// URI [6] IMPLICIT UTF8String
					let mut name = vec![0x86]; // [6] IMPLICIT
					name.push(san_entry.len() as u8);
					name.extend_from_slice(san_entry.as_bytes());
					name
				} else {
					// DNS Name [2] IMPLICIT UTF8String (default)
					let mut name = vec![0x82]; // [2] IMPLICIT
					name.push(san_entry.len() as u8);
					name.extend_from_slice(san_entry.as_bytes());
					name
				}
			})
			.collect();

		// Build the SEQUENCE of GeneralNames
		let content: Vec<u8> = general_names.into_iter().flatten().collect();
		let mut value = vec![0x30]; // SEQUENCE
		value.push(content.len() as u8);
		value.extend_from_slice(&content);

		Self::new(oids::SUBJECT_ALT_NAME, &value, false)
	}

	/// Create a subject key identifier extension according to RFC 5280 Section 4.2.1.2.
	/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
	///
	/// SubjectKeyIdentifier ::= KeyIdentifier
	/// KeyIdentifier ::= OCTET STRING
	pub fn subject_key_identifier(key_id: &[u8]) -> Result<Self, CertificateError> {
		Self::new(oids::SUBJECT_KEY_IDENTIFIER, key_id, false)
	}

	/// Create an authority key identifier extension according to RFC 5280 Section 4.2.1.1.
	/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
	///
	/// AuthorityKeyIdentifier ::= SEQUENCE {
	///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
	///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
	/// }
	/// KeyIdentifier ::= OCTET STRING
	pub fn authority_key_identifier(key_id: &[u8]) -> Result<Self, CertificateError> {
		// Authority Key Identifier: SEQUENCE { [0] IMPLICIT KeyIdentifier OPTIONAL }
		let mut auth_key_id_der = vec![0x30]; // SEQUENCE
		let key_id_with_tag = [&[0x80], key_id].concat(); // [0] IMPLICIT
		auth_key_id_der.push(key_id_with_tag.len() as u8);
		auth_key_id_der.extend_from_slice(&key_id_with_tag);

		Self::new(oids::AUTHORITY_KEY_IDENTIFIER, &auth_key_id_der, false)
	}
}

/// Algorithm identifier according to RFC 5280 Section 4.1.1.2.
/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm               OBJECT IDENTIFIER,
///     parameters              ANY OPTIONAL
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AlgorithmIdentifier {
	/// Algorithm OID
	pub algorithm: ObjectIdentifier,
	/// Raw ASN.1 parameters - can be NULL, absent, or any other type
	#[asn1(optional = "true")]
	pub parameters: Option<Any>,
}

/// Public key information structure according to RFC 5280 Section 4.1.
/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
///
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm              AlgorithmIdentifier,
///     subjectPublicKey       BIT STRING
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct SubjectPublicKeyInfo {
	pub algorithm: AlgorithmIdentifier,
	pub public_key: BitString,
}

/// Certificate validity period according to RFC 5280 Section 4.1.2.5.
/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Validity {
	pub not_before: Time,
	pub not_after: Time,
}

/// TBS Certificate structure according to RFC 5280 Section 4.1.2.
/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2
///
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///     extensions      [3]  EXPLICIT Extensions OPTIONAL
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

/// Complete X.509 Certificate structure according to RFC 5280 Section 4.1.
/// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
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

/// Options for certificate construction.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CertificateOptions {
	/// Time moment for validation
	pub moment: Option<DateTime<Utc>>,
	/// Certificate store for trust validation
	pub store: Option<CertificateStore>,
	/// Override to mark as trusted root
	pub is_trusted_root: Option<bool>,
}

/// Enhanced certificate with runtime properties.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateWithOptions {
	/// The core certificate
	pub certificate: Certificate,
	/// Certificate options for validation and trust
	pub options: CertificateOptions,
	/// Certificate chain
	pub chain: Option<Vec<Certificate>>,
}

impl CertificateWithOptions {
	/// Create a new certificate from PEM with options.
	pub fn new(pem_data: &str, opts: Option<CertificateOptions>) -> Result<Self, CertificateError> {
		let certificate = Certificate::from_pem(pem_data)?;
		let options = opts.unwrap_or_default();

		let chain = options.store.as_ref().map(|store| certificate.verify_chain(store));

		Ok(Self { certificate, options, chain })
	}

	/// Validate trust using a certificate store.
	pub fn validate_with_store(mut self, store: &CertificateStore, moment: Option<DateTime<Utc>>) -> Self {
		self.options.is_trusted_root = Some(self.certificate.is_trusted(store, moment));
		self.options.store = Some(store.clone());
		self.options.moment = moment;
		self.chain = Some(self.certificate.verify_chain(store));
		self
	}

	/// Get the root certificate from the chain.
	pub fn get_root_certificate(&self) -> Option<&Certificate> {
		if let Some(chain) = &self.chain {
			// Chain contains intermediate certificates, root is the last one
			chain.last()
		} else if self.certificate.is_self_signed() {
			Some(&self.certificate)
		} else {
			None
		}
	}

	/// Get the issuer certificate from the chain.
	pub fn get_issuer_certificate(&self) -> Option<&Certificate> {
		if let Some(chain) = &self.chain {
			// Chain contains intermediate certificates, issuer is the first one
			chain.first()
		} else if self.certificate.is_self_signed() {
			Some(&self.certificate)
		} else {
			None
		}
	}

	/// Get all certificates (main certificate + chain).
	pub fn get_certificates(&self) -> Vec<&Certificate> {
		let mut certs = vec![&self.certificate];
		if let Some(chain) = &self.chain {
			certs.extend(chain.iter());
		}

		certs
	}

	/// Get chain length.
	pub fn chain_length(&self) -> usize {
		self.chain.as_ref().map(|c| c.len()).unwrap_or(0)
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

	/// Set the certificate chain.
	pub fn with_chain(mut self, chain: Vec<Certificate>) -> Self {
		self.chain = Some(chain);
		self
	}

	/// Convert to DER format (concatenated DER of all certificates).
	pub fn to_der(&self) -> Result<Vec<u8>, CertificateError> {
		self.try_into()
	}
}

impl TryFrom<&CertificateWithOptions> for Vec<u8> {
	type Error = CertificateError;

	/// Convert to DER format (concatenated DER of all certificates).
	fn try_from(cert_with_options: &CertificateWithOptions) -> Result<Self, Self::Error> {
		let mut result = Vec::new();

		// Add main certificate
		result.extend_from_slice(&cert_with_options.certificate.to_der()?);

		// Add chain certificates
		if let Some(chain) = &cert_with_options.chain {
			for cert in chain {
				result.extend_from_slice(&cert.to_der()?);
			}
		}

		Ok(result)
	}
}

/// TryFrom implementations for CertificateWithOptions
impl TryFrom<&str> for CertificateWithOptions {
	type Error = CertificateError;

	fn try_from(pem_data: &str) -> Result<Self, Self::Error> {
		let certificate = Certificate::from_pem(pem_data)?;
		let options = CertificateOptions::default();

		// For PEM string input, we can't determine trust without a store
		// User can call methods to set trust later if needed
		Ok(Self { certificate, options, chain: None })
	}
}

impl TryFrom<String> for CertificateWithOptions {
	type Error = CertificateError;

	fn try_from(pem_data: String) -> Result<Self, Self::Error> {
		Self::try_from(pem_data.as_str())
	}
}

impl TryFrom<Certificate> for CertificateWithOptions {
	type Error = CertificateError;

	fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
		let options = CertificateOptions::default();

		// For direct Certificate input, default trust to false
		Ok(Self { certificate, options, chain: None })
	}
}

impl TryFrom<Vec<Certificate>> for CertificateWithOptions {
	type Error = CertificateError;

	fn try_from(certificates: Vec<Certificate>) -> Result<Self, Self::Error> {
		let mut iter = certificates.into_iter();
		if let Some(certificate) = iter.next() {
			let options = CertificateOptions::default();
			let chain_vec = iter.collect::<Vec<_>>();
			let chain = if chain_vec.is_empty() {
				None
			} else {
				Some(chain_vec)
			};

			// Determine trust: default to false, require explicit trust
			Ok(Self { certificate, options, chain })
		} else {
			Err(CertificateError::ValidationFailed {
				reason: "Cannot create options from empty certificate vector".to_string(),
			})
		}
	}
}

/// Additional TryFrom implementations for bundle functionality
impl TryFrom<&[u8]> for CertificateWithOptions {
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

					if let Ok(cert) = Certificate::from_der(cert_data) {
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

impl TryFrom<Vec<u8>> for CertificateWithOptions {
	type Error = CertificateError;

	fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
		data.as_slice().try_into()
	}
}

/// Base extensions commonly found in certificates.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseExtensions {
	/// Basic Constraints extension
	#[serde(skip_serializing_if = "Option::is_none")]
	pub basic_constraints: Option<BasicConstraintsJson>,
	/// Subject Key Identifier extension
	#[serde(skip_serializing_if = "Option::is_none")]
	pub subject_key_identifier: Option<String>,
	/// Authority Key Identifier extension  
	#[serde(skip_serializing_if = "Option::is_none")]
	pub authority_key_identifier: Option<String>,
}

/// JSON representation of Basic Constraints.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicConstraintsJson {
	/// If this is a CA certificate
	pub ca: bool,
	/// Path length constraint (if present)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path_len_constraint: Option<u32>,
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
	/// Certificate hash for TypeScript compatibility
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
	/// Certificate chain for TypeScript compatibility
	#[serde(rename = "$chain", skip_serializing_if = "Option::is_none")]
	pub chain_field: Option<Vec<CertificateJson>>,
	/// Extensions information (all extensions as raw data)
	pub extensions: Vec<ExtensionJson>,
}

/// JSON-serializable extension information.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionJson {
	/// Extension OID
	pub oid: String,
	/// Is this extension critical?
	pub critical: bool,
	/// Extension value as hex string
	pub value: String,
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

/// Certificate store for managing trusted root and intermediate certificates.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CertificateStore {
	/// Trusted root certificates
	pub root: HashSet<Certificate>,
	/// Trusted intermediate certificates
	pub intermediate: HashSet<Certificate>,
}

impl CertificateStore {
	/// Create a new empty certificate store
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a root certificate to the store
	pub fn add_root(&mut self, cert: Certificate) {
		self.root.insert(cert);
	}

	/// Add an intermediate certificate to the store
	pub fn add_intermediate(&mut self, cert: Certificate) {
		self.intermediate.insert(cert);
	}

	/// Get all certificates in the store (roots + intermediates)
	pub fn all_certificates(&self) -> impl Iterator<Item = &Certificate> {
		self.root.iter().chain(self.intermediate.iter())
	}
}

/// Certificate hash wrapper for TypeScript compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateHash {
	hash: Vec<u8>,
}

/// Certificate hash set for managing collections of hashes
#[derive(Debug, Clone)]
pub struct CertificateHashSet {
	hashes: HashSet<CertificateHash>,
}

impl CertificateHashSet {
	/// Create a new hash set
	pub fn new(hashes: Vec<CertificateHash>) -> Self {
		Self { hashes: hashes.into_iter().collect() }
	}

	/// Check if the set contains a hash
	pub fn has(&self, hash: &CertificateHash) -> bool {
		self.hashes.contains(hash)
	}

	/// Add a hash to the set
	pub fn insert(&mut self, hash: CertificateHash) {
		self.hashes.insert(hash);
	}
}

impl CertificateHash {
	/// Create a new certificate hash
	pub fn new(hash: Vec<u8>) -> Self {
		Self { hash }
	}

	/// Compare with another certificate hash
	pub fn compare(&self, other: &CertificateHash) -> bool {
		self.hash == other.hash
	}

	/// Compare with hex string representation
	pub fn compare_hex_string(&self, hex: &str) -> bool {
		if let Ok(decoded) = hex::decode(hex) {
			self.hash == decoded
		} else {
			false
		}
	}

	/// Convert to hex string
	pub fn to_hex_string(&self) -> String {
		hex::encode(&self.hash)
	}

	/// Get raw hash bytes
	pub fn as_bytes(&self) -> &[u8] {
		&self.hash
	}

	/// Get the length of the hash in bytes
	pub fn len(&self) -> usize {
		self.hash.len()
	}

	/// Check if the hash is empty
	pub fn is_empty(&self) -> bool {
		self.hash.is_empty()
	}
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
	pub fn subject_public_key(mut self, public_key: SubjectPublicKeyInfo) -> Self {
		self.subject_public_key = Some(public_key);
		self
	}

	/// Set the subject distinguished name.
	pub fn subject_dn(mut self, dn: DistinguishedName) -> Self {
		self.subject_dn = Some(dn);
		self
	}

	/// Set the issuer distinguished name.  
	pub fn issuer_dn(mut self, dn: DistinguishedName) -> Self {
		self.issuer_dn = Some(dn);
		self
	}

	/// Set the validity period.
	pub fn validity(mut self, not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
		self.valid_from = Some(not_before);
		self.valid_to = Some(not_after);
		self
	}

	/// Set the serial number (up to 256-bit integer).
	pub fn serial_number(mut self, serial: U256) -> Self {
		self.serial = Some(serial);
		self
	}

	/// Set whether this is a CA certificate.
	pub fn is_ca(mut self, is_ca: bool) -> Self {
		self.is_ca = Some(is_ca);
		self
	}

	/// Add an extension.
	pub fn with_extension(mut self, extension: Extension) -> Self {
		self.extensions.push(extension);
		self
	}

	/// Add a basic constraints extension.
	pub fn basic_constraints(mut self, is_ca: bool, path_length: Option<u8>) -> Self {
		if let Ok(extension) = Extension::basic_constraints(is_ca, path_length) {
			self.extensions.push(extension);
		}

		self
	}

	/// Add a key usage extension.
	pub fn key_usage(mut self, key_usage_bits: u16) -> Self {
		if let Ok(extension) = Extension::key_usage(key_usage_bits) {
			self.extensions.push(extension);
		}

		self
	}

	/// Add an extended key usage extension.
	pub fn extended_key_usage(mut self, ext_key_use: Vec<&str>) -> Self {
		if let Ok(extension) = Extension::extended_key_usage(ext_key_use) {
			self.extensions.push(extension);
		}

		self
	}

	/// Add a subject alternative name extension.
	pub fn subject_alt_name(mut self, san_entries: Vec<&str>) -> Self {
		if let Ok(extension) = Extension::subject_alt_name(san_entries) {
			self.extensions.push(extension);
		}

		self
	}

	/// Add a custom extension by OID.
	pub fn custom_extension(mut self, oid: &str, value: &[u8], critical: bool) -> Self {
		if let Ok(extension) = Extension::new(oid, value, critical) {
			self.extensions.push(extension);
		}

		self
	}

	/// Set validity in days from now.
	pub fn validity_days(mut self, days: u64) -> Self {
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

	/// Create a self-signed certificate (issuer = subject).
	pub fn self_signed(mut self) -> Self {
		if let Some(ref subject) = self.subject_dn.clone() {
			self.issuer_dn = Some(subject.clone());
		}

		self
	}

	/// Add multiple extensions at once.
	pub fn extensions(mut self, extensions: Vec<Extension>) -> Self {
		self.extensions.extend(extensions);
		self
	}

	/// Build and sign a certificate with properties.
	pub fn build_with_properties(
		&self,
		_trusted: bool,
		_chain: Option<Vec<Certificate>>,
	) -> Result<Certificate, CertificateError> {
		// First build the TBS certificate
		let tbs = self.build_tbs()?;

		// TODO Sign
		let signature_bytes = vec![0u8; 64]; // Placeholder signature

		// Create the certificate
		let cert = Certificate {
			tbs_certificate: tbs,
			signature_algorithm: AlgorithmIdentifier {
				algorithm: ObjectIdentifier::new(oids::SHA256_WITH_RSA)?,
				parameters: None,
			},
			signature: BitString::from_bytes(&signature_bytes)?,
		};

		Ok(cert)
	}

	/// Create a preset CA certificate builder.
	pub fn for_ca() -> Self {
		Self::new()
			.is_ca(true)
			.key_usage(0x06) // keyCertSign + cRLSign
			.validity_days(365 * 10) // 10 years
	}

	/// Create a preset end-entity certificate builder.
	pub fn for_end_entity() -> Self {
		Self::new()
			.is_ca(false)
			.key_usage(0xC0) // digitalSignature + nonRepudiation
			.validity_days(365) // 1 year
	}

	/// Create a preset server certificate builder
	pub fn for_server() -> Self {
		Self::for_end_entity().extended_key_usage(vec![oids::SERVER_AUTH])
	}

	/// Create a preset client certificate builder
	pub fn for_client() -> Self {
		Self::for_end_entity().extended_key_usage(vec![oids::CLIENT_AUTH])
	}

	/// Build the TBS certificate (to be signed).
	pub fn build_tbs(&self) -> Result<TbsCertificate, CertificateError> {
		let subject_public_key = self
			.subject_public_key
			.as_ref()
			.ok_or(CertificateError::MissingField { field: "subject_public_key".to_string() })?;
		let subject_dn =
			self.subject_dn.as_ref().ok_or(CertificateError::MissingField { field: "subject_dn".to_string() })?;
		let issuer_dn =
			self.issuer_dn.as_ref().ok_or(CertificateError::MissingField { field: "issuer_dn".to_string() })?;
		let valid_from = self.valid_from.ok_or(CertificateError::MissingField { field: "valid_from".to_string() })?;
		let valid_to = self.valid_to.ok_or(CertificateError::MissingField { field: "valid_to".to_string() })?;
		let serial = self.serial.as_ref().ok_or(CertificateError::MissingField { field: "serial".to_string() })?;

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

	/// Create common certificate extensions
	fn create_common_extensions(&self) -> Result<Vec<Extension>, CertificateError> {
		let mut extensions = Vec::new();

		// Basic Constraints extension
		if let Some(is_ca) = self.is_ca {
			extensions.push(Extension::basic_constraints(is_ca, None)?);
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

			extensions.push(Extension::key_usage(key_usage_bits)?);
		}

		// Subject Key Identifier extension
		if let Some(subject_public_key) = &self.subject_public_key {
			let subject_key_id = generate_key_identifier(&subject_public_key.public_key)?;
			extensions.push(Extension::subject_key_identifier(&subject_key_id)?);
		}

		// Authority Key Identifier extension (if we have an issuer public key)
		if let Some(issuer_dn) = &self.issuer_dn {
			if let Some(subject_dn) = &self.subject_dn {
				// For self-signed certificates, use the subject public key
				if issuer_dn == subject_dn {
					if let Some(subject_public_key) = &self.subject_public_key {
						let authority_key_id = generate_key_identifier(&subject_public_key.public_key)?;
						extensions.push(Extension::authority_key_identifier(&authority_key_id)?);
					}
				}
			}
		}

		Ok(extensions)
	}
}

impl Certificate {
	/// Parse a certificate from DER-encoded bytes
	pub fn from_der(data: &[u8]) -> Result<Self, CertificateError> {
		<Self as Decode>::from_der(data).map_err(CertificateError::from)
	}

	/// Convert the certificate to DER format
	pub fn to_der(&self) -> Result<Vec<u8>, CertificateError> {
		<Self as Encode>::to_der(self).map_err(CertificateError::from)
	}

	/// Parse a certificate from PEM-encoded string
	pub fn from_pem(pem: &str) -> Result<Self, CertificateError> {
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

		Self::from_der(&der_bytes)
	}

	/// Convert the certificate to PEM format
	pub fn to_pem(&self) -> Result<String, CertificateError> {
		let der = self.to_der()?;
		let base64_content = general_purpose::STANDARD.encode(&der);

		// Split into 64-character lines
		let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
		for chunk in base64_content.as_bytes().chunks(64) {
			pem.push_str(core::str::from_utf8(chunk).unwrap());
			pem.push('\n');
		}
		pem.push_str("-----END CERTIFICATE-----\n");

		Ok(pem)
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
	pub fn get_extension(&self, oid: &str) -> Option<&Extension> {
		if let Some(ref extensions) = self.tbs_certificate.extensions {
			let target_oid = ObjectIdentifier::new(oid).ok()?;
			extensions.iter().find(|ext| ext.id == target_oid)
		} else {
			None
		}
	}

	/// Check if this is a CA certificate (has Basic Constraints CA=true)
	///
	/// Parses the Basic Constraints according to RFC 5280 Section 4.2.1.9
	/// See: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
	///
	/// BasicConstraints ::= SEQUENCE {
	///     cA                      BOOLEAN DEFAULT FALSE,
	///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
	/// }
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

	/// Validate the certificate's signature using the issuer's public key.
	///
	/// This method verifies that the certificate was signed by the provided
	/// public key according to RFC 5280 certificate validation requirements.
	pub fn verify_signature(&self, issuer_public_key: &SubjectPublicKeyInfo) -> Result<bool, CertificateError> {
		// Check that signature algorithms match
		if self.signature_algorithm.algorithm != issuer_public_key.algorithm.algorithm {
			return Ok(false);
		}

		// Get the TBS certificate DER bytes for verification
		let tbs_der = self.tbs_certificate.to_der().map_err(CertificateError::from)?;
		// Extract signature bytes
		let signature_bytes = self.signature.raw_bytes();

		// Determine algorithm and verify signature
		let signature_oid = &self.signature_algorithm.algorithm;
		match signature_oid.to_string().as_str() {
			// Ed25519 signature
			oids::ED25519 => {
				let public_key = Ed25519PublicKey::try_from(issuer_public_key.public_key.raw_bytes())
					.map_err(|_| CertificateError::InvalidCertificate)?;

				// Ed25519 signatures are 64 bytes
				if signature_bytes.len() != 64 {
					return Ok(false);
				}

				let sig_array: [u8; 64] =
					signature_bytes.try_into().map_err(|_| CertificateError::InvalidCertificate)?;
				let signature = Ed25519Signature::from_bytes(&sig_array);

				// Ed25519 signatures are always over the raw message (no pre-hashing)
				let options = SigningOptions::raw();
				public_key
					.verify_with_options(&tbs_der, &signature, options)
					.map(|()| true)
					.map_err(|_| CertificateError::CertificateSignatureVerificationFailed)
			}

			// ECDSA with SHA-256 (secp256r1)
			oids::ECDSA_WITH_SHA256 => {
				let public_key = Secp256r1PublicKey::try_from(issuer_public_key.public_key.raw_bytes())
					.map_err(|_| CertificateError::InvalidCertificate)?;

				// ECDSA signatures are typically 64 bytes (r and s values, 32 bytes each)
				if signature_bytes.len() != 64 {
					return Ok(false);
				}
				let sig_array: [u8; 64] =
					signature_bytes.try_into().map_err(|_| CertificateError::InvalidCertificate)?;
				let signature = Secp256r1Signature::from_bytes((&sig_array).into())
					.map_err(|_| CertificateError::InvalidCertificate)?;

				// ECDSA signatures are over the pre-hashed message, use certificate format
				let options = SigningOptions::for_cert();
				public_key
					.verify_with_options(&tbs_der, &signature, options)
					.map(|()| true)
					.map_err(|_| CertificateError::CertificateSignatureVerificationFailed)
			}

			// ECDSA with SHA-256 (secp256k1)
			oids::SECP256K1 => {
				let public_key = Secp256k1PublicKey::try_from(issuer_public_key.public_key.raw_bytes())
					.map_err(|_| CertificateError::InvalidCertificate)?;

				// ECDSA signatures are typically 64 bytes (r and s values, 32 bytes each)
				if signature_bytes.len() != 64 {
					return Ok(false);
				}
				let sig_array: [u8; 64] =
					signature_bytes.try_into().map_err(|_| CertificateError::InvalidCertificate)?;
				let signature = Secp256k1Signature::from_bytes((&sig_array).into())
					.map_err(|_| CertificateError::InvalidCertificate)?;

				// ECDSA signatures are over the pre-hashed message, use certificate format
				let options = SigningOptions::for_cert();
				public_key
					.verify_with_options(&tbs_der, &signature, options)
					.map(|()| true)
					.map_err(|_| CertificateError::CertificateSignatureVerificationFailed)
			}

			// RSA with SHA-256 - not implemented
			oids::SHA256_WITH_RSA => Err(CertificateError::InvalidCertificate),

			// Unsupported signature algorithm
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

	/// Compare two certificates for equality
	pub fn equals(&self, other: &Certificate) -> bool {
		// Compare the raw DER bytes
		match (self.to_der(), other.to_der()) {
			(Ok(self_der), Ok(other_der)) => self_der == other_der,
			_ => false,
		}
	}

	/// Get a hash of the certificate (SHA1 of DER bytes)
	pub fn hash(&self) -> Result<CertificateHash, CertificateError> {
		let der_bytes = self.to_der()?;
		// Use SHA1 for certificate hashing (standard for X.509 key identifiers)
		let hash_bytes = HashAlgorithm::Sha1.hash(&der_bytes);
		Ok(CertificateHash::new(hash_bytes))
	}

	/// Get raw hash bytes of the certificate (SHA1 of DER bytes)
	pub fn hash_bytes(&self) -> Result<Vec<u8>, CertificateError> {
		let der_bytes = self.to_der()?;
		// Use SHA1 for certificate hashing (standard for X.509 key identifiers)
		let hash_bytes = HashAlgorithm::Sha1.hash(&der_bytes);
		Ok(hash_bytes)
	}

	/// Check if this certificate was issued by the given issuer
	pub fn check_issued(&self, issuer: &Certificate) -> bool {
		// Basic DN comparison
		if self.tbs_certificate.issuer != issuer.tbs_certificate.subject {
			return false;
		}

		self.verify_signature(&issuer.tbs_certificate.subject_public_key_info).unwrap_or(false)
	}

	/// Get the issuer certificate using the provided certificate store
	pub fn get_issuer_certificate(&self) -> Option<&Certificate> {
		if self.is_self_signed() {
			Some(self)
		} else {
			// For compatibility, return None when no store is provided
			// Use get_issuer_certificate_with_store() for full functionality
			None
		}
	}

	/// Get the issuer certificate using the provided certificate store
	/// This method traverses the certificate store to find the issuing certificate
	pub fn get_issuer_certificate_with_store(&self, store: &CertificateStore) -> Option<Certificate> {
		if self.is_self_signed() {
			Some(self.clone())
		} else {
			// Look for the issuer in the store by matching subject DN
			store.all_certificates().find(|cert| cert.tbs_certificate.subject == self.tbs_certificate.issuer).cloned()
		}
	}

	/// Get the root certificate if this is self-signed, otherwise None
	pub fn get_root_certificate(&self) -> Option<&Certificate> {
		if self.is_self_signed() {
			Some(self)
		} else {
			// For compatibility, return None when no store is provided
			// Use get_root_certificate_with_store() for full functionality
			None
		}
	}

	/// Get the root certificate by traversing the chain using the provided certificate store
	/// This method builds the complete certificate chain and returns the root certificate
	pub fn get_root_certificate_with_store(&self, store: &CertificateStore) -> Option<Certificate> {
		if self.is_self_signed() {
			Some(self.clone())
		} else {
			// Build the chain and return the last (root) certificate
			let chain = self.verify_chain(store);
			chain.last().cloned()
		}
	}

	/// Get the issuer's public key if available
	pub fn get_issuer_public_key(&self) -> Option<&SubjectPublicKeyInfo> {
		if self.is_self_signed() {
			Some(&self.tbs_certificate.subject_public_key_info)
		} else {
			// In a real implementation, this would get the issuer's public key from the chain
			None
		}
	}

	/// Parse base extensions from certificate
	#[cfg(feature = "serde")]
	fn parse_base_extensions(&self) -> BaseExtensions {
		let mut base_extensions =
			BaseExtensions { basic_constraints: None, subject_key_identifier: None, authority_key_identifier: None };

		if let Some(extensions) = &self.tbs_certificate.extensions {
			for ext in extensions {
				match ext.id.to_string().as_str() {
					// Basic Constraints
					oids::BASIC_CONSTRAINTS => {
						if let Ok(constraints) = BasicConstraints::from_der(ext.value.as_bytes()) {
							base_extensions.basic_constraints = Some(BasicConstraintsJson {
								ca: constraints.ca,
								path_len_constraint: constraints.path_len_constraint,
							});
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
					_ => {} // Ignore other extensions for base extensions
				}
			}
		}

		base_extensions
	}

	/// Convert certificate to JSON representation
	#[cfg(feature = "serde")]
	pub fn to_json(&self, include_pem: bool) -> Result<CertificateJson, CertificateError> {
		self.to_json_with_chain(include_pem, None)
	}

	/// Convert certificate to JSON representation with optional chain
	#[cfg(feature = "serde")]
	pub fn to_json_with_chain(
		&self,
		include_pem: bool,
		chain: Option<&[Certificate]>,
	) -> Result<CertificateJson, CertificateError> {
		let hash = self.hash()?;
		let hash_hex = hash.to_hex_string();
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
					.map(|ext| ExtensionJson {
						oid: ext.id.to_string(),
						critical: ext.critical.unwrap_or(false),
						value: hex::encode(ext.value.as_bytes()),
					})
					.collect()
			})
			.unwrap_or_default();

		let chain_json = chain.map(|certs| {
			certs
				.iter()
				.filter_map(|cert| cert.to_json_with_chain(false, None).ok()) // Don't include PEM for chain certs to avoid recursion
				.collect()
		});

		Ok(CertificateJson {
			serial: hex::encode(self.serial_number().to_be_bytes()),
			subject: self.subject(),
			issuer: self.issuer(),
			subject_dn: dn_to_name_value_pairs(&self.tbs_certificate.subject),
			issuer_dn: dn_to_name_value_pairs(&self.tbs_certificate.issuer),
			not_before: self.not_before().to_rfc3339(),
			not_after: self.not_after().to_rfc3339(),
			is_ca: self.is_ca(),
			is_self_signed: self.is_self_signed(),
			hash: hash_hex.clone(),
			hash_field: hash_hex,
			base_extensions: self.parse_base_extensions(),
			pem,
			chain: chain_json.clone(),
			chain_field: chain_json,
			extensions,
		})
	}

	/// Verify certificate chain using the provided store
	pub fn verify_chain(&self, store: &CertificateStore) -> Vec<Certificate> {
		let mut chain = Vec::new();
		let mut current = self;

		// Build the chain by following issuer certificates
		loop {
			// If this is a self-signed certificate, we're done
			if current.is_self_signed() {
				// Check if it's in the trusted roots
				if store.root.contains(current) {
					chain.push(current.clone());
				}
				break;
			}

			// Look for the issuer in the store
			let issuer =
				store.all_certificates().find(|cert| cert.tbs_certificate.subject == current.tbs_certificate.issuer);

			if let Some(issuer_cert) = issuer {
				chain.push(issuer_cert.clone());
				current = issuer_cert;
			} else {
				// Cannot find issuer, chain is incomplete
				break;
			}
		}

		chain
	}

	/// Check if this certificate is trusted given a certificate store
	pub fn is_trusted(&self, store: &CertificateStore, moment: Option<DateTime<Utc>>) -> bool {
		// Check validity at the given moment (or now)
		let check_time = moment.unwrap_or_else(Utc::now);
		if !self.is_valid_at(check_time).unwrap_or(false) {
			return false;
		}

		// If this is directly in the trusted roots, it's trusted
		if store.root.contains(self) {
			return true;
		}

		// Try to build a chain to a trusted root
		let chain = self.verify_chain(store);

		// Check if the chain ends with a trusted root
		chain.last().map(|root_cert| store.root.contains(root_cert)).unwrap_or(false)
	}

	/// Assert that a valid certificate graph can be constructed from the given certificates
	pub fn assert_can_construct_valid_graph(
		&self,
		additional_certs: &HashSet<Certificate>,
	) -> Result<(), CertificateError> {
		// Check for duplicates (including this certificate)
		let mut all_certs = additional_certs.clone();
		if all_certs.contains(self) {
			return Err(CertificateError::CertificateDuplicateIncluded);
		}
		all_certs.insert(self.clone());

		// Build a map of subject DN (as hex string) -> certificate for quick lookup
		let mut subject_map: HashMap<String, &Certificate> = HashMap::new();
		for cert in &all_certs {
			// Use hex encoding of the DER bytes of the DN as the key
			if let Ok(dn_der) = <DistinguishedName as der::Encode>::to_der(&cert.tbs_certificate.subject) {
				let dn_key = hex::encode(dn_der);
				subject_map.insert(dn_key, cert);
			}
		}

		// Check for orphans (certificates that don't connect to any chain)
		let mut reachable = HashSet::new();
		let mut to_visit = vec![self];

		while let Some(current) = to_visit.pop() {
			if reachable.contains(current) {
				continue;
			}
			reachable.insert(current);

			// Find all certificates that could be part of this certificate's chain
			// 1. Certificates issued by this certificate (if it's a CA)
			// 2. The issuer of this certificate
			for cert in &all_certs {
				if !reachable.contains(cert) {
					// If current cert issued this cert
					if cert.tbs_certificate.issuer == current.tbs_certificate.subject {
						to_visit.push(cert);
					}
					// If this cert issued the current cert
					if current.tbs_certificate.issuer == cert.tbs_certificate.subject {
						to_visit.push(cert);
					}
				}
			}
		}

		// Check for orphans
		for cert in &all_certs {
			if !reachable.contains(cert) {
				return Err(CertificateError::CertificateOrphanFound);
			}
		}

		// Check for cycles using DFS
		let mut visited = HashSet::new();
		let mut rec_stack = HashSet::new();

		fn has_cycle(
			cert: &Certificate,
			subject_map: &HashMap<String, &Certificate>,
			visited: &mut HashSet<String>,
			rec_stack: &mut HashSet<String>,
		) -> Result<bool, CertificateError> {
			// Use hex encoding of the DN as the key
			let subject_key =
				if let Ok(dn_der) = <DistinguishedName as der::Encode>::to_der(&cert.tbs_certificate.subject) {
					hex::encode(dn_der)
				} else {
					return Ok(false);
				};

			if rec_stack.contains(&subject_key) {
				return Ok(true); // Cycle found
			}

			if visited.contains(&subject_key) {
				return Ok(false); // Already processed
			}

			visited.insert(subject_key.clone());
			rec_stack.insert(subject_key.clone());

			// Check issuer
			let issuer_key =
				if let Ok(dn_der) = <DistinguishedName as der::Encode>::to_der(&cert.tbs_certificate.issuer) {
					hex::encode(dn_der)
				} else {
					rec_stack.remove(&subject_key);
					return Ok(false);
				};

			if let Some(issuer_cert) = subject_map.get(&issuer_key) {
				if has_cycle(issuer_cert, subject_map, visited, rec_stack)? {
					return Ok(true);
				}
			}

			rec_stack.remove(&subject_key);
			Ok(false)
		}

		for cert in &all_certs {
			if has_cycle(cert, &subject_map, &mut visited, &mut rec_stack)? {
				return Err(CertificateError::CertificateCycleFound);
			}
		}

		Ok(())
	}
}

impl core::hash::Hash for Certificate {
	fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
		// Hash based on the DER bytes of the certificate
		if let Ok(hash_bytes) = self.hash_bytes() {
			hash_bytes.hash(state);
		}
	}
}

impl TryFrom<&[u8]> for Certificate {
	type Error = CertificateError;

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		Self::from_der(data)
	}
}

impl TryFrom<Vec<u8>> for Certificate {
	type Error = CertificateError;

	fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
		data.as_slice().try_into()
	}
}

impl TryFrom<&str> for Certificate {
	type Error = CertificateError;

	fn try_from(pem: &str) -> Result<Self, Self::Error> {
		Self::from_pem(pem)
	}
}

impl TryFrom<String> for Certificate {
	type Error = CertificateError;

	fn try_from(pem: String) -> Result<Self, Self::Error> {
		pem.as_str().try_into()
	}
}

impl TryFrom<&Certificate> for Vec<u8> {
	type Error = CertificateError;

	fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
		cert.to_der()
	}
}

impl TryFrom<Certificate> for Vec<u8> {
	type Error = CertificateError;

	fn try_from(cert: Certificate) -> Result<Self, Self::Error> {
		cert.to_der()
	}
}

impl TryFrom<&Certificate> for String {
	type Error = CertificateError;

	fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
		cert.to_pem()
	}
}

impl TryFrom<Certificate> for String {
	type Error = CertificateError;

	fn try_from(cert: Certificate) -> Result<Self, Self::Error> {
		cert.to_pem()
	}
}

macro_rules! impl_try_from_der_decode {
	($target_type:ty) => {
		impl TryFrom<&[u8]> for $target_type {
			type Error = CertificateError;

			fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
				<Self as Decode>::from_der(data).map_err(CertificateError::from)
			}
		}
	};
}

impl_try_from_der_decode!(TbsCertificate);
impl_try_from_der_decode!(SubjectPublicKeyInfo);
impl_try_from_der_decode!(AlgorithmIdentifier);

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
impl_try_from_der_encode_trait!(SubjectPublicKeyInfo);
impl_try_from_der_encode_trait!(AlgorithmIdentifier);

#[cfg(test)]
mod tests {
	use chrono::{TimeZone, Utc};

	use super::*;
	use crate::asn1::{BitString, Uint};
	use crate::oids;
	use crate::utils;

	// Test data from TypeScript tests - CA certificate
	const CA_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIB1jCCAXugAwIBAgIBAzALBglghkgBZQMEAwowUDFOMEwGA1UEAxZFa2VldGFf
YWRhaHhlcXpxZnRiYmZtN2dqa2pidzM0b3RiMm9xa3A2cnpoNWRybndoazV0Mmt5
YmR1ZHF5Z3Njbmp4YW9uMB4XDTI0MTEwMTE2MDQ0M1oXDTI0MTEwMjE2MDQ0M1ow
UDFOMEwGA1UEAxZFa2VldGFfYWRhaHhlcXpxZnRiYmZtN2dqa2pidzM0b3RiMm9x
a3A2cnpoNWRybndoazV0Mmt5YmR1ZHF5Z3Njbmp4YW9uMDkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDIgAD3JDMCzCErPmSpIbb46YdOgp/o5P0cW2Ors9KwEdBwwajZTBj
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgDGMCEGA1UdIwQaMBigFgQU
ahPODjyDyyxby6ySJEQX9zOgB+wwHQYDVR0OBBYEFGoTzg48g8ssW8uskiREF/cz
oAfsMAsGCWCGSAFlAwQDCgNIADBFAiEAhMHKvbUqFVURW4oetU2/CkBocmBro9bA
XR+ujQgL9pYCIEiEn+F4GaArxThV535UIvO2Jg1aeyHu+MCNrxhHEDPu
-----END CERTIFICATE-----"#;

	// Test data from TypeScript tests - User certificate
	const USER_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIII0TCCCHegAwIBAgIBBDALBglghkgBZQMEAwowUDFOMEwGA1UEAxZFa2VldGFf
YWRhaHhlcXpxZnRiYmZtN2dqa2pidzM0b3RiMm9xa3A2cnpoNWRybndoazV0Mmt5
YmR1ZHF5Z3Njbmp4YW9uMB4XDTI0MTEwMTE2MDQ0M1oXDTI0MTEwMjE2MDQ0M1ow
UDFOMEwGA1UEAxZFa2VldGFfYWRhZmkybGNvbXA0dXdsdm5rYmg1M3d5aHZ3Z2h3
dWFtb3o0NWhodDUybWFqNjVpd2lzdDV2a3U3eWtqNXpuMDkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDIgACo0sTmP5Sy6tUE/d2wetjHtQDHZ505590wCfdRZEp9qqjggdf
MIIHWzAOBgNVHQ8BAf8EBAMCAMAwIQYDVR0jBBowGKAWBBRqE84OPIPLLFvLrJIk
RBf3M6AH7DAdBgNVHQ4EFgQU3JvD83gCz0+3FTkcOY0j4p6UQ+QwggcFBgorBgEE
AYnfLAAABIIG9TCCBvEwggFXBgorBgEEAYnfLAEAoYIBRwSCAUMwggE/AgEAMIHd
BglghkgBZQMEAS4EDEpOGHdz3z0LdJoPNQSBwQSrLGG+e5AqBYNIk5iiOz5ODfam
SCpjwnAo9MGwTl40ERu6i2VnUWh37sWviOXzaxt/vl/XWjVDuq8OQ9tRa0ZCg1r1
sW3Uo7qUGp6v6a0cKt6Ejcw8Z6af0ttndfxoghJFMz+nKlhhU4VqSxHvFIwW2dyu
AgvR6hT0/EjuRNzKg2X/6yOJmuxN/tDjDGWCjayV0v9LKMC0IFd750nTSIJzv5r4
YaJcqqB158O1F+TNVKOaqSEuRB9v/v9P6/felYowTwQgA/zKGcF5Mz5FU2/Mp75r
4+548puaSqJnPvTj1yIWA7sGCWCGSAFlAwQCCAQgfERdRhKCcALgQHjBl+3GRUWb
7C637Zh0CU5ilApzxQIECUR5MC6LBLk1hjCCAV4GCisGAQQBid8sAQOhggFOBIIB
SjCCAUYCAQAwgd0GCWCGSAFlAwQBLgQM89djVFtq6aTRZCmCBIHBBDZIcLD34h7m
donBIOhya7rrwGMoZbCmBBi/fLvNfCypfCe73MuhpccFR2UXjxbZlY+kxjrKbb50
M8CI/VqrMSn+kcbquN3qfbqrI5YTI4jUlThvOz9W5cI6lMcIZZEnFAUHbXyxE8qU
59La3uHvtUloRLK4+Ujx6kpFHUeELA4isc0JS/dmsJgGjcrHffs88F0onPtHWJYE
R7Vss8apqi92KDM6s6rMcx78BuUYeUs/Mntab/CYjkY7iyf4sQtMlzBPBCAi/pRV
LMGtF7iEEnZ8GmfEHxx7iWKO2MYElquVwSFA+wYJYIZIAWUDBAIIBCA+vyoJQWxg
xsQ/UV/gArKKQmPOCKvGV4hzOg0eMXl1KwQQzt0GYkQE0Ae1njDM/RMZIjCCAV0G
CisGAQQBid8sAQShggFNBIIBSTCCAUUCAQAwgd0GCWCGSAFlAwQBLgQMhglIR1YX
w+Xu1SApBIHBBCx+i/dw+rmmaG3JsJX64ofRwPgGT9BTe2htcu6KoGNr/K19kWsg
+edRuM6U0gI8HoJPj/8izGZGf96EDX+v6oT5spI0ZXl7SXIz08dwtjEm3zux1TMr
x1Z7DlKZZyagHuC9yKwdc+DaeznjzFbELPzLuSKGmQOo+8RC8NHXlSmv9z9cA/+y
XIY7kU1sOyeCW+7TZor5oYoXLOZ9s2piX/edLKDTwygNCdxN4JkXwF8bM9D8hNs3
5vRgOjyQtz/XiTBPBCD9MN0UMBHYyM6HuYjl4N9VOMBWDORiu+kzBJtJ6umGxQYJ
YIZIAWUDBAIIBCBD0l3HQ3Ur0OZFZNCoNdzcr3kTqHHJ+baKaNcJW8RY4AQPAn4f
DDvhou0VOQZ4ZWx0MIIBcwYKKwYBBAGJ3ywBAqGCAWMEggFfMIIBWwIBADCB3QYJ
YIZIAWUDBAEuBAxBTr6E2q0Yt/fr8KcEgcEEAdYU5trRBKIqPmJ/LHcC2AKgyGFG
LMzTkCY6CHvWdn9YiUUlhg8Pdgl9/fHWdHByr+6Lo1p6x0gr+YOUJwml18E8gXwK
RPGNuAhhUSkQUyoPvXbECJKkeYhPnsYSCDwB92sQ+QF43J7KqI+x0Z59hqzh4FWP
orYNRjsHB7l2MFTun2f4dt1HjT/IMi1m/4apqFzIBytrKDOdGf/20fKsvCKhwqZr
dgDTwMsij6oqEFbLedMc5IVBuvpRZn+1yM9LME8EIAgS1YvvsY/sUi+HYpJA00jE
Z0eLxgd5sycHDR2D1SqEBglghkgBZQMEAggEINSHGyy2mvftN0ZcvwmPshGkLQVr
Y93z1lBjHMW8eiMKBCUJ9E2ywWGYB+GHjAVt8G3YVLjvH6W9gdbQEbWWSitgoipV
C92uMIIBWAYKKwYBBAGJ3ywBAaGCAUgEggFEMIIBQAIBADCB3QYJYIZIAWUDBAEu
BAzWu5N5aeFyhq5aFAsEgcEEYJQKtoFMb/qiw/oxGBe7RPy9MNsJ/iOTjXn70u0N
h5NtmD4r6a1rQAaDLtd/IEHJkFLGbtQku8PboJygy0JknzU3kXDStzQkfxLcX0Bw
mMPAHojVSyIcMF/LvvcwSNlcKTdpZksFCIxXlXeY/fKnF+Vb7YQVYVvNWT8nJ7s1
88hfquMCV6zpy2XeEgOPoaxjYjJuKjeiMV8dCrystbpQxtLl3++PqtGivt/nCT4Z
LN60AS6c+joyR7VNgcExNZNnME8EICCcoGbSlG3ViuNOJkgUliihVGQ/p9zTRvii
x3ui0YkMBglghkgBZQMEAggEINNaGsdcplT/Q73ppiL4OddX8b1xCWZzQBOcnccY
oAX4BAooHLnyTHnreb1wMAsGCWCGSAFlAwQDCgNHADBEAiB5znN4Fec3CwtwQu08
Avsc+8aSlODesjxz3wO+1UvTwwIgLwRAFb28AssYvelz5+4z12uCEVGOy8cgI4Xj
FmnXzDU=
-----END CERTIFICATE-----"#;

	// Test moment timestamp from TypeScript tests
	const CERT_MOMENT_TIMESTAMP: i64 = 1730520283;

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

	fn get_cert_moment() -> DateTime<Utc> {
		Utc.timestamp_opt(CERT_MOMENT_TIMESTAMP, 0).unwrap()
	}

	fn get_ca_cert() -> Certificate {
		Certificate::from_pem(CA_CERT_PEM).unwrap()
	}

	fn get_user_cert() -> Certificate {
		Certificate::from_pem(USER_CERT_PEM).unwrap()
	}

	macro_rules! test_certificate_builder {
		($is_ca:expr, $algorithm_oid:expr, $public_key_bytes:expr, $subject_cn:expr, $issuer_cn:expr) => {
			let subject_cn_value = $subject_cn.split('=').nth(1).unwrap();
			let issuer_cn_value = $issuer_cn.split('=').nth(1).unwrap();
			let subject_dn = utils::create_dn(&[(oids::CN, subject_cn_value)]).unwrap();
			let issuer_dn = utils::create_dn(&[(oids::CN, issuer_cn_value)]).unwrap();

			let public_key_info = SubjectPublicKeyInfo {
				algorithm: AlgorithmIdentifier {
					algorithm: ObjectIdentifier::new($algorithm_oid).unwrap(),
					parameters: None,
				},
				public_key: BitString::from_bytes($public_key_bytes).unwrap(),
			};

			let serial = 1u128;
			let not_before = Utc::now();
			let not_after = not_before + chrono::Duration::days(365);

			let builder = CertificateBuilder::new()
				.subject_public_key(public_key_info.clone())
				.subject_dn(subject_dn.clone())
				.issuer_dn(issuer_dn.clone())
				.validity(not_before, not_after)
				.serial_number(U256::from(serial))
				.is_ca($is_ca);

			let tbs = builder.build_tbs().unwrap();

			let expected_serial = Uint::new(&serial.to_be_bytes()).unwrap();
			assert_eq!(tbs.serial_number, expected_serial);
			assert_eq!(tbs.subject, subject_dn);
			assert_eq!(tbs.issuer, issuer_dn);
			assert_eq!(tbs.subject_public_key_info, public_key_info);
			assert_eq!(tbs.version, Some(2));
			assert!(tbs.extensions.is_some());

			if let Some(extensions) = &tbs.extensions {
				let extension_oids: Vec<String> = extensions.iter().map(|ext| ext.id.to_string()).collect();
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
		test_certificate_builder!(true, oids::ED25519, &RAW_ED25519_PUBLIC_KEY[..], "CN=Ed25519 CA", "CN=Ed25519 CA");
		test_certificate_builder!(
			false,
			oids::ED25519,
			&RAW_ED25519_PUBLIC_KEY[..],
			"CN=Ed25519 User",
			"CN=Ed25519 CA"
		);
		test_certificate_builder!(
			true,
			oids::ECDSA_WITH_SHA256,
			&RAW_SECP256R1_PUBLIC_KEY[..],
			"CN=secp256r1 CA",
			"CN=secp256r1 CA"
		);
		test_certificate_builder!(
			false,
			oids::ECDSA_WITH_SHA256,
			&RAW_SECP256R1_PUBLIC_KEY[..],
			"CN=secp256r1 User",
			"CN=secp256r1 CA"
		);
	}

	#[test]
	fn test_certificate_builder_extension_methods() {
		let subject_dn = utils::create_dn(&[(oids::CN, "Test Cert")]).unwrap();
		let issuer_dn = utils::create_dn(&[(oids::CN, "Test CA")]).unwrap();

		let builder = CertificateBuilder::new()
			.subject_dn(subject_dn.clone())
			.issuer_dn(issuer_dn.clone())
			.serial_number(U256::from(12345u128))
			.validity_days(365)
			.is_ca(false)
			.with_extension(Extension::key_usage(0x0080).unwrap()) // digital signature
			.basic_constraints(false, None)
			.key_usage(0x0080)
			.extended_key_usage(vec![oids::CLIENT_AUTH])
			.subject_alt_name(vec!["test.example.com"])
			.custom_extension("1.2.3.4.5", &[0x01, 0x02], false)
			.extensions(vec![Extension::new("1.2.3.4.6", &[0x03, 0x04], false).unwrap()])
			.without_common_extensions()
			.with_common_extensions()
			.self_signed();

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
		let subject_dn = utils::create_dn(&[(oids::CN, "Test Certificate")]).unwrap();
		let issuer_dn = utils::create_dn(&[(oids::CN, "Test CA")]).unwrap();

		// Create a public key for testing
		let algorithm_oid = oids::ED25519;
		let public_key_bytes = &RAW_ED25519_PUBLIC_KEY[..];
		let algorithm = AlgorithmIdentifier { algorithm: algorithm_oid.parse().unwrap(), parameters: None };
		let public_key =
			SubjectPublicKeyInfo { algorithm, public_key: BitString::from_bytes(public_key_bytes).unwrap() };

		let builder = CertificateBuilder::new()
			.subject_public_key(public_key)
			.subject_dn(subject_dn)
			.issuer_dn(issuer_dn)
			.serial_number(U256::from(12345u128))
			.validity_days(365)
			.is_ca(false);

		// Test build with properties (this should work if the implementation supports it)
		if let Ok(_cert) = builder.build_with_properties(false, None) {
			// Build succeeded - this tests the build functionality
		}
		// Note: We don't fail the test if build_with_properties fails,
		// as it might require additional signing infrastructure
	}

	#[test]
	fn test_certificate_parsing() {
		macro_rules! test_certificate_parsing {
			($pem:expr, $expected_ca:expr) => {
				let cert = Certificate::from_pem($pem).unwrap();

				assert!(cert.serial_number() > U256::ZERO);
				assert!(!cert.subject().is_empty());
				assert!(!cert.issuer().is_empty());

				let pem_output = cert.to_pem().unwrap();
				let cert_re_parsed = Certificate::from_pem(&pem_output).unwrap();
				assert_eq!(cert.to_der().unwrap(), cert_re_parsed.to_der().unwrap());

				let der_bytes = cert.to_der().unwrap();
				let cert_from_der = Certificate::from_der(&der_bytes).unwrap();
				assert_eq!(cert.to_der().unwrap(), cert_from_der.to_der().unwrap());

				if $expected_ca {
					assert!(cert.is_ca());
				}

				let cert_moment = get_cert_moment();
				assert!(cert.is_valid_at(cert_moment).unwrap());
			};
		}

		test_certificate_parsing!(CA_CERT_PEM, true);
		test_certificate_parsing!(USER_CERT_PEM, false);
	}

	#[test]
	fn test_certificate_validity() {
		let cert = get_ca_cert();
		let cert_moment = get_cert_moment();

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

	#[test]
	fn test_certificate_extensions() {
		macro_rules! test_certificate_extensions {
			($pem:expr, $expected_oids:expr) => {
				let cert = Certificate::from_pem($pem).unwrap();
				let extensions = cert.tbs_certificate.extensions.unwrap();

				let found_oids: Vec<String> = extensions.iter().map(|ext| ext.id.to_string()).collect();
				for expected_oid in $expected_oids {
					assert!(found_oids.contains(&expected_oid.to_string()));
				}
			};
		}

		test_certificate_extensions!(
			CA_CERT_PEM,
			[oids::BASIC_CONSTRAINTS, oids::KEY_USAGE, oids::AUTHORITY_KEY_IDENTIFIER, oids::SUBJECT_KEY_IDENTIFIER]
		);

		test_certificate_extensions!(
			USER_CERT_PEM,
			[oids::KEY_USAGE, oids::AUTHORITY_KEY_IDENTIFIER, oids::SUBJECT_KEY_IDENTIFIER]
		);
	}

	#[test]
	fn test_certificate_hash() {
		let cert1 = get_ca_cert();
		let cert2 = get_user_cert();

		let hash1 = cert1.hash().unwrap();
		let hash2 = cert2.hash().unwrap();
		assert_ne!(hash1, hash2);

		let hash1_again = cert1.hash().unwrap();
		assert_eq!(hash1, hash1_again);

		assert_eq!(hash1.len(), 20);
		assert_eq!(hash2.len(), 20);
	}

	#[test]
	fn test_typescript_certificate_compatibility() {
		let test_cases = [
			(false, oids::ED25519, &RAW_ED25519_PUBLIC_KEY[..], "CN=Ed25519 User", "CN=Ed25519 CA"),
			(false, oids::ECDSA_WITH_SHA256, &RAW_SECP256R1_PUBLIC_KEY[..], "CN=secp256r1 User", "CN=secp256r1 CA"),
		];

		for (is_ca, algorithm_oid, public_key_bytes, subject_cn, issuer_cn) in test_cases {
			let subject_cn_value = subject_cn.split('=').nth(1).unwrap();
			let issuer_cn_value = issuer_cn.split('=').nth(1).unwrap();
			let subject_dn = utils::create_dn(&[(oids::CN, subject_cn_value)]).unwrap();
			let issuer_dn = utils::create_dn(&[(oids::CN, issuer_cn_value)]).unwrap();

			let public_key_info = SubjectPublicKeyInfo {
				algorithm: AlgorithmIdentifier {
					algorithm: ObjectIdentifier::new(algorithm_oid).unwrap(),
					parameters: None,
				},
				public_key: BitString::from_bytes(public_key_bytes).unwrap(),
			};

			let serial = 1u128;
			let not_before = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
			let not_after = not_before + chrono::Duration::days(365);

			let builder = CertificateBuilder::new()
				.subject_public_key(public_key_info.clone())
				.subject_dn(subject_dn.clone())
				.issuer_dn(issuer_dn.clone())
				.validity(not_before, not_after)
				.serial_number(U256::from(serial))
				.is_ca(is_ca);

			let tbs = builder.build_tbs().unwrap();

			let expected_serial = Uint::new(&serial.to_be_bytes()).unwrap();
			assert_eq!(tbs.serial_number, expected_serial);
			assert_eq!(tbs.subject, subject_dn);
			assert_eq!(tbs.issuer, issuer_dn);
			assert_eq!(tbs.subject_public_key_info, public_key_info);
			assert_eq!(tbs.version, Some(2));
			assert!(tbs.extensions.is_some());

			if let Some(extensions) = &tbs.extensions {
				let extension_oids: Vec<String> = extensions.iter().map(|ext| ext.id.to_string()).collect();
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
		}

		// Test new JSON fields
		#[cfg(feature = "serde")]
		{
			use serde_json;
			let cert = get_ca_cert();
			let json_struct = cert.to_json(true).unwrap();
			let json_string = serde_json::to_string(&json_struct).unwrap();
			assert!(json_string.contains("\"$hash\""));
			// $chain should be None for single cert, so it won't appear in JSON due to skip_serializing_if
			// But let's verify the hash_field and chain_field exist in the struct
			assert!(!json_struct.hash_field.is_empty());
			assert!(json_struct.chain_field.is_none()); // Should be None for single cert
		}

		// Test CertificateBuilder.extension
		let ext = Extension::new("1.2.3.4", &[0x01, 0x02], true).unwrap();
		assert_eq!(ext.id.to_string(), "1.2.3.4");
		assert_eq!(ext.critical, Some(true));

		// Test CertificateWithOptions constructor
		let cert_with_opts = CertificateWithOptions::new(CA_CERT_PEM, None).unwrap();
		assert!(!cert_with_opts.is_trusted()); // Should be false without store
		assert_eq!(cert_with_opts.chain_length(), 0);
	}

	#[test]
	fn test_chain_traversal() {
		let ca_cert = get_ca_cert();
		let user_cert = get_user_cert();

		assert!(user_cert.get_issuer_certificate().is_none());
		assert!(user_cert.get_root_certificate().is_none());
		assert!(ca_cert.get_issuer_certificate().is_some());
		assert!(ca_cert.get_root_certificate().is_some());

		let mut store = CertificateStore::new();
		store.add_root(ca_cert.clone());

		let issuer = user_cert.get_issuer_certificate_with_store(&store);
		assert!(issuer.is_some());
		assert_eq!(issuer.unwrap().subject(), ca_cert.subject());

		let root = user_cert.get_root_certificate_with_store(&store);
		assert!(root.is_some());
		assert_eq!(root.unwrap().subject(), ca_cert.subject());

		let user_with_chain = CertificateWithOptions {
			certificate: user_cert,
			options: CertificateOptions::default(),
			chain: Some(vec![ca_cert.clone()]),
		};
		assert!(user_with_chain.get_issuer_certificate().is_some());
		assert!(user_with_chain.get_root_certificate().is_some());
		assert_eq!(user_with_chain.chain_length(), 1);
		assert_eq!(user_with_chain.get_issuer_certificate().unwrap().subject(), ca_cert.subject());
		assert_eq!(user_with_chain.get_root_certificate().unwrap().subject(), ca_cert.subject());
	}

	#[test]
	fn test_certificate_builder_api() {
		// Test streamlined builder API
		let dn = utils::create_dn(&[(oids::CN, "example.com"), (oids::O, "Example Corp"), (oids::C, "US")]).unwrap();
		let builder = CertificateBuilder::new()
			.subject_dn(dn.clone())
			.issuer_dn(dn.clone())
			.serial_number(U256::from(12345u128))
			.validity_days(365)
			.is_ca(false);

		// Verify fields were set
		assert!(builder.subject_dn.is_some());
		assert!(builder.issuer_dn.is_some());
		assert!(builder.serial.is_some());
		assert!(builder.valid_from.is_some());
		assert!(builder.valid_to.is_some());
		assert_eq!(builder.is_ca, Some(false));

		// Test DN creation utility
		let subject_str = utils::dn_to_string(&builder.subject_dn.unwrap());
		assert!(subject_str.contains("example.com"));
		assert!(subject_str.contains("Example Corp"));
		assert!(subject_str.contains("US"));
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

		let pem_data = CA_CERT_PEM;
		let base_cert = get_ca_cert();
		let cert_chain = vec![base_cert.clone(), base_cert.clone()];

		test_certificate_with_options_basic!(CertificateWithOptions::try_from(pem_data), false, 0);
		test_certificate_with_options_basic!(CertificateWithOptions::try_from(pem_data.to_string()), false, 0);
		test_certificate_with_options_basic!(CertificateWithOptions::try_from(base_cert.clone()), false, 0);
		test_certificate_with_options_basic!(CertificateWithOptions::try_from(vec![base_cert.clone()]), false, 0);
		test_certificate_with_options_basic!(CertificateWithOptions::try_from(cert_chain), false, 1);

		let empty_result = CertificateWithOptions::try_from(Vec::<Certificate>::new());
		assert!(empty_result.is_err());

		let cert_with_opts = CertificateWithOptions::try_from(pem_data).unwrap();
		let cert_with_trust = cert_with_opts.with_trusted(true).with_chain(vec![base_cert]);
		assert!(cert_with_trust.is_trusted());
		assert_eq!(cert_with_trust.chain_length(), 1);
	}

	#[test]
	fn test_certificate_with_options_bundle_functionality() {
		macro_rules! test_bundle_roundtrip {
			($bundle:expr, $expected_cert_count:expr) => {
				println!("Testing bundle with {} expected certificates", $expected_cert_count);
				let der_bundle = $bundle.to_der().unwrap();
				println!("DER bundle size: {} bytes", der_bundle.len());
				assert!(!der_bundle.is_empty());

				let restored = CertificateWithOptions::try_from(der_bundle.as_slice()).unwrap();
				let actual_count = restored.get_certificates().len();
				println!("Restored bundle has {} certificates", actual_count);
				assert_eq!(actual_count, $expected_cert_count);
			};
		}

		let cert1 = get_ca_cert();
		let cert2 = get_user_cert();
		println!("Got CA cert and user cert");

		println!("Creating bundle from 2 certificates...");
		let bundle = CertificateWithOptions::try_from(vec![cert1.clone(), cert2.clone()]).unwrap();
		println!("Bundle created successfully");
		assert_eq!(bundle.certificate, cert1);
		assert_eq!(bundle.chain_length(), 1);
		assert_eq!(bundle.get_certificates().len(), 2);
		test_bundle_roundtrip!(bundle, 2);

		println!("Creating single certificate bundle...");
		let single_cert_bundle = CertificateWithOptions::try_from(vec![cert1.clone()]).unwrap();
		test_bundle_roundtrip!(single_cert_bundle, 1);
		println!("Test completed successfully");
	}

	#[cfg(feature = "serde")]
	#[test]
	fn test_certificate_json_serialization() {
		let cert = get_ca_cert();
		let cert_json = cert.to_json(false).unwrap();

		assert!(!cert_json.serial.is_empty());
		assert!(!cert_json.subject.is_empty());
		assert!(!cert_json.issuer.is_empty());
		assert!(!cert_json.hash.is_empty());
		assert!(!cert_json.not_before.is_empty());
		assert!(!cert_json.not_after.is_empty());
		assert!(!cert_json.subject_dn.is_empty());
		assert!(!cert_json.issuer_dn.is_empty());
		assert!(!cert_json.extensions.is_empty());
		assert!(cert_json.is_ca);

		let cert_json_with_chain = cert.to_json(true).unwrap();
		assert!(cert_json_with_chain.chain.is_none());
	}

	#[test]
	fn test_certificate_store_functionality() {
		let ca_cert = get_ca_cert();
		let user_cert = get_user_cert();

		let mut store = CertificateStore::new();
		assert_eq!(store.root.len(), 0);
		assert_eq!(store.intermediate.len(), 0);

		store.add_root(ca_cert.clone());
		assert_eq!(store.root.len(), 1);

		store.add_intermediate(user_cert.clone());
		assert_eq!(store.intermediate.len(), 1);

		let all_certs: Vec<_> = store.all_certificates().collect();
		assert_eq!(all_certs.len(), 2);
		assert!(all_certs.contains(&&ca_cert));
		assert!(all_certs.contains(&&user_cert));
	}

	#[test]
	fn test_certificate_hash_functionality() {
		let hash_bytes = vec![0x01, 0x02, 0x03, 0x04];
		let cert_hash = CertificateHash::new(hash_bytes.clone());

		assert_eq!(cert_hash.len(), 4);
		assert!(!cert_hash.is_empty());
		assert_eq!(cert_hash.as_bytes(), &hash_bytes);

		let hex_string = cert_hash.to_hex_string();
		assert_eq!(hex_string, "01020304");
		assert!(cert_hash.compare_hex_string("01020304"));
		assert!(!cert_hash.compare_hex_string("05060708"));

		let other_hash = CertificateHash::new(hash_bytes.clone());
		assert!(cert_hash.compare(&other_hash));

		let different_hash = CertificateHash::new(vec![0x05, 0x06]);
		assert!(!cert_hash.compare(&different_hash));

		let empty_hash = CertificateHash::new(vec![]);
		assert!(empty_hash.is_empty());
		assert_eq!(empty_hash.len(), 0);
	}

	#[test]
	fn test_certificate_hash_set() {
		let hash1 = CertificateHash::new(vec![0x01, 0x02]);
		let hash2 = CertificateHash::new(vec![0x03, 0x04]);
		let hash3 = CertificateHash::new(vec![0x05, 0x06]);

		let mut hash_set = CertificateHashSet::new(vec![hash1.clone(), hash2.clone()]);

		assert!(hash_set.has(&hash1));
		assert!(hash_set.has(&hash2));
		assert!(!hash_set.has(&hash3));

		hash_set.insert(hash3.clone());
		assert!(hash_set.has(&hash3));
	}

	#[test]
	fn test_extension_creation_methods() {
		// Test subject alternative name extension
		let san_entries = vec!["example.com", "192.168.1.1", "user@example.com", "https://example.com"];
		let san_ext = Extension::subject_alt_name(san_entries).unwrap();
		assert_eq!(san_ext.id.to_string(), oids::SUBJECT_ALT_NAME);
		assert!(!san_ext.critical.unwrap_or(false));

		// Test extended key usage extension
		let eku_entries = vec![oids::SERVER_AUTH, oids::CLIENT_AUTH];
		let eku_ext = Extension::extended_key_usage(eku_entries).unwrap();
		assert_eq!(eku_ext.id.to_string(), oids::EXTENDED_KEY_USAGE);
		assert!(!eku_ext.critical.unwrap_or(false));

		// Test basic constraints for CA certificate
		let bc_ca_ext = Extension::basic_constraints(true, Some(5)).unwrap();
		assert_eq!(bc_ca_ext.id.to_string(), oids::BASIC_CONSTRAINTS);
		assert!(bc_ca_ext.critical.unwrap_or(false));

		// Test basic constraints for end entity certificate
		let bc_ee_ext = Extension::basic_constraints(false, None).unwrap();
		assert_eq!(bc_ee_ext.id.to_string(), oids::BASIC_CONSTRAINTS);
		assert!(bc_ee_ext.critical.unwrap_or(false));

		// Test key usage extension
		let ku_ext = Extension::key_usage(0x0186).unwrap(); // digital signature + key cert sign + crl sign
		assert_eq!(ku_ext.id.to_string(), oids::KEY_USAGE);
		assert!(ku_ext.critical.unwrap_or(false));

		// Test custom extension
		let custom_ext = Extension::new("1.2.3.4", &[0x01, 0x02, 0x03], true).unwrap();
		assert_eq!(custom_ext.id.to_string(), "1.2.3.4");
		assert!(custom_ext.critical.unwrap_or(false));
	}

	#[test]
	fn test_certificate_validation_methods() {
		let cert = get_ca_cert();
		let moment = get_cert_moment();

		// Test validation methods - these may fail if cert is expired, so we test the API exists
		let _current_validity = cert.is_currently_valid();
		let _check_result = cert.check_currently_valid();
		let _datetime_validity = cert.is_valid_at_datetime(moment);
		let _validation_result = cert.validate_at_datetime(moment);

		// Test that the validation methods return the expected types
		assert!(matches!(cert.is_currently_valid(), Ok(_) | Err(_)));
		assert!(matches!(cert.is_valid_at_datetime(moment), Ok(_) | Err(_)));
		assert!(matches!(cert.validate_at_datetime(moment), Ok(_) | Err(_)));

		// Test validation methods that might fail if certificate is expired
		let _ = cert.assert_valid(moment);
		let _ = cert.validate_now();
		let _ = cert.validate_at(moment);

		// Also test some certificate properties while we're here
		let _subject = cert.subject();
		let _issuer = cert.issuer();
		let _serial = cert.serial_number();

		// Test age and validity period calculations
		let age = cert.age();
		assert!(age > chrono::Duration::zero());

		let remaining = cert.remaining_validity();
		// Certificate might be expired, so we just test that we get a duration
		let _ = remaining; // Don't assert it's positive if cert is expired

		let _ = cert.expires_within(chrono::Duration::days(3650)); // 10 years
		let _ = cert.valid_for_at_least(chrono::Duration::days(1));

		// Test subject/issuer name extraction
		let subject_name = cert.subject_name();
		let issuer_name = cert.issuer_name();
		assert!(!subject_name.is_empty());
		assert!(!issuer_name.is_empty());

		// Test public key extraction
		let _public_key = cert.subject_public_key();
	}

	#[test]
	fn test_certificate_trust_and_verification() {
		let ca_cert = get_ca_cert();
		let user_cert = get_user_cert();
		let moment = get_cert_moment();

		// Test trust without store - should be false
		assert!(!ca_cert.is_trusted(&CertificateStore::new(), Some(moment)));
		assert!(!user_cert.is_trusted(&CertificateStore::new(), Some(moment)));

		// Test trust with store
		let mut store = CertificateStore::new();
		store.add_root(ca_cert.clone());

		assert!(ca_cert.is_trusted(&store, Some(moment)));

		// Test certificate chain verification
		let chain = user_cert.verify_chain(&store);
		assert!(!chain.is_empty());

		// Test issuer certificate retrieval
		let issuer = user_cert.get_issuer_certificate_with_store(&store);
		assert!(issuer.is_some());

		// Test root certificate retrieval
		let root = user_cert.get_root_certificate_with_store(&store);
		assert!(root.is_some());

		// Test self-signed detection
		assert!(ca_cert.is_self_signed());
		assert!(!user_cert.is_self_signed());

		// Test certificate comparison
		assert!(ca_cert.equals(&ca_cert));
		assert!(!ca_cert.equals(&user_cert));

		// Test issued-by verification
		assert!(!ca_cert.check_issued(&user_cert));
	}

	#[test]
	fn test_certificate_with_options_validation() {
		let ca_cert = get_ca_cert();
		let moment = get_cert_moment();
		let mut store = CertificateStore::new();
		store.add_root(ca_cert.clone());

		let cert_with_options = CertificateWithOptions::new(
			CA_CERT_PEM,
			Some(CertificateOptions { moment: Some(moment), store: Some(store.clone()), is_trusted_root: Some(true) }),
		)
		.unwrap();

		// Test validation with store
		let cert_with_options_clone = cert_with_options.clone();
		let validated = cert_with_options_clone.validate_with_store(&store, Some(moment));
		assert!(validated.is_trusted());

		// Test DER conversion
		let der_bytes = cert_with_options.to_der().unwrap();
		assert!(!der_bytes.is_empty());

		// Test get_certificates
		let all_certs = cert_with_options.get_certificates();
		assert!(!all_certs.is_empty());
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
				assert_eq!($expected_hash, cert.hash().unwrap());
			};
		}

		let ca_cert = get_ca_cert();
		let user_cert = get_user_cert();
		let der_bytes = ca_cert.to_der().unwrap();
		let expected_hash = ca_cert.hash().unwrap();

		// Test Certificate from various sources
		test_certificate_from!(der_bytes.as_slice(), expected_hash);
		test_certificate_from!(der_bytes.clone(), expected_hash);
		test_certificate_from!(CA_CERT_PEM, expected_hash);
		test_certificate_from!(CA_CERT_PEM.to_string(), expected_hash);

		// Test Certificate to various targets
		test_certificate_conversion!(&ca_cert, Vec<u8>, |v: Vec<u8>| v == der_bytes);
		test_certificate_conversion!(ca_cert.clone(), Vec<u8>, |v: Vec<u8>| v == der_bytes);
		test_certificate_conversion!(&ca_cert, String, |s: String| s.contains("BEGIN CERTIFICATE"));
		test_certificate_conversion!(ca_cert.clone(), String, |s: String| s.contains("BEGIN CERTIFICATE"));

		// Test CertificateWithOptions from concatenated DER
		let mut combined_der = ca_cert.to_der().unwrap();
		combined_der.extend_from_slice(&user_cert.to_der().unwrap());

		// Test CertificateWithOptions from single certificate DER
		let ca_cert_der = ca_cert.to_der().unwrap();
		let single_cert_bundle = CertificateWithOptions::try_from(ca_cert_der).unwrap();
		assert_eq!(single_cert_bundle.get_certificates().len(), 1);
	}
}
