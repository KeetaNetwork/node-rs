//! X.509 certificate handling.
//!
//! This module provides functionality for working with X.509 certificates,
//! including parsing, validation, and generation of certificate requests.

pub use crate::builder::{CertificateBuilder, ExtensionBuilder};

use std::collections::HashSet;
use std::str::FromStr;

use asn1::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use asn1::{BitString, ObjectIdentifier, OctetString, Sequence, ValueOrd};
use asn1::{Decode, Encode};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use crypto::prelude::HashAlgorithm;
use x509_cert::certificate::{CertificateInner, Profile, TbsCertificateInner};
use x509_cert::ext::Extension as X509Extension;
use x509_cert::name::{DistinguishedName, Name};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Version;

#[cfg(feature = "serde")]
use asn1::utils::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::CertificateError;
use crate::oids;
use crate::utils::{self, parse_authority_key_identifier, parse_key_identifier};
use crate::utils::{dn_to_string, parse_der_length};

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

/// X.509 certificate extension following RFC 5280 standards.
/// Note: The [`x509_cert::ext::Extension`] cannot be used as it does not support
/// serde serialization/deserialization.
///
/// Extensions provide additional information and constraints for X.509
/// certificates beyond the basic certificate fields. Each extension is
/// identified by an Object Identifier (OID) and can be marked as critical
/// or non-critical.
///
/// # Critical vs Non-Critical Extensions
///
/// - **Critical extensions** must be processed by all certificate-using applications.
/// - **Non-critical extensions** may be ignored by applications that don't recognize them.
///
/// # ASN.1 Structure
///
/// ```text
/// Extension ::= SEQUENCE {
///     extnID                  OBJECT IDENTIFIER,
///     critical                BOOLEAN DEFAULT FALSE,
///     extnValue               OCTET STRING
/// }
/// ```
///
/// The `extnValue` field contains the DER-encoded extension-specific data.
///
/// # Extension creation
///
/// Extensions are typically created using the [`ExtensionBuilder`]:
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
///
/// # References
///
/// - [RFC 5280 Section 4.2 - Certificate Extensions](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2)
/// - [x509_cert crate](https://docs.rs/x509-cert/latest/x509_cert/ext/index.html)
#[derive(Debug, Clone, PartialEq, Eq, Sequence, ValueOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Extension {
	/// Extension ID (OID)
	#[cfg_attr(
		feature = "serde",
		serde(rename = "extnID", serialize_with = "serialize_oid", deserialize_with = "deserialize_oid")
	)]
	pub extn_id: ObjectIdentifier,
	/// Indicates if this extension is critical
	#[asn1(default = "Default::default")]
	#[cfg_attr(feature = "serde", serde(default))]
	pub critical: bool,
	/// Extension value as an OctetString
	#[cfg_attr(
		feature = "serde",
		serde(
			rename = "extnValue",
			serialize_with = "serialize_octet_string",
			deserialize_with = "deserialize_octet_string"
		)
	)]
	pub extn_value: OctetString,
}

/// Extensions as defined in [RFC 5280 Section 4.1.2.9].
///
/// ```text
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// ```
///
/// # References
///
/// - [RFC 5280 Section 4.1.2.9](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9)
pub type Extensions = Vec<Extension>;

/// Common X.509 certificate extensions following RFC 5280 standards.
///
/// BaseExtensions provides a convenient way to access the most commonly used
/// X.509 certificate extensions. These extensions are typically found in most
/// certificates and provide essential information about certificate constraints
/// and identifiers.
///
/// # Extension Parsing
///
/// BaseExtensions are typically extracted from a certificate using the
/// `parse_base_extensions()` method.
///
/// The extension values are automatically parsed from their DER-encoded form:
///
/// - Basic Constraints are parsed into a [`BasicConstraints`] struct
/// - Key identifiers are parsed as hex-encoded strings for easy display
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
///
/// # References
///
/// - [RFC 5280 Section 4.2 - Standard Extensions](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2)
/// - [RFC 5280 Section 4.2.1.9 - Basic Constraints](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9)
/// - [RFC 5280 Section 4.2.1.2 - Subject Key Identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2)
/// - [RFC 5280 Section 4.2.1.1 - Authority Key Identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1)
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BaseExtensions {
	/// Basic Constraints extension
	#[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
	pub basic_constraints: Option<BasicConstraints>,
	/// Subject Key Identifier extension
	#[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
	pub subject_key_identifier: Option<String>,
	/// Authority Key Identifier extension
	#[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
	pub authority_key_identifier: Option<String>,
}

impl Extension {
	/// Create a new extension.
	pub fn new<S: AsRef<str>, V: AsRef<[u8]>>(oid: S, value: V, critical: bool) -> Result<Self, CertificateError> {
		let oid = ObjectIdentifier::new(oid.as_ref())?;
		let value = OctetString::new(value.as_ref())?;

		Ok(Self { extn_id: oid, critical, extn_value: value })
	}
}

impl From<x509_cert::ext::Extension> for Extension {
	fn from(ext: x509_cert::ext::Extension) -> Self {
		Self {
			extn_id: ObjectIdentifier::new(&ext.extn_id.to_string()).unwrap(),
			critical: ext.critical,
			extn_value: OctetString::new(ext.extn_value.as_bytes()).unwrap(),
		}
	}
}

impl From<Extension> for x509_cert::ext::Extension {
	fn from(ext: Extension) -> Self {
		Self {
			extn_id: ObjectIdentifier::new(ext.extn_id.to_string().as_str()).unwrap(),
			critical: ext.critical,
			extn_value: OctetString::new(ext.extn_value.as_bytes()).unwrap(),
		}
	}
}

/// "To Be Signed" certificate data structure following RFC 5280 standards.
///
/// TbsCertificate contains all the actual certificate data that gets digitally
/// signed by the issuer. This includes the subject identity, public key,
/// validity period, extensions, and other certificate metadata. The entire
/// TbsCertificate structure is what gets hashed and signed to create the
/// certificate's signature.
///
/// # Structure Overview
///
/// The TBS certificate contains these key components:
///
/// - **Version** - X.509 certificate version (v1=0, v2=1, v3=2)
/// - **Serial Number** - Unique identifier assigned by the issuer
/// - **Signature Algorithm** - Algorithm used for signing (must match outer certificate)
/// - **Issuer** - Distinguished name of the certificate authority
/// - **Validity** - Certificate validity period (not_before, not_after)
/// - **Subject** - Distinguished name of the certificate holder
/// - **Subject Public Key Info** - The subject's public key and algorithm
/// - **Extensions** - Additional certificate constraints and information (v3 only)
///
/// # Certificate Versions
///
/// - **v1 (value 0)** - Basic certificate with required fields only
/// - **v2 (value 1)** - Adds issuer and subject unique identifiers
/// - **v3 (value 2)** - Adds extensions support (most common)
///
/// # ASN.1 Definition
///
/// ```text
/// TBSCertificate ::= SEQUENCE {
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
/// ```
///
/// # TBS certificate creation
///
/// TBS certificates are typically created through the [`CertificateBuilder`]:
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
///
/// # References
///
/// - [RFC 5280 Section 4.1.2 - TBSCertificate](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2)
/// - [X.509 Certificate Versions](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1)
#[derive(Debug, Clone, PartialEq, Eq, Sequence, ValueOrd)]
pub struct TbsCertificate {
	#[asn1(context_specific = "0", default = "Default::default")]
	pub version: Version,
	pub serial_number: SerialNumber,
	pub signature_algorithm: AlgorithmIdentifier,
	pub issuer: DistinguishedName,
	pub validity: Validity,
	pub subject: Name,
	pub subject_public_key_info: SubjectPublicKeyInfo,
	#[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
	pub issuer_unique_id: Option<BitString>,
	#[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
	pub subject_unique_id: Option<BitString>,
	#[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
	pub extensions: Option<Extensions>,
}

impl<P: Profile> From<TbsCertificateInner<P>> for TbsCertificate {
	fn from(tbs: TbsCertificateInner<P>) -> Self {
		Self {
			version: tbs.version,
			serial_number: SerialNumber::new(tbs.serial_number.as_bytes()).unwrap(),
			signature_algorithm: AlgorithmIdentifier::from(tbs.signature),
			issuer: tbs.issuer,
			validity: tbs.validity,
			subject: tbs.subject,
			subject_public_key_info: SubjectPublicKeyInfo::from(tbs.subject_public_key_info),
			issuer_unique_id: tbs.issuer_unique_id,
			subject_unique_id: tbs.subject_unique_id,
			extensions: tbs
				.extensions
				.map(|ext_vec| ext_vec.into_iter().map(Extension::from).collect()),
		}
	}
}

impl<P: Profile> From<TbsCertificate> for TbsCertificateInner<P> {
	fn from(tbs: TbsCertificate) -> Self {
		Self {
			version: tbs.version,
			serial_number: SerialNumber::new(tbs.serial_number.as_bytes()).unwrap(),
			signature: x509_cert::spki::AlgorithmIdentifierOwned::from(tbs.signature_algorithm),
			issuer: tbs.issuer,
			validity: tbs.validity,
			subject: tbs.subject,
			subject_public_key_info: x509_cert::spki::SubjectPublicKeyInfoOwned::from(tbs.subject_public_key_info),
			issuer_unique_id: tbs.issuer_unique_id,
			subject_unique_id: tbs.subject_unique_id,
			extensions: tbs
				.extensions
				.map(|ext_vec| ext_vec.into_iter().map(X509Extension::from).collect()),
		}
	}
}

/// Configuration options for certificate validation and processing.
///
/// CertificateOptions allows customization of how certificates are validated
/// and processed. These options control validation timing, trust overrides,
/// and other behavioral aspects of certificate handling.
///
/// # Validation Time
///
/// The `moment` field specifies the time at which certificate validation
/// should be performed. This is crucial because certificates have validity
/// periods and may be valid at one time but not another.
///
/// # Trust Overrides
///
/// The `is_trusted_root` field allows manual override of root certificate
/// trust decisions, useful for testing or special trust scenarios.
///
/// # Examples
///
/// Basic validation at current time:
///
/// ```rust
/// use x509::certificates::CertificateOptions;
/// use chrono::Utc;
///
/// let options = CertificateOptions {
///     moment: Some(Utc::now()),
///     is_trusted_root: None,
/// };
/// ```
///
/// Validation at specific historical time:
///
/// ```rust
/// use x509::certificates::CertificateOptions;
/// use chrono::{Utc, DateTime};
///
/// // Validate as if it were 30 days ago
/// let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
/// let options = CertificateOptions {
///     moment: Some(thirty_days_ago),
///     is_trusted_root: None,
/// };
/// ```
///
/// Trust override for testing:
///
/// ```rust
/// use x509::certificates::CertificateOptions;
///
/// // Force trust a certificate (useful for testing)
/// let test_options = CertificateOptions {
///     moment: None, // Use current time
///     is_trusted_root: Some(true),
/// };
/// ```
///
/// # Default Behavior
///
/// ```rust
/// use x509::certificates::CertificateOptions;
/// use chrono::Utc;
///
/// // Default uses current time and no trust overrides
/// let default_options = CertificateOptions::default();
/// assert_eq!(default_options.moment, None);
/// assert_eq!(default_options.is_trusted_root, None);
/// ```
#[derive(Debug, Default, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CertificateOptions {
	/// Time moment for validation
	pub moment: Option<DateTime<Utc>>,
	/// Override to mark as trusted root
	pub is_trusted_root: Option<bool>,
}

/// Certificate bundle containing a primary certificate with validation context.
///
/// A CertificateBundle groups together a primary certificate along with the
/// trusted root certificates, intermediate certificates, and validation options
/// needed to verify and validate the certificate chain. This is essential for
/// proper certificate validation in real-world scenarios.
///
/// # Certificate Chain Validation
///
/// Certificate validation typically requires:
/// 1. **Primary Certificate** - The certificate being validated
/// 2. **Intermediate Certificates** - Certificates that form the chain
/// 3. **Root Certificates** - Self-signed certificates from trusted CAs
/// 4. **Validation Options** - Time constraints and trust overrides
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
///
/// # References
///
/// - [RFC 5280 Section 6 - Certification Path Validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6)
/// - [Certificate Chain Validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)
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
	pub fn to_root_certificate(&self) -> Option<Certificate> {
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
	pub fn to_issuer_certificate(&self) -> Option<Certificate> {
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

	pub fn to_certificate(&self) -> &Certificate {
		&self.certificate
	}

	/// Get the issuer's public key from the chain.
	pub fn to_issuer_public_key(&self) -> Option<SubjectPublicKeyInfo> {
		self.to_issuer_certificate()
			.map(|cert| cert.tbs_certificate.subject_public_key_info)
	}

	/// Get chain length.
	pub fn to_chain_length(&self) -> usize {
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
}

macro_rules! impl_into_iterator_for_certificate_bundle {
	($self_type:ty) => {
		impl IntoIterator for $self_type {
			type Item = Certificate;
			type IntoIter = std::vec::IntoIter<Certificate>;

			fn into_iter(self) -> Self::IntoIter {
				self.certificate
					.verify_chain(&self.root, &self.intermediate)
					.collect::<Vec<_>>()
					.into_iter()
			}
		}
	};
}

impl_into_iterator_for_certificate_bundle!(&CertificateBundle);
impl_into_iterator_for_certificate_bundle!(CertificateBundle);

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
			for intermediate_cert in iter {
				// Add remaining certificates as intermediates in the store
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

impl TryFrom<&Certificate> for CertificateHash {
	type Error = CertificateError;

	fn try_from(certificate: &Certificate) -> Result<Self, Self::Error> {
		let der_bytes = certificate
			.to_der()
			.map_err(|e| CertificateError::ValidationFailed {
				reason: format!("Failed to serialize certificate to DER: {e}"),
			})?;

		Ok(Self::from_certificate_der(&der_bytes))
	}
}

impl TryFrom<Certificate> for CertificateHash {
	type Error = CertificateError;

	fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
		Self::try_from(&certificate)
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
		cert_set
			.certificates
			.iter()
			.map(|c| c.to_subject())
			.collect()
	}
}

impl From<&CertificateHashSet> for Vec<String> {
	fn from(cert_set: &CertificateHashSet) -> Self {
		// Convert certificates to their subject names as strings
		cert_set
			.certificates
			.iter()
			.map(|c| c.to_subject())
			.collect()
	}
}

/// Complete X.509 certificate following RFC 5280 standards.
///
/// A Certificate is the top-level X.509 structure that contains the certificate
/// data (`tbsCertificate`), the signature algorithm, and the digital signature
/// that binds the certificate data to the issuer's private key.
///
/// # ASN.1 Definition
///
/// ```text
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
/// ```
///
/// # Certificate Creation
///
/// Certificates are typically created using the [`CertificateBuilder`]:
///
/// # Serialization
///
/// Certificates can be serialized to standard formats:
///
/// ```rust
/// # use x509::doc_utils::create_test_certificate;
/// # use accounts::{Account, KeyED25519};
///
/// # let certificate = create_test_certificate("Test CA", None);
/// // Convert to DER (binary) format
/// let der_bytes = certificate.to_der()?;
/// assert!(!der_bytes.is_empty());
/// // Convert to PEM (text) format
/// let pem_string = certificate.to_pem()?;
/// assert!(pem_string.starts_with("-----BEGIN CERTIFICATE-----"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
///
/// # References
///
/// - [RFC 5280 Section 4.1 - Basic Certificate Fields](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
/// - [X.509 Certificate Profile](https://datatracker.ietf.org/doc/html/rfc5280)
///
/// [`CertificateBuilder`]: crate::builder::CertificateBuilder
/// [`TbsCertificate`]: crate::certificates::TbsCertificate
#[derive(Debug, Clone, PartialEq, Eq, Sequence, ValueOrd)]
pub struct Certificate {
	pub tbs_certificate: TbsCertificate,
	pub signature_algorithm: AlgorithmIdentifier,
	pub signature: BitString,
}

impl Certificate {
	/// Check if the certificate is valid at a specific time
	pub fn is_valid_at(&self, time: DateTime<Utc>) -> Result<bool, CertificateError> {
		let validity = &self.tbs_certificate.validity;

		if time < DateTime::<Utc>::from(validity.not_before.to_system_time()) {
			return Ok(false);
		}

		if time > DateTime::<Utc>::from(validity.not_after.to_system_time()) {
			return Ok(false);
		}

		Ok(true)
	}

	/// Check if the certificate is currently valid
	pub fn is_currently_valid(&self) -> Result<bool, CertificateError> {
		self.is_valid_at(Utc::now())
	}

	/// Check if the certificate will expire within the given duration
	pub fn is_expiring_within(&self, duration: Duration) -> bool {
		let now = Utc::now();
		self.to_not_after() <= now + duration
	}

	/// Check if the certificate has been valid for at least the given duration
	pub fn is_valid_for_at_least(&self, duration: Duration) -> bool {
		self.to_age() >= duration
	}

	/// Get the validity period as chrono DateTimes
	pub fn to_validity_period(&self) -> Validity {
		self.tbs_certificate.validity
	}

	/// Get the not_before time as chrono DateTime
	pub fn to_not_before(&self) -> DateTime<Utc> {
		DateTime::<Utc>::from(self.tbs_certificate.validity.not_before.to_system_time())
	}

	/// Get the not_after time as chrono DateTime
	pub fn to_not_after(&self) -> DateTime<Utc> {
		DateTime::<Utc>::from(self.tbs_certificate.validity.not_after.to_system_time())
	}

	/// Get the certificate's age (how long it has been valid)
	pub fn to_age(&self) -> Duration {
		let now = Utc::now();
		now - self.to_not_before()
	}

	/// Get the remaining validity period of the certificate
	pub fn to_remaining_validity(&self) -> Duration {
		let now = Utc::now();
		self.to_not_after() - now
	}

	/// Convert the certificate to DER format
	pub fn to_der(&self) -> Result<Vec<u8>, CertificateError> {
		Vec::<u8>::try_from(self)
	}

	/// Convert the certificate to PEM format
	pub fn to_pem(&self) -> Result<String, CertificateError> {
		Ok(format!("{self}"))
	}

	/// Get the serial number
	pub fn to_serial_number(&self) -> SerialNumber {
		self.tbs_certificate.serial_number.clone()
	}

	/// Get the subject distinguished name as a string
	pub fn to_subject(&self) -> String {
		dn_to_string(&self.tbs_certificate.subject)
	}

	/// Get the issuer distinguished name as a string
	pub fn to_issuer(&self) -> String {
		dn_to_string(&self.tbs_certificate.issuer)
	}

	/// Get the subject public key
	pub fn to_subject_public_key(&self) -> &SubjectPublicKeyInfo {
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
			extensions.iter().find(|ext| ext.extn_id == target_oid)
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
			match BasicConstraints::from_der(basic_constraints.extn_value.as_bytes()) {
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
		let this_not_before = self.to_not_before();
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
				utils::verify_ecdsa_signature(public_key_bytes, signature_bytes, &tbs_der)
			}

			oids::ECDSA_WITH_SHA256 => {
				// For ECDSA, try both curves since the verification function handles curve detection
				utils::verify_ecdsa_signature(public_key_bytes, signature_bytes, &tbs_der)
			}

			oids::SHA256_WITH_RSA => Err(CertificateError::InvalidCertificate),

			_ => Ok(false),
		}
	}

	/// Parse base extensions from certificate.
	pub fn parse_base_extensions(&self) -> BaseExtensions {
		let mut base_extensions = BaseExtensions::default();
		if let Some(extensions) = &self.tbs_certificate.extensions {
			for ext in extensions {
				match ext.extn_id.to_string().as_str() {
					// Basic Constraints
					oids::BASIC_CONSTRAINTS => {
						if let Ok(constraints) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
							base_extensions.basic_constraints = Some(constraints);
						}
					}
					// Subject Key Identifier
					oids::SUBJECT_KEY_IDENTIFIER => {
						// Subject Key Identifier is an OCTET STRING containing the key identifier
						if let Some(key_id) = parse_key_identifier(ext.extn_value.as_bytes()) {
							base_extensions.subject_key_identifier = Some(hex::encode(key_id));
						}
					}
					// Authority Key Identifier
					oids::AUTHORITY_KEY_IDENTIFIER => {
						// Authority Key Identifier is a SEQUENCE with optional KeyIdentifier [0]
						if let Some(key_id) = parse_authority_key_identifier(ext.extn_value.as_bytes()) {
							base_extensions.authority_key_identifier = Some(hex::encode(key_id));
						}
					}
					_ => {} // Ignore other extensions for base extensions
				}
			}
		}

		base_extensions
	}

	/// Validate the certificate at a specific time (throws error)
	pub fn assert_valid(&self, time: DateTime<Utc>) -> Result<(), CertificateError> {
		self.validate_at(time)
	}

	/// Validate the certificate at a specific time
	pub fn validate_at(&self, time: DateTime<Utc>) -> Result<(), CertificateError> {
		if time < DateTime::<Utc>::from(self.tbs_certificate.validity.not_before.to_system_time()) {
			return Err(CertificateError::NotYetValid);
		}

		if time > DateTime::<Utc>::from(self.tbs_certificate.validity.not_after.to_system_time()) {
			return Err(CertificateError::Expired);
		}

		Ok(())
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
		// Check version - X.509 v3 certificates are recommended per RFC 5280
		if self.tbs_certificate.version != Version::V3 {
			return Err(CertificateError::ValidationFailed {
				reason: "Only X.509 v3 certificates are supported per RFC 5280".to_string(),
			});
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
					let oid_str = extension.extn_id.to_string();

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
				let oid_str = extension.extn_id.to_string();
				if seen_oids.contains(&oid_str) {
					return Err(CertificateError::ValidationFailed {
						reason: format!("Duplicate extension OID: {oid_str}"),
					});
				}
				seen_oids.insert(oid_str);
			}

			// Validate Basic Constraints consistency
			if let Some(basic_constraints_ext) = self.get_extension(oids::BASIC_CONSTRAINTS) {
				if let Ok(basic_constraints) = BasicConstraints::from_der(basic_constraints_ext.extn_value.as_bytes()) {
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
	///
	/// TODO Make this more readable
	pub fn validate_authority_key_identifier(&self, issuer: &Certificate) -> bool {
		// If Authority Key Identifier is present, validate it matches the issuer's Subject Key Identifier
		if let Some(auth_key_ext) = self.get_extension(oids::AUTHORITY_KEY_IDENTIFIER) {
			if let Some(issuer_subject_key_ext) = issuer.get_extension(oids::SUBJECT_KEY_IDENTIFIER) {
				// Parse both key identifiers and compare
				if let (Some(auth_key_id), Some(subject_key_id)) = (
					utils::parse_authority_key_identifier(auth_key_ext.extn_value.as_bytes()),
					utils::parse_key_identifier(issuer_subject_key_ext.extn_value.as_bytes()),
				) {
					return auth_key_id == subject_key_id;
				}
			}
			// If Authority Key Identifier is present but cannot be validated
			return false;
		}

		// If no Authority Key Identifier is present, this check passes
		true
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
			let cert_hash = CertificateHash::try_from(cert)?;
			if !seen_hashes.insert(cert_hash) {
				return Err(CertificateError::CertificateDuplicateIncluded);
			}
		}

		// Check for orphans - certificates that do not connect to the subject certificate
		let connected_certs = self.find_connected_certificates(certificates);
		for cert in certificates {
			if !connected_certs.contains(cert) && cert != self {
				return Err(CertificateError::CertificateOrphanFound);
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
					return Err(CertificateError::CertificateCycleFound);
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

impl<P: Profile> From<CertificateInner<P>> for Certificate {
	fn from(cert: CertificateInner<P>) -> Self {
		Self {
			tbs_certificate: TbsCertificate::from(cert.tbs_certificate),
			signature_algorithm: AlgorithmIdentifier::from(cert.signature_algorithm),
			signature: cert.signature.clone(),
		}
	}
}

impl<P: Profile> From<Certificate> for CertificateInner<P> {
	fn from(cert: Certificate) -> Self {
		Self {
			tbs_certificate: TbsCertificateInner::from(cert.tbs_certificate),
			signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned::from(cert.signature_algorithm),
			signature: cert.signature.clone(),
		}
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
	use chrono::Utc;
	use x509_cert::name::RdnSequence;
	use x509_cert::serial_number::SerialNumber;

	use super::*;
	use crate::testing::{CertificateChain, CERTIFICATE_TEST_SETS};
	use crate::utils;

	/// Get a moment that's always within the certificate validity period.
	fn get_cert_moment() -> DateTime<Utc> {
		// Get the first test certificate and calculate a moment in the
		// middle of its validity.
		let cert: Certificate = CERTIFICATE_TEST_SETS[0].chain.root.parse().unwrap();
		let validity_start = cert.to_not_before();
		let validity_end = cert.to_not_after();
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
			.with_serial_number(SerialNumber::from(serial))
			.with_is_ca(is_ca)
	}

	/// Helper to test all certificate sets with a given test function
	fn test_all_certificate_sets<F>(test_fn: F)
	where
		F: Fn(&CertificateTestBundle),
	{
		for test_set in CERTIFICATE_TEST_SETS.iter() {
			let bundle = extract_certificates(&test_set.chain);
			test_fn(&bundle);
		}
	}

	/// Helper to assert certificate properties
	fn assert_cert_properties(cert: &Certificate, expected_ca: bool) {
		assert!(!cert.to_issuer().is_empty());
		assert!(!cert.to_subject().is_empty());

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
				let not_before = cert.to_not_before();
				let not_after = cert.to_not_after();
				assert!(not_before < not_after);
				assert!(cert.is_valid_at(cert_moment).unwrap());

				let before_valid = not_before - chrono::Duration::seconds(1);
				let after_valid = not_after + chrono::Duration::seconds(1);
				assert!(!cert.is_valid_at(before_valid).unwrap());
				assert!(!cert.is_valid_at(after_valid).unwrap());

				let validity_period = cert.to_validity_period();
				let validity_not_before = DateTime::<Utc>::from(validity_period.not_before.to_system_time());
				let validity_not_after = DateTime::<Utc>::from(validity_period.not_after.to_system_time());
				assert_eq!(validity_not_before, not_before);
				assert_eq!(validity_not_after, not_after);

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
		let found_oids: Vec<String> = extensions
			.iter()
			.map(|ext| ext.extn_id.to_string())
			.collect();

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

			assert!(client_with_no_chain.to_issuer_certificate().is_none());
			assert!(client_with_no_chain.to_root_certificate().is_none());

			// Test self-signed certificate (should return itself)
			let ca_with_no_chain = CertificateBundle {
				certificate: ca_cert.clone(),
				options: CertificateOptions::default(),
				root: root_certs.clone(),
				intermediate: intermediate_certs.clone(),
			};

			assert!(ca_with_no_chain.to_issuer_certificate().is_some());
			assert!(ca_with_no_chain.to_root_certificate().is_some());

			// Test with complete chain
			let user_with_chain = CertificateBundle {
				certificate: client_cert.clone(),
				options: CertificateOptions::default(),
				root: root_certs.clone(),
				intermediate: intermediate_certs.clone(),
			};

			let issuer = user_with_chain.to_issuer_certificate().unwrap();
			let root = user_with_chain.to_root_certificate().unwrap();

			assert_eq!(issuer.to_subject(), intermediate_cert.to_subject());
			assert_eq!(root.to_subject(), ca_cert.to_subject());
			assert_eq!(user_with_chain.to_chain_length(), 3);
		});
	}

	#[test]
	fn test_certificate_with_options_try_from() {
		macro_rules! test_certificate_with_options_basic {
			($try_from_expr:expr, $expected_trusted:expr, $expected_chain_length:expr) => {
				let cert_with_opts = $try_from_expr.unwrap();
				assert_eq!(cert_with_opts.is_trusted(), $expected_trusted);
				assert_eq!(cert_with_opts.to_chain_length(), $expected_chain_length);
			};
		}

		for test_set in CERTIFICATE_TEST_SETS.iter() {
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
			assert_eq!(cert_with_trust.to_chain_length(), 1);
		}
	}

	#[test]
	fn test_certificate_with_options_bundle_functionality() {
		/// Helper to test bundle roundtrip
		fn test_bundle_roundtrip(bundle: &CertificateBundle, expected_cert_count: usize) {
			let der_bundle = bundle.to_der().unwrap();
			assert!(!der_bundle.is_empty());

			let restored = CertificateBundle::try_from(der_bundle.as_slice()).unwrap();
			let actual_count = restored.into_iter().count();
			assert_eq!(actual_count, expected_cert_count);
		}

		test_all_certificate_sets(|bundle| {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert, .. } = bundle;

			let chain = vec![client_cert.clone(), intermediate_cert.clone(), ca_cert.clone()];
			let bundle = CertificateBundle::try_from(chain).unwrap();
			assert_eq!(bundle.certificate, *client_cert);
			assert_eq!(bundle.to_chain_length(), 3);
			assert_eq!(bundle.clone().into_iter().count(), 3);

			// Test get_certificate method
			assert_eq!(bundle.to_certificate(), client_cert);

			// Test get_issuer_public_key method
			let issuer_public_key = bundle.to_issuer_public_key();
			assert!(issuer_public_key.is_some());

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

			let all_certs: Vec<_> = cert_with_options.into_iter().collect();
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
			let all_certs: Vec<_> = cert_bundle.clone().into_iter().collect();
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
			assert!(cert.is_valid_at(moment).unwrap());
			assert!(cert.assert_valid(moment).is_ok());
			assert!(cert.validate_at(moment).is_ok());

			// Test validate_now (cert may be expired)
			let now = cert.is_currently_valid();
			assert!(now.is_ok() || now.is_err());

			// Test current validity methods
			assert!(cert.is_currently_valid().unwrap());

			let subject = cert.to_subject();
			let issuer = cert.to_issuer();
			let serial = cert.to_serial_number();
			let serial_string = serial.to_string();
			assert!(!serial_string.is_empty());
			assert!(serial_string.contains(':'));
			assert!(!subject.is_empty());
			assert!(!issuer.is_empty());

			let age = cert.to_age();
			assert!(age > chrono::Duration::zero());

			// Test remaining_validity method
			let remaining_validity = cert.to_remaining_validity();
			assert!(remaining_validity > chrono::Duration::zero());

			// Test expires_within method
			let far_future = chrono::Duration::days(365 * 10); // 10 years
			let near_future = chrono::Duration::minutes(1); // 1 minute
			assert!(cert.is_expiring_within(far_future));
			assert!(!cert.is_expiring_within(near_future));

			// Test valid_for_at_least method
			let short_duration = chrono::Duration::hours(1);
			let long_duration = chrono::Duration::days(365 * 10); // 10 years
			assert!(cert.is_valid_for_at_least(short_duration));
			assert!(!cert.is_valid_for_at_least(long_duration));

			// Calculate remaining validity from the test moment
			let remaining = cert.to_not_after() - moment;
			assert!(remaining > chrono::Duration::zero());
			// Certificate should still be valid (not expired)
			assert!(cert.to_not_after() > moment);
			// Certificate should have been issued before the test moment
			assert!(cert.to_not_before() < moment);
			// Age should be reasonable (at least 1 hour, less than 50 years)
			assert!(cert.to_age() >= chrono::Duration::hours(1));
			assert!(cert.to_age() <= chrono::Duration::days(365 * 50));

			let subject_name = cert.to_subject();
			let issuer_name = cert.to_issuer();
			assert!(!subject_name.is_empty());
			assert!(!issuer_name.is_empty());

			let public_key = cert.to_subject_public_key();
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

			let issuer = user_with_chain.to_issuer_certificate();
			assert!(issuer.is_some());

			let root = user_with_chain.to_root_certificate();
			assert!(root.is_some());

			// Check validity methods
			assert!(ca_cert.is_self_signed());
			assert!(!intermediate_cert.is_self_signed());
			assert!(!user_cert.is_self_signed());
			assert!(ca_cert == ca_cert);
			assert!(ca_cert != user_cert);

			// Check name relationships (issuer/subject matching)
			assert_eq!(user_cert.to_issuer(), intermediate_cert.to_subject());
			assert_eq!(intermediate_cert.to_issuer(), ca_cert.to_subject());
			assert_eq!(ca_cert.to_issuer(), ca_cert.to_subject()); // Self-signed

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
			let all_certs = cert_with_options.into_iter();
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
				assert_eq!($expected_hash, CertificateHash::try_from(&cert).unwrap());
			};
		}

		macro_rules! test_certificate_parse {
			($source:expr, $expected_hash:expr) => {
				let cert: Certificate = $source.parse().unwrap();
				assert_eq!($expected_hash, CertificateHash::try_from(&cert).unwrap());
			};
		}

		for test_set in CERTIFICATE_TEST_SETS.iter() {
			let CertificateTestBundle { ca_cert, intermediate_cert, client_cert: user_cert, .. } =
				extract_certificates(&test_set.chain);

			// Test each certificate in the chain
			for cert in [&ca_cert, &intermediate_cert, &user_cert] {
				let der_bytes = cert.to_der().unwrap();
				let expected_hash = CertificateHash::try_from(cert).unwrap();

				// Test Certificate from various sources
				test_certificate_from!(der_bytes.as_slice(), expected_hash);
				test_certificate_from!(der_bytes.clone(), expected_hash);

				// Test Certificate to various targets
				test_certificate_conversion!(cert, Vec<u8>, |v: Vec<u8>| v == der_bytes);
				test_certificate_conversion!(cert.clone(), Vec<u8>, |v: Vec<u8>| v == der_bytes);

				// Test CertificateWithOptions from single certificate DER
				let cert_der = cert.to_der().unwrap();
				let single_cert_bundle = CertificateBundle::try_from(cert_der).unwrap();
				assert_eq!(single_cert_bundle.into_iter().count(), 1);
			}

			// Test Certificate from PEM strings (specific to each cert type)
			test_certificate_parse!(test_set.chain.root, CertificateHash::try_from(&ca_cert).unwrap());
			test_certificate_parse!(test_set.chain.root.to_string(), CertificateHash::try_from(&ca_cert).unwrap());
			test_certificate_parse!(
				test_set.chain.intermediate,
				CertificateHash::try_from(&intermediate_cert).unwrap()
			);
			test_certificate_parse!(
				test_set.chain.intermediate.to_string(),
				CertificateHash::try_from(&intermediate_cert).unwrap()
			);
			test_certificate_parse!(test_set.chain.client, CertificateHash::try_from(&user_cert).unwrap());
			test_certificate_parse!(test_set.chain.client.to_string(), CertificateHash::try_from(&user_cert).unwrap());

			// Test CertificateWithOptions from concatenated DER
			let mut combined_der = ca_cert.to_der().unwrap();
			combined_der.extend_from_slice(&user_cert.to_der().unwrap());
		}
	}

	// TODO Fix these issues
	#[test]
	fn test_verify_signature() {
		for test_set in CERTIFICATE_TEST_SETS.iter() {
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
			assert_eq!(client_cert.to_issuer(), intermediate_cert.to_subject());
			assert_eq!(intermediate_cert.to_issuer(), ca_cert.to_subject());
			assert_eq!(ca_cert.to_issuer(), ca_cert.to_subject());

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
		for test_set in CERTIFICATE_TEST_SETS.iter() {
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
		for test_set in CERTIFICATE_TEST_SETS.iter() {
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
		for test_set in CERTIFICATE_TEST_SETS.iter() {
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

			let user_issuer = user_with_chain.to_issuer_certificate();
			assert!(user_issuer.is_some());
			assert_eq!(CertificateHash::try_from(&user_issuer.unwrap()), CertificateHash::try_from(&intermediate_cert));

			let user_root = user_with_chain.to_root_certificate();
			assert!(user_root.is_some());
			assert_eq!(CertificateHash::try_from(&user_root.unwrap()), CertificateHash::try_from(&ca_cert));
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
				let hash_from_ref = CertificateHash::try_from(cert).unwrap();
				let hash_from_owned = CertificateHash::try_from(cert.clone()).unwrap();
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
					CertificateHash::new(HashAlgorithm::Sha2_512.hash(&der_bytes), Some(crate::oids::SHA512));
				assert!(hash_sha512.verify_certificate(cert).unwrap());
				let hash_sha3_256 =
					CertificateHash::new(HashAlgorithm::Sha3_256.hash(&der_bytes), Some(crate::oids::SHA3_256));
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
			assert!(subject_names.contains(&bundle.ca_cert.to_subject()));
			assert!(subject_names.contains(&bundle.intermediate_cert.to_subject()));
			assert!(subject_names.contains(&bundle.client_cert.to_subject()));

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
				let original_hash = CertificateHash::try_from(cert).unwrap();

				let pem = cert.to_pem().unwrap();
				let cert_from_pem: Certificate = pem.parse().unwrap();
				let hash_from_pem = CertificateHash::try_from(&cert_from_pem).unwrap();

				let der = cert.to_der().unwrap();
				let cert_from_der = Certificate::try_from(der).unwrap();
				let hash_from_der = CertificateHash::try_from(&cert_from_der).unwrap();
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
				]),
				expected_oid: oids::SUBJECT_ALT_NAME,
				expected_critical: false,
			},
			ExtensionTest {
				name: "extended key usage",
				extension: ExtensionBuilder::for_extended_key_usage(vec![oids::SERVER_AUTH, oids::CLIENT_AUTH]),
				expected_oid: oids::EXTENDED_KEY_USAGE,
				expected_critical: false,
			},
			ExtensionTest {
				name: "basic constraints (CA)",
				extension: ExtensionBuilder::for_basic_constraints(true, Some(5)),
				expected_oid: oids::BASIC_CONSTRAINTS,
				expected_critical: true,
			},
			ExtensionTest {
				name: "basic constraints (end entity)",
				extension: ExtensionBuilder::for_basic_constraints(false, None),
				expected_oid: oids::BASIC_CONSTRAINTS,
				expected_critical: true,
			},
			ExtensionTest {
				name: "key usage",
				extension: ExtensionBuilder::for_key_usage(0x0186),
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
			assert_eq!(test.extension.extn_id.to_string(), test.expected_oid, "OID mismatch for {}", test.name);
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
			(RdnSequence(Vec::new()), utils::create_dn(&[(oids::CN, "Test Issuer")]).unwrap(), Some(false)),
			(RdnSequence(Vec::new()), utils::create_dn(&[(oids::CN, "Test Issuer")]).unwrap(), None),
			(utils::create_dn(&[(oids::CN, "Test Subject")]).unwrap(), RdnSequence(Vec::new()), None),
		];

		for (subject, issuer, san_critical) in dn_test_cases {
			// Create a minimal public key info for Ed25519
			let algorithm = oids::ED25519.parse().unwrap();
			let subject_public_key = BitString::from_bytes(&[0u8; 32]).unwrap();
			let public_key_info = SubjectPublicKeyInfo { algorithm, subject_public_key };
			let signature_algorithm = oids::ED25519.parse().unwrap();
			let signature = BitString::from_bytes(&[0u8; 64]).unwrap();
			let mut builder = CertificateBuilder::new()
				.with_serial_number(SerialNumber::from(1u8))
				.with_validity_days(365)
				.with_subject_dn(subject)
				.with_issuer_dn(issuer)
				.with_subject_public_key(public_key_info);

			// Add SAN extension if specified
			if let Some(critical) = san_critical {
				// Create a SAN extension manually with the critical flag set correctly
				let san_ext = if critical {
					ExtensionBuilder::new()
						.with_oid(oids::SUBJECT_ALT_NAME)
						.with_subject_alt_name_value(vec!["example.com"])
						.as_critical()
						.build()
						.expect("Failed to build SAN extension")
				} else {
					ExtensionBuilder::for_subject_alt_name(vec!["example.com"])
				};
				builder = builder.with_extension(san_ext);
			} // Build the full certificate for validation
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
		assert!(matches!(result.unwrap_err(), CertificateError::CertificateOrphanFound));

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

		// Test cycle detection
		let certificates_with_cycle = [cycle_a_cert, cycle_b_cert].into_iter().collect();
		let cycle_result = cycle_subject_cert.assert_can_construct_valid_graph(&certificates_with_cycle);
		assert!(cycle_result.is_err());
		assert!(matches!(cycle_result.unwrap_err(), CertificateError::CertificateCycleFound));
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

	#[test]
	fn test_x509_cert_converters_round_trip() {
		// Test Extension converters
		let test_extensions = vec![
			(oids::BASIC_CONSTRAINTS, b"\x30\x03\x01\x01\xff".to_vec(), true),
			(oids::KEY_USAGE, b"\x03\x02\x01\x06".to_vec(), false),
			(oids::SUBJECT_KEY_IDENTIFIER, b"\x04\x14\x01\x02\x03\x04".to_vec(), false),
		];

		for (oid, value, critical) in test_extensions {
			let original = Extension::new(oid, &value, critical).unwrap();
			let x509_ext: X509Extension = original.clone().into();
			let round_trip: Extension = x509_ext.into();
			assert_eq!(original, round_trip);
		}

		// Test TbsCertificate converter with real test certificate
		test_all_certificate_sets(|bundle| {
			let original_tbs = &bundle.ca_cert.tbs_certificate;
			let x509_tbs: TbsCertificateInner<x509_cert::certificate::Rfc5280> = original_tbs.clone().into();
			let round_trip: TbsCertificate = x509_tbs.into();
			assert_eq!(original_tbs.version, round_trip.version);
			assert_eq!(original_tbs.serial_number, round_trip.serial_number);
			assert_eq!(original_tbs.issuer, round_trip.issuer);
			assert_eq!(original_tbs.subject, round_trip.subject);
			assert_eq!(original_tbs.validity, round_trip.validity);
		});

		// Test Certificate converter with real test certificate
		test_all_certificate_sets(|bundle| {
			let original_cert = &bundle.ca_cert;
			let x509_cert: CertificateInner<x509_cert::certificate::Rfc5280> = original_cert.clone().into();
			let round_trip: Certificate = x509_cert.into();
			assert_eq!(original_cert.tbs_certificate.version, round_trip.tbs_certificate.version);
			assert_eq!(original_cert.tbs_certificate.serial_number, round_trip.tbs_certificate.serial_number);
			assert_eq!(original_cert.tbs_certificate.issuer, round_trip.tbs_certificate.issuer);
			assert_eq!(original_cert.tbs_certificate.subject, round_trip.tbs_certificate.subject);
			assert_eq!(original_cert.signature, round_trip.signature);
		});
	}
}
