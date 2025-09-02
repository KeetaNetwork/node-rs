//! X.509 certificate and extension builders.
//!
//! This module provides builder patterns for creating X.509 certificates
//! and extensions following RFC 5280 standards. It includes fluent APIs for
//! both individual extension creation and batch extension operations.
//!
//! # Quick Start
//!
//! ## Creating a Self-Signed Certificate
//!
//! ```rust
//! use keetanetwork_account::{Account, KeyPair, KeyED25519};
//! use keetanetwork_asn1::{SubjectPublicKeyInfo, AlgorithmIdentifier, BitString};
//! use keetanetwork_crypto::bigint::U256;
//! use keetanetwork_crypto::algorithms::ed25519::Ed25519Derivation;
//! use keetanetwork_crypto::prelude::KeyDerivation;
//! use keetanetwork_crypto::utils::generate_random_seed;
//! use keetanetwork_x509::builder::{CertificateBuilder, ExtensionBuilder};
//! use keetanetwork_x509::{utils, oids};
//! use keetanetwork_x509::SerialNumber;
//!
//! // Generate a keypair for signing
//! let seed = generate_random_seed()?;
//! let private_key = Ed25519Derivation::derive_from_seed(seed)?;
//! let account = Account::<KeyED25519>::from(private_key);
//! let public_key = account.keypair.to_public_key();
//!
//! // Create the public key info structure
//! let public_key_info = SubjectPublicKeyInfo::from(public_key);
//! // Create a distinguished name
//! let subject_dn = utils::create_dn(&[
//!     (oids::CN, "Example Certificate"),
//!     (oids::O, "Example Organization"),
//!     (oids::C, "US"),
//! ])?;
//!
//! // Create multiple extensions efficiently
//! let extensions = ExtensionBuilder::batch()
//!     .include_basic_constraints(true, Some(1))  // CA with path length 1
//!     .include_key_usage(0x06)                   // keyCertSign + cRLSign
//!     .include_extended_key_usage(vec![
//!         "1.3.6.1.5.5.7.3.1",                   // Server Authentication
//!     ])
//!     .include_subject_alt_name(vec!["ca.example.com"])
//!     .build_all()?;
//!
//! // Build and sign the certificate
//! let certificate = CertificateBuilder::new()
//!     .with_subject_public_key(public_key_info.clone())
//!     .with_subject_dn(subject_dn.clone())
//!     .with_issuer_dn(subject_dn) // Self-signed
//!     .with_serial_number(SerialNumber::from(1u64))
//!     .with_validity_days(365)
//!     .with_basic_constraints(false, None)
//!     .with_extensions(extensions)
//!     .with_key_usage(0x80) // Digital signature
//!     .with_subject_alt_name(vec!["example.com", "www.example.com"])
//!     .build(&account)?;
//!
//! // Validate certificate
//! assert!(certificate.verify_signature(&public_key_info).is_ok());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::time::SystemTime;

use chrono::{DateTime, Duration, Utc};
use der::asn1::ObjectIdentifier;
use der::Encode;
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_crypto::prelude::{Algorithm, CryptoSignerWithOptions, SignatureEncoding, SigningOptions};
use x509_cert::name::DistinguishedName;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::Version;

use crate::certificates::{Certificate, Extension, TbsCertificate};
use crate::error::CertificateError;
use crate::oids;
use crate::utils::generate_key_identifier;

/// Macro to generate include_* methods for batch operations.
macro_rules! include_extension {
	// Simple case without generics
	(
		$(#[$meta:meta])*
		$method_name:ident,
		$for_method:ident,
		($($param:ident: $param_type:ty),*)
	) => {
		$(#[$meta])*
		pub fn $method_name(mut self, $($param: $param_type),*) -> Self {
			if self.batch_mode {
				let extension = Self::$for_method($($param),*);
				self.extensions.push(extension);
			}
			self
		}
	};
	// Case with I, S generics for iterator types
	(
		$(#[$meta:meta])*
		$method_name:ident,
		$for_method:ident,
		($($param:ident: $param_type:ty),*)
		where_is
	) => {
		$(#[$meta])*
		pub fn $method_name<I, S>(mut self, $($param: $param_type),*) -> Self
		where
			I: IntoIterator<Item = S>,
			S: AsRef<str>,
		{
			if self.batch_mode {
				let extension = Self::$for_method($($param),*);
				self.extensions.push(extension);
			}
			self
		}
	};
	// Case with T generic for AsRef<[u8]>
	(
		$(#[$meta:meta])*
		$method_name:ident,
		$for_method:ident,
		($($param:ident: $param_type:ty),*)
		where_t
	) => {
		$(#[$meta])*
		pub fn $method_name<T>(mut self, $($param: $param_type),*) -> Self
		where
			T: AsRef<[u8]>,
		{
			if self.batch_mode {
				let extension = Self::$for_method($($param),*);
				self.extensions.push(extension);
			}
			self
		}
	};
}

/// Builder for creating X.509 certificate extensions with fluent API.
///
/// The `ExtensionBuilder` provides a convenient way to create various types of
/// X.509 certificate extensions following RFC 5280 standards. It supports both
/// standard extensions (like Basic Constraints, Key Usage, etc.) and custom
/// extensions with arbitrary OIDs and values.
///
/// # Standard Extensions Supported
///
/// - **Basic Constraints** (RFC 5280 Section 4.2.1.9) - Indicates whether the certificate is a CA
/// - **Key Usage** (RFC 5280 Section 4.2.1.3) - Defines the cryptographic purposes of the key
/// - **Extended Key Usage** (RFC 5280 Section 4.2.1.12) - Additional key usage purposes
/// - **Subject Alternative Name** (RFC 5280 Section 4.2.1.6) - Alternative names for the subject
/// - **Subject Key Identifier** (RFC 5280 Section 4.2.1.2) - Identifier for the subject's public key
/// - **Authority Key Identifier** (RFC 5280 Section 4.2.1.1) - Identifier for the issuer's public key
///
/// # Examples
///
/// ## Creating a Basic Constraints Extension for a CA Certificate
///
/// ```rust
/// use keetanetwork_x509::builder::ExtensionBuilder;
///
/// // Create a basic constraints extension for a CA with path length constraint
/// let ca_extension = ExtensionBuilder::for_basic_constraints(true, Some(2));
///
/// assert!(ca_extension.critical);
/// assert_eq!(ca_extension.extn_id.to_string(), "2.5.29.19"); // Basic Constraints OID
/// ```
///
/// # Error Handling
///
/// The builder methods return `Result<Extension, CertificateError>` and will fail if:
/// - Required fields (OID or value) are missing
/// - Invalid OID format is provided
/// - ASN.1 encoding fails during value construction
///
/// # Thread Safety
///
/// This builder is `Send + Sync` and can be safely used across threads.
///
/// # References
/// - [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
/// - [RFC 5280 Section 4.2.1.9: Basic Constraints](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9)
/// - [RFC 5280 Section 4.2.1.3: Key Usage](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)
/// - [RFC 5280 Section 4.2.1.12: Extended Key Usage](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)
/// - [RFC 5280 Section 4.2.1.6: Subject Alternative Name](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
/// - [RFC 5280 Section 4.2.1.2: Subject Key Identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2)
/// - [RFC 5280 Section 4.2.1.1: Authority Key Identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionBuilder {
	/// Single extension OID
	oid: Option<String>,
	/// Critical flag for single extension
	critical: bool,
	/// Extension value for single extension
	value: Option<Vec<u8>>,
	/// Batch mode extensions
	extensions: Vec<Extension>,
	/// Batch mode flag
	batch_mode: bool,
}

impl ExtensionBuilder {
	/// Create a new extension builder with default values.
	///
	/// The builder starts with the critical flag set to `false`.
	/// Use the fluent API methods to configure the extension before building.
	pub fn new() -> Self {
		Self::default()
	}

	/// Create a basic constraints according to RFC 5280 Section 4.2.1.9.
	///
	/// This extension indicates whether the certificate subject is a
	/// Certificate Authority (CA) and optionally constrains the maximum depth
	/// of valid certification paths that include this certificate.
	///
	/// # Arguments
	///
	/// * `is_ca` - Whether the certificate is a CA certificate
	/// * `path_length` - Optional path length constraint (only meaningful if `is_ca` is true)
	///
	/// # ASN.1 Structure
	///
	/// ```text
	/// BasicConstraints ::= SEQUENCE {
	///     cA                      BOOLEAN DEFAULT FALSE,
	///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
	/// }
	/// ```
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Create a CA certificate with unlimited path length
	/// let ca_basic_constraints = ExtensionBuilder::for_basic_constraints(true, None);
	/// // Create a CA certificate with path length constraint of 0 (can only issue end-entity certs)
	/// let intermediate_ca = ExtensionBuilder::for_basic_constraints(true, Some(0));
	/// // Create an end-entity certificate (non-CA)
	/// let end_entity = ExtensionBuilder::for_basic_constraints(false, None);
	/// ```
	///
	/// # References
	/// - [RFC 5280 Section 4.2.1.9: Basic Constraints](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9)
	pub fn for_basic_constraints(is_ca: bool, path_length: Option<u8>) -> Extension {
		Self::new()
			.with_oid(oids::BASIC_CONSTRAINTS)
			.with_critical(true)
			.with_basic_constraints_value(is_ca, path_length)
			.build()
			.expect("Valid basic constraints extension")
	}

	/// Create a key usage extension according to RFC 5280 Section 4.2.1.3.
	///
	/// This extension defines the cryptographic purposes for which the
	/// certificate's public key may be used. The extension is always marked
	/// as critical as recommended by RFC 5280.
	///
	/// # Arguments
	///
	/// * `key_usage_bits` - Bit field representing allowed key usages
	///
	/// # Key Usage Bits
	///
	/// |-----|--------|----------------------------------------|
	/// | Bit | Value  | Purpose                                |
	/// |-----|--------|----------------------------------------|
	/// | 0   | 0x80   | Digital Signature                      |
	/// | 1   | 0x40   | Non-Repudiation (Content Commitment)   |
	/// | 2   | 0x20   | Key Encipherment                       |
	/// | 3   | 0x10   | Data Encipherment                      |
	/// | 4   | 0x08   | Key Agreement                          |
	/// | 5   | 0x04   | Key Certificate Sign                   |
	/// | 6   | 0x02   | CRL Sign                               |
	/// | 7   | 0x01   | Encipher Only                          |
	/// | 15  | 0x8000 | Decipher Only (requires Key Agreement) |
	/// |-----|--------|----------------------------------------|
	///
	/// # ASN.1 Structure
	///
	/// ```text
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
	/// ```
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // CA certificate: certificate signing and CRL signing
	/// let ca_key_usage = ExtensionBuilder::for_key_usage(0x04 | 0x02); // keyCertSign + cRLSign
	/// // End-entity certificate: digital signature and key encipherment
	/// let ee_key_usage = ExtensionBuilder::for_key_usage(0x80 | 0x20); // digitalSignature + keyEncipherment
	/// // Server certificate: digital signature and key agreement
	/// let server_key_usage = ExtensionBuilder::for_key_usage(0x80 | 0x08); // digitalSignature + keyAgreement
	/// ```
	///
	/// # References
	/// - [RFC 5280 Section 4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)
	pub fn for_key_usage(key_usage_bits: u16) -> Extension {
		Self::new()
			.with_oid(oids::KEY_USAGE)
			.with_key_usage_value(key_usage_bits)
			.as_critical()
			.build()
			.expect("Valid key usage extension")
	}

	/// Create an extended key usage according to RFC 5280 Section 4.2.1.12.
	///
	/// This extension indicates additional purposes for which the certificate's
	/// public key may be used, beyond those indicated in the Key Usage
	/// extension. This extension is typically marked as non-critical.
	///
	/// # Arguments
	///
	/// * `ext_key_use` - Iterator of OID strings representing extended key usage purposes
	///
	/// # Common Extended Key Usage OIDs
	///
	/// - `1.3.6.1.5.5.7.3.1` - Server Authentication (TLS WWW server authentication)
	/// - `1.3.6.1.5.5.7.3.2` - Client Authentication (TLS WWW client authentication)
	/// - `1.3.6.1.5.5.7.3.3` - Code Signing
	/// - `1.3.6.1.5.5.7.3.4` - Email Protection (S/MIME)
	/// - `1.3.6.1.5.5.7.3.8` - Time Stamping
	/// - `1.3.6.1.5.5.7.3.9` - OCSP Signing
	///
	/// # ASN.1 Structure
	///
	/// ```text
	/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
	/// KeyPurposeId      ::= OBJECT IDENTIFIER
	/// ```
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Server certificate with server and client authentication
	/// let server_eku = ExtensionBuilder::for_extended_key_usage(vec![
	///     "1.3.6.1.5.5.7.3.1", // Server Authentication
	///     "1.3.6.1.5.5.7.3.2", // Client Authentication
	/// ]);
	///
	/// // Code signing certificate
	/// // Code signing certificate
	/// let code_signing_eku = ExtensionBuilder::for_extended_key_usage(vec![
	///     "1.3.6.1.5.5.7.3.3", // Code Signing
	/// ]);
	///
	/// // Email protection certificate
	/// let email_eku = ExtensionBuilder::for_extended_key_usage(vec![
	///     "1.3.6.1.5.5.7.3.4", // Email Protection
	/// ]);
	/// ```
	///
	/// # References
	/// - [RFC 5280 Section 4.2.1.12](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)
	pub fn for_extended_key_usage<I, S>(ext_key_use: I) -> Extension
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		Self::new()
			.with_oid(oids::EXTENDED_KEY_USAGE)
			.with_extended_key_usage_value(ext_key_use)
			.as_non_critical()
			.build()
			.expect("Valid extended key usage extension")
	}

	/// Create a subject alternative name according to RFC 5280 Section 4.2.1.6.
	///
	/// This extension allows additional identities to be bound to the
	/// certificate subject. The extension supports various name types including
	/// DNS names, IP addresses, email addresses, and URIs.
	///
	/// # Arguments
	///
	/// * `san_entries` - Iterator of alternative name strings in various formats
	///
	/// # Supported Name Formats
	///
	/// The method automatically detects the name type based on the format:
	/// - **DNS Name**: Domain names (e.g., "example.com", "www.example.com")
	/// - **IP Address**: IPv4 or IPv6 addresses (e.g., "192.168.1.1", "::1")
	/// - **Email Address**: RFC 822 email addresses (e.g., "user@example.com")
	/// - **URI**: HTTP/HTTPS URIs (e.g., "<https://example.com/path>")
	///
	/// # ASN.1 Structure
	///
	/// ```text
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
	/// ```
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Web server certificate with multiple DNS names
	/// let web_server_san = ExtensionBuilder::for_subject_alt_name(vec![
	///     "example.com",
	///     "www.example.com",
	///     "api.example.com",
	/// ]);
	///
	/// // Certificate with mixed name types
	/// let mixed_san = ExtensionBuilder::for_subject_alt_name(vec![
	///     "example.com",              // DNS name
	///     "192.168.1.100",           // IPv4 address
	///     "2001:db8::1",             // IPv6 address
	///     "admin@example.com",       // Email address
	///     "https://example.com/api", // URI
	/// ]);
	///
	/// // Load balancer certificate with IP addresses
	/// let lb_san = ExtensionBuilder::for_subject_alt_name(vec![
	///     "10.0.1.100",
	///     "10.0.1.101",
	///     "10.0.1.102",
	/// ]);
	/// ```
	///
	/// # References
	/// - [RFC 5280 Section 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
	pub fn for_subject_alt_name<I, S>(san_entries: I) -> Extension
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		Self::new()
			.with_oid(oids::SUBJECT_ALT_NAME)
			.with_subject_alt_name_value(san_entries)
			.as_non_critical()
			.build()
			.expect("Valid subject alternative name extension")
	}

	/// Create a subject key identifier according to RFC 5280 Section 4.2.1.2.
	///
	/// This extension provides a means of identifying the public key
	/// corresponding to the private key used to sign a certificate. This is
	/// useful when an issuer has multiple signing keys.
	///
	/// # Arguments
	///
	/// * `key_id` - The key identifier bytes (typically 20 bytes from SHA-1 hash)
	///
	/// # ASN.1 Structure
	///
	/// ```text
	/// SubjectKeyIdentifier ::= KeyIdentifier
	/// KeyIdentifier        ::= OCTET STRING
	/// ```
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	/// use keetanetwork_crypto::hash::HashAlgorithm;
	///
	/// // Generate key identifier from public key
	/// let public_key_bytes = b"example_public_key_data";
	/// let key_id = HashAlgorithm::Sha3_256.hash(public_key_bytes);
	///
	/// let ski_extension = ExtensionBuilder::for_subject_key_identifier(&key_id);
	///
	/// // Using a predefined key identifier
	/// let predefined_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	///                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	///                      0x11, 0x12, 0x13, 0x14];
	/// let ski_extension = ExtensionBuilder::for_subject_key_identifier(&predefined_id);
	/// ```
	///
	/// # References
	/// - [RFC 5280 Section 4.2.1.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2)
	pub fn for_subject_key_identifier<T: AsRef<[u8]>>(key_id: T) -> Extension {
		Self::new()
			.with_oid(oids::SUBJECT_KEY_IDENTIFIER)
			.with_value(key_id)
			.as_non_critical()
			.build()
			.expect("Valid subject key identifier extension")
	}

	/// Create an authority key identifier according to RFC 5280 Section 4.2.1.1.
	///
	/// This extension provides a means of identifying the public key
	/// corresponding to the private key used by the CA that signed the
	/// certificate. This is particularly useful when the CA has multiple
	/// signing keys.
	///
	/// # Arguments
	///
	/// * `key_id` - The authority's key identifier bytes
	///
	/// # ASN.1 Structure
	///
	/// ```text
	/// AuthorityKeyIdentifier ::= SEQUENCE {
	///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
	///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
	/// }
	/// KeyIdentifier ::= OCTET STRING
	/// ```
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Create AKI extension using CA's key identifier
	/// let ca_key_id = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
	///                  0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00,
	///                  0x01, 0x02, 0x03, 0x04];
	/// let aki_extension = ExtensionBuilder::for_authority_key_identifier(&ca_key_id);
	///
	/// // For self-signed certificates, AKI typically matches SKI
	/// let self_signed_key_id = [0xFF; 20];
	/// let self_signed_aki = ExtensionBuilder::for_authority_key_identifier(&self_signed_key_id);
	/// ```
	///
	/// # References
	/// - [RFC 5280 Section 4.2.1.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1)
	pub fn for_authority_key_identifier<T: AsRef<[u8]>>(key_id: T) -> Extension {
		Self::new()
			.with_oid(oids::AUTHORITY_KEY_IDENTIFIER)
			.with_authority_key_identifier_value(key_id)
			.as_non_critical()
			.build()
			.expect("Valid authority key identifier extension")
	}

	/// Set the extension OID (Object Identifier).
	///
	/// The OID identifies the type of extension. Standard extension OIDs are
	/// defined in RFC 5280 and other standards. Custom extensions can use
	/// enterprise-specific OIDs.
	///
	/// # Arguments
	///
	/// * `oid` - The OID string in dotted decimal notation (e.g., "2.5.29.19")
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// let extension = ExtensionBuilder::new()
	///     .with_oid("2.5.29.19") // Basic Constraints OID
	///     .with_value(&[0x30, 0x00]) // Empty SEQUENCE for non-CA
	///     .build();
	///
	/// match extension {
	///     Ok(ext) => {
	///         // Use the built extension
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	/// ```
	pub fn with_oid<S: AsRef<str>>(mut self, oid: S) -> Self {
		self.oid = Some(oid.as_ref().to_string());
		self
	}

	/// Mark the extension as critical.
	///
	/// Critical extensions must be processed by all certificate-using
	/// applications. If an application encounters a critical extension it does
	/// not recognize, it must reject the certificate.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// let critical_extension = ExtensionBuilder::new()
	///     .with_oid("2.5.29.15") // Key Usage OID
	///     .with_value(&[0x03, 0x02, 0x01, 0x06])
	///     .as_critical()
	///     .build();
	///
	/// match critical_extension {
	///     Ok(ext) => {
	///         // Use the built extension
	///         assert!(ext.critical);
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	/// ```
	pub fn as_critical(mut self) -> Self {
		self.critical = true;
		self
	}

	/// Mark the extension as non-critical (default).
	///
	/// Non-critical extensions may be ignored by applications that do not
	/// recognize them. This is the default setting for new builders.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// let non_critical_extension = ExtensionBuilder::new()
	///     .with_oid("2.5.29.17") // Subject Alternative Name OID
	///     .with_value(&[0x30, 0x0B, 0x82, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74])
	///     .as_non_critical()
	///     .build();
	///
	/// match non_critical_extension {
	///     Ok(ext) => {
	///         // Use the built extension
	///         assert!(!ext.critical);
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	/// ```
	pub fn as_non_critical(mut self) -> Self {
		self.critical = false;
		self
	}

	/// Set whether the extension is critical.
	///
	/// This method provides a programmatic way to set the critical flag
	/// based on a boolean value.
	///
	/// # Arguments
	///
	/// * `critical` - Whether the extension should be marked as critical
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// let is_ca_cert = true;
	/// let extension = ExtensionBuilder::new()
	///     .with_oid("2.5.29.19") // Basic Constraints OID
	///     .with_value(&[0x30, 0x03, 0x01, 0x01, 0xFF])
	///     .with_critical(is_ca_cert) // Critical for CA certificates
	///     .build();
	///
	/// match extension {
	///     Ok(ext) => {
	///         // Use the built extension
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	/// ```
	pub fn with_critical(mut self, critical: bool) -> Self {
		self.critical = critical;
		self
	}

	/// Set the extension value directly from raw bytes.
	///
	/// This method allows setting the DER-encoded extension value directly.
	/// For standard extensions, prefer using the specific factory methods
	/// like `for_basic_constraints()` which handle the DER encoding
	/// automatically.
	///
	/// # Arguments
	///
	/// * `value` - The DER-encoded extension value bytes
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Create a custom extension with raw DER bytes
	/// let der_value = vec![0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00];
	/// let extension = ExtensionBuilder::new()
	///     .with_oid("1.2.3.4.5")
	///     .with_value(&der_value)
	///     .as_critical()
	///     .build();
	///
	/// match extension {
	///     Ok(ext) => {
	///         // Use the built extension
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	pub fn with_value<T: AsRef<[u8]>>(mut self, value: T) -> Self {
		self.set_value(value.as_ref().to_vec());
		self
	}

	/// Set subject alternative name value with automatic type detection.
	///
	/// This method handles the low-level ASN.1 DER encoding for Subject
	/// Alternative Name (SAN) extensions according to RFC 5280 Section 4.2.1.6.
	/// It automatically detects the type of each name entry and encodes it
	/// appropriately.
	///
	/// # Supported Name Types
	///
	/// The method automatically detects and encodes the following name types:
	///
	/// ```text
	/// |---------------|-------------------------|--------------|----------------------------------|
	/// | Type          | Detection Rule          | ASN.1 Tag    | Example                          |
	/// |---------------|-------------------------|--------------|----------------------------------|
	/// | DNS Name      | Default fallback        | [2] IMPLICIT | `"example.com"`                  |
	/// | Email Address | Contains `@`            | [1] IMPLICIT | `"user@example.com"`             |
	/// | URI           | `http://` or `https://` | [6] IMPLICIT | `"https://example.com"`          |
	/// | IP Address    | Valid IPv4/IPv6         | [7] IMPLICIT | `"192.168.1.1"`, `"2001:db8::1"` |
	/// |---------------|-------------------------|--------------|----------------------------------|
	/// ```
	///
	/// # ASN.1 Structure
	///
	/// ```text
	/// SubjectAltName ::= GeneralNames
	/// GeneralNames   ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	/// GeneralName    ::= CHOICE {
	///     otherName                   [0] OtherName,
	///     rfc822Name                  [1] IA5String,      -- Email
	///     dNSName                     [2] IA5String,      -- DNS Name
	///     x400Address                 [3] ORAddress,
	///     directoryName               [4] Name,
	///     ediPartyName                [5] EDIPartyName,
	///     uniformResourceIdentifier   [6] IA5String,      -- URI
	///     iPAddress                   [7] OCTET STRING,   -- IP Address
	///     registeredID                [8] OBJECT IDENTIFIER
	/// }
	/// ```
	///
	/// # Examples
	///
	/// ## Basic Usage
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	/// use keetanetwork_x509::oids;
	///
	/// // Single DNS name
	/// let single_dns = ExtensionBuilder::new()
	///     .with_oid(oids::SUBJECT_ALT_NAME)
	///     .with_subject_alt_name_value(vec!["example.com"])
	///     .build();
	///
	/// match single_dns {
	///     Ok(ext) => {
	///         // Use the built extension
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	/// ```
	///
	/// ## Mixed Name Types
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	/// use keetanetwork_x509::oids;
	///
	/// // Web server certificate with various name types
	/// let web_server_san = ExtensionBuilder::new()
	///     .with_oid(oids::SUBJECT_ALT_NAME)
	///     .with_subject_alt_name_value(vec![
	///         "example.com",                    // DNS name
	///         "www.example.com",               // DNS name
	///         "api.example.com",               // DNS name
	///         "192.168.1.100",                 // IPv4 address
	///         "2001:db8::1",                   // IPv6 address
	///         "admin@example.com",             // Email address
	///         "https://example.com/api",       // URI
	///     ])
	///     .build();
	///
	/// match web_server_san {
	///     Ok(ext) => {
	///         // Use the built extension
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	/// ```
	///
	/// # Implementation Details
	///
	/// The method uses simple heuristics for type detection:
	/// - **Email**: Contains `@` character
	/// - **URI**: Starts with `http://` or `https://`
	/// - **IP Address**: Can be parsed as IPv4 or IPv6
	/// - **DNS Name**: Default for all other strings
	///
	/// Each name is encoded with the appropriate ASN.1 context-specific tag:
	/// - Email addresses use  `[1] IMPLICIT` (0x81)
	/// - DNS names use        `[2] IMPLICIT` (0x82)
	/// - URIs use             `[6] IMPLICIT` (0x86)
	/// - IP addresses use     `[7] IMPLICIT` (0x87)
	///
	/// # Limitations
	///
	/// - Only supports the four most common GeneralName types
	/// - Uses simple string pattern matching for type detection
	/// - Does not validate that DNS names conform to RFC standards
	/// - Does not support otherName, x400Address, directoryName, ediPartyName, or registeredID
	///
	/// # Arguments
	///
	/// * `san_entries` - An iterable collection of string-like values representing the alternative names
	///
	/// # References
	///
	/// - [RFC 5280 Section 4.2.1.6 - Subject Alternative Name](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
	/// - [RFC 5280 Section 4.2.1.7 - Issuer Alternative Name](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7)
	pub fn with_subject_alt_name_value<I, S>(mut self, san_entries: I) -> Self
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

		self.set_value(value);
		self
	}

	/// Build the extension from the configured parameters.
	///
	/// This method validates that all required fields (OID and value) are set
	/// and constructs the final `Extension` object.
	///
	/// # Returns
	///
	/// - Ok if the extension is successfully built, or
	/// - Err if required fields are missing or invalid.
	///
	/// # Errors
	///
	/// - `CertificateError::MissingField` - If OID or value is not set
	/// - `CertificateError::InvalidOid` - If the OID format is invalid
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Successful build
	/// let extension = ExtensionBuilder::new()
	///     .with_oid("2.5.29.15") // Key Usage
	///     .with_value(&[0x03, 0x02, 0x01, 0x06])
	///     .as_critical()
	///     .build();
	///
	/// match extension {
	///     Ok(ext) => {
	///         // Use the built extension
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extension: {}", e);
	///     }
	/// }
	///
	/// // Error case - missing OID
	/// let result = ExtensionBuilder::new()
	///     .with_value(&[0x01, 0x02])
	///     .build();
	/// assert!(result.is_err());
	///
	/// // Error case - missing value
	/// let result = ExtensionBuilder::new()
	///     .with_oid("2.5.29.15")
	///     .build();
	/// assert!(result.is_err());
	/// ```
	pub fn build(self) -> Result<Extension, CertificateError> {
		let oid = self
			.oid
			.ok_or(CertificateError::MissingField { field: "oid".to_string() })?;
		let value = self
			.value
			.ok_or(CertificateError::MissingField { field: "value".to_string() })?;

		Extension::new(&oid, &value, self.critical)
	}

	/// Create a new batch builder for building multiple extensions efficiently.
	///
	/// This returns an `ExtensionBuilder` in batch mode that allows you to
	/// chain multiple extension creation calls and build them all at once.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Create multiple extensions at once
	/// let extensions = ExtensionBuilder::batch()
	///     .include_basic_constraints(false, None)
	///     .include_key_usage(0x80 | 0x20)
	///     .include_extended_key_usage(vec!["1.3.6.1.5.5.7.3.1"])
	///     .include_subject_alt_name(vec!["example.com"])
	///     .build_all();
	///
	/// match extensions {
	///     Ok(exts) => {
	///         // Use the built extensions
	///     },
	///     Err(e) => {
	///         // Handle the error
	///         panic!("Failed to build extensions: {}", e);
	///     }
	/// }
	pub fn batch() -> Self {
		Self { batch_mode: true, ..Default::default() }
	}

	/// Build all extensions in the batch.
	///
	/// This method finalizes the batch operation and returns all extensions
	/// that were added using the `include_*` methods. The method consumes the
	/// builder and can only be called when the builder is in batch mode.
	///
	/// # Returns
	///
	/// - Ok containing all extensions in the batch
	/// - Err if the builder is not in batch mode.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::ExtensionBuilder;
	///
	/// // Create multiple extensions in a batch
	/// let extensions = ExtensionBuilder::batch()
	///     .include_basic_constraints(true, Some(2))    // CA with path length 2
	///     .include_key_usage(0x06)                     // keyCertSign + cRLSign
	///     .include_extended_key_usage(vec![
	///         "1.3.6.1.5.5.7.3.1",                    // Server Authentication
	///         "1.3.6.1.5.5.7.3.2",                    // Client Authentication
	///     ])
	///     .include_subject_alt_name(vec![
	///         "ca.example.com",
	///         "root-ca.example.com",
	///     ])
	///     .build_all()
	///     .expect("Failed to build extensions batch");
	///
	/// // Verify we got all the extensions
	/// assert_eq!(extensions.len(), 4);
	///
	/// // Extensions are returned in the order they were added
	/// assert_eq!(extensions[0].extn_id.to_string(), "2.5.29.19");  // Basic Constraints
	/// assert_eq!(extensions[1].extn_id.to_string(), "2.5.29.15");  // Key Usage
	/// assert_eq!(extensions[2].extn_id.to_string(), "2.5.29.37");  // Extended Key Usage
	/// assert_eq!(extensions[3].extn_id.to_string(), "2.5.29.17");  // Subject Alt Name
	/// ```
	///
	/// # Errors
	///
	/// - `CertificateError::MissingField` - If not in batch mode // TODO add a better error variant
	///
	/// # See Also
	///
	/// - `ExtensionBuilder::batch()` - Create a batch builder
	/// - `include_basic_constraints()` - Add basic constraints extension
	/// - `include_key_usage()` - Add key usage extension
	/// - `include_extended_key_usage()` - Add extended key usage extension
	/// - `include_subject_alt_name()` - Add subject alternative name extension
	pub fn build_all(self) -> Result<Vec<Extension>, CertificateError> {
		if !self.batch_mode {
			return Err(CertificateError::MissingField { field: "batch mode not enabled".to_string() });
		}
		Ok(self.extensions)
	}

	/// Internal method to set extension value and handle batch mode.
	fn set_value(&mut self, value: Vec<u8>) {
		self.value = Some(value);
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

		self.set_value(value);
		self
	}

	/// Set key usage extension value.
	fn with_key_usage_value(mut self, key_usage_bits: u16) -> Self {
		let bytes = key_usage_bits.to_be_bytes();
		let value = vec![0x03, 0x02, 0x00, bytes[1]];

		self.set_value(value);
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

		self.set_value(value);
		self
	}

	/// Set authority key identifier extension value.
	fn with_authority_key_identifier_value<T: AsRef<[u8]>>(mut self, key_id: T) -> Self {
		let key_id = key_id.as_ref();
		let mut auth_key_id_der = vec![0x30]; // SEQUENCE
		let key_id_with_tag = [&[0x80], key_id].concat(); // [0] IMPLICIT

		auth_key_id_der.push(key_id_with_tag.len() as u8);
		auth_key_id_der.extend_from_slice(&key_id_with_tag);

		self.set_value(auth_key_id_der);
		self
	}

	include_extension!(
		/// Include a basic constraints extension in the batch.
		///
		/// This is the batch equivalent of `for_basic_constraints()`.
		include_basic_constraints,
		for_basic_constraints,
		(is_ca: bool, path_length: Option<u8>)
	);

	include_extension!(
		/// Include a key usage extension in the batch.
		///
		/// This is the batch equivalent of `for_key_usage()`.
		include_key_usage,
		for_key_usage,
		(key_usage_bits: u16)
	);

	include_extension!(
		/// Include an extended key usage extension in the batch.
		///
		/// This is the batch equivalent of `for_extended_key_usage()`.
		include_extended_key_usage,
		for_extended_key_usage,
		(ext_key_use: I)
		where_is
	);

	include_extension!(
		/// Include a subject alternative name extension in the batch.
		///
		/// This is the batch equivalent of `for_subject_alt_name()`.
		include_subject_alt_name,
		for_subject_alt_name,
		(san_entries: I)
		where_is
	);

	include_extension!(
		/// Include a subject key identifier extension in the batch.
		///
		/// This is the batch equivalent of `for_subject_key_identifier()`.
		include_subject_key_identifier,
		for_subject_key_identifier,
		(key_id: T)
		where_t
	);

	include_extension!(
		/// Include an authority key identifier extension in the batch.
		///
		/// This is the batch equivalent of `for_authority_key_identifier()`.
		include_authority_key_identifier,
		for_authority_key_identifier,
		(key_id: T)
		where_t
	);
}

/// Builder for creating X.509 certificates with a fluent API.
///
/// The `CertificateBuilder` provides a convenient way to create X.509
/// certificates following RFC 5280 standards. It supports both Certificate
/// Authority (CA) certificates and end-entity certificates with automatic
/// extension management and flexible signing options.
///
/// # Certificate Types Supported
///
/// - **Certificate Authority (CA)** - For issuing other certificates
/// - **End-Entity** - For individual users, devices, or services
/// - **Server** - For TLS/SSL server authentication
/// - **Client** - For TLS/SSL client authentication
/// - **Self-Signed** - For root CAs or testing purposes
///
/// # Required Fields
///
/// Before building a certificate, these fields must be set:
/// - `subject_public_key` - The public key to be certified
/// - `subject_dn` - The distinguished name of the certificate subject
/// - `issuer_dn` - The distinguished name of the certificate issuer
/// - `serial` - A unique serial number for the certificate
/// - `valid_from` and `valid_to` - The certificate validity period
///
/// # Automatic Extensions
///
/// When `include_common_exts` is enabled (default), the builder automatically adds:
/// - **Basic Constraints** - CA flag and path length constraints
/// - **Key Usage** - Appropriate key usage flags based on certificate type
/// - **Subject Key Identifier** - Hash of the subject's public key
/// - **Authority Key Identifier** - Hash of the issuer's public key (for self-signed certificates)
///
/// # Examples
///
/// ## Creating a Self-Signed CA Certificate
///
/// ```rust
/// use keetanetwork_x509::builder::CertificateBuilder;
/// use keetanetwork_x509::utils;
/// use keetanetwork_x509::oids;
/// use keetanetwork_x509::SerialNumber;
/// use keetanetwork_crypto::bigint::U256;
/// use chrono::Utc;
/// use keetanetwork_asn1::{SubjectPublicKeyInfo, AlgorithmIdentifier, BitString};
/// # #[cfg(all(feature = "rasn", not(feature = "der")))]
/// # use keetanetwork_asn1::BitStringExt;
///
/// // Create distinguished names
/// let subject_dn = utils::create_dn(&[(oids::CN, "My Root CA")])?;
/// let public_key_info = SubjectPublicKeyInfo {
///     algorithm: oids::ED25519.parse()?,
///     subject_public_key: BitString::from_bytes(&[0u8; 32])?,
/// };
///
/// let ca_cert_builder = CertificateBuilder::new()
///     .with_subject_public_key(public_key_info)
///     .with_subject_dn(subject_dn.clone())
///     .with_issuer_dn(subject_dn) // Self-signed
///     .with_serial_number(SerialNumber::from(1u64))
///     .with_validity_days(365 * 10) // 10 years
///     .as_ca()
///     .as_self_signed();
///
/// // Build TBS certificate for signing
/// match ca_cert_builder.build_tbs() {
///     Ok(tbs) => {
///         // Sign with your private key
///     },
///     Err(e) => {
///         // Handle error
///         panic!("Failed to build TBS certificate: {}", e);
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Creating a Server Certificate
///
/// ```rust
/// use keetanetwork_x509::{builder::CertificateBuilder, utils, oids};
/// use keetanetwork_x509::SerialNumber;
/// use keetanetwork_crypto::bigint::U256;
/// use keetanetwork_asn1::{SubjectPublicKeyInfo, AlgorithmIdentifier, BitString};
/// # #[cfg(all(feature = "rasn", not(feature = "der")))]
/// # use keetanetwork_asn1::BitStringExt;
///
/// let subject_dn = utils::create_dn(&[(oids::CN, "www.example.com")])?;
/// let issuer_dn = utils::create_dn(&[(oids::CN, "Example CA")])?;
/// let public_key_info = SubjectPublicKeyInfo {
///     algorithm: oids::ED25519.parse()?,
///     subject_public_key: BitString::from_bytes(&[0u8; 32])?,
/// };
///
/// let server_cert_builder = CertificateBuilder::for_server()
///     .with_subject_public_key(public_key_info)
///     .with_subject_dn(subject_dn)
///     .with_issuer_dn(issuer_dn)
///     .with_serial_number(SerialNumber::from(12345u64))
///     .with_validity_days(365) // 1 year
///     .with_subject_alt_name(vec![
///         "www.example.com",
///         "example.com",
///         "api.example.com"
///     ]);
///
/// match server_cert_builder.build_tbs() {
///     Ok(tbs) => {
///         // Sign with CA's private key
///     },
///     Err(e) => {
///         // Handle error
///         panic!("Failed to build TBS certificate: {}", e);
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Using Preset Configurations
///
/// ```rust
/// use keetanetwork_x509::builder::CertificateBuilder;
///
/// // CA certificate with 10-year validity and appropriate key usage
/// let ca_builder = CertificateBuilder::for_ca();
/// // End-entity certificate with 1-year validity
/// let ee_builder = CertificateBuilder::for_end_entity();
/// // Server certificate with server authentication extension
/// let server_builder = CertificateBuilder::for_server();
/// // Client certificate with client authentication extension
/// let client_builder = CertificateBuilder::for_client();
/// ```
///
/// ## Adding Custom Extensions
///
/// ```rust
/// use keetanetwork_x509::builder::{CertificateBuilder, ExtensionBuilder};
///
/// let builder = CertificateBuilder::new()
///     // ... set required fields ...
///     .with_extension(ExtensionBuilder::for_key_usage(0x80)) // Digital signature
///     .with_custom_extension("1.2.3.4.5", &[0x01, 0x02, 0x03], false)
///     .with_extensions(vec![
///         ExtensionBuilder::for_basic_constraints(false, None),
///         ExtensionBuilder::for_subject_alt_name(vec!["test.com"]),
///     ]);
/// ```
///
/// # Error Handling
///
/// The builder methods return a Result and will fail if:
/// - Required fields are missing
/// - Invalid OID formats are provided
/// - ASN.1 encoding fails
/// - Signing operations fail
///
/// # Thread Safety
///
/// This builder is `Send + Sync` and can be safely used across threads.
///
/// # References
///
/// - [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://datatracker.ietf.org/doc/html/rfc5280)
/// - [RFC 3279 - Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://datatracker.ietf.org/doc/html/rfc3279)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBuilder {
	pub subject_public_key: Option<SubjectPublicKeyInfoOwned>,
	pub subject_dn: Option<DistinguishedName>,
	pub issuer_dn: Option<DistinguishedName>,
	pub valid_from: Option<DateTime<Utc>>,
	pub valid_to: Option<DateTime<Utc>>,
	pub serial: Option<SerialNumber>,
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

	/// Set the subject's public key information.
	///
	/// This is the public key that will be certified by this certificate.
	/// The public key information includes both the algorithm identifier
	/// and the raw public key bytes.
	///
	/// # Arguments
	///
	/// * `public_key` - The subject's public key information in ASN.1 format
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_asn1::{SubjectPublicKeyInfo, AlgorithmIdentifier, BitString};
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::oids;
	/// # #[cfg(all(feature = "rasn", not(feature = "der")))]
	/// # use keetanetwork_asn1::BitStringExt;
	///
	/// let public_key_info = SubjectPublicKeyInfo {
	///     algorithm: oids::ED25519.parse().unwrap(),
	///     subject_public_key: BitString::from_bytes(&[0u8; 32]).unwrap(),
	/// };
	///
	/// let builder = CertificateBuilder::new()
	///     .with_subject_public_key(public_key_info);
	/// ```
	pub fn with_subject_public_key(mut self, public_key: SubjectPublicKeyInfo) -> Self {
		let spki_key = SubjectPublicKeyInfoOwned::from(public_key);

		self.subject_public_key = Some(spki_key);
		self
	}

	/// Set the subject distinguished name.
	///
	/// The subject DN identifies the entity being certified. For end-entity
	/// certificates, this typically includes the common name (CN) and other
	/// identifying information. For CA certificates, this identifies the
	/// certificate authority.
	///
	/// # Arguments
	///
	/// * `dn` - The distinguished name for the certificate subject
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::{utils, oids};
	///
	/// // Create a distinguished name for a web server
	/// let subject_dn = utils::create_dn(&[
	///     (oids::CN, "www.example.com"),
	///     (oids::O, "Example Corporation"),
	///     (oids::C, "US"),
	/// ])?;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_subject_dn(subject_dn);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_subject_dn(mut self, dn: DistinguishedName) -> Self {
		self.subject_dn = Some(dn);
		self
	}

	/// Set the issuer distinguished name.
	///
	/// The issuer DN identifies the entity that signs and issues this
	/// certificate. For self-signed certificates, the issuer DN should be the
	/// same as the subject DN. For CA-issued certificates, this should be the
	/// CA's distinguished name.
	///
	/// # Arguments
	///
	/// * `dn` - The distinguished name for the certificate issuer
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::{utils, oids};
	///
	/// // Create a distinguished name for a certificate authority
	/// let issuer_dn = utils::create_dn(&[
	///     (oids::CN, "Example Root CA"),
	///     (oids::O, "Example Corporation"),
	///     (oids::C, "US"),
	/// ])?;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_issuer_dn(issuer_dn);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn with_issuer_dn(mut self, dn: DistinguishedName) -> Self {
		self.issuer_dn = Some(dn);
		self
	}

	/// Set the certificate validity period.
	///
	/// Specifies the time interval during which the certificate is valid.
	/// The certificate must not be used before `not_before` or after `not_after`.
	///
	/// # Arguments
	///
	/// * `not_before` - The earliest time the certificate is valid (inclusive)
	/// * `not_after` - The latest time the certificate is valid (inclusive)
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use chrono::{Utc, Duration};
	///
	/// let now = Utc::now();
	/// let one_year_later = now + Duration::days(365);
	///
	/// let builder = CertificateBuilder::new()
	///     .with_validity(now, one_year_later);
	/// ```
	pub fn with_validity(mut self, not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
		self.valid_from = Some(not_before);
		self.valid_to = Some(not_after);
		self
	}

	/// Set the certificate serial number.
	///
	/// The serial number must be unique for each certificate issued by a given
	/// CA. It can be up to 256 bits (32 bytes) in length. For production use,
	/// serial numbers should be cryptographically random or generated using a
	/// secure sequence to prevent prediction attacks.
	///
	/// # Arguments
	///
	/// * `serial` - A unique serial number for this certificate
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::SerialNumber;
	/// use keetanetwork_crypto::bigint::{U256, Encoding};
	///
	/// // Simple sequential serial number
	/// let builder = CertificateBuilder::new()
	///     .with_serial_number(SerialNumber::from(12345u64));
	///
	/// // Large random serial number (up to 20 bytes per RFC 5280)
	/// let large_serial = U256::from_be_bytes([
	///     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	///     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	///     0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00,
	///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/// ]);
	/// let large_bytes = &large_serial.to_be_bytes()[0..20]; // Only use first 20 bytes
	/// let builder = CertificateBuilder::new()
	///     .with_serial_number(SerialNumber::new(large_bytes).unwrap());
	/// ```
	pub fn with_serial_number(mut self, serial: SerialNumber) -> Self {
		self.serial = Some(serial);
		self
	}

	/// Add a custom extension to the certificate.
	///
	/// Extensions provide additional information and constraints for the
	/// certificate. This method allows adding any extension that has already
	/// been constructed.
	///
	/// # Arguments
	///
	/// * `extension` - A pre-built extension to add to the certificate
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::{CertificateBuilder, ExtensionBuilder};
	///
	/// // Create a custom extension
	/// let key_usage_ext = ExtensionBuilder::for_key_usage(0x80); // Digital signature
	/// let builder = CertificateBuilder::new()
	///     .with_extension(key_usage_ext);
	/// ```
	pub fn with_extension(mut self, extension: Extension) -> Self {
		self.extensions.push(extension);
		self
	}

	/// Add a basic constraints extension.
	///
	/// This extension indicates whether the certificate subject is a
	/// Certificate Authority (CA) and may specify a path length constraint
	/// for subordinate CA certificates.
	///
	/// # Arguments
	///
	/// * `is_ca` - Whether this certificate represents a Certificate Authority
	/// * `path_length` - Optional maximum number of subordinate CA certificates that may follow
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Root CA certificate (no path length constraint)
	/// let root_ca = CertificateBuilder::new()
	///     .with_basic_constraints(true, None);
	///
	/// // Intermediate CA with path length constraint of 1
	/// let intermediate_ca = CertificateBuilder::new()
	///     .with_basic_constraints(true, Some(1));
	///
	/// // End-entity certificate (not a CA)
	/// let end_entity = CertificateBuilder::new()
	///     .with_basic_constraints(false, None);
	/// ```
	pub fn with_basic_constraints(mut self, is_ca: bool, path_length: Option<u8>) -> Self {
		let extension = ExtensionBuilder::for_basic_constraints(is_ca, path_length);
		self.extensions.push(extension);

		self
	}

	/// Add a key usage extension.
	///
	/// This extension defines the cryptographic purposes for which the
	/// certificate's public key may be used. Different certificate types
	/// require different key usage flags.
	///
	/// # Arguments
	///
	/// * `key_usage_bits` - Bit field representing allowed key usages
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // CA certificate for signing other certificates
	/// let ca_cert = CertificateBuilder::new()
	///     .with_key_usage(0x06); // keyCertSign + cRLSign
	///
	/// // Server certificate for TLS
	/// let server_cert = CertificateBuilder::new()
	///     .with_key_usage(0x80); // digitalSignature
	///
	/// // Client authentication certificate
	/// let client_cert = CertificateBuilder::new()
	///     .with_key_usage(0xC0); // digitalSignature + nonRepudiation
	/// ```
	pub fn with_key_usage(mut self, key_usage_bits: u16) -> Self {
		let extension = ExtensionBuilder::for_key_usage(key_usage_bits);
		self.extensions.push(extension);

		self
	}

	/// Add an extended key usage extension.
	///
	/// This extension indicates additional purposes for which the certificate's
	/// public key may be used, beyond those indicated in the Key Usage
	/// extension. This is commonly used to specify the intended application
	/// for the certificate.
	///
	/// # Arguments
	///
	/// * `ext_key_use` - An iterable of OID strings representing extended key usage purposes
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Web server certificate
	/// let server_cert = CertificateBuilder::new()
	///     .with_extended_key_usage(vec!["1.3.6.1.5.5.7.3.1"]); // Server Authentication
	///
	/// // Client certificate for mutual TLS
	/// let client_cert = CertificateBuilder::new()
	///     .with_extended_key_usage(vec!["1.3.6.1.5.5.7.3.2"]); // Client Authentication
	///
	/// // Multi-purpose certificate
	/// let multi_cert = CertificateBuilder::new()
	///     .with_extended_key_usage(vec![
	///         "1.3.6.1.5.5.7.3.1", // Server Authentication
	///         "1.3.6.1.5.5.7.3.2", // Client Authentication
	///     ]);
	/// ```
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
		let extension = ExtensionBuilder::for_extended_key_usage(ext_key_use_vec);
		self.extensions.push(extension);

		self
	}

	/// Add a subject alternative name extension.
	///
	/// This extension allows additional identities to be bound to the
	/// certificate subject.
	///
	/// # Arguments
	///
	/// * `san_entries` - An iterable collection of alternative names in various formats
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Web server certificate with multiple domains
	/// let web_cert = CertificateBuilder::new()
	///     .with_subject_alt_name(vec![
	///         "example.com",
	///         "www.example.com",
	///         "api.example.com",
	///         "*.dev.example.com", // Wildcard subdomain
	///     ]);
	///
	/// // Certificate with mixed name types
	/// let mixed_cert = CertificateBuilder::new()
	///     .with_subject_alt_name(vec![
	///         "example.com",              // DNS name
	///         "192.168.1.100",            // IPv4 address
	///         "admin@example.com",        // Email address
	///         "https://example.com/api",  // URI
	///     ]);
	/// ```
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
		let extension = ExtensionBuilder::for_subject_alt_name(san_entries_vec);
		self.extensions.push(extension);

		self
	}

	/// Add a custom extension by OID and raw value.
	///
	/// This method allows adding arbitrary X.509 extensions by specifying the
	/// OID, DER-encoded value, and criticality flag directly. Use this for
	/// extensions not supported by the built-in convenience methods.
	///
	/// # Arguments
	///
	/// * `oid` - The extension's Object Identifier in dotted decimal notation
	/// * `value` - The DER-encoded extension value bytes
	/// * `critical` - Whether the extension should be marked as critical
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// let builder = CertificateBuilder::new()
	///     .with_custom_extension(
	///         "1.2.3.4.5.6.7.8",                     // Custom OID
	///         &[0x04, 0x04, 0x01, 0x02, 0x03, 0x04], // DER-encoded OCTET STRING
	///         false                                  // Non-critical
	///     );
	/// ```
	pub fn with_custom_extension<S: AsRef<str>, T: AsRef<[u8]>>(mut self, oid: S, value: T, critical: bool) -> Self {
		if let Ok(extension) = Extension::new(oid, value, critical) {
			self.extensions.push(extension);
		}

		self
	}

	/// Set certificate validity period in days from now.
	///
	/// This is a convenience method that sets the certificate's validity period
	/// starting from the current time and extending for the specified number of
	/// days. For precise control over validity dates, use `with_validity()`.
	///
	/// # Arguments
	///
	/// * `days` - Number of days from now that the certificate should be valid
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Certificate valid for 1 year (365 days)
	/// let builder = CertificateBuilder::new()
	///     .with_validity_days(365);
	///
	/// // Long-lived CA certificate (10 years)
	/// let ca_builder = CertificateBuilder::new()
	///     .with_validity_days(365 * 10);
	/// ```
	pub fn with_validity_days(mut self, days: u64) -> Self {
		let now = Utc::now();
		let expiry = now + Duration::days(days as i64);
		self.valid_from = Some(now);
		self.valid_to = Some(expiry);

		self
	}

	/// Disable automatic addition of common extensions.
	///
	/// By default, the builder automatically adds common extensions like Basic Constraints,
	/// Key Usage, Subject Key Identifier, and Authority Key Identifier based on the
	/// certificate type. This method disables that automatic behavior.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Create a certificate with only manually added extensions
	/// let builder = CertificateBuilder::new()
	///     .without_common_extensions()
	///     .with_basic_constraints(false, None); // Manual extension only
	/// ```
	pub fn without_common_extensions(mut self) -> Self {
		self.include_common_exts = false;
		self
	}

	/// Enable automatic addition of common extensions (default behavior).
	///
	/// This method re-enables the automatic addition of common extensions if it was
	/// previously disabled. Common extensions are enabled by default when creating
	/// a new builder.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Re-enable after disabling
	/// let builder = CertificateBuilder::new()
	///     .without_common_extensions()
	///     .with_common_extensions(); // Back to default behavior
	/// ```
	pub fn with_common_extensions(mut self) -> Self {
		self.include_common_exts = true;
		self
	}

	/// Set whether this certificate represents a Certificate Authority.
	///
	/// This affects the automatic generation of extensions like Basic Constraints
	/// and Key Usage. CA certificates get different default key usage flags and
	/// the Basic Constraints extension is set to indicate CA status.
	///
	/// # Arguments
	///
	/// * `is_ca` - `true` for CA certificates, `false` for end-entity certificates
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Explicitly set as CA
	/// let ca_builder = CertificateBuilder::new()
	///     .with_is_ca(true);
	///
	/// // Explicitly set as end-entity
	/// let ee_builder = CertificateBuilder::new()
	///     .with_is_ca(false);
	/// ```
	pub fn with_is_ca(mut self, is_ca: bool) -> Self {
		self.is_ca = Some(is_ca);
		self
	}

	/// Mark the certificate as a Certificate Authority.
	///
	/// This is a convenience method equivalent to `with_is_ca(true)`. It configures
	/// the certificate to be a CA, which affects automatic extension generation.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// // Create a CA certificate
	/// let ca_builder = CertificateBuilder::new()
	///     .as_ca();
	/// ```
	pub fn as_ca(self) -> Self {
		self.with_is_ca(true)
	}

	/// Create a self-signed certificate by setting issuer equal to subject.
	///
	/// This method automatically sets the issuer DN to match the subject DN,
	/// creating a self-signed certificate. This is commonly used for root CA
	/// certificates or testing purposes.
	///
	/// Note: The subject DN must be set before calling this method.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::{utils, oids};
	///
	/// let subject_dn = utils::create_dn(&[(oids::CN, "Root CA")])?;
	/// let self_signed_builder = CertificateBuilder::new()
	///     .with_subject_dn(subject_dn)
	///     .as_self_signed(); // Issuer will be set to same as subject
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn as_self_signed(mut self) -> Self {
		if let Some(ref subject) = self.subject_dn.clone() {
			self.issuer_dn = Some(subject.clone());
		}

		self
	}

	/// Add multiple extensions at once from an iterable collection.
	///
	/// This method allows adding several pre-built extensions in a single call,
	/// which can be more convenient than calling `with_extension()` multiple times.
	///
	/// # Arguments
	///
	/// * `extensions` - An iterable collection of `Extension` objects
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::{CertificateBuilder, ExtensionBuilder};
	///
	/// // Create multiple extensions
	/// let extensions = vec![
	///     ExtensionBuilder::for_key_usage(0x80),        // Digital signature
	///     ExtensionBuilder::for_basic_constraints(false, None), // End-entity
	///     ExtensionBuilder::for_subject_alt_name(vec!["example.com"]),
	/// ];
	///
	/// // Add them all at once
	/// let builder = CertificateBuilder::new()
	///     .with_extensions(extensions);
	/// ```
	pub fn with_extensions<I>(mut self, extensions: I) -> Self
	where
		I: IntoIterator<Item = Extension>,
	{
		self.extensions.extend(extensions);
		self
	}

	/// Create a preset Certificate Authority (CA) certificate builder.
	///
	/// This preset configures the builder with settings for a CA certificate:
	/// - Marks the certificate as a CA (`is_ca = true`)
	/// - Sets key usage to certificate signing and CRL signing
	/// - Sets validity period to 10 years
	/// - Enables automatic common extensions
	///
	/// You still need to set the other required fields.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::{utils, oids};
	/// use keetanetwork_x509::SerialNumber;
	/// use keetanetwork_crypto::bigint::U256;
	/// use keetanetwork_asn1::{SubjectPublicKeyInfo, AlgorithmIdentifier, BitString};
	/// # #[cfg(all(feature = "rasn", not(feature = "der")))]
	/// # use keetanetwork_asn1::BitStringExt;
	///
	/// let ca_dn = utils::create_dn(&[(oids::CN, "Example Root CA")])?;
	/// let public_key_info = SubjectPublicKeyInfo {
	///     algorithm: oids::ED25519.parse()?,
	///     subject_public_key: BitString::from_bytes(&[0u8; 32])?,
	/// };
	///
	/// let ca_builder = CertificateBuilder::for_ca()
	///     .with_subject_public_key(public_key_info)
	///     .with_subject_dn(ca_dn.clone())
	///     .with_issuer_dn(ca_dn) // Self-signed
	///     .with_serial_number(SerialNumber::from(1u64));
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn for_ca() -> Self {
		Self::new()
			.with_is_ca(true)
			.with_key_usage(0x06) // keyCertSign + cRLSign
			.with_validity_days(365 * 10) // 10 years
	}

	/// Create a preset end-entity certificate builder.
	///
	/// This preset configures the builder with settings for an end-entity certificate:
	/// - Marks the certificate as not a CA (`is_ca = false`)
	/// - Sets key usage to digital signature and non-repudiation
	/// - Sets validity period to 1 year
	/// - Enables automatic common extensions
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// let ee_builder = CertificateBuilder::for_end_entity();
	/// // Add required fields like subject DN, public key, etc.
	/// ```
	pub fn for_end_entity() -> Self {
		Self::new()
			.with_is_ca(false)
			.with_key_usage(0xC0) // digitalSignature + nonRepudiation
			.with_validity_days(365) // 1 year
	}

	/// Create a preset server certificate builder.
	///
	/// This creates an end-entity certificate configured for TLS server
	/// authentication. It includes the Server Authentication extended key
	/// usage extension.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// let server_builder = CertificateBuilder::for_server()
	///     .with_subject_alt_name(vec![
	///         "www.example.com",
	///         "example.com",
	///     ]);
	/// // Add other required fields...
	/// ```
	pub fn for_server() -> Self {
		Self::for_end_entity().with_extended_key_usage(vec![oids::SERVER_AUTH])
	}

	/// Create a preset client certificate builder.
	///
	/// This creates an end-entity certificate configured for TLS client
	/// authentication. It includes the Client Authentication extended key
	/// usage extension.
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	///
	/// let client_builder = CertificateBuilder::for_client();
	/// // Add required fields like subject DN, public key, etc.
	/// ```
	pub fn for_client() -> Self {
		Self::for_end_entity().with_extended_key_usage(vec![oids::CLIENT_AUTH])
	}

	/// Build the TBS (To Be Signed) certificate structure.
	///
	/// This method creates the TbsCertificate structure that contains all
	/// the certificate information except the signature. The resulting TBS
	/// certificate can then be signed to create the final certificate.
	///
	/// This method validates that all required fields are present and
	/// automatically adds common extensions if enabled.
	///
	/// # Returns
	///
	/// Returns `Ok(TbsCertificate)` if all required fields are present and
	/// valid, or `Err(CertificateError)` if any required fields are missing
	/// or invalid.
	///
	/// # Required Fields
	///
	/// Before calling this method, ensure these fields are set:
	/// - `subject_public_key` (via `with_subject_public_key()`)
	/// - `subject_dn` (via `with_subject_dn()`)
	/// - `issuer_dn` (via `with_issuer_dn()`)
	/// - `valid_from` and `valid_to` (via `with_validity()` or `with_validity_days()`)
	/// - `serial` (via `with_serial_number()`)
	///
	/// # Examples
	///
	/// ```rust
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::{utils, oids};
	/// use keetanetwork_x509::SerialNumber;
	/// use keetanetwork_crypto::bigint::U256;
	/// use chrono::Utc;
	/// use keetanetwork_asn1::{SubjectPublicKeyInfo, AlgorithmIdentifier, BitString};
	/// # #[cfg(all(feature = "rasn", not(feature = "der")))]
	/// # use keetanetwork_asn1::BitStringExt;
	///
	/// let subject_dn = utils::create_dn(&[(oids::CN, "Test Certificate")])?;
	/// let issuer_dn = utils::create_dn(&[(oids::CN, "Test CA")])?;
	/// let public_key_info = SubjectPublicKeyInfo {
	///     algorithm: oids::ED25519.parse()?,
	///     subject_public_key: BitString::from_bytes(&[0u8; 32])?,
	/// };
	///
	/// let builder = CertificateBuilder::new()
	///     .with_subject_public_key(public_key_info)
	///     .with_subject_dn(subject_dn)
	///     .with_issuer_dn(issuer_dn)
	///     .with_serial_number(SerialNumber::from(1u64))
	///     .with_validity_days(365);
	///
	/// match builder.build_tbs() {
	///     Ok(tbs) => {
	///         // TBS certificate ready for signing
	///     },
	///     Err(e) => {
	///         // Handle missing or invalid fields
	///         panic!("Failed to build TBS certificate: {}", e);
	///     }
	/// }
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
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
			version: Version::V3, // X.509 v3
			serial_number: serial.to_owned(),
			signature_algorithm: AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new(oids::SHA256_WITH_RSA)?,
				parameters: None,
			},
			issuer: issuer_dn.clone(),
			validity: Validity {
				not_before: Time::try_from(SystemTime::from(valid_from))?,
				not_after: Time::try_from(SystemTime::from(valid_to))?,
			},
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
			signature_algorithm: AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new(oids::SHA256_WITH_RSA)?,
				parameters: None,
			},
			signature: der::asn1::BitString::from_bytes(&signature_bytes)?,
		})
	}

	/// Build and sign a certificate with any compatible signer.
	///
	/// This method creates a complete, signed X.509 certificate by first
	/// building the TBS (To Be Signed) certificate structure, then signing it
	/// with the provided signer. The method is generic and works with any type
	/// that implements `CryptoSignerWithOptions`.
	///
	/// # Arguments
	///
	/// * `signer` - Any object that can sign data, such as Account types
	///
	/// # Supported Signers
	///
	/// The method works with various signer types:
	/// - **Account types**: `Account<KeyED25519>`, `Account<KeyECDSASECP256K1>`, etc.
	/// - **Private keys**: `Ed25519PrivateKey`, `Secp256k1PrivateKey`, `Secp256r1PrivateKey`
	/// - **Custom signers**: Any type implementing `CryptoSignerWithOptions`
	///
	/// # Signature Algorithms
	///
	/// The method automatically selects the appropriate signature algorithm:
	/// - **Ed25519**: Pure Ed25519 signatures (no hashing)
	/// - **ECDSA (secp256k1/secp256r1)**: ECDSA with SHA-256
	///
	/// # Returns
	///
	/// Returns `Ok(Certificate)` with a complete, signed certificate, or
	/// `Err(CertificateError)` if signing fails or required fields are missing.
	///
	/// # Examples
	///
	/// ## Using an Account
	///
	/// ```rust
	/// use keetanetwork_x509::SerialNumber;
	/// use keetanetwork_x509::builder::CertificateBuilder;
	/// use keetanetwork_x509::{utils, oids};
	/// use keetanetwork_account::{KeyPair, Account, KeyED25519};
	/// use keetanetwork_asn1::{SubjectPublicKeyInfo, AlgorithmIdentifier, BitString};
	/// use keetanetwork_crypto::bigint::U256;
	/// use keetanetwork_crypto::algorithms::ed25519::Ed25519Derivation;
	/// use keetanetwork_crypto::prelude::KeyDerivation;
	/// use keetanetwork_crypto::utils::generate_random_seed;
	///
	/// // Create an account for signing
	/// let seed = generate_random_seed()?;
	/// let private_key = Ed25519Derivation::derive_from_seed(seed)?;
	/// let account = Account::<KeyED25519>::from(private_key);
	///
	/// // Get the public key info from the account public key
	/// let public_key = account.keypair.to_public_key();
	/// // Convert the public key to the SubjectPublicKeyInfo format
	/// let public_key_info = SubjectPublicKeyInfo::from(public_key);
	/// // Create the subject distinguished name (DN)
	/// let subject_dn = utils::create_dn(&[(oids::CN, "Test Certificate")])?;
	///
	/// // Build the certificate
	/// let builder = CertificateBuilder::new()
	///     .with_subject_public_key(public_key_info.clone())
	///     .with_subject_dn(subject_dn.clone())
	///     .with_issuer_dn(subject_dn) // Self-signed
	///     .with_serial_number(SerialNumber::from(1u64))
	///     .with_validity_days(365);
	///
	/// match builder.build(&account) {
	///     Ok(certificate) => {
	///         assert!(certificate.verify_signature(&public_key_info).is_ok());
	///     },
	///     Err(e) => {
	///         // Handle signing error
	///         panic!("Failed to build certificate: {}", e);
	///     }
	/// }
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	///
	/// # Errors
	///
	/// This method can fail if:
	/// - Any required fields are missing (same as `build_tbs()`)
	/// - The signer fails to sign the TBS certificate
	/// - ASN.1 encoding fails during certificate construction
	pub fn build<T, S>(&self, signer: &T) -> Result<Certificate, CertificateError>
	where
		T: CryptoSignerWithOptions<S> + 'static,
		S: SignatureEncoding,
	{
		// Determine signature algorithm OID based on the algorithm
		// Get the algorithm from the signer
		let algorithm = signer.to_algorithm();
		let signature_algorithm_oid = match algorithm {
			Algorithm::Ed25519 => oids::ED25519,
			Algorithm::Secp256k1 => oids::ECDSA_WITH_SHA256,
			Algorithm::Secp256r1 => oids::ECDSA_WITH_SHA256,
		};

		// Build the TBS certificate with the correct signature algorithm
		let mut tbs_certificate = self.build_tbs()?;
		let oid = ObjectIdentifier::new(signature_algorithm_oid)?;

		tbs_certificate.signature_algorithm = AlgorithmIdentifierOwned { oid, parameters: None };

		// Serialize the TBS certificate for signing
		let tbs_der = Vec::<u8>::try_from(&tbs_certificate)?;

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
		let signature_bit_string = der::asn1::BitString::from_bytes(signature_bytes.as_ref())?;

		// Create the final certificate
		let cert = Certificate {
			tbs_certificate,
			signature_algorithm: AlgorithmIdentifierOwned { oid, parameters: None },
			signature: signature_bit_string,
		};

		Ok(cert)
	}

	/// Create common certificate extensions
	fn create_common_extensions(&self) -> Result<Vec<Extension>, CertificateError> {
		let mut extensions = Vec::new();

		// Basic Constraints extension
		if let Some(is_ca) = self.is_ca {
			extensions.push(ExtensionBuilder::for_basic_constraints(is_ca, None));
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

			extensions.push(ExtensionBuilder::for_key_usage(key_usage_bits));
		}

		// Subject Key Identifier extension
		if let Some(subject_public_key) = &self.subject_public_key {
			let subject_key_id = generate_key_identifier(&subject_public_key.subject_public_key)?;
			extensions.push(ExtensionBuilder::for_subject_key_identifier(&subject_key_id));
		}

		// Authority Key Identifier extension (for self-signed certificates)
		if let (Some(issuer_dn), Some(subject_dn), Some(subject_public_key)) =
			(&self.issuer_dn, &self.subject_dn, &self.subject_public_key)
		{
			if issuer_dn == subject_dn {
				let authority_key_id = generate_key_identifier(&subject_public_key.subject_public_key)?;
				extensions.push(ExtensionBuilder::for_authority_key_identifier(&authority_key_id));
			}
		}

		Ok(extensions)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "der")]
	use std::str::FromStr;

	use chrono::Utc;
	use der::Decode;

	use keetanetwork_account::{Account, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
	use keetanetwork_asn1::{AlgorithmIdentifier, BitString};
	use keetanetwork_crypto::algorithms::ed25519::Ed25519PrivateKey;
	use keetanetwork_crypto::algorithms::secp256k1::Secp256k1PrivateKey;
	use keetanetwork_crypto::algorithms::secp256r1::Secp256r1PrivateKey;
	use keetanetwork_crypto::prelude::{AnyPrivateKey, KeyGeneration};

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	use keetanetwork_asn1::{BitStringExt, ObjectIdentifierExt};

	use super::*;
	use crate::certificates::{Certificate, TbsCertificate};
	use crate::oids;
	use crate::testing::TEST_CERTIFICATE_SETS;
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
					algorithm: keetanetwork_asn1::ObjectIdentifier::from_str(algorithm_oid).unwrap(),
					parameters: None,
				},
				subject_public_key: BitString::from_bytes(public_key_bytes).unwrap(),
			};

			let serial = SerialNumber::from(1u8);
			let not_before = Utc::now();
			let not_after = not_before + chrono::Duration::days(365);

			let builder = CertificateBuilder::new()
				.with_subject_public_key(public_key_info.clone())
				.with_subject_dn(subject_dn.clone())
				.with_issuer_dn(issuer_dn.clone())
				.with_validity(not_before, not_after)
				.with_serial_number(serial.clone())
				.with_is_ca($is_ca);

			let tbs = builder.build_tbs().unwrap();

			let expected_serial = SerialNumber::from(serial);
			assert_eq!(tbs.serial_number, expected_serial);
			assert_eq!(tbs.subject, subject_dn);
			assert_eq!(tbs.issuer, issuer_dn);
			assert_eq!(tbs.subject_public_key_info, SubjectPublicKeyInfoOwned::from(public_key_info));
			assert_eq!(tbs.version, Version::V3);
			assert!(tbs.extensions.is_some());

			if let Some(extensions) = &tbs.extensions {
				let extension_oids: Vec<String> = extensions
					.iter()
					.map(|ext| ext.extn_id.to_string())
					.collect();
				assert!(extension_oids.contains(&oids::BASIC_CONSTRAINTS.to_string()));
				assert!(extension_oids.contains(&oids::KEY_USAGE.to_string()));
				assert!(extension_oids.contains(&oids::SUBJECT_KEY_IDENTIFIER.to_string()));

				if subject_dn == issuer_dn {
					assert!(extension_oids.contains(&oids::AUTHORITY_KEY_IDENTIFIER.to_string()));
				}
			}

			let tbs_der = Vec::<u8>::try_from(&tbs).unwrap();
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
		let key_usage_ext = ExtensionBuilder::for_key_usage(0x0080);

		let builder = CertificateBuilder::new()
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(issuer_dn.clone())
			.with_serial_number(SerialNumber::from(12345u64))
			.with_validity_days(365)
			.with_extension(key_usage_ext)
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
			let algorithm = AlgorithmIdentifier {
				algorithm: keetanetwork_asn1::ObjectIdentifier::from_str(algorithm_oid).unwrap(),
				parameters: None,
			};
			let subject_public_key = BitString::from_bytes(public_key_bytes).unwrap();
			let public_key_info = SubjectPublicKeyInfo { algorithm, subject_public_key };

			let builder = CertificateBuilder::new()
				.with_subject_public_key(public_key_info)
				.with_subject_dn(subject_dn)
				.with_issuer_dn(issuer_dn)
				.with_serial_number(SerialNumber::from(12345u64))
				.with_validity_days(365)
				.with_is_ca(false);

			let result = builder.build_test();
			assert!(result.is_ok());
		}
	}

	#[test]
	fn test_certificate_builder_api() {
		const TEST_CERTIFICATE_SETS: &[fn() -> AnyPrivateKey] = &[
			|| AnyPrivateKey::Ed25519(Ed25519PrivateKey::generate_random().unwrap()),
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
				.with_serial_number(SerialNumber::from(serial))
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
			assert_eq!(certificate.tbs_certificate.serial_number, SerialNumber::from(serial));
			assert!(!certificate.signature.raw_bytes().is_empty());

			// Verify the certificate is self-signed and can be verified with its own public key
			let subject_public_key = &certificate.to_subject_public_key();
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

			let der_output = Vec::<u8>::try_from(&certificate);
			assert!(der_output.is_ok());

			// Verify we can parse the certificate back from PEM
			let re_parsed_cert = pem_output.unwrap().parse::<Certificate>();
			assert!(re_parsed_cert.is_ok());

			let re_parsed_cert = re_parsed_cert.unwrap();
			assert_eq!(Vec::<u8>::try_from(certificate).unwrap(), Vec::<u8>::try_from(re_parsed_cert).unwrap());
		}
	}

	#[test]
	fn test_extension_builder() {
		struct ExtensionTestCase {
			builder_fn: Box<dyn Fn() -> Extension>,
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
					let value = ext.extn_value.as_bytes();
					!value.is_empty() && value[0] == 0x30 // SEQUENCE tag
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| ExtensionBuilder::for_basic_constraints(false, None)),
				expected_oid: oids::BASIC_CONSTRAINTS,
				expected_critical: true,
				validation_fn: Box::new(|ext| {
					let value = ext.extn_value.as_bytes();
					value.len() >= 2 && value[0] == 0x30 && value[1] == 0x00 // Empty SEQUENCE
				}),
			},
			ExtensionTestCase {
				// digitalSignature + keyCertSign + cRLSign
				builder_fn: Box::new(|| ExtensionBuilder::for_key_usage(0x0186)),
				expected_oid: oids::KEY_USAGE,
				expected_critical: true,
				validation_fn: Box::new(|ext| {
					let value = ext.extn_value.as_bytes();
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
					let value = ext.extn_value.as_bytes();
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
					let value = ext.extn_value.as_bytes();
					!value.is_empty() && value[0] == 0x30 // SEQUENCE tag
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| ExtensionBuilder::for_subject_key_identifier([0x01, 0x02, 0x03, 0x04])),
				expected_oid: oids::SUBJECT_KEY_IDENTIFIER,
				expected_critical: false,
				validation_fn: Box::new(|ext| {
					let value = ext.extn_value.as_bytes();
					value == [0x01, 0x02, 0x03, 0x04]
				}),
			},
			ExtensionTestCase {
				builder_fn: Box::new(|| ExtensionBuilder::for_authority_key_identifier([0x05, 0x06, 0x07, 0x08])),
				expected_oid: oids::AUTHORITY_KEY_IDENTIFIER,
				expected_critical: false,
				validation_fn: Box::new(|ext| {
					let value = ext.extn_value.as_bytes();
					!value.is_empty() && value[0] == 0x30 // SEQUENCE tag
				}),
			},
		];

		// Test all extension types
		for test_case in test_cases {
			// Build the extension
			let extension = (test_case.builder_fn)();

			// Verify OID
			assert_eq!(extension.extn_id.to_string(), test_case.expected_oid);
			// Verify critical flag
			assert_eq!(extension.critical, test_case.expected_critical);
			// Run custom validation
			assert!((test_case.validation_fn)(&extension));
		}

		// Test fluent API customization
		let custom_basic_constraints = ExtensionBuilder::new()
			.with_oid(oids::BASIC_CONSTRAINTS)
			.with_basic_constraints_value(true, None)
			.as_non_critical()
			.build()
			.unwrap();
		assert_eq!(custom_basic_constraints.extn_id.to_string(), oids::BASIC_CONSTRAINTS);
		assert!(!custom_basic_constraints.critical);

		// Test custom extension with fluent API
		let custom_extension = ExtensionBuilder::new()
			.with_oid("1.2.3.4.5.6")
			.with_value([0xDE, 0xAD, 0xBE, 0xEF])
			.as_critical()
			.build()
			.unwrap();
		assert_eq!(custom_extension.extn_id.to_string(), "1.2.3.4.5.6");
		assert!(custom_extension.critical);
		assert_eq!(custom_extension.extn_value.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);

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
	fn test_extension_builder_batch_operations() {
		let ca_key_id = [
			0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00, 0x01, 0x02,
			0x03, 0x04,
		];
		let subject_key_id = [0xFF; 20];
		let extensions = ExtensionBuilder::batch()
			.include_basic_constraints(true, Some(5))
			.include_key_usage(0x06) // keyCertSign + cRLSign
			.include_extended_key_usage(vec![
				"1.3.6.1.5.5.7.3.1", // Server Authentication
				"1.3.6.1.5.5.7.3.2", // Client Authentication
			])
			.include_subject_alt_name(vec!["example.com", "www.example.com", "192.168.1.1", "admin@example.com"])
			.include_subject_key_identifier(subject_key_id)
			.include_authority_key_identifier(ca_key_id)
			.build_all()
			.expect("Failed to build batch extensions");

		// Verify we got all 6 extensions
		assert_eq!(extensions.len(), 6);

		// Verify basic constraints extension
		let basic_constraints = &extensions[0];
		assert_eq!(basic_constraints.extn_id.to_string(), oids::BASIC_CONSTRAINTS);
		assert!(basic_constraints.critical);

		// Verify key usage extension
		let key_usage = &extensions[1];
		assert_eq!(key_usage.extn_id.to_string(), oids::KEY_USAGE);
		assert!(key_usage.critical);

		// Verify extended key usage extension
		let extended_key_usage = &extensions[2];
		assert_eq!(extended_key_usage.extn_id.to_string(), oids::EXTENDED_KEY_USAGE);
		assert!(!extended_key_usage.critical);

		// Verify subject alternative name extension
		let subject_alt_name = &extensions[3];
		assert_eq!(subject_alt_name.extn_id.to_string(), oids::SUBJECT_ALT_NAME);
		assert!(!subject_alt_name.critical);

		// Verify subject key identifier extension
		let subject_key_identifier = &extensions[4];
		assert_eq!(subject_key_identifier.extn_id.to_string(), oids::SUBJECT_KEY_IDENTIFIER);
		assert!(!subject_key_identifier.critical);

		// Verify authority key identifier extension
		let authority_key_identifier = &extensions[5];
		assert_eq!(authority_key_identifier.extn_id.to_string(), oids::AUTHORITY_KEY_IDENTIFIER);
		assert!(!authority_key_identifier.critical);
	}

	#[test]
	fn test_extension_builder_batch_mode_enforcement() {
		// Test that include_* methods only work in batch mode
		let regular_builder = ExtensionBuilder::new();
		// These should not add extensions since we're not in batch mode
		let result = regular_builder
			.include_basic_constraints(false, None)
			.include_key_usage(0x80)
			.build_all();

		// Should fail because not in batch mode
		assert!(result.is_err());

		// Test empty batch
		let empty_extensions = ExtensionBuilder::batch()
			.build_all()
			.expect("Failed to build empty batch");
		assert_eq!(empty_extensions.len(), 0);
	}

	#[test]
	fn test_extension_builder_batch_vs_individual() {
		let ca_key_id = [0xAA; 20];
		// Create extensions individually
		let individual_basic = ExtensionBuilder::for_basic_constraints(false, None);
		let individual_key_usage = ExtensionBuilder::for_key_usage(0x80);
		let individual_san = ExtensionBuilder::for_subject_alt_name(vec!["test.com"]);
		let individual_aki = ExtensionBuilder::for_authority_key_identifier(ca_key_id);

		// Create extensions via batch
		let batch_extensions = ExtensionBuilder::batch()
			.include_basic_constraints(false, None)
			.include_key_usage(0x80)
			.include_subject_alt_name(vec!["test.com"])
			.include_authority_key_identifier(ca_key_id)
			.build_all()
			.expect("Failed to build batch extensions");

		// Compare results - should be equivalent
		assert_eq!(batch_extensions.len(), 4);

		// Compare each extension
		assert_eq!(batch_extensions[0].extn_id, individual_basic.extn_id);
		assert_eq!(batch_extensions[0].critical, individual_basic.critical);
		assert_eq!(batch_extensions[0].extn_value, individual_basic.extn_value);

		assert_eq!(batch_extensions[1].extn_id, individual_key_usage.extn_id);
		assert_eq!(batch_extensions[1].critical, individual_key_usage.critical);
		assert_eq!(batch_extensions[1].extn_value, individual_key_usage.extn_value);

		assert_eq!(batch_extensions[2].extn_id, individual_san.extn_id);
		assert_eq!(batch_extensions[2].critical, individual_san.critical);
		assert_eq!(batch_extensions[2].extn_value, individual_san.extn_value);

		assert_eq!(batch_extensions[3].extn_id, individual_aki.extn_id);
		assert_eq!(batch_extensions[3].critical, individual_aki.critical);
		assert_eq!(batch_extensions[3].extn_value, individual_aki.extn_value);
	}
}
