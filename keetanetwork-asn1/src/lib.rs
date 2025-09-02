//! ASN.1 structures and utilities for cryptographic operations.
//!
//! This crate provides ASN.1 data structures commonly used in cryptographic
//! protocols, particularly X.509 certificates and related standards.
//!
//! ## Features
//!
//! - `der` - Use the `der` crate for ASN.1 handling
//! - `rasn` - Use the `rasn` crate for ASN.1 handling
//! - `serde` - Enable serde serialization support
//!
//! Exactly one of `der` or `rasn` must be enabled.
//! If both are enabled, `der` will be used by default.

// Compile-time check to ensure at least one backend is enabled
#[cfg(not(any(feature = "der", feature = "rasn")))]
compile_error!("Must enable at least one of 'der' or 'rasn' features.");

pub mod error;
pub mod oids;
pub mod utils;

// Generated types (only available with rasn feature when der is not enabled)
#[cfg(all(feature = "rasn", not(feature = "der")))]
pub mod generated;

// Backend-specific modules
#[cfg(feature = "der")]
pub mod der;

#[cfg(all(feature = "rasn", not(feature = "der")))]
pub mod rasn;

// Re-export error type
pub use error::Asn1Error;

// Re-export types based on enabled features
#[cfg(feature = "der")]
pub use der::{
	// Re-export commonly used types for convenience
	AlgorithmIdentifier,
	Any,
	BitString,
	Decode,
	Encode,
	Header,
	Ia5String,
	ObjectIdentifier,
	OctetString,
	Reader,
	Sequence,
	SetOfVec,
	SliceReader,
	SubjectPublicKeyInfo,
	Tag,
	TagNumber,
	Tagged,
	Uint,
	ValueOrd,
};

#[cfg(all(feature = "rasn", not(feature = "der")))]
pub use crate::rasn::{
	// Re-export commonly used types for convenience
	AlgorithmIdentifier,
	Any,
	BitString,
	BitStringExt,
	Decode,
	Encode,
	Ia5String,
	Integer,
	ObjectIdentifier,
	ObjectIdentifierExt,
	OctetString,
	SubjectPublicKeyInfo,
};
