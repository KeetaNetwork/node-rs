//! ASN.1 structures and utilities for cryptographic operations.
//!
//! This crate provides ASN.1 data structures commonly used in cryptographic
//! protocols, particularly X.509 certificates and related standards.
//!
//! ## Features
//!
//! - `std` - Standard library support (default)
//! - `alloc` - Heap allocation without std
//! - `der` - Use the `der` crate for ASN.1 handling
//! - `rasn` - Use the `rasn` crate for ASN.1 handling
//! - `serde` - Enable serde serialization support
//!
//! Exactly one of `der` or `rasn` must be enabled.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(feature = "der", feature = "rasn")))]
compile_error!("Must enable at least one of 'der' or 'rasn' features.");

#[macro_use]
extern crate alloc;

#[cfg(feature = "rasn")]
use alloc::vec::Vec;

pub mod error;
pub mod oids;
pub mod utils;

// `Asn1Time` works with whichever backend is active; it just needs `chrono`
// for the underlying `DateTime` representation.
#[cfg(feature = "chrono")]
mod asn1_time;

// Backend-neutral block transport API. Requires `chrono` for [`Asn1Time`]
// and at least one codec backend (`der` or `rasn`).
#[cfg(all(feature = "chrono", any(feature = "rasn", feature = "der")))]
pub mod block;

#[cfg(feature = "rasn")]
pub mod generated;

#[cfg(feature = "der")]
pub mod der;

#[cfg(feature = "rasn")]
pub mod rasn;

pub use error::Asn1Error;

// Unprefixed re-exports: `der` wins when both features are enabled
// (preserves the legacy surface used by x509 / account / crypto).
#[cfg(feature = "der")]
pub use der::{
	AlgorithmIdentifier, Any, BitString, Decode, Encode, Header, Ia5String, ObjectIdentifier, OctetString, Reader,
	Sequence, SetOfVec, SliceReader, SubjectPublicKeyInfo, Tag, TagNumber, Tagged, Uint, ValueOrd,
};

#[cfg(all(feature = "rasn", not(feature = "der")))]
pub use crate::rasn::{
	AlgorithmIdentifier, Any, BitString, BitStringExt, Decode, Encode, Ia5String, Integer, ObjectIdentifier,
	ObjectIdentifierExt, OctetString, SubjectPublicKeyInfo,
};

#[cfg(feature = "chrono")]
pub use crate::asn1_time::Asn1Time;

/// Encode an ASN.1-compatible value as canonical DER bytes.
///
/// This is the supported entry point for serializing types defined in
/// `keetanetwork-asn1` (or any other `rasn::Encode` implementor).
#[cfg(feature = "rasn")]
pub fn encode<T: ::rasn::Encode>(value: &T) -> Result<Vec<u8>, Asn1Error> {
	::rasn::der::encode(value).map_err(Asn1Error::from)
}

/// Decode canonical DER bytes into an ASN.1-compatible value.
///
/// This is the supported entry point for deserializing types defined in
/// `keetanetwork-asn1` (or any other `rasn::Decode` implementor).
#[cfg(feature = "rasn")]
pub fn decode<T: ::rasn::Decode>(bytes: &[u8]) -> Result<T, Asn1Error> {
	::rasn::der::decode(bytes).map_err(|error| Asn1Error::RasnError { reason: format!("decode error: {error}") })
}
