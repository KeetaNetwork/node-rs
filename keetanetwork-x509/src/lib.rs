//! X.509 certificate handling module
//!
//! This module provides functionality for creating, parsing, signing, and
//! validating X.509 certificates.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod asn1;
pub mod builder;
pub mod certificates;
pub mod error;
pub mod oids;
pub mod utils;

// Re-exports from x509_cert
pub use x509_cert::attr::{Attribute, AttributeType, AttributeValue};
pub use x509_cert::certificate::Version;
pub use x509_cert::name::{DistinguishedName, Name, RdnSequence, RelativeDistinguishedName};
pub use x509_cert::serial_number::SerialNumber;
pub use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
pub use x509_cert::time::{Time, Validity};

#[cfg(feature = "std")]
#[doc(hidden)]
pub mod doc_utils;
#[cfg(feature = "serde")]
pub mod serde;
#[cfg(test)]
pub mod testing;
