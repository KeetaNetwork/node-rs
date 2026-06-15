//! Object identifiers used by the vote certificate format.
//!
//! Each constant is the canonical OID for an attribute, key algorithm,
//! curve, hash, signature algorithm, or extension that appears in a vote
//! certificate's wire form. RFC references are noted on each constant
//! where applicable.

use der::oid::ObjectIdentifier;

/// `commonName` attribute (RFC 5280) - used by the issuer DN.
pub(crate) const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// `serialNumber` attribute (RFC 5280) - used by the subject DN.
pub(crate) const SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

/// Generic "EC public key" algorithm OID (RFC 5480).
pub(crate) const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp256k1 curve OID.
pub(crate) const SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
/// secp256r1 / NIST P-256 curve OID.
pub(crate) const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// Ed25519 algorithm OID (RFC 8410).
pub(crate) const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// `sha3-256` hash algorithm OID.
pub(crate) const SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
/// `sha3-256WithEcDSA` signature algorithm OID.
pub(crate) const ECDSA_WITH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10");

/// Block-hash extension carrier OID.
pub(crate) const HASH_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.3.1.3");
/// Fees extension OID.
pub(crate) const FEES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62675.0.1.0");
