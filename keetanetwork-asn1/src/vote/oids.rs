//! Object identifiers consumed by the vote codec.
//!
//! Each constant is the canonical OID for an attribute, key algorithm,
//! curve, hash, signature algorithm, or extension that appears in a
//! vote certificate's transport form. RFC references are noted on each
//! constant where applicable.

use super::types::VoteOid;

/// `commonName` attribute (RFC 5280) — used by the issuer DN.
pub const COMMON_NAME: VoteOid = VoteOid::from_static(&[2, 5, 4, 3]);
/// `serialNumber` attribute (RFC 5280) — used by the subject DN.
pub const SERIAL_NUMBER: VoteOid = VoteOid::from_static(&[2, 5, 4, 5]);

/// Generic "EC public key" algorithm OID (RFC 5480).
pub const EC_PUBLIC_KEY: VoteOid = VoteOid::from_static(&[1, 2, 840, 10045, 2, 1]);
/// secp256k1 curve OID.
pub const SECP256K1: VoteOid = VoteOid::from_static(&[1, 3, 132, 0, 10]);
/// secp256r1 / NIST P-256 curve OID.
pub const SECP256R1: VoteOid = VoteOid::from_static(&[1, 2, 840, 10045, 3, 1, 7]);
/// Ed25519 algorithm OID (RFC 8410).
pub const ED25519: VoteOid = VoteOid::from_static(&[1, 3, 101, 112]);

/// `sha3-256` hash algorithm OID.
pub const SHA3_256: VoteOid = VoteOid::from_static(&[2, 16, 840, 1, 101, 3, 4, 2, 8]);
/// `sha3-256WithEcDSA` signature algorithm OID.
pub const ECDSA_WITH_SHA3_256: VoteOid = VoteOid::from_static(&[2, 16, 840, 1, 101, 3, 4, 3, 10]);

/// Block-hash extension carrier OID.
pub const HASH_DATA: VoteOid = VoteOid::from_static(&[2, 16, 840, 1, 101, 3, 3, 1, 3]);
/// Fees extension OID.
pub const FEES: VoteOid = VoteOid::from_static(&[1, 3, 6, 1, 4, 1, 62675, 0, 1, 0]);
