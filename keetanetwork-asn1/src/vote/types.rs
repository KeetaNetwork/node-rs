//! Public domain types for the keetanetwork vote transport format.
//!
//! See `keetanetwork-asn1/asn1/vote.asn` for the canonical schema and
//! [`crate::vote::codec`] for the byte-level encode/decode entry points.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use num_bigint::BigInt;

use crate::Asn1Time;

/// Backend-neutral object identifier carried by the vote codec.
///
/// Stored as a borrowed-or-owned arc array so that well-known OIDs
/// declared in [`super::oids`] are zero-cost constants while values
/// surfaced from a decoder remain owned and self-contained.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VoteOid(Cow<'static, [u32]>);

impl VoteOid {
	/// Build an OID from a `'static` slice in `const` context (the
	/// constructor [`From::from`] cannot be called in `const`).
	pub const fn from_static(arcs: &'static [u32]) -> Self {
		Self(Cow::Borrowed(arcs))
	}

	/// Borrow the arcs as a slice.
	///
	/// Equivalent to [`AsRef::as_ref`]; offered as an inherent method so
	/// call sites inside iterator chains avoid having to disambiguate the
	/// `AsRef` target type.
	pub fn arcs(&self) -> &[u32] {
		self.0.as_ref()
	}
}

impl From<&'static [u32]> for VoteOid {
	fn from(arcs: &'static [u32]) -> Self {
		Self(Cow::Borrowed(arcs))
	}
}

impl From<Vec<u32>> for VoteOid {
	fn from(arcs: Vec<u32>) -> Self {
		Self(Cow::Owned(arcs))
	}
}

impl AsRef<[u32]> for VoteOid {
	fn as_ref(&self) -> &[u32] {
		self.0.as_ref()
	}
}

/// Signature algorithm carried in a vote certificate.
///
/// Vote certificates fix the algorithm to one of two transport-level
/// schemes: `Ed25519` for `KeyED25519` issuers, or `EcdsaWithSha3_256`
/// for any of the supported ECDSA curves (secp256k1, secp256r1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteSignatureAlgo {
	Ed25519,
	EcdsaWithSha3_256,
}

/// Curve identifier carried inside an ECDSA `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcdsaCurve {
	Secp256k1,
	Secp256r1,
}

/// `subjectPublicKeyInfo` of a vote certificate.
///
/// The transport algorithm shape depends on the keypair: `Ed25519`
/// carries a single OID with no parameters; ECDSA variants carry the
/// `id-ecPublicKey` OID with the curve OID as parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteSubjectPublicKey {
	/// Ed25519 (`id-Ed25519` algorithm, no parameters).
	Ed25519 {
		/// Raw 32-byte Ed25519 public key bits (BIT STRING contents).
		key: Vec<u8>,
	},
	/// ECDSA on `secp256k1` or `secp256r1`.
	Ecdsa {
		/// Curve identifier carried in the algorithm `parameters` slot.
		curve: EcdsaCurve,
		/// Raw uncompressed SEC1 public key bits (BIT STRING contents).
		key: Vec<u8>,
	},
}

/// A single attribute of a `RelativeDistinguishedName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeTypeAndValue {
	pub oid: VoteOid,
	pub value: String,
}

/// Outer `Name` (RFC 5280): an ordered list of `RelativeDistinguishedName`s,
/// each of which is an unordered set of attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinguishedName {
	pub rdns: Vec<Vec<AttributeTypeAndValue>>,
}

/// Vote certificate validity window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validity {
	pub not_before: Asn1Time,
	pub not_after: Asn1Time,
}

/// One X.509 v3 `Extension` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
	pub oid: VoteOid,
	pub critical: bool,
	/// Contents of the `extnValue` `OCTET STRING` (i.e. the inner DER, not
	/// including the outer `OCTET STRING` tag/length).
	pub value: Vec<u8>,
}

/// `tbsCertificate` body of a vote certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbsCertificate {
	pub serial_number: BigInt,
	pub signature_algo: VoteSignatureAlgo,
	pub issuer: DistinguishedName,
	pub validity: Validity,
	pub subject: DistinguishedName,
	pub subject_public_key: VoteSubjectPublicKey,
	pub extensions: Vec<Extension>,
}

/// Outer vote certificate (the transport form of a vote).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteCertificate {
	pub tbs: TbsCertificate,
	pub signature_algo: VoteSignatureAlgo,
	/// Raw signature bytes (BIT STRING contents, no zero-pad-bits prefix).
	pub signature: Vec<u8>,
}

/// Result of decoding a [`VoteCertificate`] from canonical DER bytes.
///
/// Carries the parsed certificate alongside the exact `tbsCertificate`
/// DER bytes consumed during decode. Signature verification is performed
/// against those bytes; surfacing them avoids any need to re-encode the
/// parsed body to recover what was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedVoteCertificate {
	pub tbs: TbsCertificate,
	pub tbs_bytes: Vec<u8>,
	pub signature_algo: VoteSignatureAlgo,
	pub signature: Vec<u8>,
}

/// Uncompressed contents of a `VoteStaple` (deflated to produce the
/// on-the-transport artifact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteStapleBundle {
	/// Each entry is the canonical bytes of one signed `Block`.
	pub blocks: Vec<Vec<u8>>,
	/// Each entry is the canonical bytes of one signed `Vote`.
	pub votes: Vec<Vec<u8>>,
}

/// Decoded body of the `hashData` extension carried inside a TBS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashData {
	/// Hash algorithm OID (always `id-sha3-256` for the current schema).
	pub algorithm: VoteOid,
	/// Raw 32-byte block hashes, in declaration order.
	pub hashes: Vec<Vec<u8>>,
}

/// One entry inside the `fees` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeEntry {
	pub quote: bool,
	pub amount: BigInt,
	pub pay_to: Option<Vec<u8>>,
	pub token: Option<Vec<u8>>,
}

/// Decoded body of the `fees` extension.
///
/// The schema branches at the outer `[0] EXPLICIT`: a single fee entry
/// is encoded inline, multiple entries are wrapped in a second
/// `[0] EXPLICIT` around the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fees {
	Single(FeeEntry),
	Multiple(Vec<FeeEntry>),
}

/// Slot inside a vote certificate where a decode failure was detected.
///
/// Surfaced via [`crate::Asn1Error::VoteDecode`] so callers (e.g. the
/// `keetanetwork-vote` crate) can map structural failures to their
/// reference-compatible error codes without re-implementing the
/// schema walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteDecodeSlot {
	/// Outer wrapper SEQUENCE failed to parse as a SEQUENCE.
	Wrapper,
	/// Trailing bytes appeared after the wrapper SEQUENCE.
	WrapperExtraData,
	/// TBS slot inside the wrapper failed to parse as a SEQUENCE.
	TbsContent,
	/// Version `[0] EXPLICIT` slot was missing or malformed.
	Version,
	/// Version INTEGER inside `[0] EXPLICIT` was missing or wrong-typed.
	VersionValue,
	/// Serial INTEGER slot was missing or wrong-typed.
	Serial,
	/// TBS-level signature algorithm SEQUENCE was missing or wrong-typed.
	SignatureAlgorithm,
	/// Issuer DN SEQUENCE was missing or wrong-typed.
	Issuer,
	/// Validity SEQUENCE was missing or wrong-typed.
	Validity,
	/// Subject DN SEQUENCE was missing or wrong-typed.
	Subject,
	/// SubjectPublicKeyInfo SEQUENCE was missing or wrong-typed.
	SubjectPublicKey,
	/// Extensions `[3] EXPLICIT` slot was missing or wrong-typed.
	Extensions,
	/// Trailing bytes inside the TBS SEQUENCE.
	TbsExtraData,
	/// Wrapper-level signature algorithm SEQUENCE was missing or wrong-typed.
	WrapperSignatureAlgorithm,
	/// Signature BIT STRING was missing or wrong-typed.
	SignatureValue,
}

/// Slot inside a vote staple bundle where a decode failure was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteStapleDecodeSlot {
	/// Outer wrapper SEQUENCE failed to parse.
	Wrapper,
	/// Blocks SEQUENCE slot was missing or wrong-typed.
	Blocks,
	/// Votes SEQUENCE slot was missing or wrong-typed.
	Votes,
	/// Trailing bytes appeared after the wrapper SEQUENCE.
	WrapperExtraData,
}

#[cfg(test)]
mod tests {
	use super::*;

	const STATIC_ARCS: &[u32] = &[1, 2, 3, 4];

	#[test]
	fn test_vote_oid_from_static_slice_borrows() {
		let oid: VoteOid = STATIC_ARCS.into();
		assert_eq!(oid.arcs(), STATIC_ARCS);
		assert_eq!(<VoteOid as AsRef<[u32]>>::as_ref(&oid), STATIC_ARCS);
	}

	#[test]
	fn test_vote_oid_from_owned_vec_owns() {
		let owned = alloc::vec![5u32, 6, 7];
		let oid = VoteOid::from(owned.clone());
		assert_eq!(oid.arcs(), owned.as_slice());
	}

	#[test]
	fn test_vote_oid_const_static_matches_from() {
		const A: VoteOid = VoteOid::from_static(STATIC_ARCS);
		let b = VoteOid::from(STATIC_ARCS);
		assert_eq!(A, b);
	}
}
