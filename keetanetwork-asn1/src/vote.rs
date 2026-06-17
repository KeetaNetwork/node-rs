//! Public, backend-neutral API for the keetanetwork vote transport format.
//!
//! The vote transport is an X.509-shaped certificate (`VoteCertificate`)
//! and a deflated `(blocks, votes)` bundle (`VoteStapleBundle`). See
//! [`types`] for the transport shapes and [`codec`] for the byte-level
//! encode/decode entry points.

pub mod codec;
pub mod oids;
pub mod types;

pub use codec::{
	decode_extension, decode_fees, decode_hash_data, decode_vote, decode_vote_staple, encode_extension, encode_fees,
	encode_hash_data, encode_tbs, encode_vote, encode_vote_staple,
};
pub use types::{
	AttributeTypeAndValue, DecodedVoteCertificate, DistinguishedName, EcdsaCurve, Extension, FeeEntry, Fees, HashData,
	TbsCertificate, Validity, VoteCertificate, VoteDecodeSlot, VoteOid, VoteSignatureAlgo, VoteStapleBundle,
	VoteStapleDecodeSlot, VoteSubjectPublicKey,
};
