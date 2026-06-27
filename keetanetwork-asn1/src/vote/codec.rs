//! Backend-neutral codec for vote and vote-staple transport types.

use alloc::vec::Vec;

use super::types::{
	DecodedVoteCertificate, Extension, Fees, HashData, TbsCertificate, VoteCertificate, VoteDecodeSlot,
	VoteStapleBundle, VoteStapleDecodeSlot,
};
use crate::Asn1Error;

/// Attaches positional decode context to a backend `Result`.
trait VoteDecodeContext<T> {
	fn or_slot(self, slot: VoteDecodeSlot) -> Result<T, Asn1Error>;
	fn or_staple_slot(self, slot: VoteStapleDecodeSlot) -> Result<T, Asn1Error>;
}

impl<T, E> VoteDecodeContext<T> for Result<T, E> {
	fn or_slot(self, slot: VoteDecodeSlot) -> Result<T, Asn1Error> {
		self.map_err(|_| Asn1Error::VoteDecode { slot })
	}

	fn or_staple_slot(self, slot: VoteStapleDecodeSlot) -> Result<T, Asn1Error> {
		self.map_err(|_| Asn1Error::VoteStapleDecode { slot })
	}
}

#[cfg(feature = "der")]
mod der_codec;

#[cfg(all(feature = "rasn", not(feature = "der")))]
mod rasn_codec;

#[cfg(feature = "der")]
use der_codec as backend;

#[cfg(all(feature = "rasn", not(feature = "der")))]
use rasn_codec as backend;

/// Encode a `tbsCertificate` body to canonical DER bytes (the bytes
/// signed by the issuer).
pub fn encode_tbs(tbs: &TbsCertificate) -> Result<Vec<u8>, Asn1Error> {
	backend::encode_tbs(tbs)
}

/// Encode a complete vote certificate (TBS + signature wrapper).
pub fn encode_vote(value: &VoteCertificate) -> Result<Vec<u8>, Asn1Error> {
	backend::encode_vote(value)
}

/// Decode a vote certificate from canonical DER bytes, surfacing the
/// exact `tbsCertificate` slice that signature verification must consume.
///
/// Returns [`Asn1Error::InvalidVoteVersion`] if the certificate's
/// version field is anything other than `INTEGER 2` (the only version
/// the keetanetwork transport format supports).
pub fn decode_vote(bytes: &[u8]) -> Result<DecodedVoteCertificate, Asn1Error> {
	backend::decode_vote(bytes)
}

/// Encode a `VoteStapleBundle` (uncompressed canonical DER bytes).
pub fn encode_vote_staple(bundle: &VoteStapleBundle) -> Result<Vec<u8>, Asn1Error> {
	backend::encode_vote_staple(bundle)
}

/// Decode a `VoteStapleBundle` from uncompressed canonical DER bytes.
pub fn decode_vote_staple(bytes: &[u8]) -> Result<VoteStapleBundle, Asn1Error> {
	backend::decode_vote_staple(bytes)
}

/// Encode the body of a `hashData` extension as a self-contained DER
/// value (the `extnValue` contents, not including the outer `OCTET
/// STRING` wrapper).
pub fn encode_hash_data(value: &HashData) -> Result<Vec<u8>, Asn1Error> {
	backend::encode_hash_data(value)
}

/// Decode a `hashData` extension body produced by [`encode_hash_data`].
pub fn decode_hash_data(bytes: &[u8]) -> Result<HashData, Asn1Error> {
	backend::decode_hash_data(bytes)
}

/// Encode the body of a `fees` extension.
pub fn encode_fees(value: &Fees) -> Result<Vec<u8>, Asn1Error> {
	backend::encode_fees(value)
}

/// Decode a `fees` extension body produced by [`encode_fees`].
pub fn decode_fees(bytes: &[u8]) -> Result<Fees, Asn1Error> {
	backend::decode_fees(bytes)
}

/// Encode a single X.509 v3 `Extension` element (a SEQUENCE).
pub fn encode_extension(value: &Extension) -> Result<Vec<u8>, Asn1Error> {
	backend::encode_extension(value)
}

/// Decode a single X.509 v3 `Extension` element from a SEQUENCE-shaped
/// DER blob.
pub fn decode_extension(bytes: &[u8]) -> Result<Extension, Asn1Error> {
	backend::decode_extension(bytes)
}
