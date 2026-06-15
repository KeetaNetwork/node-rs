//! Vote certificate types.
//!
//! This module defines the concrete vote shapes the rest of the crate
//! produces and consumes:
//!
//! * [`UnsignedVote`] - a vote that has been validated for internal
//!   consistency but not yet signed. Produced by [`crate::VoteBuilder`]
//!   and consumed by [`UnsignedVote::sign`].
//! * [`Vote`] - a signed, byte-canonical certificate. The issuer commits
//!   to seeing the listed blocks confirmed in the ledger.
//! * [`VoteQuote`] - a non-binding vote whose fees declare `quote = true`.
//!   Used to negotiate fees without committing to confirmation.
//! * [`PossiblyExpiredVote`] - a parsed, signature-verified vote whose
//!   validity window may already have ended. Surfaced for inspection
//!   paths that must not commit to inclusion until the moment is
//!   re-checked.
//!
//! Encoding and decoding flow through the X.509-shaped wrapper in
//! [`crate::cert`]. Signing dispatches through the
//! [`CertSigner`] trait so callers do not need to branch on the issuer's
//! key algorithm: ECDSA prehashes with SHA3-256 and emits DER signatures,
//! Ed25519 signs the TBS bytes directly and emits the raw 64-byte form.

use std::sync::Arc;

use keetanetwork_account::cert::{CertSigner, CertVerifier};
use keetanetwork_block::{AccountRef, BlockHash, BlockTime};
use num_bigint::BigInt;

use crate::cert::{decode_wrapper, encode_tbs, encode_wrapper, DecodedVote, SignatureAlgo};
use crate::error::VoteError;
use crate::fee::Fees;
use crate::hash::VoteHash;
use crate::validation::ValidationConfig;
use crate::validity::Validity;

/// A vote prior to signing.
#[derive(Debug, Clone)]
pub struct UnsignedVote {
	serial: BigInt,
	issuer: AccountRef,
	validity: Validity,
	blocks: Vec<BlockHash>,
	fees: Option<Fees>,
}

impl UnsignedVote {
	/// Construct a new unsigned vote, validating internal consistency:
	///
	/// * issuer must be a signing key (ECDSA secp256k1/r1 or Ed25519);
	/// * `blocks` must be non-empty;
	/// * the `quote` flag (when fees are present) must distinguish a
	///   [`Vote`] (`false`) from a [`VoteQuote`] (`true`) - both shapes are
	///   constructed via the same primitive and validated by the wrappers.
	pub fn try_new(
		serial: BigInt,
		issuer: AccountRef,
		validity: Validity,
		blocks: Vec<BlockHash>,
		fees: Option<Fees>,
	) -> Result<Self, VoteError> {
		// Confirm the issuer can produce certificate-mode signatures.
		SignatureAlgo::from_issuer(&issuer)?;
		if blocks.is_empty() {
			return Err(VoteError::MalformedVoteNoBlocksFound);
		}
		Ok(Self { serial, issuer, validity, blocks, fees })
	}

	/// The vote's serial number.
	pub fn serial(&self) -> &BigInt {
		&self.serial
	}

	/// The issuing representative.
	pub fn issuer(&self) -> &AccountRef {
		&self.issuer
	}

	/// The validity range.
	pub fn validity(&self) -> &Validity {
		&self.validity
	}

	/// The covered block hashes (in declaration order).
	pub fn blocks(&self) -> &[BlockHash] {
		&self.blocks
	}

	/// Optional fees declared by the issuer.
	pub fn fees(&self) -> Option<&Fees> {
		self.fees.as_ref()
	}

	/// Whether this is a quote vote (fees present and `quote = true`).
	pub fn is_quote(&self) -> bool {
		matches!(&self.fees, Some(fees) if fees.quote())
	}

	/// Build the TBS bytes that will be signed.
	pub fn tbs_bytes(&self) -> Result<Vec<u8>, VoteError> {
		let algo = SignatureAlgo::from_issuer(&self.issuer)?;
		encode_tbs(&self.serial, algo, &self.issuer, self.validity, &self.blocks, self.fees.as_ref())
	}

	/// Sign and serialize this vote using the supplied signer.
	///
	/// `signer` must correspond to [`Self::issuer`]; the contract is that
	/// the resulting certificate's `signatureValue` is verifiable against
	/// the issuer's public key.
	pub fn sign(self, signer: &(impl CertSigner + ?Sized)) -> Result<Vote, VoteError> {
		let algo = SignatureAlgo::from_issuer(&self.issuer)?;
		let tbs_bytes = encode_tbs(&self.serial, algo, &self.issuer, self.validity, &self.blocks, self.fees.as_ref())?;
		let signature = signer.sign_for_cert(&tbs_bytes).map_err(VoteError::from)?;
		let serialized = encode_wrapper(&tbs_bytes, algo, &signature)?;
		let decoded = DecodedVote {
			serial: self.serial,
			signature_algo: algo,
			issuer: self.issuer,
			validity: self.validity,
			blocks: self.blocks,
			fees: self.fees,
			signature,
			tbs_bytes,
		};
		Ok(Vote { decoded: Arc::new(decoded), serialized: Arc::new(serialized) })
	}
}

/// A signed, byte-for-byte canonical vote certificate.
#[derive(Debug, Clone)]
pub struct Vote {
	decoded: Arc<DecodedVote>,
	/// The DER-encoded vote certificate.
	serialized: Arc<Vec<u8>>,
}

impl Vote {
	/// Decode a vote certificate without verifying its signature.
	///
	/// Use this only when the bytes have already been authenticated through
	/// another path. Most callers should prefer [`Self::verify`].
	pub fn from_serialized(bytes: impl Into<Vec<u8>>) -> Result<Self, VoteError> {
		let bytes: Vec<u8> = bytes.into();
		let decoded = decode_wrapper(&bytes)?;
		// Reject non-canonical DER: re-encoding the parsed components must
		// reproduce the input bytes exactly, otherwise the wire form was
		// not the unique canonical representation of its contents.
		let canonical = encode_wrapper(&decoded.tbs_bytes, decoded.signature_algo, &decoded.signature)?;
		if canonical != bytes {
			return Err(VoteError::MalformedNonCanonicalEncoding);
		}
		Ok(Self { decoded: Arc::new(decoded), serialized: Arc::new(bytes) })
	}

	/// Decode and verify the certificate's signature.
	pub fn verify(bytes: impl Into<Vec<u8>>) -> Result<Self, VoteError> {
		let vote = Self::from_serialized(bytes)?;
		vote.decoded
			.issuer
			.verify_for_cert(&vote.decoded.tbs_bytes, &vote.decoded.signature)
			.map_err(VoteError::from)?;
		Ok(vote)
	}

	/// The serialized DER bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.serialized
	}

	/// Take ownership of the serialized bytes.
	pub fn into_bytes(self) -> Vec<u8> {
		Arc::try_unwrap(self.serialized).unwrap_or_else(|arc| (*arc).clone())
	}

	/// SHA3-256 hash of the serialized bytes.
	pub fn hash(&self) -> VoteHash {
		VoteHash::of(self.as_bytes())
	}

	/// Vote serial.
	pub fn serial(&self) -> &BigInt {
		&self.decoded.serial
	}

	/// The issuing representative.
	pub fn issuer(&self) -> &AccountRef {
		&self.decoded.issuer
	}

	/// The validity range.
	pub fn validity(&self) -> &Validity {
		&self.decoded.validity
	}

	/// The block hashes covered by the vote.
	pub fn blocks(&self) -> &[BlockHash] {
		&self.decoded.blocks
	}

	/// Optional fee schedule declared by the issuer.
	pub fn fees(&self) -> Option<&Fees> {
		self.decoded.fees.as_ref()
	}

	/// Whether this is a quote vote (fees present and `quote = true`).
	pub fn is_quote(&self) -> bool {
		matches!(self.fees(), Some(fees) if fees.quote())
	}

	/// Whether the vote is expired at `moment` under `config`.
	pub fn is_expired_at(&self, moment: BlockTime, config: ValidationConfig) -> bool {
		self.decoded.validity.is_expired_at(moment, config)
	}

	/// Whether the vote is permanent at `moment` under `config`.
	pub fn is_permanent_at(&self, moment: BlockTime, config: ValidationConfig) -> bool {
		self.decoded.validity.is_permanent_at(moment, config)
	}
}

impl AsRef<[u8]> for Vote {
	fn as_ref(&self) -> &[u8] {
		self.as_bytes()
	}
}

/// A vote restricted to the quote phase: fees must be present with
/// `quote = true`.
#[derive(Debug, Clone)]
pub struct VoteQuote(Vote);

impl VoteQuote {
	/// Construct from an already-verified [`Vote`], enforcing the quote
	/// invariant.
	pub fn try_from_vote(vote: Vote) -> Result<Self, VoteError> {
		if !vote.is_quote() {
			return Err(VoteError::QuoteFeeRequired);
		}
		Ok(Self(vote))
	}

	/// Decode and verify the certificate, then enforce quote semantics.
	pub fn verify(bytes: impl Into<Vec<u8>>) -> Result<Self, VoteError> {
		Self::try_from_vote(Vote::verify(bytes)?)
	}

	/// Reference to the underlying vote.
	pub fn as_vote(&self) -> &Vote {
		&self.0
	}

	/// Consume the wrapper and recover the underlying vote.
	pub fn into_vote(self) -> Vote {
		self.0
	}

	/// SHA3-256 hash of the serialized bytes.
	pub fn hash(&self) -> VoteHash {
		self.0.hash()
	}
}

impl AsRef<Vote> for VoteQuote {
	fn as_ref(&self) -> &Vote {
		&self.0
	}
}

/// A vote that has been parsed but may currently be expired. Useful for
/// inspection paths (e.g. retrieving signature or contents) without
/// committing to the staple-inclusion contract.
#[derive(Debug, Clone)]
pub struct PossiblyExpiredVote(Vote);

impl PossiblyExpiredVote {
	/// Decode and verify the signature, regardless of whether the vote has
	/// expired.
	pub fn verify(bytes: impl Into<Vec<u8>>) -> Result<Self, VoteError> {
		Ok(Self(Vote::verify(bytes)?))
	}

	/// Promote to a [`Vote`] if the vote is still valid at `moment` under
	/// `config`.
	pub fn ensure_active_at(self, moment: BlockTime, config: ValidationConfig) -> Result<Vote, VoteError> {
		if self.0.is_expired_at(moment, config) {
			return Err(VoteError::Expired);
		}
		Ok(self.0)
	}

	/// Reference to the underlying vote.
	pub fn as_vote(&self) -> &Vote {
		&self.0
	}
}

impl AsRef<Vote> for PossiblyExpiredVote {
	fn as_ref(&self) -> &Vote {
		&self.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_block::Amount;

	use crate::fee::Fee;
	use crate::testing::{
		ed25519_issuer, find_version_tag, moment, secp256k1_issuer, secp256r1_issuer, validity_seconds,
	};

	/// One block, two-byte clone-friendly default for tests that don't
	/// care about block contents.
	fn default_blocks() -> Vec<BlockHash> {
		vec![BlockHash::from([7u8; 32])]
	}

	/// Build an `UnsignedVote` with sensible defaults; callers override only
	/// the dimensions they care about.
	fn unsigned_with(issuer: &AccountRef, blocks: Vec<BlockHash>, fees: Option<Fees>) -> UnsignedVote {
		UnsignedVote::try_new(BigInt::from(11u8), issuer.clone(), validity_seconds(0, 60), blocks, fees)
			.expect("UnsignedVote must build")
	}

	/// Sign `unsigned` with `issuer`.
	fn sign_with(unsigned: UnsignedVote, issuer: &AccountRef) -> Vote {
		unsigned
			.sign(issuer.as_ref())
			.expect("signing must succeed")
	}

	#[test]
	fn test_unsigned_vote_requires_blocks() {
		let issuer = ed25519_issuer(b"alice");
		let result = UnsignedVote::try_new(BigInt::from(1u8), issuer, validity_seconds(0, 60), Vec::new(), None);
		assert!(matches!(result, Err(VoteError::MalformedVoteNoBlocksFound)));
	}

	#[test]
	fn test_sign_verify_round_trip_ed25519() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let blocks = default_blocks();
		let vote = sign_with(unsigned_with(&issuer, blocks.clone(), None), &issuer);

		let verified = Vote::verify(vote.as_bytes().to_vec())?;
		assert_eq!(verified.serial(), &BigInt::from(11u8));
		assert_eq!(verified.blocks(), blocks.as_slice());
		assert_eq!(verified.hash(), vote.hash());
		Ok(())
	}

	#[test]
	fn test_sign_verify_round_trip_secp256k1() -> Result<(), VoteError> {
		let issuer = secp256k1_issuer(b"alice");
		let vote = sign_with(unsigned_with(&issuer, default_blocks(), None), &issuer);
		Vote::verify(vote.as_bytes().to_vec())?;
		Ok(())
	}

	#[test]
	fn test_sign_verify_round_trip_secp256r1() -> Result<(), VoteError> {
		let issuer = secp256r1_issuer(b"alice");
		let vote = sign_with(unsigned_with(&issuer, default_blocks(), None), &issuer);
		Vote::verify(vote.as_bytes().to_vec())?;
		Ok(())
	}

	#[test]
	fn test_corrupted_signature_rejected() {
		let issuer = ed25519_issuer(b"alice");
		let vote = sign_with(unsigned_with(&issuer, default_blocks(), None), &issuer);

		let mut tampered = vote.as_bytes().to_vec();
		let last = tampered.len() - 1;
		tampered[last] ^= 0xFF;
		assert!(Vote::verify(tampered).is_err());
	}

	#[test]
	fn test_corrupted_tbs_rejected() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let vote = sign_with(unsigned_with(&issuer, default_blocks(), None), &issuer);

		let mut tampered = vote.as_bytes().to_vec();
		let position = find_version_tag(&tampered)?;
		tampered[position + 4] = 0xff;
		assert!(Vote::verify(tampered).is_err());
		Ok(())
	}

	#[test]
	fn test_quote_invariant_enforced() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let fees = Fees::Single { quote: true, fee: Fee { amount: Amount::from(1u64), pay_to: None, token: None } };
		let vote = sign_with(unsigned_with(&issuer, default_blocks(), Some(fees)), &issuer);
		let quote = VoteQuote::try_from_vote(vote.clone())?;
		assert!(quote.as_vote().is_quote());

		let unsigned_no_quote = UnsignedVote::try_new(
			BigInt::from(12u8),
			vote.issuer().clone(),
			*vote.validity(),
			vote.blocks().to_vec(),
			None,
		)?;
		let other_vote = sign_with(unsigned_no_quote, &issuer);
		assert!(matches!(VoteQuote::try_from_vote(other_vote), Err(VoteError::QuoteFeeRequired)));
		Ok(())
	}

	#[test]
	fn test_possibly_expired_promotion() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let unsigned =
			UnsignedVote::try_new(BigInt::from(11u8), issuer.clone(), validity_seconds(0, 1), default_blocks(), None)?;
		let vote = sign_with(unsigned, &issuer);

		let possibly = PossiblyExpiredVote::verify(vote.as_bytes().to_vec())?;
		possibly
			.clone()
			.ensure_active_at(moment(0), ValidationConfig::default())?;

		let result = possibly.ensure_active_at(moment(10_000_000), ValidationConfig::default());
		assert!(matches!(result, Err(VoteError::Expired)));
		Ok(())
	}

	#[test]
	fn test_non_canonical_bytes_rejected() {
		let issuer = ed25519_issuer(b"alice");
		let vote = sign_with(unsigned_with(&issuer, default_blocks(), None), &issuer);

		let mut tampered = vote.as_bytes().to_vec();
		tampered.push(0x00);
		assert!(Vote::from_serialized(tampered).is_err());
	}
}
