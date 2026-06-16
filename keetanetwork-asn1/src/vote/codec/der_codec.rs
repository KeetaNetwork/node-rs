//! `der`-backed encode/decode for vote certificate transport types.
//!
//! Hand-rolled canonical DER. The byte layout is the source of truth
//! consumed by the reference TypeScript node; both backends must agree
//! with this implementation byte-for-byte.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use der::asn1::{AnyRef, BitStringRef, OctetStringRef, Utf8StringRef};
use der::oid::ObjectIdentifier;
use der::{Decode, Encode, ErrorKind, Length, Reader, SliceReader, Tag, TagNumber, Tagged};
use num_bigint::BigInt;

use super::super::oids;
use super::super::types::{
	AttributeTypeAndValue, DecodedVoteCertificate, DistinguishedName, EcdsaCurve, Extension, FeeEntry, Fees, HashData,
	TbsCertificate, Validity, VoteCertificate, VoteDecodeSlot, VoteOid, VoteSignatureAlgo, VoteStapleBundle,
	VoteStapleDecodeSlot, VoteSubjectPublicKey,
};
use crate::Asn1Error;
use crate::Asn1Time;

const VERSION_TAG: TagNumber = TagNumber::N0;
const EXTENSIONS_TAG: TagNumber = TagNumber::N3;
const HASH_DATA_OUTER_TAG: TagNumber = TagNumber::N0;
const FEE_OUTER_TAG: TagNumber = TagNumber::N0;
const FEE_MULTIPLE_TAG: TagNumber = TagNumber::N0;
const FEE_PAY_TO_TAG: TagNumber = TagNumber::N0;
const FEE_TOKEN_TAG: TagNumber = TagNumber::N1;
const VOTE_VERSION_VALUE: u8 = 2;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub(super) fn encode_tbs(tbs: &TbsCertificate) -> Result<Vec<u8>, Asn1Error> {
	let mut out = Vec::new();

	let mut version = Vec::new();
	encode_bigint(&mut version, &BigInt::from(VOTE_VERSION_VALUE))?;
	out.extend_from_slice(&wrap_explicit_context(VERSION_TAG, &version)?);

	encode_bigint(&mut out, &tbs.serial_number)?;
	out.extend_from_slice(&encode_signature_algo_sequence(tbs.signature_algo)?);
	out.extend_from_slice(&encode_distinguished_name(&tbs.issuer)?);
	out.extend_from_slice(&encode_validity(&tbs.validity)?);
	out.extend_from_slice(&encode_distinguished_name(&tbs.subject)?);
	out.extend_from_slice(&encode_subject_public_key_info(&tbs.subject_public_key)?);
	out.extend_from_slice(&encode_extensions_field(&tbs.extensions)?);

	wrap_sequence(&out)
}

pub(super) fn encode_vote(value: &VoteCertificate) -> Result<Vec<u8>, Asn1Error> {
	let tbs_bytes = encode_tbs(&value.tbs)?;
	let mut out = Vec::new();
	out.extend_from_slice(&tbs_bytes);
	out.extend_from_slice(&encode_signature_algo_sequence(value.signature_algo)?);
	out.extend_from_slice(&encode_signature_bit_string(&value.signature)?);
	wrap_sequence(&out)
}

pub(super) fn decode_vote(bytes: &[u8]) -> Result<DecodedVoteCertificate, Asn1Error> {
	let mut outer = SliceReader::new(bytes).map_err(|_| slot(VoteDecodeSlot::Wrapper))?;
	let wrapper_inner = read_sequence(&mut outer).map_err(|_| slot(VoteDecodeSlot::Wrapper))?;
	if !outer.is_finished() {
		return Err(slot(VoteDecodeSlot::WrapperExtraData));
	}

	// Reference rejects wrappers that are not exactly 3 elements (TBS,
	// signature algorithm, signature) before inspecting individual slot
	// types, so we mirror that ordering here.
	let mut count_reader = SliceReader::new(wrapper_inner).map_err(|_| slot(VoteDecodeSlot::Wrapper))?;
	let mut wrapper_count: usize = 0;
	while !count_reader.is_finished() {
		AnyRef::decode(&mut count_reader).map_err(|_| slot(VoteDecodeSlot::Wrapper))?;
		wrapper_count = wrapper_count.saturating_add(1);
	}
	if wrapper_count != 3 {
		return Err(slot(VoteDecodeSlot::Wrapper));
	}

	let mut wrapper_reader = SliceReader::new(wrapper_inner).map_err(|_| slot(VoteDecodeSlot::Wrapper))?;

	let tbs_bytes = capture_tlv(&mut wrapper_reader, Tag::Sequence).map_err(|_| slot(VoteDecodeSlot::TbsContent))?;
	let mut tbs_outer = SliceReader::new(&tbs_bytes).map_err(|_| slot(VoteDecodeSlot::TbsContent))?;
	let tbs_content = read_sequence(&mut tbs_outer).map_err(|_| slot(VoteDecodeSlot::TbsContent))?;
	if !tbs_outer.is_finished() {
		return Err(slot(VoteDecodeSlot::TbsContent));
	}

	let mut tbs_reader = SliceReader::new(tbs_content).map_err(|_| slot(VoteDecodeSlot::TbsContent))?;
	let version_bytes =
		read_explicit_context(&mut tbs_reader, VERSION_TAG).map_err(|_| slot(VoteDecodeSlot::Version))?;
	let mut version_reader = SliceReader::new(version_bytes).map_err(|_| slot(VoteDecodeSlot::VersionValue))?;
	let version = read_bigint(&mut version_reader).map_err(|_| slot(VoteDecodeSlot::VersionValue))?;
	if !version_reader.is_finished() {
		return Err(slot(VoteDecodeSlot::VersionValue));
	}
	if version != BigInt::from(VOTE_VERSION_VALUE) {
		return Err(Asn1Error::InvalidVoteVersion);
	}

	let serial_number = read_bigint(&mut tbs_reader).map_err(|_| slot(VoteDecodeSlot::Serial))?;
	let signature_algo_tbs =
		decode_signature_algo_sequence(&mut tbs_reader).map_err(|_| slot(VoteDecodeSlot::SignatureAlgorithm))?;
	let issuer = decode_distinguished_name(&mut tbs_reader).map_err(|_| slot(VoteDecodeSlot::Issuer))?;
	let validity = decode_validity(&mut tbs_reader).map_err(|_| slot(VoteDecodeSlot::Validity))?;
	let subject = decode_distinguished_name(&mut tbs_reader).map_err(|_| slot(VoteDecodeSlot::Subject))?;
	let subject_public_key =
		decode_subject_public_key_info(&mut tbs_reader).map_err(|_| slot(VoteDecodeSlot::SubjectPublicKey))?;
	let extensions = decode_extensions_field(&mut tbs_reader).map_err(|_| slot(VoteDecodeSlot::Extensions))?;
	if !tbs_reader.is_finished() {
		return Err(slot(VoteDecodeSlot::TbsExtraData));
	}

	let signature_algo_outer = decode_signature_algo_sequence(&mut wrapper_reader)
		.map_err(|_| slot(VoteDecodeSlot::WrapperSignatureAlgorithm))?;
	let signature =
		decode_signature_bit_string(&mut wrapper_reader).map_err(|_| slot(VoteDecodeSlot::SignatureValue))?;
	if !wrapper_reader.is_finished() {
		return Err(slot(VoteDecodeSlot::SignatureValue));
	}

	let tbs = TbsCertificate {
		serial_number,
		signature_algo: signature_algo_tbs,
		issuer,
		validity,
		subject,
		subject_public_key,
		extensions,
	};

	Ok(DecodedVoteCertificate { tbs, tbs_bytes, signature_algo: signature_algo_outer, signature })
}

fn slot(slot: VoteDecodeSlot) -> Asn1Error {
	Asn1Error::VoteDecode { slot }
}

fn staple_slot(slot: VoteStapleDecodeSlot) -> Asn1Error {
	Asn1Error::VoteStapleDecode { slot }
}

pub(super) fn encode_vote_staple(bundle: &VoteStapleBundle) -> Result<Vec<u8>, Asn1Error> {
	let mut blocks_content = Vec::new();
	for block in &bundle.blocks {
		encode_octet(&mut blocks_content, block)?;
	}

	let blocks_sequence = wrap_sequence(&blocks_content)?;

	let mut votes_content = Vec::new();
	for vote in &bundle.votes {
		encode_octet(&mut votes_content, vote)?;
	}

	let votes_sequence = wrap_sequence(&votes_content)?;

	let mut content = Vec::new();
	content.extend_from_slice(&blocks_sequence);
	content.extend_from_slice(&votes_sequence);

	wrap_sequence(&content)
}

pub(super) fn decode_vote_staple(bytes: &[u8]) -> Result<VoteStapleBundle, Asn1Error> {
	let mut outer = SliceReader::new(bytes).map_err(|_| staple_slot(VoteStapleDecodeSlot::Wrapper))?;
	let inner = read_sequence(&mut outer).map_err(|_| staple_slot(VoteStapleDecodeSlot::Wrapper))?;
	if !outer.is_finished() {
		return Err(staple_slot(VoteStapleDecodeSlot::WrapperExtraData));
	}

	// Reference rejects staple wrappers that are not exactly 2 elements
	// (blocks SEQUENCE, votes SEQUENCE) before inspecting individual slot
	// types, so we mirror that ordering here.
	let mut count_reader = SliceReader::new(inner).map_err(|_| staple_slot(VoteStapleDecodeSlot::Wrapper))?;
	let mut wrapper_count: usize = 0;
	while !count_reader.is_finished() {
		AnyRef::decode(&mut count_reader).map_err(|_| staple_slot(VoteStapleDecodeSlot::Wrapper))?;
		wrapper_count = wrapper_count.saturating_add(1);
	}
	if wrapper_count != 2 {
		return Err(staple_slot(VoteStapleDecodeSlot::Wrapper));
	}

	let mut inner_reader = SliceReader::new(inner).map_err(|_| staple_slot(VoteStapleDecodeSlot::Wrapper))?;

	let blocks_inner = read_sequence(&mut inner_reader).map_err(|_| staple_slot(VoteStapleDecodeSlot::Blocks))?;
	let mut blocks_reader = SliceReader::new(blocks_inner).map_err(|_| staple_slot(VoteStapleDecodeSlot::Blocks))?;
	let mut blocks: Vec<Vec<u8>> = Vec::new();
	while !blocks_reader.is_finished() {
		let raw = read_octet(&mut blocks_reader).map_err(|_| staple_slot(VoteStapleDecodeSlot::Blocks))?;
		blocks.push(raw.to_vec());
	}

	let votes_inner = read_sequence(&mut inner_reader).map_err(|_| staple_slot(VoteStapleDecodeSlot::Votes))?;
	let mut votes_reader = SliceReader::new(votes_inner).map_err(|_| staple_slot(VoteStapleDecodeSlot::Votes))?;
	let mut votes: Vec<Vec<u8>> = Vec::new();
	while !votes_reader.is_finished() {
		let raw = read_octet(&mut votes_reader).map_err(|_| staple_slot(VoteStapleDecodeSlot::Votes))?;
		votes.push(raw.to_vec());
	}

	if !inner_reader.is_finished() {
		return Err(staple_slot(VoteStapleDecodeSlot::WrapperExtraData));
	}

	Ok(VoteStapleBundle { blocks, votes })
}

pub(super) fn encode_hash_data(value: &HashData) -> Result<Vec<u8>, Asn1Error> {
	let mut hashes_content = Vec::new();
	for hash in &value.hashes {
		encode_octet(&mut hashes_content, hash)?;
	}

	let hashes_sequence = wrap_sequence(&hashes_content)?;
	let mut inner = Vec::new();

	encode_oid(&mut inner, &value.algorithm)?;
	inner.extend_from_slice(&hashes_sequence);

	let inner_sequence = wrap_sequence(&inner)?;
	wrap_explicit_context(HASH_DATA_OUTER_TAG, &inner_sequence)
}

pub(super) fn decode_hash_data(bytes: &[u8]) -> Result<HashData, Asn1Error> {
	let mut outer_reader = SliceReader::new(bytes)?;
	let outer_inner = read_explicit_context(&mut outer_reader, HASH_DATA_OUTER_TAG)?;
	if !outer_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	let mut sequence_reader = SliceReader::new(outer_inner)?;
	let sequence_bytes = read_sequence(&mut sequence_reader)?;
	if !sequence_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	let mut inner_reader = SliceReader::new(sequence_bytes)?;
	let algorithm = decode_oid(&mut inner_reader)?;
	let hashes_bytes = read_sequence(&mut inner_reader)?;
	if !inner_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	let mut hashes_reader = SliceReader::new(hashes_bytes)?;
	let mut hashes: Vec<Vec<u8>> = Vec::new();
	while !hashes_reader.is_finished() {
		let raw = read_octet(&mut hashes_reader)?;
		hashes.push(raw.to_vec());
	}

	Ok(HashData { algorithm, hashes })
}

pub(super) fn encode_fees(value: &Fees) -> Result<Vec<u8>, Asn1Error> {
	let inner = match value {
		Fees::Single(entry) => encode_fee_entry(entry)?,
		Fees::Multiple(entries) => {
			let mut content = Vec::new();
			for entry in entries {
				content.extend_from_slice(&encode_fee_entry(entry)?);
			}

			let sequence_of = wrap_sequence(&content)?;
			wrap_explicit_context(FEE_MULTIPLE_TAG, &sequence_of)?
		}
	};
	wrap_explicit_context(FEE_OUTER_TAG, &inner)
}

pub(super) fn decode_fees(bytes: &[u8]) -> Result<Fees, Asn1Error> {
	let mut outer_reader = SliceReader::new(bytes)?;
	let inner_bytes = read_explicit_context(&mut outer_reader, FEE_OUTER_TAG)?;
	if !outer_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	let mut inner_reader = SliceReader::new(inner_bytes)?;
	let next = peek_tag(&inner_reader)?;
	match next {
		Tag::Sequence => {
			let entry_bytes = read_sequence(&mut inner_reader)?;
			let entry = decode_fee_entry(entry_bytes)?;
			if !inner_reader.is_finished() {
				return Err(unexpected_tag_err(Tag::Sequence));
			}

			Ok(Fees::Single(entry))
		}
		Tag::ContextSpecific { constructed: true, number } if number == FEE_MULTIPLE_TAG => {
			let multi_bytes = read_explicit_context(&mut inner_reader, FEE_MULTIPLE_TAG)?;
			if !inner_reader.is_finished() {
				return Err(unexpected_tag_err(Tag::Sequence));
			}

			let mut sequence_of_reader = SliceReader::new(multi_bytes)?;
			let entries_bytes = read_sequence(&mut sequence_of_reader)?;
			if !sequence_of_reader.is_finished() {
				return Err(unexpected_tag_err(Tag::Sequence));
			}

			let mut entries_reader = SliceReader::new(entries_bytes)?;
			let mut entries: Vec<FeeEntry> = Vec::new();
			while !entries_reader.is_finished() {
				let entry_bytes = read_sequence(&mut entries_reader)?;
				entries.push(decode_fee_entry(entry_bytes)?);
			}

			Ok(Fees::Multiple(entries))
		}
		actual => Err(unexpected_tag_err(actual)),
	}
}

pub(super) fn encode_extension(value: &Extension) -> Result<Vec<u8>, Asn1Error> {
	let mut content = Vec::new();
	encode_oid(&mut content, &value.oid)?;

	if value.critical {
		encode_bool(&mut content, true)?;
	}

	encode_octet(&mut content, &value.value)?;
	wrap_sequence(&content)
}

pub(super) fn decode_extension(bytes: &[u8]) -> Result<Extension, Asn1Error> {
	let mut outer = SliceReader::new(bytes)?;
	let inner_bytes = read_sequence(&mut outer)?;
	if !outer.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	let mut reader = SliceReader::new(inner_bytes)?;
	let oid = decode_oid(&mut reader)?;
	let critical = match peek_tag(&reader)? {
		Tag::Boolean => read_bool(&mut reader)?,
		Tag::OctetString => true,
		actual => return Err(unexpected_tag_err(actual)),
	};

	let value = read_octet(&mut reader)?.to_vec();
	if !reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}
	Ok(Extension { oid, critical, value })
}

// ---------------------------------------------------------------------------
// Helpers shared by encode/decode
// ---------------------------------------------------------------------------

fn encode_signature_algo_sequence(algo: VoteSignatureAlgo) -> Result<Vec<u8>, Asn1Error> {
	let mut content = Vec::new();
	encode_oid(&mut content, &signature_algo_oid(algo))?;
	wrap_sequence(&content)
}

fn decode_signature_algo_sequence(reader: &mut SliceReader<'_>) -> Result<VoteSignatureAlgo, Asn1Error> {
	let inner = read_sequence(reader)?;
	let mut inner_reader = SliceReader::new(inner)?;
	let oid = decode_oid(&mut inner_reader)?;
	if !inner_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	signature_algo_from_oid(&oid)
}

fn signature_algo_oid(algo: VoteSignatureAlgo) -> VoteOid {
	match algo {
		VoteSignatureAlgo::Ed25519 => oids::ED25519,
		VoteSignatureAlgo::EcdsaWithSha3_256 => oids::ECDSA_WITH_SHA3_256,
	}
}

fn signature_algo_from_oid(oid: &VoteOid) -> Result<VoteSignatureAlgo, Asn1Error> {
	if oid_eq(oid, &oids::ED25519) {
		Ok(VoteSignatureAlgo::Ed25519)
	} else if oid_eq(oid, &oids::ECDSA_WITH_SHA3_256) {
		Ok(VoteSignatureAlgo::EcdsaWithSha3_256)
	} else {
		Err(Asn1Error::InvalidOid { reason: format_oid(oid) })
	}
}

fn encode_distinguished_name(dn: &DistinguishedName) -> Result<Vec<u8>, Asn1Error> {
	let mut content = Vec::new();
	for rdn in &dn.rdns {
		let mut rdn_content = Vec::new();
		for attr in rdn {
			let mut attr_content = Vec::new();
			encode_oid(&mut attr_content, &attr.oid)?;
			Utf8StringRef::new(&attr.value)?.encode_to_vec(&mut attr_content)?;
			let attr_seq = wrap_sequence(&attr_content)?;
			rdn_content.extend_from_slice(&attr_seq);
		}

		content.extend_from_slice(&wrap_set(&rdn_content)?);
	}

	wrap_sequence(&content)
}

fn decode_distinguished_name(reader: &mut SliceReader<'_>) -> Result<DistinguishedName, Asn1Error> {
	let dn_inner = read_sequence(reader)?;
	let mut dn_reader = SliceReader::new(dn_inner)?;
	let mut rdns: Vec<Vec<AttributeTypeAndValue>> = Vec::new();
	while !dn_reader.is_finished() {
		let set_inner = read_set(&mut dn_reader)?;
		let mut set_reader = SliceReader::new(set_inner)?;
		let mut attributes: Vec<AttributeTypeAndValue> = Vec::new();
		while !set_reader.is_finished() {
			let attr_inner = read_sequence(&mut set_reader)?;
			let mut attr_reader = SliceReader::new(attr_inner)?;
			let oid = decode_oid(&mut attr_reader)?;
			let value = read_utf8(&mut attr_reader)?;
			if !attr_reader.is_finished() {
				return Err(unexpected_tag_err(Tag::Sequence));
			}

			attributes.push(AttributeTypeAndValue { oid, value });
		}

		rdns.push(attributes);
	}

	Ok(DistinguishedName { rdns })
}

fn encode_validity(validity: &Validity) -> Result<Vec<u8>, Asn1Error> {
	let mut content = Vec::new();
	validity.not_before.encode_to_vec(&mut content)?;
	validity.not_after.encode_to_vec(&mut content)?;

	wrap_sequence(&content)
}

fn decode_validity(reader: &mut SliceReader<'_>) -> Result<Validity, Asn1Error> {
	let inner = read_sequence(reader)?;
	let mut inner_reader = SliceReader::new(inner)?;
	let not_before = Asn1Time::decode(&mut inner_reader)?;
	let not_after = Asn1Time::decode(&mut inner_reader)?;
	if !inner_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}
	Ok(Validity { not_before, not_after })
}

fn encode_subject_public_key_info(spki: &VoteSubjectPublicKey) -> Result<Vec<u8>, Asn1Error> {
	let (algo_seq, raw) = match spki {
		VoteSubjectPublicKey::Ed25519 { key } => {
			let mut content = Vec::new();
			encode_oid(&mut content, &oids::ED25519)?;
			(wrap_sequence(&content)?, key.as_slice())
		}
		VoteSubjectPublicKey::Ecdsa { curve, key } => {
			let curve_oid = match curve {
				EcdsaCurve::Secp256k1 => oids::SECP256K1,
				EcdsaCurve::Secp256r1 => oids::SECP256R1,
			};
			let mut content = Vec::new();
			encode_oid(&mut content, &oids::EC_PUBLIC_KEY)?;
			encode_oid(&mut content, &curve_oid)?;

			(wrap_sequence(&content)?, key.as_slice())
		}
	};

	let bit_string = BitStringRef::from_bytes(raw)?.to_der()?;
	let mut content = Vec::new();
	content.extend_from_slice(&algo_seq);
	content.extend_from_slice(&bit_string);

	wrap_sequence(&content)
}

fn decode_subject_public_key_info(reader: &mut SliceReader<'_>) -> Result<VoteSubjectPublicKey, Asn1Error> {
	let inner = read_sequence(reader)?;
	let mut inner_reader = SliceReader::new(inner)?;
	let algo_inner = read_sequence(&mut inner_reader)?;

	let mut algo_reader = SliceReader::new(algo_inner)?;
	let first_oid = decode_oid(&mut algo_reader)?;
	let key_kind = if oid_eq(&first_oid, &oids::ED25519) {
		if !algo_reader.is_finished() {
			return Err(unexpected_tag_err(Tag::Sequence));
		}

		None
	} else if oid_eq(&first_oid, &oids::EC_PUBLIC_KEY) {
		let curve_oid = decode_oid(&mut algo_reader)?;
		if !algo_reader.is_finished() {
			return Err(unexpected_tag_err(Tag::Sequence));
		}
		let curve = if oid_eq(&curve_oid, &oids::SECP256K1) {
			EcdsaCurve::Secp256k1
		} else if oid_eq(&curve_oid, &oids::SECP256R1) {
			EcdsaCurve::Secp256r1
		} else {
			return Err(Asn1Error::InvalidOid { reason: format_oid(&curve_oid) });
		};

		Some(curve)
	} else {
		return Err(Asn1Error::InvalidOid { reason: format_oid(&first_oid) });
	};

	let raw = read_bit_string(&mut inner_reader)?.to_vec();
	if !inner_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	let spki = match key_kind {
		None => VoteSubjectPublicKey::Ed25519 { key: raw },
		Some(curve) => VoteSubjectPublicKey::Ecdsa { curve, key: raw },
	};

	Ok(spki)
}

fn encode_extensions_field(extensions: &[Extension]) -> Result<Vec<u8>, Asn1Error> {
	let mut content = Vec::new();
	for extension in extensions {
		content.extend_from_slice(&encode_extension(extension)?);
	}

	let sequence = wrap_sequence(&content)?;
	wrap_explicit_context(EXTENSIONS_TAG, &sequence)
}

fn decode_extensions_field(reader: &mut SliceReader<'_>) -> Result<Vec<Extension>, Asn1Error> {
	let extensions_inner = read_explicit_context(reader, EXTENSIONS_TAG)?;
	let mut extensions_reader = SliceReader::new(extensions_inner)?;
	let sequence_inner = read_sequence(&mut extensions_reader)?;
	if !extensions_reader.is_finished() {
		return Err(unexpected_tag_err(Tag::Sequence));
	}

	let mut sequence_reader = SliceReader::new(sequence_inner)?;
	let mut extensions: Vec<Extension> = Vec::new();
	while !sequence_reader.is_finished() {
		let tlv = capture_tlv(&mut sequence_reader, Tag::Sequence)?;
		extensions.push(decode_extension(&tlv)?);
	}

	Ok(extensions)
}

fn encode_fee_entry(entry: &FeeEntry) -> Result<Vec<u8>, Asn1Error> {
	let mut content = Vec::new();
	encode_bool(&mut content, entry.quote)?;
	encode_bigint(&mut content, &entry.amount)?;

	if let Some(pay_to) = &entry.pay_to {
		content.extend_from_slice(&wrap_implicit_octet_context(FEE_PAY_TO_TAG, pay_to)?);
	}
	if let Some(token) = &entry.token {
		content.extend_from_slice(&wrap_implicit_octet_context(FEE_TOKEN_TAG, token)?);
	}

	wrap_sequence(&content)
}

fn decode_fee_entry(content: &[u8]) -> Result<FeeEntry, Asn1Error> {
	let mut reader = SliceReader::new(content)?;
	let quote = read_bool(&mut reader)?;
	let amount = read_bigint(&mut reader)?;
	let mut pay_to: Option<Vec<u8>> = None;
	let mut token: Option<Vec<u8>> = None;

	while !reader.is_finished() {
		let tag = peek_tag(&reader)?;
		match tag {
			Tag::ContextSpecific { constructed: false, number } if number == FEE_PAY_TO_TAG => {
				let raw = read_implicit_octet_context(&mut reader, FEE_PAY_TO_TAG)?;
				pay_to = Some(raw.to_vec());
			}
			Tag::ContextSpecific { constructed: false, number } if number == FEE_TOKEN_TAG => {
				let raw = read_implicit_octet_context(&mut reader, FEE_TOKEN_TAG)?;
				token = Some(raw.to_vec());
			}
			actual => return Err(unexpected_tag_err(actual)),
		}
	}

	Ok(FeeEntry { quote, amount, pay_to, token })
}

fn encode_signature_bit_string(signature: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	Ok(BitStringRef::from_bytes(signature)?.to_der()?)
}

fn decode_signature_bit_string(reader: &mut SliceReader<'_>) -> Result<Vec<u8>, Asn1Error> {
	let value = BitStringRef::decode(reader)?;
	let bytes = value
		.as_bytes()
		.ok_or_else(|| unexpected_tag_err(Tag::BitString))?;
	Ok(bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Low-level DER primitives
// ---------------------------------------------------------------------------

fn encode_octet(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Asn1Error> {
	OctetStringRef::new(bytes)?.encode_to_vec(out)?;
	Ok(())
}

fn encode_bool(out: &mut Vec<u8>, value: bool) -> Result<(), Asn1Error> {
	value.encode_to_vec(out)?;
	Ok(())
}

fn encode_bigint(out: &mut Vec<u8>, value: &BigInt) -> Result<(), Asn1Error> {
	let bytes = bigint_to_der_integer_bytes(value);
	let any = AnyRef::new(Tag::Integer, &bytes)?;
	any.encode_to_vec(out)?;
	Ok(())
}

fn encode_oid(out: &mut Vec<u8>, oid: &VoteOid) -> Result<(), Asn1Error> {
	let parsed = vote_oid_to_der(oid)?;
	parsed.encode_to_vec(out)?;
	Ok(())
}

fn wrap_sequence(content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	Ok(AnyRef::new(Tag::Sequence, content)?.to_der()?)
}

fn wrap_set(content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	Ok(AnyRef::new(Tag::Set, content)?.to_der()?)
}

fn wrap_explicit_context(number: TagNumber, content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	let tag = Tag::ContextSpecific { constructed: true, number };
	Ok(AnyRef::new(tag, content)?.to_der()?)
}

fn wrap_implicit_octet_context(number: TagNumber, content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	let tag = Tag::ContextSpecific { constructed: false, number };
	Ok(AnyRef::new(tag, content)?.to_der()?)
}

fn read_sequence<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], Asn1Error> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != Tag::Sequence {
		return Err(unexpected_tag_err(any.tag()));
	}
	Ok(any.value())
}

fn read_set<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], Asn1Error> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != Tag::Set {
		return Err(unexpected_tag_err(any.tag()));
	}
	Ok(any.value())
}

fn read_octet<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], Asn1Error> {
	Ok(OctetStringRef::decode(reader)?.as_bytes())
}

fn read_bool(reader: &mut SliceReader<'_>) -> Result<bool, Asn1Error> {
	Ok(bool::decode(reader)?)
}

fn read_bigint(reader: &mut SliceReader<'_>) -> Result<BigInt, Asn1Error> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != Tag::Integer {
		return Err(unexpected_tag_err(any.tag()));
	}
	Ok(BigInt::from_signed_bytes_be(any.value()))
}

fn read_utf8(reader: &mut SliceReader<'_>) -> Result<String, Asn1Error> {
	Ok(Utf8StringRef::decode(reader)?.as_str().to_string())
}

fn read_bit_string<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], Asn1Error> {
	let value = BitStringRef::decode(reader)?;
	value
		.as_bytes()
		.ok_or_else(|| unexpected_tag_err(Tag::BitString))
}

fn read_explicit_context<'a>(reader: &mut SliceReader<'a>, number: TagNumber) -> Result<&'a [u8], Asn1Error> {
	let any = AnyRef::decode(reader)?;
	let expected = Tag::ContextSpecific { constructed: true, number };
	if any.tag() != expected {
		return Err(unexpected_tag_err(any.tag()));
	}
	Ok(any.value())
}

fn read_implicit_octet_context<'a>(reader: &mut SliceReader<'a>, number: TagNumber) -> Result<&'a [u8], Asn1Error> {
	let any = AnyRef::decode(reader)?;
	let expected = Tag::ContextSpecific { constructed: false, number };
	if any.tag() != expected {
		return Err(unexpected_tag_err(any.tag()));
	}
	Ok(any.value())
}

fn peek_tag(reader: &SliceReader<'_>) -> Result<Tag, Asn1Error> {
	let mut probe = reader.clone();
	Ok(AnyRef::decode(&mut probe)?.tag())
}

fn capture_tlv(reader: &mut SliceReader<'_>, expected: Tag) -> Result<Vec<u8>, Asn1Error> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != expected {
		return Err(unexpected_tag_err(any.tag()));
	}
	Ok(any.to_der()?)
}

fn decode_oid(reader: &mut SliceReader<'_>) -> Result<VoteOid, Asn1Error> {
	let oid = ObjectIdentifier::decode(reader)?;
	Ok(der_oid_to_vote(&oid))
}

fn unexpected_tag_err(actual: Tag) -> Asn1Error {
	der::Error::new(ErrorKind::TagUnexpected { expected: None, actual }, Length::ZERO).into()
}

fn vote_oid_to_der(oid: &VoteOid) -> Result<ObjectIdentifier, Asn1Error> {
	let dotted = format_oid(oid);
	ObjectIdentifier::new(&dotted).map_err(|err| Asn1Error::InvalidOid { reason: format!("{err:?}") })
}

fn der_oid_to_vote(oid: &ObjectIdentifier) -> VoteOid {
	let arcs: Vec<u32> = oid.arcs().collect();
	VoteOid::from(arcs)
}

fn oid_eq(left: &VoteOid, right: &VoteOid) -> bool {
	left.arcs() == right.arcs()
}

fn format_oid(oid: &VoteOid) -> String {
	let mut out = String::new();
	for (i, arc) in oid.arcs().iter().enumerate() {
		if i > 0 {
			out.push('.');
		}
		out.push_str(&arc.to_string());
	}
	out
}

fn bigint_to_der_integer_bytes(value: &BigInt) -> Vec<u8> {
	value.to_signed_bytes_be()
}
