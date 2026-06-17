//! `rasn`-backed encode/decode for vote certificate transport types.
//!
//! Converts between the public neutral types in [`super::super::types`]
//! and the rasn-compiler-generated transport types in
//! [`crate::generated`].

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use rasn::types::{Any, BitString, Integer, ObjectIdentifier, OctetString, SetOf, Utf8String};

use super::super::oids;
use super::super::types::{
	AttributeTypeAndValue, DecodedVoteCertificate, DistinguishedName, EcdsaCurve, Extension, FeeEntry, Fees, HashData,
	TbsCertificate, Validity, VoteCertificate, VoteDecodeSlot, VoteOid, VoteSignatureAlgo, VoteStapleBundle,
	VoteStapleDecodeSlot, VoteSubjectPublicKey,
};
// Generated rasn-compiler types. Names that collide with the neutral
// types above are renamed with a `Rasn` prefix; the rest keep their
// original names.
use crate::generated::{
	AlgorithmIdentifier, AttributeTypeAndValue as RasnAttributeTypeAndValue,
	DistinguishedName as RasnDistinguishedName, Extension as RasnExtension, Extensions, FeeEntries,
	FeeEntry as RasnFeeEntry, FeesMultiple, FeesMultipleInner, FeesSingle, HashData as RasnHashData, HashDataInner,
	RelativeDistinguishedName, SubjectPublicKeyInfo, TbsCertificate as RasnTbsCertificate, Validity as RasnValidity,
	VoteCertificate as RasnVoteCertificate, VoteStapleBundle as RasnVoteStapleBundle,
};
use crate::Asn1Error;
use num_bigint::{BigInt, ToBigInt};

const VOTE_VERSION_VALUE: u8 = 2;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub(super) fn encode_tbs(tbs: &TbsCertificate) -> Result<Vec<u8>, Asn1Error> {
	let transport = tbs_to_transport(tbs)?;
	::rasn::der::encode(&transport).map_err(Asn1Error::from)
}

pub(super) fn encode_vote(value: &VoteCertificate) -> Result<Vec<u8>, Asn1Error> {
	let transport = vote_certificate_to_transport(value)?;
	::rasn::der::encode(&transport).map_err(Asn1Error::from)
}

pub(super) fn decode_vote(bytes: &[u8]) -> Result<DecodedVoteCertificate, Asn1Error> {
	let transport: RasnVoteCertificate =
		::rasn::der::decode(bytes).map_err(|_| Asn1Error::VoteDecode { slot: VoteDecodeSlot::Wrapper })?;
	let tbs = tbs_from_transport(&transport.tbs_certificate)?;
	if tbs.signature_algo != signature_algo_from_algorithm_identifier(&transport.signature_algorithm)? {
		return Err(Asn1Error::VoteDecode { slot: VoteDecodeSlot::WrapperSignatureAlgorithm });
	}
	let signature_algo = tbs.signature_algo;
	let tbs_bytes = ::rasn::der::encode(&transport.tbs_certificate).map_err(Asn1Error::from)?;
	let signature = transport.signature_value.as_raw_slice().to_vec();
	Ok(DecodedVoteCertificate { tbs, tbs_bytes, signature_algo, signature })
}

pub(super) fn encode_vote_staple(bundle: &VoteStapleBundle) -> Result<Vec<u8>, Asn1Error> {
	let transport = RasnVoteStapleBundle {
		blocks: bundle.blocks.iter().map(bytes_to_octet).collect(),
		votes: bundle.votes.iter().map(bytes_to_octet).collect(),
	};
	::rasn::der::encode(&transport).map_err(Asn1Error::from)
}

pub(super) fn decode_vote_staple(bytes: &[u8]) -> Result<VoteStapleBundle, Asn1Error> {
	let transport: RasnVoteStapleBundle =
		::rasn::der::decode(bytes).map_err(|_| Asn1Error::VoteStapleDecode { slot: VoteStapleDecodeSlot::Wrapper })?;
	Ok(VoteStapleBundle {
		blocks: transport.blocks.into_iter().map(octet_to_bytes).collect(),
		votes: transport.votes.into_iter().map(octet_to_bytes).collect(),
	})
}

pub(super) fn encode_hash_data(value: &HashData) -> Result<Vec<u8>, Asn1Error> {
	let transport = RasnHashData(HashDataInner {
		algorithm: vote_oid_to_rasn(&value.algorithm),
		hashes: value.hashes.iter().map(bytes_to_octet).collect(),
	});
	::rasn::der::encode(&transport).map_err(Asn1Error::from)
}

pub(super) fn decode_hash_data(bytes: &[u8]) -> Result<HashData, Asn1Error> {
	let transport: RasnHashData = ::rasn::der::decode(bytes)
		.map_err(|error| Asn1Error::RasnError { reason: format!("decode error: {error}") })?;
	Ok(HashData {
		algorithm: rasn_oid_to_vote(&transport.0.algorithm),
		hashes: transport.0.hashes.into_iter().map(octet_to_bytes).collect(),
	})
}

pub(super) fn encode_fees(value: &Fees) -> Result<Vec<u8>, Asn1Error> {
	match value {
		Fees::Single(entry) => {
			let transport = FeesSingle(fee_entry_to_transport(entry));
			::rasn::der::encode(&transport).map_err(Asn1Error::from)
		}
		Fees::Multiple(entries) => {
			let inner = FeeEntries(entries.iter().map(fee_entry_to_transport).collect());
			let transport = FeesMultiple(FeesMultipleInner(inner));
			::rasn::der::encode(&transport).map_err(Asn1Error::from)
		}
	}
}

pub(super) fn decode_fees(bytes: &[u8]) -> Result<Fees, Asn1Error> {
	if let Ok(single) = ::rasn::der::decode::<FeesSingle>(bytes) {
		return Ok(Fees::Single(fee_entry_from_transport(&single.0)));
	}
	let multi: FeesMultiple = ::rasn::der::decode(bytes)
		.map_err(|error| Asn1Error::RasnError { reason: format!("decode error: {error}") })?;
	let entries: Vec<FeeEntry> = multi.0 .0 .0.iter().map(fee_entry_from_transport).collect();
	Ok(Fees::Multiple(entries))
}

pub(super) fn encode_extension(value: &Extension) -> Result<Vec<u8>, Asn1Error> {
	let transport = extension_to_transport(value);
	::rasn::der::encode(&transport).map_err(Asn1Error::from)
}

pub(super) fn decode_extension(bytes: &[u8]) -> Result<Extension, Asn1Error> {
	let transport: RasnExtension = ::rasn::der::decode(bytes)
		.map_err(|error| Asn1Error::RasnError { reason: format!("decode error: {error}") })?;
	Ok(extension_from_transport(transport))
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

fn vote_certificate_to_transport(value: &VoteCertificate) -> Result<RasnVoteCertificate, Asn1Error> {
	let tbs_certificate = tbs_to_transport(&value.tbs)?;
	let signature_algorithm = signature_algo_to_algorithm_identifier(value.signature_algo);
	let signature_value = BitString::from_slice(&value.signature);
	Ok(RasnVoteCertificate { tbs_certificate, signature_algorithm, signature_value })
}

fn tbs_to_transport(tbs: &TbsCertificate) -> Result<RasnTbsCertificate, Asn1Error> {
	Ok(RasnTbsCertificate {
		version: Integer::from(BigInt::from(VOTE_VERSION_VALUE)),
		serial_number: Integer::from(tbs.serial_number.clone()),
		signature: signature_algo_to_algorithm_identifier(tbs.signature_algo),
		issuer: distinguished_name_to_transport(&tbs.issuer),
		validity: validity_to_transport(&tbs.validity),
		subject: distinguished_name_to_transport(&tbs.subject),
		subject_public_key_info: subject_public_key_to_transport(&tbs.subject_public_key)?,
		extensions: Extensions(tbs.extensions.iter().map(extension_to_transport).collect()),
	})
}

fn tbs_from_transport(transport: &RasnTbsCertificate) -> Result<TbsCertificate, Asn1Error> {
	let version = bigint_from_integer(&transport.version);
	if version != BigInt::from(VOTE_VERSION_VALUE) {
		return Err(Asn1Error::InvalidVoteVersion);
	}

	let signature_algo = signature_algo_from_algorithm_identifier(&transport.signature)?;
	Ok(TbsCertificate {
		serial_number: bigint_from_integer(&transport.serial_number),
		signature_algo,
		issuer: distinguished_name_from_transport(&transport.issuer),
		validity: validity_from_transport(&transport.validity),
		subject: distinguished_name_from_transport(&transport.subject),
		subject_public_key: subject_public_key_from_transport(&transport.subject_public_key_info)?,
		extensions: transport
			.extensions
			.0
			.iter()
			.cloned()
			.map(extension_from_transport)
			.collect(),
	})
}

fn validity_to_transport(value: &Validity) -> RasnValidity {
	RasnValidity { not_before: value.not_before, not_after: value.not_after }
}

fn validity_from_transport(value: &RasnValidity) -> Validity {
	Validity { not_before: value.not_before, not_after: value.not_after }
}

fn distinguished_name_to_transport(value: &DistinguishedName) -> RasnDistinguishedName {
	let rdns: Vec<RelativeDistinguishedName> = value
		.rdns
		.iter()
		.map(|attrs| {
			let set: SetOf<RasnAttributeTypeAndValue> =
				SetOf::from_vec(attrs.iter().map(attribute_to_transport).collect());
			RelativeDistinguishedName(set)
		})
		.collect();
	RasnDistinguishedName(rdns)
}

fn distinguished_name_from_transport(value: &RasnDistinguishedName) -> DistinguishedName {
	let rdns: Vec<Vec<AttributeTypeAndValue>> = value
		.0
		.iter()
		.map(|rdn| {
			rdn.0
				.to_vec()
				.into_iter()
				.map(|attr| attribute_from_transport(&attr))
				.collect()
		})
		.collect();
	DistinguishedName { rdns }
}

fn attribute_to_transport(value: &AttributeTypeAndValue) -> RasnAttributeTypeAndValue {
	RasnAttributeTypeAndValue { r_type: vote_oid_to_rasn(&value.oid), value: Utf8String::from(value.value.clone()) }
}

fn attribute_from_transport(value: &RasnAttributeTypeAndValue) -> AttributeTypeAndValue {
	AttributeTypeAndValue { oid: rasn_oid_to_vote(&value.r_type), value: value.value.to_string() }
}

fn extension_to_transport(value: &Extension) -> RasnExtension {
	RasnExtension {
		extn_id: vote_oid_to_rasn(&value.oid),
		critical: value.critical,
		extn_value: bytes_to_octet(&value.value),
	}
}

fn extension_from_transport(value: RasnExtension) -> Extension {
	Extension {
		oid: rasn_oid_to_vote(&value.extn_id),
		critical: value.critical,
		value: octet_to_bytes(value.extn_value),
	}
}

fn fee_entry_to_transport(value: &FeeEntry) -> RasnFeeEntry {
	RasnFeeEntry {
		quote: value.quote,
		amount: Integer::from(value.amount.clone()),
		pay_to: value.pay_to.as_ref().map(bytes_to_octet),
		token: value.token.as_ref().map(bytes_to_octet),
	}
}

fn fee_entry_from_transport(value: &RasnFeeEntry) -> FeeEntry {
	FeeEntry {
		quote: value.quote,
		amount: bigint_from_integer(&value.amount),
		pay_to: value
			.pay_to
			.as_ref()
			.map(|bytes| octet_to_bytes(bytes.clone())),
		token: value
			.token
			.as_ref()
			.map(|bytes| octet_to_bytes(bytes.clone())),
	}
}

fn subject_public_key_to_transport(value: &VoteSubjectPublicKey) -> Result<SubjectPublicKeyInfo, Asn1Error> {
	let (algorithm, key) = match value {
		VoteSubjectPublicKey::Ed25519 { key } => {
			(AlgorithmIdentifier { algorithm: vote_oid_to_rasn(&oids::ED25519), parameters: None }, key.as_slice())
		}
		VoteSubjectPublicKey::Ecdsa { curve, key } => {
			let curve_oid = match curve {
				EcdsaCurve::Secp256k1 => oids::SECP256K1,
				EcdsaCurve::Secp256r1 => oids::SECP256R1,
			};
			let parameters = encode_oid_as_any(&curve_oid)?;
			(
				AlgorithmIdentifier { algorithm: vote_oid_to_rasn(&oids::EC_PUBLIC_KEY), parameters: Some(parameters) },
				key.as_slice(),
			)
		}
	};
	Ok(SubjectPublicKeyInfo { algorithm, subject_public_key: BitString::from_slice(key) })
}

fn subject_public_key_from_transport(value: &SubjectPublicKeyInfo) -> Result<VoteSubjectPublicKey, Asn1Error> {
	let algo_oid = rasn_oid_to_vote(&value.algorithm.algorithm);
	let key = value.subject_public_key.as_raw_slice().to_vec();

	if oid_eq(&algo_oid, &oids::ED25519) {
		if value.algorithm.parameters.is_some() {
			return Err(Asn1Error::RasnError { reason: "Ed25519 SPKI must not carry algorithm parameters".into() });
		}

		Ok(VoteSubjectPublicKey::Ed25519 { key })
	} else if oid_eq(&algo_oid, &oids::EC_PUBLIC_KEY) {
		let parameters = value
			.algorithm
			.parameters
			.as_ref()
			.ok_or_else(|| Asn1Error::RasnError {
				reason: "ECDSA SPKI must carry curve OID in algorithm parameters".into(),
			})?;
		let curve_oid = decode_oid_from_any(parameters)?;
		let curve = if oid_eq(&curve_oid, &oids::SECP256K1) {
			EcdsaCurve::Secp256k1
		} else if oid_eq(&curve_oid, &oids::SECP256R1) {
			EcdsaCurve::Secp256r1
		} else {
			return Err(Asn1Error::InvalidOid { reason: format_oid(&curve_oid) });
		};

		Ok(VoteSubjectPublicKey::Ecdsa { curve, key })
	} else {
		Err(Asn1Error::InvalidOid { reason: format_oid(&algo_oid) })
	}
}

fn signature_algo_to_algorithm_identifier(algo: VoteSignatureAlgo) -> AlgorithmIdentifier {
	AlgorithmIdentifier { algorithm: vote_oid_to_rasn(&signature_algo_oid(algo)), parameters: None }
}

fn signature_algo_from_algorithm_identifier(algo: &AlgorithmIdentifier) -> Result<VoteSignatureAlgo, Asn1Error> {
	let oid = rasn_oid_to_vote(&algo.algorithm);
	if oid_eq(&oid, &oids::ED25519) {
		Ok(VoteSignatureAlgo::Ed25519)
	} else if oid_eq(&oid, &oids::ECDSA_WITH_SHA3_256) {
		Ok(VoteSignatureAlgo::EcdsaWithSha3_256)
	} else {
		Err(Asn1Error::InvalidOid { reason: format_oid(&oid) })
	}
}

fn signature_algo_oid(algo: VoteSignatureAlgo) -> VoteOid {
	match algo {
		VoteSignatureAlgo::Ed25519 => oids::ED25519,
		VoteSignatureAlgo::EcdsaWithSha3_256 => oids::ECDSA_WITH_SHA3_256,
	}
}

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

fn vote_oid_to_rasn(oid: &VoteOid) -> ObjectIdentifier {
	ObjectIdentifier::new_unchecked(Cow::Owned(oid.arcs().to_vec()))
}

fn rasn_oid_to_vote(oid: &ObjectIdentifier) -> VoteOid {
	VoteOid::from(oid.to_vec())
}

fn oid_eq(left: &VoteOid, right: &VoteOid) -> bool {
	left.arcs() == right.arcs()
}

fn format_oid(oid: &VoteOid) -> alloc::string::String {
	use alloc::string::ToString;
	let mut out = alloc::string::String::new();
	for (i, arc) in oid.arcs().iter().enumerate() {
		if i > 0 {
			out.push('.');
		}
		out.push_str(&arc.to_string());
	}

	out
}

fn bytes_to_octet(value: impl AsRef<[u8]>) -> OctetString {
	OctetString::from(value.as_ref().to_vec())
}

fn octet_to_bytes(value: OctetString) -> Vec<u8> {
	value.to_vec()
}

fn bigint_from_integer(value: &Integer) -> BigInt {
	value.to_bigint().unwrap_or_default()
}

fn encode_oid_as_any(oid: &VoteOid) -> Result<Any, Asn1Error> {
	let rasn_oid = vote_oid_to_rasn(oid);
	let bytes = ::rasn::der::encode(&rasn_oid).map_err(Asn1Error::from)?;
	Ok(Any::new(bytes))
}

fn decode_oid_from_any(value: &Any) -> Result<VoteOid, Asn1Error> {
	let oid: ObjectIdentifier = ::rasn::der::decode(value.as_bytes())
		.map_err(|error| Asn1Error::RasnError { reason: format!("decode error: {error}") })?;
	Ok(rasn_oid_to_vote(&oid))
}
