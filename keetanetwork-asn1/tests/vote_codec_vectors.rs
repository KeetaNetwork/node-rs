//! Byte conformance tests for the backend-neutral vote codec.

use chrono::DateTime;
use keetanetwork_asn1::vote::{codec, oids};
use keetanetwork_asn1::vote::{
	AttributeTypeAndValue, DistinguishedName, Extension, FeeEntry, Fees, HashData, TbsCertificate, Validity,
	VoteCertificate, VoteSignatureAlgo, VoteStapleBundle, VoteSubjectPublicKey,
};
use keetanetwork_asn1::Asn1Time;
use num_bigint::BigInt;

const VOTE_VECTOR: &str = "3081da30818da00302010202012a300506032b657030163114301206035504030c0b54657374204973737565723022180f32303230303931333132323634305a180f32303233313131343232313332305a3010310e300c06035504050c053132333435302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111a3023000300506032b657003410022222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
const TBS_VECTOR: &str = "30818da00302010202012a300506032b657030163114301206035504030c0b54657374204973737565723022180f32303230303931333132323634305a180f32303233313131343232313332305a3010310e300c06035504050c053132333435302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111a3023000";
const STAPLE_VECTOR: &str = "300e3005040301020330050403040506";
const HASH_DATA_VECTOR: &str =
	"a031302f0609608648016503040208302204200000000000000000000000000000000000000000000000000000000000000000";
const FEES_VECTOR: &str = "a0083006010100020164";
const EXTENSION_VECTOR: &str = "300e06096086480165030301030401aa";

fn time(seconds: i64) -> Asn1Time {
	let timestamp = DateTime::from_timestamp(seconds, 0).expect("fixture timestamp must be representable");
	Asn1Time::new(timestamp)
}

fn vote_certificate() -> VoteCertificate {
	let issuer = DistinguishedName {
		rdns: vec![vec![AttributeTypeAndValue { oid: oids::COMMON_NAME, value: "Test Issuer".into() }]],
	};
	let subject = DistinguishedName {
		rdns: vec![vec![AttributeTypeAndValue { oid: oids::SERIAL_NUMBER, value: "12345".into() }]],
	};
	let validity = Validity { not_before: time(1_600_000_000), not_after: time(1_700_000_000) };
	let tbs = TbsCertificate {
		serial_number: BigInt::from(42),
		signature_algo: VoteSignatureAlgo::Ed25519,
		issuer,
		validity,
		subject,
		subject_public_key: VoteSubjectPublicKey::Ed25519 { key: vec![0x11; 32] },
		extensions: vec![],
	};

	VoteCertificate { tbs, signature_algo: VoteSignatureAlgo::Ed25519, signature: vec![0x22; 64] }
}

fn staple() -> VoteStapleBundle {
	VoteStapleBundle { blocks: vec![vec![1, 2, 3]], votes: vec![vec![4, 5, 6]] }
}

fn hash_data() -> HashData {
	HashData { algorithm: oids::SHA3_256, hashes: vec![vec![0u8; 32]] }
}

fn fees_single() -> Fees {
	Fees::Single(FeeEntry { quote: false, amount: BigInt::from(100), pay_to: None, token: None })
}

fn extension() -> Extension {
	Extension { oid: oids::HASH_DATA, critical: false, value: vec![0xAA] }
}

#[test]
fn test_vote_certificate_reference_bytes() {
	let cert = vote_certificate();

	let vote_bytes = codec::encode_vote(&cert).expect("encode vote");
	let tbs_bytes = codec::encode_tbs(&cert.tbs).expect("encode tbs");
	assert_eq!(hex::encode(vote_bytes), VOTE_VECTOR, "vote certificate bytes");
	assert_eq!(hex::encode(tbs_bytes), TBS_VECTOR, "tbsCertificate bytes");
}

#[test]
fn test_vote_certificate_round_trip_from_reference() {
	let bytes = hex::decode(VOTE_VECTOR).expect("reference hex");
	let decoded = codec::decode_vote(&bytes).expect("decode vote");
	assert_eq!(hex::encode(&decoded.tbs_bytes), TBS_VECTOR, "decoded tbs slice must match the reference tbs");

	let rebuilt =
		VoteCertificate { tbs: decoded.tbs, signature_algo: decoded.signature_algo, signature: decoded.signature };

	let re_encoded = codec::encode_vote(&rebuilt).expect("re-encode vote");
	assert_eq!(hex::encode(re_encoded), VOTE_VECTOR, "vote certificate must round-trip byte-for-byte");
}

#[test]
fn test_vote_staple_reference_bytes() {
	let bundle = staple();

	let encoded = codec::encode_vote_staple(&bundle).expect("encode staple");
	assert_eq!(hex::encode(encoded), STAPLE_VECTOR, "vote staple bytes");

	let bytes = hex::decode(STAPLE_VECTOR).expect("reference hex");
	let decoded = codec::decode_vote_staple(&bytes).expect("decode staple");
	assert_eq!(decoded, bundle, "vote staple must round-trip");
}

#[test]
fn test_hash_data_reference_bytes() {
	let value = hash_data();

	let encoded = codec::encode_hash_data(&value).expect("encode hash data");
	assert_eq!(hex::encode(encoded), HASH_DATA_VECTOR, "hashData");

	let bytes = hex::decode(HASH_DATA_VECTOR).expect("reference hex");
	let decoded = codec::decode_hash_data(&bytes).expect("decode hash");
	assert_eq!(decoded, value, "hashData must round-trip");
}

#[test]
fn test_fees_reference_bytes() {
	let value = fees_single();

	let encoded = codec::encode_fees(&value).expect("encode fees");
	assert_eq!(hex::encode(encoded), FEES_VECTOR, "fees");

	let bytes = hex::decode(FEES_VECTOR).expect("reference hex");
	let decoded = codec::decode_fees(&bytes).expect("decode fees");
	assert_eq!(decoded, value, "fees must round-trip");
}

#[test]
fn test_extension_reference_bytes() {
	let value = extension();

	let encoded = codec::encode_extension(&value).expect("encode extension");
	assert_eq!(hex::encode(encoded), EXTENSION_VECTOR, "extension");

	let bytes = hex::decode(EXTENSION_VECTOR).expect("reference hex");
	let decoded = codec::decode_extension(&bytes).expect("decode ext");
	assert_eq!(decoded, value, "extension must round-trip");
}
