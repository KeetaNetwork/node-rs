//! Wire-format corruption tests for `Vote` and `VoteStaple`.

mod support;

use std::io::{Read, Write};

use der::asn1::AnyRef;
use der::{Encode, Tag};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_block::Hashable;
use keetanetwork_vote::{Vote, VoteBuilder, VoteError, VoteStaple, VoteStapleBuilder};

use support::{baseline_vote_bytes, future_validity, integer_zero_tlv, join_seq, join_with_tag, split_seq, TestResult};

// --- Vote corruption table --------------------------------------------------

/// One vote-decode corruption scenario. `mutate` takes the bytes of a
/// known-good signed vote and returns a corrupted variant; `expected` is
/// the [`VoteError`] code the decoder must surface.
struct VoteCase {
	description: &'static str,
	mutate: fn(Vec<u8>) -> Vec<u8>,
	expected: &'static str,
}

const VOTE_CASES: &[VoteCase] = &[
	VoteCase { description: "empty input", mutate: |_| Vec::new(), expected: "VOTE_MALFORMED_WRAPPER" },
	VoteCase {
		description: "non-sequence top-level",
		mutate: |_| integer_zero_tlv(),
		expected: "VOTE_MALFORMED_WRAPPER",
	},
	VoteCase {
		description: "trailing bytes after wrapper",
		mutate: |mut bytes| {
			bytes.push(0x00);
			bytes
		},
		expected: "VOTE_MALFORMED_WRAPPER",
	},
	VoteCase {
		description: "wrapper has only one element",
		mutate: |_| join_seq([integer_zero_tlv()]),
		expected: "VOTE_MALFORMED_VOTE_CONTENT",
	},
	VoteCase {
		description: "tbs slot is INTEGER, not SEQUENCE",
		mutate: |bytes| {
			let mut wrapper = split_seq(&bytes);
			wrapper[0] = integer_zero_tlv();
			join_seq(wrapper)
		},
		expected: "VOTE_MALFORMED_VOTE_CONTENT",
	},
	VoteCase {
		description: "version slot has no [0] EXPLICIT context tag",
		mutate: |bytes| replace_tbs_slot(&bytes, 0, integer_zero_tlv()),
		expected: "VOTE_MALFORMED_VOTE_CONTENT",
	},
	VoteCase {
		description: "version inside [0] EXPLICIT is INTEGER 0",
		mutate: |bytes| {
			let bad_version = join_with_tag(
				Tag::ContextSpecific { constructed: true, number: der::TagNumber::N0 },
				[integer_zero_tlv()],
			);
			replace_tbs_slot(&bytes, 0, bad_version)
		},
		expected: "VOTE_INVALID_VERSION",
	},
	VoteCase {
		description: "version inside [0] EXPLICIT is OCTET STRING",
		mutate: |bytes| {
			let bad_version = join_with_tag(
				Tag::ContextSpecific { constructed: true, number: der::TagNumber::N0 },
				[AnyRef::new(Tag::OctetString, &[0x00])
					.expect("octet")
					.to_der()
					.expect("der")],
			);
			replace_tbs_slot(&bytes, 0, bad_version)
		},
		expected: "VOTE_MALFORMED_VOTE_VERSION",
	},
	VoteCase {
		description: "serial slot is OCTET STRING",
		mutate: |bytes| {
			let bad_serial = AnyRef::new(Tag::OctetString, &[0x00])
				.expect("octet")
				.to_der()
				.expect("der");
			replace_tbs_slot(&bytes, 1, bad_serial)
		},
		expected: "VOTE_MALFORMED_VOTE_SERIAL",
	},
	VoteCase {
		description: "tbs signature algorithm slot is INTEGER",
		mutate: |bytes| replace_tbs_slot(&bytes, 2, integer_zero_tlv()),
		expected: "VOTE_MALFORMED_VOTE_SIGNATURE_INFORMATION",
	},
	VoteCase {
		description: "issuer DN slot is INTEGER",
		mutate: |bytes| replace_tbs_slot(&bytes, 3, integer_zero_tlv()),
		expected: "VOTE_MALFORMED_VOTE_ISSUER_INFORMATION",
	},
	VoteCase {
		description: "validity slot is INTEGER",
		mutate: |bytes| replace_tbs_slot(&bytes, 4, integer_zero_tlv()),
		expected: "VOTE_MALFORMED_VOTE_VALIDITY_INFORMATION",
	},
	VoteCase {
		description: "subject DN slot is INTEGER",
		mutate: |bytes| replace_tbs_slot(&bytes, 5, integer_zero_tlv()),
		expected: "VOTE_MALFORMED_VOTE_SUBJECT_INFORMATION",
	},
	VoteCase {
		description: "subject public key slot is INTEGER",
		mutate: |bytes| replace_tbs_slot(&bytes, 6, integer_zero_tlv()),
		expected: "VOTE_MALFORMED_VOTE_SUBJECT_PUBLIC_KEY_INFORMATION",
	},
	VoteCase {
		description: "extensions slot is INTEGER (no context tag)",
		mutate: |bytes| replace_tbs_slot(&bytes, 7, integer_zero_tlv()),
		expected: "VOTE_MALFORMED_VOTE_EXTENSIONS",
	},
	VoteCase {
		description: "trailing bytes inside tbs",
		mutate: |bytes| {
			let mut wrapper = split_seq(&bytes);
			let mut tbs_parts = split_seq(&wrapper[0]);
			tbs_parts.push(integer_zero_tlv());
			wrapper[0] = join_seq(tbs_parts);
			join_seq(wrapper)
		},
		expected: "VOTE_MALFORMED_VOTE_CONTENT_EXTRA_DATA",
	},
];

#[test]
fn test_vote_corruption_table() {
	for case in VOTE_CASES {
		let mutated = (case.mutate)(baseline_vote_bytes(7));
		let err = Vote::verify(mutated).expect_err(case.description);
		assert_eq!(err.code(), Some(case.expected), "case `{}` produced unexpected error: {err:?}", case.description);
	}
}

// --- Staple corruption table ------------------------------------------------

struct StapleCase {
	description: &'static str,
	mutate: fn(Vec<u8>) -> Vec<u8>,
	expected: &'static str,
}

const STAPLE_CASES: &[StapleCase] = &[
	StapleCase { description: "empty input", mutate: |_| Vec::new(), expected: "VOTE_MALFORMED_STAPLE" },
	StapleCase {
		description: "wrapper is INTEGER, not SEQUENCE",
		mutate: |_| deflate_test(&integer_zero_tlv()),
		expected: "VOTE_MALFORMED_STAPLE",
	},
	StapleCase {
		// Wrapper holds exactly one inner TLV (an INTEGER instead of the
		// expected blocks SEQUENCE) - decoder fails on the blocks slot
		// rather than reaching the votes slot.
		description: "wrapper has only one inner element (INTEGER)",
		mutate: |_| deflate_test(&join_seq([integer_zero_tlv()])),
		expected: "VOTE_MALFORMED_STAPLE_BLOCKS",
	},
	StapleCase {
		description: "trailing bytes after wrapper",
		mutate: |bytes| {
			let mut canonical = inflate_test(&bytes);
			canonical.push(0x00);
			deflate_test(&canonical)
		},
		expected: "VOTE_MALFORMED_STAPLE",
	},
	StapleCase {
		description: "blocks slot is INTEGER",
		mutate: |bytes| {
			let canonical = inflate_test(&bytes);
			let mut parts = split_seq(&canonical);
			parts[0] = integer_zero_tlv();
			deflate_test(&join_seq(parts))
		},
		expected: "VOTE_MALFORMED_STAPLE_BLOCKS",
	},
	StapleCase {
		description: "votes slot is INTEGER",
		mutate: |bytes| {
			let canonical = inflate_test(&bytes);
			let mut parts = split_seq(&canonical);
			parts[1] = integer_zero_tlv();
			deflate_test(&join_seq(parts))
		},
		expected: "VOTE_MALFORMED_STAPLE_VOTES",
	},
	StapleCase {
		description: "blocks SEQUENCE is empty",
		mutate: |bytes| {
			let canonical = inflate_test(&bytes);
			let mut parts = split_seq(&canonical);
			parts[0] = join_seq(Vec::<Vec<u8>>::new());
			deflate_test(&join_seq(parts))
		},
		expected: "VOTE_MALFORMED_STAPLE_BLOCKS_AT_LEAST_ONE",
	},
	StapleCase {
		description: "votes SEQUENCE is empty",
		mutate: |bytes| {
			let canonical = inflate_test(&bytes);
			let mut parts = split_seq(&canonical);
			parts[1] = join_seq(Vec::<Vec<u8>>::new());
			deflate_test(&join_seq(parts))
		},
		expected: "VOTE_MALFORMED_STAPLE_VOTES_AT_LEAST_ONE",
	},
];

#[test]
fn test_staple_corruption_table() -> TestResult {
	let baseline = baseline_staple_bytes()?;
	for case in STAPLE_CASES {
		let mutated = (case.mutate)(baseline.clone());
		let err = VoteStaple::verify(mutated, keetanetwork_vote::ValidationConfig::default(), now_blocktime())
			.expect_err(case.description);
		assert_eq!(err.code(), Some(case.expected), "case `{}` produced unexpected error: {err:?}", case.description);
	}
	Ok(())
}

// --- helpers ----------------------------------------------------------------

/// Replace the `index`th TLV inside the TBS SEQUENCE with `replacement`
/// and re-emit the whole vote wire bytes.
fn replace_tbs_slot(bytes: &[u8], index: usize, replacement: Vec<u8>) -> Vec<u8> {
	let mut wrapper = split_seq(bytes);
	let mut tbs_parts = split_seq(&wrapper[0]);
	tbs_parts[index] = replacement;
	wrapper[0] = join_seq(tbs_parts);
	join_seq(wrapper)
}

fn deflate_test(canonical: &[u8]) -> Vec<u8> {
	let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
	encoder
		.write_all(canonical)
		.expect("zlib write must succeed");
	encoder.finish().expect("zlib finish must succeed")
}

fn inflate_test(compressed: &[u8]) -> Vec<u8> {
	let mut decoder = ZlibDecoder::new(compressed);
	let mut out = Vec::new();
	decoder
		.read_to_end(&mut out)
		.expect("zlib decode must succeed");
	out
}

fn now_blocktime() -> keetanetwork_block::BlockTime {
	let millis = chrono::Utc::now().timestamp_millis();
	keetanetwork_block::BlockTime::from_unix_millis(millis).expect("now must map to BlockTime")
}

fn baseline_staple_bytes() -> Result<Vec<u8>, VoteError> {
	let validity = future_validity();
	let voter = generate_ed25519_ref(0xB0);
	let block = build_minimal_block();
	let block_hashes = [block.hash()];

	let vote = VoteBuilder::new()
		.serial(1u64)
		.issuer(voter.clone())
		.validity(validity.from, validity.to)
		.add_blocks(block_hashes.iter().copied())
		.build_signed(voter.as_ref())?;

	let staple = VoteStapleBuilder::new()
		.add_vote(vote)
		.add_block(block)
		.build()?;
	Ok(staple.as_bytes().to_vec())
}

fn build_minimal_block() -> keetanetwork_block::Block {
	let owner = generate_ed25519_ref(0xB1);
	let representative = generate_ed25519_ref(0xB2);
	keetanetwork_block::BlockBuilder::default()
		.with_network(0u8)
		.with_account(owner)
		.as_opening()
		.with_operation(keetanetwork_block::SetRep { to: representative })
		.build()
		.expect("opening must build")
		.sign()
		.expect("opening must sign")
}
