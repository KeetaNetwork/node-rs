//! End-to-end binding coverage for the value-type handle.

use std::time::{SystemTime, UNIX_EPOCH};

use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_block::{AccountRef, Hashable};
use keetanetwork_ffi::{Block, FfiError, Vote, VoteStaple};
use keetanetwork_vote::testing::{ed25519_issuer, future_validity, opening_block, sign_simple_vote};
use keetanetwork_vote::VoteStapleBuilder;

const SERIAL: u64 = 1;

fn now_ms() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("clock must be after the epoch")
		.as_millis() as i64
}

fn owner() -> AccountRef {
	generate_ed25519_ref(1)
}

fn representative() -> AccountRef {
	generate_ed25519_ref(2)
}

fn sample_block() -> keetanetwork_block::Block {
	opening_block(&owner(), &representative())
}

fn sample_vote(block: &keetanetwork_block::Block) -> keetanetwork_vote::Vote {
	let issuer = ed25519_issuer(b"ffi-binding-issuer");
	sign_simple_vote(&issuer, SERIAL, future_validity(), [block.hash()], None)
}

fn sample_staple() -> keetanetwork_vote::VoteStaple {
	let block = sample_block();
	let vote = sample_vote(&block);
	VoteStapleBuilder::new()
		.add_block(block)
		.add_vote(vote)
		.build()
		.expect("staple must build")
}

#[test]
fn block_handle_projects_every_field() {
	let block = sample_block();
	let bytes = block.to_bytes().to_vec();

	let handle = Block::from_bytes(bytes.clone()).expect("block bytes must decode");

	assert_eq!(handle.to_bytes(), bytes, "round-trip bytes must equal the input");
	assert_eq!(handle.hash_hex(), hex::encode_upper(block.hash().as_bytes()), "hash hex must match the core hash");
	assert_eq!(handle.account(), owner().to_string(), "account must be the owner public-key string");
	assert!(handle.is_opening(), "the fixture is an opening block");
	assert_eq!(handle.operation_count(), 1, "the fixture carries a single SetRep operation");
	assert_eq!(handle.signatures().len(), 1, "a single-signer block has one signature");
}

#[test]
fn block_handle_rejects_garbage() {
	let Err(FfiError::Keeta { code, .. }) = Block::from_bytes(vec![0u8; 4]) else {
		panic!("garbage must not decode");
	};
	assert!(!code.is_empty(), "a decode failure must carry a code");
}

#[test]
fn vote_handle_projects_every_field() {
	let block = sample_block();
	let vote = sample_vote(&block);
	let bytes = vote.as_bytes().to_vec();

	let handle = Vote::from_bytes(bytes.clone()).expect("vote bytes must decode");
	assert_eq!(handle.to_bytes(), bytes, "round-trip bytes must equal the input");
	assert_eq!(handle.hash_hex(), hex::encode_upper(vote.hash().as_bytes()), "hash hex must match the core hash");
	assert_eq!(handle.serial(), SERIAL.to_string(), "serial must be the decimal string");
	assert_eq!(handle.issuer(), vote.issuer().to_string(), "issuer must be the public-key string");
	assert_eq!(handle.block_hashes(), vec![hex::encode_upper(block.hash().as_bytes())], "block hash list must match");
	assert_eq!(handle.validity_from_ms(), vote.validity().from.unix_millis(), "validity-from must match");
	assert!(!handle.is_quote(), "the fixture is not a quote vote");
	assert!(!handle.has_fees(), "the fixture declares no fees");
}

#[test]
fn staple_handle_exposes_children() {
	let staple = sample_staple();
	let bytes = staple.as_bytes().to_vec();

	let handle = VoteStaple::from_bytes(bytes.clone(), now_ms()).expect("staple bytes must decode");

	assert_eq!(handle.to_bytes(), bytes, "round-trip bytes must equal the input");
	assert_eq!(handle.hash_hex(), hex::encode_upper(staple.hash().as_bytes()), "hash hex must match the core hash");
	assert_eq!(handle.block_count(), 1, "the fixture endorses a single block");
	assert_eq!(handle.vote_count(), 1, "the fixture carries a single vote");

	let blocks = handle.blocks();
	assert_eq!(blocks.len(), 1, "blocks accessor must mirror the count");
	assert_eq!(blocks[0].hash_hex(), hex::encode_upper(staple.blocks()[0].hash().as_bytes()), "child block hash");

	let votes = handle.votes();
	assert_eq!(votes.len(), 1, "votes accessor must mirror the count");
	assert_eq!(votes[0].serial(), SERIAL.to_string(), "child vote serial");
}

#[test]
fn staple_handle_rejects_unrepresentable_moment() {
	let staple = sample_staple();
	let bytes = staple.as_bytes().to_vec();

	let Err(FfiError::Keeta { code, .. }) = VoteStaple::from_bytes(bytes, i64::MAX) else {
		panic!("an out-of-range moment must fail");
	};
	assert_eq!(code, "INVALID_MOMENT", "moment overflow must surface the boundary code");
}
