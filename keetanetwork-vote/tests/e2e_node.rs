//! Live vote staple round trips against a running reference node.

mod support;

use std::str::FromStr;
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_block::{AccountRef, Block, BlockBuilder, BlockHash, BlockTime, Hashable, SetRep};
use keetanetwork_utils::node_harness::E2eNode;
use keetanetwork_vote::{ValidationConfig, VoteBuilder, VoteError, VoteStaple, VoteStapleBuilder};
use serde_json::{json, Value};

use support::{assert_ts_staple_matches_rust, future_validity, hex_decode, json_str, TestResult};

const FORWARD_SEED_BYTE: u8 = 0x33;
const REVERSE_SEED_BYTE: u8 = 0x44;
const RUST_BUILT_SEED_BYTE: u8 = 0x55;
const FUNDING_AMOUNT: u64 = 4_200;

fn parse_account(value: &Value, field: &str) -> AccountRef {
	let text = value[field]
		.as_str()
		.unwrap_or_else(|| panic!("account field {field} must be a string"));
	let account =
		GenericAccount::from_str(text).unwrap_or_else(|err| panic!("account string {text} must parse: {err}"));
	Arc::new(account)
}

fn now_blocktime() -> BlockTime {
	let millis = chrono::Utc::now().timestamp_millis();
	BlockTime::from_unix_millis(millis).expect("the current time must be representable as BlockTime")
}

fn fund(node: &mut E2eNode, account: &AccountRef, label: &str) {
	node.request("send", json!({ "to": account.to_string(), "amount": FUNDING_AMOUNT.to_string(), "external": label }))
		.unwrap_or_else(|err| panic!("funding send must succeed: {err}"));
}

fn build_opening(rust: &AccountRef, representative: &AccountRef) -> Block {
	BlockBuilder::default()
		.with_network(0u8)
		.with_account(rust.clone())
		.as_opening()
		.with_operation(SetRep { to: representative.clone() })
		.build()
		.expect("opening block must build")
		.sign()
		.expect("opening block must sign")
}

/// Boot the harness, mint initial supply, and return `(node,
/// representative)`.
fn start_harness() -> (E2eNode, AccountRef) {
	let mut node = E2eNode::start().expect("the reference node harness must start");
	node.request("init_supply", json!({ "amount": "1000000" }))
		.expect("network initialization must succeed");
	let representative = parse_account(&node.info().clone(), "representative");
	(node, representative)
}

fn shutdown(node: E2eNode) {
	node.shutdown().expect("the harness must shut down cleanly");
}

/// Wrap `openings` in a Rust-built staple signed by deterministic
/// representative + trusted votes. Rep and vote both list `openings`
/// in the supplied order, so the canonical block order in the
/// resulting staple matches the input.
fn build_rust_staple(openings: &[Block]) -> Result<VoteStaple, VoteError> {
	let rep_signer = generate_ed25519_ref(0xA1);
	let trusted_signer = generate_ed25519_ref(0xA2);
	let validity = future_validity();
	let block_hashes: Vec<BlockHash> = openings.iter().map(Hashable::hash).collect();

	let rep_vote = VoteBuilder::new()
		.serial(1u64)
		.issuer(rep_signer.clone())
		.validity(validity.from, validity.to)
		.add_blocks(block_hashes.iter().copied())
		.build_signed(rep_signer.as_ref())?;
	let trusted_vote = VoteBuilder::new()
		.serial(1u64)
		.issuer(trusted_signer.clone())
		.validity(validity.from, validity.to)
		.add_blocks(block_hashes.iter().copied())
		.build_signed(trusted_signer.as_ref())?;

	let mut builder = VoteStapleBuilder::new()
		.add_vote(rep_vote)
		.add_vote(trusted_vote);
	for opening in openings {
		builder = builder.add_block(opening.clone());
	}
	builder.build()
}

#[test]
fn test_ts_mints_staple_from_rust_block() -> TestResult {
	let (mut node, representative) = start_harness();

	let account = generate_ed25519_ref(FORWARD_SEED_BYTE);
	fund(&mut node, &account, "vote staple e2e forward");
	let opening = build_opening(&account, &representative);

	let response = node.request("transmit", json!({ "bytes": hex::encode_upper(opening.to_bytes()) }))?;
	let bytes_hex = json_str(&response, "stapleBytes");
	let staple = VoteStaple::verify(hex_decode(&bytes_hex), ValidationConfig::default(), now_blocktime())?;

	assert_eq!(hex::encode_upper(staple.as_bytes()), bytes_hex, "the staple must re-encode byte-exactly");
	assert_eq!(staple.blocks().len(), 1, "the staple must contain exactly the block we transmitted");
	assert_eq!(
		staple.blocks()[0].hash().to_string(),
		opening.hash().to_string(),
		"the staple must wrap our Rust-built block"
	);
	assert!(!staple.votes().is_empty(), "the staple must carry at least one vote");

	shutdown(node);
	Ok(())
}

#[test]
fn test_harness_built_staple_verifies_in_rust() -> TestResult {
	let (mut node, representative) = start_harness();

	let account = generate_ed25519_ref(REVERSE_SEED_BYTE);
	fund(&mut node, &account, "vote staple e2e reverse");
	let opening = build_opening(&account, &representative);

	let response = node.request("build_staple", json!({ "bytes": hex::encode_upper(opening.to_bytes()) }))?;
	let bytes_hex = json_str(&response, "bytes");
	let reported_hash = json_str(&response, "stapleHash");
	let staple = VoteStaple::verify(hex_decode(&bytes_hex), ValidationConfig::default(), now_blocktime())?;

	assert_eq!(hex::encode_upper(staple.as_bytes()), bytes_hex, "the harness-built staple must re-encode byte-exactly");
	assert_eq!(staple.hash().to_string(), reported_hash, "Rust and TS must agree on the staple hash");
	assert_eq!(staple.blocks().len(), 1, "the harness staple must wrap exactly the block we provided");
	assert_eq!(
		staple.blocks()[0].hash().to_string(),
		opening.hash().to_string(),
		"the harness staple must wrap our Rust-built block"
	);

	shutdown(node);
	Ok(())
}

#[test]
fn test_rust_built_staple_verifies_in_typescript() -> TestResult {
	let representative = generate_ed25519_ref(0xA0);
	let account = generate_ed25519_ref(RUST_BUILT_SEED_BYTE);
	let opening = build_opening(&account, &representative);
	let staple = build_rust_staple(&[opening])?;

	let mut node = E2eNode::start().expect("the reference node harness must start");
	let response = node.request("verify_staple", json!({ "bytes": hex::encode_upper(staple.as_bytes()) }))?;
	assert_ts_staple_matches_rust(&staple, &response);

	shutdown(node);
	Ok(())
}

#[test]
fn test_rust_built_multi_block_staple_verifies_in_typescript() -> TestResult {
	let representative = generate_ed25519_ref(0xA0);
	let opening_a = build_opening(&generate_ed25519_ref(0x60), &representative);
	let opening_b = build_opening(&generate_ed25519_ref(0x61), &representative);
	let staple = build_rust_staple(&[opening_a, opening_b])?;

	let mut node = E2eNode::start().expect("the reference node harness must start");
	let response = node.request("verify_staple", json!({ "bytes": hex::encode_upper(staple.as_bytes()) }))?;
	assert_ts_staple_matches_rust(&staple, &response);

	shutdown(node);
	Ok(())
}
