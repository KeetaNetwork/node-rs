//! Live end-to-end round trips against a running reference node.
//! Requires the Node.js harness (`make node-harness`); fails when it is unavailable.

mod support;

use std::str::FromStr;
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_block::{Amount, Block, BlockBuilder, Hashable, Send, SetRep};
use keetanetwork_utils::node_harness::E2eNode;
use serde_json::{json, Value};

use support::generate_ed25519_ref;

/// The seed for the account driven by the Rust side of the test.
const RUST_SEED_BYTE: u8 = 0x21;

/// The amount the harness faucet sends to the Rust account.
const FUNDING_AMOUNT: u64 = 4_200;

/// The amount the Rust account sends back to the faucet.
const RETURN_AMOUNT: u64 = 1_000;

fn parse_account(value: &Value, field: &str) -> keetanetwork_block::AccountRef {
	let text = value[field]
		.as_str()
		.expect("account field must be a string");
	Arc::new(GenericAccount::from_str(text).expect("account string must parse"))
}

/// Verify every committed block decodes in Rust, re-encodes byte-exactly
/// and agrees on the hash. Returns the number of blocks verified.
fn verify_committed_blocks(context: &str, response: &Value) -> usize {
	let blocks = response["blocks"]
		.as_array()
		.expect("response must carry blocks");
	assert!(!blocks.is_empty(), "{context}: the ledger must have committed blocks");

	for entry in blocks {
		let bytes_hex = entry["bytes"]
			.as_str()
			.expect("block bytes must be a string");
		let hash = entry["hash"].as_str().expect("block hash must be a string");
		let bytes = hex::decode(bytes_hex).expect("block bytes must be hex");

		let block = Block::try_from(bytes.as_slice())
			.unwrap_or_else(|error| panic!("{context}: committed block must decode in Rust: {error}"));

		assert_eq!(
			hex::encode_upper(block.to_bytes()),
			bytes_hex,
			"{context}: committed block must re-encode byte-exactly"
		);
		assert_eq!(block.hash().to_string(), hash, "{context}: hashes must agree across implementations");
	}

	blocks.len()
}

fn head(node: &mut E2eNode, account: &keetanetwork_block::AccountRef) -> (Option<String>, u64) {
	let response = node
		.request("head", json!({ "account": account.to_string() }))
		.expect("head query must succeed");

	let head = response["head"].as_str().map(str::to_string);
	let balance = response["balance"]
		.as_str()
		.expect("balance must be a string")
		.parse()
		.expect("balance must be numeric");

	(head, balance)
}

#[test]
fn test_live_node_round_trips() {
	let mut node = E2eNode::start().expect("the reference node harness must start");
	let rust = generate_ed25519_ref(RUST_SEED_BYTE);

	// -- TS -> Rust: every ledger-committed block must round-trip --

	let ready = node
		.request("init_supply", json!({ "amount": "1000000" }))
		.expect("network initialization must succeed");
	verify_committed_blocks("init_supply", &ready);

	let sent = node
		.request(
			"send",
			json!({ "to": rust.to_string(), "amount": FUNDING_AMOUNT.to_string(), "external": "e2e funding" }),
		)
		.expect("funding send must succeed");
	verify_committed_blocks("send", &sent);

	let info = node
		.request("set_info", json!({ "name": "LIVE_FAUCET", "description": "Live e2e faucet account", "metadata": "" }))
		.expect("set_info must succeed");
	verify_committed_blocks("set_info", &info);

	let certificate = node
		.request("manage_cert_add", json!({}))
		.expect("certificate addition must succeed");
	verify_committed_blocks("manage_cert_add", &certificate);

	// -- Rust -> TS: Rust-built blocks must be voted in by the live node --

	let info = node.info().clone();
	let base_token = parse_account(&info, "baseToken");
	let trusted = parse_account(&info, "trusted");
	let representative = parse_account(&info, "representative");

	// The funding send credits the account directly on the ledger.
	let (head_hash, balance) = head(&mut node, &rust);
	assert_eq!(head_hash, None, "the Rust account must have no blocks before transmitting");
	assert_eq!(balance, FUNDING_AMOUNT, "the funding send must be credited on the ledger");

	// Opening block: delegate to the representative.
	let opening = BlockBuilder::default()
		.with_network(0u8)
		.with_account(rust.clone())
		.as_opening()
		.with_operation(SetRep { to: representative.clone() })
		.build()
		.expect("opening block must build")
		.sign()
		.expect("opening block must sign");

	let committed = node
		.request("transmit", json!({ "bytes": hex::encode_upper(opening.to_bytes()) }))
		.expect("the live node must vote in the Rust-built opening block");
	verify_committed_blocks("transmit opening", &committed);

	let (head_hash, balance) = head(&mut node, &rust);
	assert_eq!(
		head_hash.as_deref(),
		Some(opening.hash().to_string().as_str()),
		"the ledger head must be the Rust-built opening block"
	);
	assert_eq!(balance, FUNDING_AMOUNT, "delegation must not change the balance");

	// Successor block: send part of the funds back to the faucet.
	let send_back = BlockBuilder::default()
		.with_network(0u8)
		.with_account(rust.clone())
		.with_previous(opening.hash())
		.with_operation(Send {
			to: trusted.clone(),
			amount: Amount::from(RETURN_AMOUNT),
			token: base_token.clone(),
			external: None,
		})
		.build()
		.expect("send-back block must build")
		.sign()
		.expect("send-back block must sign");

	let committed = node
		.request("transmit", json!({ "bytes": hex::encode_upper(send_back.to_bytes()) }))
		.expect("the live node must vote in the Rust-built send block");
	verify_committed_blocks("transmit send", &committed);

	let (head_hash, balance) = head(&mut node, &rust);
	assert_eq!(
		head_hash.as_deref(),
		Some(send_back.hash().to_string().as_str()),
		"the ledger head must advance to the Rust-built send block"
	);
	assert_eq!(balance, FUNDING_AMOUNT - RETURN_AMOUNT, "the returned funds must be debited on the ledger");

	node.shutdown().expect("the harness must shut down cleanly");
}
