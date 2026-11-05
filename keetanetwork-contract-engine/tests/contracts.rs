//! End-to-end tests: real Wasm contracts built with the standard CosmWasm
//! toolchain, driven with plain JSON messages the way a wallet or the
//! sequencer anchor would.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::testing::{generate_ed25519_ref, generate_identifier_ref};
use keetanetwork_block::{Operation, UnsignedBlock};
use keetanetwork_contract_engine::{
	BlockContext, Call, Engine, EngineConfig, EngineError, Execution, Fund, LedgerOp, CAPABILITIES,
};
use keetanetwork_crypto::hash::Hashable;
use num_bigint::BigUint;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn contracts_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts")
}

/// The compiled example contract `name`, building the contracts workspace
/// the first time any test asks for one. A plain release build: target
/// flags live in `tests/contracts/.cargo/config.toml`.
fn wasm(name: &str) -> Vec<u8> {
	static BUILT: OnceLock<()> = OnceLock::new();
	BUILT.get_or_init(|| {
		let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
		let status = Command::new(cargo)
			.current_dir(contracts_dir())
			.args(["build", "--release", "--locked", "--target", "wasm32-unknown-unknown"])
			// Anything set here would override the config file's rustflags.
			.env_remove("CARGO_TARGET_DIR")
			.env_remove("RUSTFLAGS")
			.env_remove("CARGO_ENCODED_RUSTFLAGS")
			.status()
			.expect("failed to run cargo for the example contracts");
		assert!(status.success(), "building the example contracts failed");
	});
	let path = contracts_dir()
		.join("target/wasm32-unknown-unknown/release")
		.join(format!("{name}.wasm"));
	std::fs::read(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

fn account(seed: u8) -> String {
	generate_ed25519_ref(seed).to_string()
}

/// A native Keeta token that exists from genesis.
fn native_token() -> String {
	generate_identifier_ref(90, KeyPairType::TOKEN, 0).to_string()
}

struct World {
	engine: Engine,
	sequencer: String,
	height: u64,
	time_millis: i64,
	alice: String,
	bob: String,
	carol: String,
}

impl World {
	fn new() -> Self {
		Self::with_config(|_| {})
	}

	fn with_config(adjust: impl FnOnce(&mut EngineConfig)) -> Self {
		let sequencer = generate_ed25519_ref(200);
		let mut config = EngineConfig::new(sequencer.clone());
		adjust(&mut config);
		Self {
			engine: Engine::new(config).expect("engine"),
			sequencer: sequencer.to_string(),
			height: 0,
			// 2026-01-01T00:00:00Z
			time_millis: 1_767_225_600_000,
			alice: account(1),
			bob: account(2),
			carol: account(3),
		}
	}

	fn now(&self) -> BlockContext {
		BlockContext { height: self.height, time_millis: self.time_millis }
	}

	/// Advance the clock and start a call from `sender`.
	fn call(&mut self, sender: &str) -> Call {
		self.advance(1_000);
		Call::new(sender, self.now())
	}

	fn advance(&mut self, millis: i64) {
		self.height += 1;
		self.time_millis += millis;
	}

	fn store(&self, name: &str) -> u64 {
		self.engine.store_code(&wasm(name)).expect("store code")
	}

	fn query<R: DeserializeOwned>(&self, contract: &str, msg: Value) -> R {
		self.engine
			.query(self.now(), contract, &msg)
			.expect("query")
	}

	fn cw20(&mut self, holders: &[(&str, u128)]) -> String {
		let code = self.store("cw20_token");
		let initial_balances: Vec<Value> = holders
			.iter()
			.map(|(address, amount)| json!({ "address": address, "amount": amount.to_string() }))
			.collect();
		let alice = self.alice.clone();
		let call = self.call(&alice);
		self.engine
			.instantiate(
				&call,
				code,
				&json!({
					"name": "Keeta Coin",
					"symbol": "KCN",
					"decimals": 6,
					"initial_balances": initial_balances,
				}),
				"cw20",
			)
			.expect("instantiate cw20")
			.contract
	}

	fn cw20_balance(&self, token: &str, address: &str) -> u128 {
		let response: Value = self.query(token, json!({ "balance": { "address": address } }));
		response["balance"].as_str().unwrap().parse().unwrap()
	}

	/// An escrow from alice: carol arbitrates, bob receives, expires in an hour.
	fn escrow(&mut self, funds: Vec<Fund>) -> Execution {
		let code = self.store("keeta_escrow");
		let expires_at = (self.time_millis + 3_600_000) as u64 * 1_000_000;
		let (alice, bob, carol) = (self.alice.clone(), self.bob.clone(), self.carol.clone());
		let call = self.call(&alice).with_funds(funds);
		self.engine
			.instantiate(
				&call,
				code,
				&json!({ "arbiter": carol, "recipient": bob, "expires_at": expires_at.to_string() }),
				"escrow",
			)
			.expect("instantiate escrow")
	}

	fn faucet(&mut self) -> Execution {
		let code = self.store("keeta_faucet");
		let alice = self.alice.clone();
		let call = self.call(&alice);
		self.engine
			.instantiate(
				&call,
				code,
				&json!({
					"subdenom": "drip",
					"name": "DRIP",
					"description": "Faucet token",
					"claim_amount": "100",
				}),
				"faucet",
			)
			.expect("instantiate faucet")
	}
}

fn big(value: u128) -> BigUint {
	BigUint::from(value)
}

fn signer_of(block: &UnsignedBlock) -> String {
	let signers = block.required_signers();
	assert_eq!(signers.len(), 1);
	signers[0].to_string()
}

fn contract_error(result: Result<Execution, EngineError>) -> String {
	match result {
		Err(EngineError::Contract { message }) => message,
		other => panic!("expected a contract error, got {other:?}"),
	}
}

// ---------------------------------------------------------------------------
// Ecosystem compatibility
// ---------------------------------------------------------------------------

#[test]
fn unmodified_cw20_base_runs() {
	let mut world = World::new();
	let (alice, bob) = (world.alice.clone(), world.bob.clone());
	let token = world.cw20(&[(&alice, 1_000)]);

	let call = world.call(&alice);
	let transfer = world
		.engine
		.execute(&call, &token, &json!({ "transfer": { "recipient": bob, "amount": "250" } }))
		.expect("transfer");

	assert_eq!(transfer.attribute("action"), Some("transfer"));
	assert_eq!(world.cw20_balance(&token, &alice), 750);
	assert_eq!(world.cw20_balance(&token, &bob), 250);
	let info: Value = world.query(&token, json!({ "token_info": {} }));
	assert_eq!(info["total_supply"], "1000");
	assert_eq!(info["symbol"], "KCN");

	// cw20 balances live in contract state, so a transfer moves no native
	// Keeta tokens and produces no blocks.
	assert!(transfer.blocks.is_empty());
	assert!(transfer.gas_used > 0);
}

#[test]
fn contracts_declare_the_keeta_capability() {
	let world = World::new();
	let cw20 = world.engine.analyze(world.store("cw20_token")).unwrap();
	let faucet = world.engine.analyze(world.store("keeta_faucet")).unwrap();
	assert!(!cw20.required_capabilities.contains("keeta"));
	assert!(faucet.required_capabilities.contains("keeta"));
}

#[test]
fn hosts_without_keeta_extensions_refuse_keeta_contracts() {
	let world = World::with_config(|config| {
		config.capabilities = CAPABILITIES
			.iter()
			.filter(|capability| **capability != "keeta")
			.map(|capability| capability.to_string())
			.collect();
	});
	assert!(world.engine.store_code(&wasm("cw20_token")).is_ok());
	let error = world.engine.store_code(&wasm("keeta_faucet")).unwrap_err();
	assert!(error.to_string().contains("keeta"), "{error}");
}

#[test]
fn rejects_code_that_is_not_a_contract() {
	let world = World::new();
	assert!(world.engine.store_code(b"definitely not wasm").is_err());
	// A valid Wasm module with no CosmWasm exports.
	assert!(world.engine.store_code(b"\0asm\x01\0\0\0").is_err());
}

// ---------------------------------------------------------------------------
// Escrow: native tokens, Keeta queries, memos, cross-contract calls
// ---------------------------------------------------------------------------

#[test]
fn escrow_releases_native_tokens_with_a_memo() {
	let mut world = World::new();
	let token = native_token();
	let (alice, bob, carol) = (world.alice.clone(), world.bob.clone(), world.carol.clone());
	world
		.engine
		.credit_genesis(&alice, &token, 1_000u32)
		.unwrap();

	let created = world.escrow(vec![Fund::new(&token, 400u32)]);
	let escrow = created.contract.clone();
	assert_eq!(world.engine.balance(&escrow, &token), big(400));
	assert_eq!(world.engine.balance(&alice, &token), big(600));

	// The staple: the sequencer creates the contract account, alice funds it.
	assert_eq!(created.blocks.len(), 2);
	assert_eq!(created.blocks[0].data().account().to_string(), world.sequencer);
	assert!(matches!(created.blocks[0].data().operations(), [Operation::CreateIdentifier(_)]));
	assert_eq!(created.blocks[1].data().account().to_string(), alice);
	assert_eq!(signer_of(&created.blocks[1]), alice);

	// Only the arbiter can approve, and a rejected call changes nothing.
	let root = world.engine.state_root();
	let call = world.call(&bob);
	let error = contract_error(
		world
			.engine
			.execute(&call, &escrow, &json!({ "approve": {} })),
	);
	assert!(error.contains("only the arbiter"), "{error}");
	assert_eq!(world.engine.state_root(), root);

	let call = world.call(&carol);
	let approved = world
		.engine
		.execute(&call, &escrow, &json!({ "approve": { "memo": "INVOICE 42" } }))
		.expect("approve");

	assert_eq!(world.engine.balance(&bob, &token), big(400));
	assert_eq!(world.engine.balance(&escrow, &token), big(0));
	assert_eq!(
		approved.operations,
		vec![LedgerOp::Send {
			from: escrow.clone(),
			to: bob.clone(),
			token: token.clone(),
			amount: big(400),
			external: Some("INVOICE 42".into()),
		}]
	);
	// The contract account's block is signed by the sequencer, which owns it.
	let [block] = approved.blocks.as_slice() else {
		panic!("one block")
	};
	assert_eq!(block.data().account().to_string(), escrow);
	assert_eq!(signer_of(block), world.sequencer);

	let call = world.call(&carol);
	let error = contract_error(
		world
			.engine
			.execute(&call, &escrow, &json!({ "approve": {} })),
	);
	assert!(error.contains("closed"), "{error}");
}

#[test]
fn escrow_refunds_only_after_expiry() {
	let mut world = World::new();
	let token = native_token();
	let (alice, bob) = (world.alice.clone(), world.bob.clone());
	world
		.engine
		.credit_genesis(&alice, &token, 1_000u32)
		.unwrap();
	let escrow = world.escrow(vec![Fund::new(&token, 400u32)]).contract;

	let call = world.call(&bob);
	let error = contract_error(
		world
			.engine
			.execute(&call, &escrow, &json!({ "refund": {} })),
	);
	assert!(error.contains("not expired"), "{error}");

	world.advance(3_600_000);
	let call = world.call(&bob);
	let refunded = world
		.engine
		.execute(&call, &escrow, &json!({ "refund": {} }))
		.expect("refund");
	assert_eq!(world.engine.balance(&alice, &token), big(1_000));
	assert!(matches!(
		refunded.operations.as_slice(),
		[LedgerOp::Send { external: Some(memo), .. }] if memo == "REFUND"
	));
}

#[test]
fn escrow_holds_cw20_and_releases_it_across_contracts() {
	let mut world = World::new();
	let (alice, bob, carol) = (world.alice.clone(), world.bob.clone(), world.carol.clone());
	let token = world.cw20(&[(&alice, 1_000)]);
	let escrow = world.escrow(Vec::new()).contract;

	// cw20 `send` calls the escrow's `receive` hook: one call, two contracts.
	let call = world.call(&alice);
	let deposit = world
		.engine
		.execute(&call, &token, &json!({ "send": { "contract": escrow, "amount": "300", "msg": "e30=" } }))
		.expect("deposit");
	let called: Vec<_> = deposit
		.events
		.iter()
		.filter(|event| event.ty == "execute")
		.map(|event| event.attributes[0].1.clone())
		.collect();
	assert_eq!(called, vec![token.clone(), escrow.clone()]);

	let holdings: Value = world.query(&escrow, json!({ "holdings": {} }));
	assert_eq!(holdings["cw20"], json!([{ "token": token, "amount": "300" }]));

	let call = world.call(&carol);
	world
		.engine
		.execute(&call, &escrow, &json!({ "approve": {} }))
		.expect("approve");
	assert_eq!(world.cw20_balance(&token, &bob), 300);
	assert_eq!(world.cw20_balance(&token, &escrow), 0);
}

#[test]
fn a_failure_deep_in_a_call_rolls_back_every_contract() {
	let mut world = World::new();
	let (alice, carol) = (world.alice.clone(), world.carol.clone());
	let token = world.cw20(&[(&alice, 1_000)]);
	let escrow = world.escrow(Vec::new()).contract;
	let call = world.call(&carol);
	world
		.engine
		.execute(&call, &escrow, &json!({ "approve": {} }))
		.expect("approve");

	// cw20 debits alice, then the closed escrow rejects the deposit: the
	// debit must be undone too.
	let root = world.engine.state_root();
	let call = world.call(&alice);
	let error = contract_error(world.engine.execute(
		&call,
		&token,
		&json!({ "send": { "contract": escrow, "amount": "300", "msg": "e30=" } }),
	));
	assert!(error.contains("closed"), "{error}");
	assert_eq!(world.cw20_balance(&token, &alice), 1_000);
	assert_eq!(world.engine.state_root(), root);
}

// ---------------------------------------------------------------------------
// Faucet: native token issuance, submessages and replies
// ---------------------------------------------------------------------------

#[test]
fn faucet_issues_a_native_keeta_token() {
	let mut world = World::new();
	let alice = world.alice.clone();
	let created = world.faucet();
	let faucet = created.contract.clone();
	let token = world
		.engine
		.token_address(&faucet, "drip")
		.expect("token created");

	// The sequencer creates both identifiers in one block; the token and the
	// faucet each get their info set on their own chains.
	let accounts: Vec<_> = created
		.blocks
		.iter()
		.map(|b| b.data().account().to_string())
		.collect();
	assert_eq!(accounts, vec![world.sequencer.clone(), token.clone(), faucet.clone()]);
	assert_eq!(created.blocks[0].data().operations().len(), 2);
	assert_eq!(world.engine.account_info(&faucet).name, "FAUCET");
	assert_eq!(world.engine.account_info(&token).name, "DRIP");

	// Contracts see the same token through their Keeta queries.
	let queried: String = world.query(&faucet, json!({ "token": {} }));
	assert_eq!(queried, token);

	let call = world.call(&alice);
	let claimed = world
		.engine
		.execute(&call, &faucet, &json!({ "claim": {} }))
		.expect("claim");
	assert_eq!(world.engine.balance(&alice, &token), big(100));
	let [mint] = claimed.blocks.as_slice() else {
		panic!("one block")
	};
	assert_eq!(mint.data().account().to_string(), token);
	assert!(matches!(mint.data().operations(), [Operation::TokenAdminSupply(_), Operation::Send(_)]));
	// The token's chain continues from the block that set its info.
	assert_eq!(*mint.data().previous(), created.blocks[1].hash());

	let call = world.call(&alice);
	let error = contract_error(
		world
			.engine
			.execute(&call, &faucet, &json!({ "claim": {} })),
	);
	assert!(error.contains("already claimed"), "{error}");

	// Hand 40 back to be burned: alice → faucet → token, then supply drops.
	let call = world.call(&alice).with_funds([Fund::new(&token, 40u32)]);
	let returned = world
		.engine
		.execute(&call, &faucet, &json!({ "return": {} }))
		.expect("return");
	assert_eq!(world.engine.balance(&alice, &token), big(60));
	assert_eq!(world.engine.token_supply(&token), Some(big(60)));
	let supply: String = world.query(&faucet, json!({ "supply": {} }));
	assert_eq!(supply, "60");
	let accounts: Vec<_> = returned
		.blocks
		.iter()
		.map(|b| b.data().account().to_string())
		.collect();
	assert_eq!(accounts, vec![alice, faucet, token]);
}

#[test]
fn airdrop_tolerates_bad_recipients_through_replies() {
	let mut world = World::new();
	let (alice, bob, carol) = (world.alice.clone(), world.bob.clone(), world.carol.clone());
	let faucet = world.faucet().contract;
	let token = world.engine.token_address(&faucet, "drip").unwrap();

	let call = world.call(&alice);
	let airdrop = world
		.engine
		.execute(&call, &faucet, &json!({ "airdrop": { "recipients": [bob, "keeta_not_an_address", carol] } }))
		.expect("airdrop");

	let stats: Value = world.query(&faucet, json!({ "airdrop_stats": {} }));
	assert_eq!(stats, json!({ "succeeded": 2, "failed": 1 }));
	assert_eq!(world.engine.balance(&bob, &token), big(100));
	assert_eq!(world.engine.balance(&carol, &token), big(100));
	assert_eq!(world.engine.token_supply(&token), Some(big(200)));
	// The failed mint left nothing behind: both successful mints land in
	// one block on the token's chain.
	assert_eq!(airdrop.blocks.len(), 1);
	assert_eq!(airdrop.blocks[0].data().operations().len(), 4);

	let call = world.call(&bob);
	let error = contract_error(
		world
			.engine
			.execute(&call, &faucet, &json!({ "airdrop": { "recipients": [] } })),
	);
	assert!(error.contains("only the admin"), "{error}");
}

#[test]
fn keeta_field_rules_apply_to_contract_output() {
	let mut world = World::new();
	let code = world.store("keeta_faucet");
	let alice = world.alice.clone();
	let root = world.engine.state_root();
	let call = world.call(&alice);
	// Token names must match `[A-Z_]*`.
	let result = world.engine.instantiate(
		&call,
		code,
		&json!({ "subdenom": "drip", "name": "lowercase", "description": "x", "claim_amount": "1" }),
		"faucet",
	);
	assert!(matches!(result, Err(EngineError::InvalidField { field: "name", .. })), "{result:?}");
	assert_eq!(world.engine.state_root(), root);
}

// ---------------------------------------------------------------------------
// Gas and determinism
// ---------------------------------------------------------------------------

#[test]
fn running_out_of_gas_aborts_and_rolls_back() {
	let mut world = World::new();
	let (alice, bob) = (world.alice.clone(), world.bob.clone());
	let token = world.cw20(&[(&alice, 1_000)]);
	let root = world.engine.state_root();

	let call = world.call(&alice).with_gas_limit(1_000_000);
	let result = world
		.engine
		.execute(&call, &token, &json!({ "transfer": { "recipient": bob, "amount": "1" } }));
	assert!(matches!(result, Err(EngineError::OutOfGas)), "{result:?}");
	assert_eq!(world.engine.state_root(), root);
}

/// The same scenario on two independent engines must agree exactly.
#[test]
fn execution_is_deterministic() {
	fn scenario() -> (Vec<[u8; 32]>, Vec<String>, Vec<u64>) {
		let mut world = World::new();
		let token = native_token();
		let (alice, bob, carol) = (world.alice.clone(), world.bob.clone(), world.carol.clone());
		world
			.engine
			.credit_genesis(&alice, &token, 1_000u32)
			.unwrap();

		let mut executions = vec![world.escrow(vec![Fund::new(&token, 400u32)])];
		let escrow = executions[0].contract.clone();
		let call = world.call(&carol);
		executions.push(
			world
				.engine
				.execute(&call, &escrow, &json!({ "approve": {} }))
				.unwrap(),
		);
		executions.push(world.faucet());
		let faucet = executions[2].contract.clone();
		let call = world.call(&alice);
		executions.push(
			world
				.engine
				.execute(&call, &faucet, &json!({ "airdrop": { "recipients": [bob, carol] } }))
				.unwrap(),
		);

		let roots = executions.iter().map(|e| e.state_root).collect();
		let hashes = executions
			.iter()
			.flat_map(|e| &e.blocks)
			.map(|block| block.hash().to_string())
			.collect();
		let gas = executions.iter().map(|e| e.gas_used).collect();
		(roots, hashes, gas)
	}

	let first = scenario();
	assert_eq!(first, scenario());
	assert_eq!(first.1.len(), 7);
}
