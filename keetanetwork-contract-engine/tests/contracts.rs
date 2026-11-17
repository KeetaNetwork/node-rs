//! End-to-end tests: real sBPF contracts built with Solana's platform tools,
//! driven with borsh instructions the way a wallet would, and run the way a
//! representative runs each `CONTRACT_CALL`.
//!
//! Every successful call is applied through [`MemoryHost::apply`], as the
//! ledger applies an accepted call: so these tests also check that no call's
//! outcome overdraws an account or breaks the ledger's permissions.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use borsh::{BorshDeserialize, BorshSerialize};
use keetanetwork_account::KeyPairType;
use keetanetwork_block::testing::{generate_ed25519_ref, generate_identifier_ref};
use keetanetwork_contract_engine::{
	to_address, AccountInfo, AccountMeta, Address, CodeHash, ContractRecord, Effect, Engine, EngineConfig, EngineError,
	Fund, Host, HostError, HostResult, Instruction, LedgerCall, LedgerOutcome, MemoryHost, StateAccess, StateId,
};
use num_bigint::BigUint;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn contracts_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts")
}

/// `cargo-build-sbf`: `$CARGO_BUILD_SBF`, on the `PATH`, or where Anza's
/// installer puts it.
fn build_sbf() -> PathBuf {
	if let Ok(path) = std::env::var("CARGO_BUILD_SBF") {
		return path.into();
	}
	if Command::new("cargo-build-sbf")
		.arg("--version")
		.output()
		.is_ok_and(|output| output.status.success())
	{
		return "cargo-build-sbf".into();
	}
	let home = std::env::var("HOME").expect("HOME is set");
	PathBuf::from(home).join(".local/share/solana/install/active_release/bin/cargo-build-sbf")
}

/// The compiled example contract `name`, building the example contracts the
/// first time any test asks for one.
fn elf(name: &str) -> Vec<u8> {
	static BUILT: OnceLock<()> = OnceLock::new();
	BUILT.get_or_init(|| {
		// Each contract on its own, with its own manifest: built together, the
		// pet's dependency on the shop with `no-entrypoint` would leave the
		// shop's own program without its entrypoint (Cargo unifies features).
		let mut contracts: Vec<_> = std::fs::read_dir(contracts_dir())
			.expect("the contracts workspace")
			.filter_map(Result::ok)
			.map(|entry| entry.path())
			.filter(|path| path.join("Cargo.toml").is_file())
			.collect();
		contracts.sort();
		for contract in contracts {
			let mut command = Command::new(build_sbf());
			command.current_dir(contracts_dir()).args([
				"--arch",
				"v3",
				"--manifest-path",
				&contract.join("Cargo.toml").to_string_lossy(),
				"--",
				"--locked",
			]);
			// What cargo sets for this test would steer the contracts' build.
			for variable in [
				"CARGO",
				"CARGO_TARGET_DIR",
				"CARGO_BUILD_TARGET",
				"CARGO_ENCODED_RUSTFLAGS",
				"RUSTFLAGS",
				"RUSTC",
				"RUSTC_WRAPPER",
				"RUSTDOC",
				"RUSTUP_TOOLCHAIN",
			] {
				command.env_remove(variable);
			}
			let status = command
				.status()
				.expect("running cargo-build-sbf (install Anza's toolchain, or set CARGO_BUILD_SBF)");
			assert!(status.success(), "building {} failed", contract.display());
		}
	});
	let path = contracts_dir()
		.join("target/deploy")
		.join(format!("{}.so", name.replace('-', "_")));
	std::fs::read(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

fn account(seed: u8) -> String {
	generate_ed25519_ref(seed).to_string()
}

/// A native Keeta token that exists from genesis.
fn native_token() -> String {
	generate_identifier_ref(90, KeyPairType::TOKEN, 0).to_string()
}

fn addr(account: &str) -> Address {
	to_address(account).expect("contract address form")
}

fn big(value: u128) -> BigUint {
	BigUint::from(value)
}

fn data<T: BorshSerialize>(value: &T) -> Vec<u8> {
	borsh::to_vec(value).expect("borsh")
}

/// Gas for every call: Solana's per-transaction maximum.
const GAS_LIMIT: u64 = 1_400_000;

/// A call from `caller`, with the funds its block sends the contract.
struct Call {
	caller: String,
	funds: Vec<Fund>,
	gas_limit: u64,
}

impl Call {
	fn with_funds(mut self, funds: impl IntoIterator<Item = Fund>) -> Self {
		self.funds.extend(funds);
		self
	}

	fn with_gas_limit(mut self, gas_limit: u64) -> Self {
		self.gas_limit = gas_limit;
		self
	}
}

struct World {
	engine: Engine,
	host: Arc<MemoryHost>,
	time_millis: i64,
	alice: String,
	bob: String,
	carol: String,
	/// Contracts deployed so far
	deployed: u32,
}

impl World {
	fn new() -> Self {
		Self::with_config(EngineConfig::default())
	}

	fn with_config(config: EngineConfig) -> Self {
		Self {
			engine: Engine::new(config).expect("engine"),
			host: Arc::new(MemoryHost::new()),
			// 2026-01-01T00:00:00Z
			time_millis: 1_767_225_600_000,
			alice: account(1),
			bob: account(2),
			carol: account(3),
			deployed: 0,
		}
	}

	/// Advance the clock and start a call from `caller`.
	fn call(&mut self, caller: &str) -> Call {
		self.advance(1_000);
		Call { caller: caller.to_string(), funds: Vec::new(), gas_limit: GAS_LIMIT }
	}

	fn advance(&mut self, millis: i64) {
		self.time_millis += millis;
	}

	/// Check `name`'s code and deploy it at a new address, as the ledger does
	/// for a `CONTRACT_DEPLOY`.
	fn deploy(&mut self, name: &str) -> String {
		let elf = elf(name);
		self.engine.store_code(&elf).expect("store code");
		let address = generate_identifier_ref(150, KeyPairType::STORAGE, self.deployed).to_string();
		self.deployed += 1;
		self.host.deploy(&address, elf);
		address
	}

	fn ledger_call(&self, call: &Call, instruction: &Instruction) -> LedgerCall {
		LedgerCall {
			caller: call.caller.clone(),
			instruction: instruction.clone(),
			funds: call.funds.clone(),
			gas_limit: call.gas_limit,
			time_millis: self.time_millis,
		}
	}

	/// Run a call and apply its outcome, as the ledger does once the call's
	/// block is accepted.
	fn execute(&self, call: &Call, instruction: &Instruction) -> Result<LedgerOutcome, EngineError> {
		let call = self.ledger_call(call, instruction);
		let outcome = self.engine.run_ledger_call(self.host.clone(), &call)?;
		self.host
			.apply(&call, &outcome)
			.expect("the ledger applies the outcome");
		Ok(outcome)
	}

	/// What an instruction returns, as alice, without applying anything.
	fn view<T: BorshDeserialize>(&self, instruction: &Instruction) -> T {
		let call = Call { caller: self.alice.clone(), funds: Vec::new(), gas_limit: GAS_LIMIT };
		let outcome = self
			.engine
			.run_ledger_call(self.host.clone(), &self.ledger_call(&call, instruction))
			.expect("view");
		borsh::from_slice(outcome.data.as_deref().unwrap_or_default()).expect("view data")
	}

	fn balance(&self, account: &str, token: &str) -> BigUint {
		self.host.balance_of(account, token)
	}
}

fn contract_error(result: Result<impl std::fmt::Debug, EngineError>) -> String {
	match result {
		Err(EngineError::Contract { message }) => message,
		other => panic!("expected a contract error, got {other:?}"),
	}
}

fn account_error(result: Result<impl std::fmt::Debug, EngineError>) -> String {
	match result {
		Err(EngineError::InvalidAccount { reason }) => reason,
		other => panic!("expected an account error, got {other:?}"),
	}
}

fn ledger_error(result: Result<impl std::fmt::Debug, EngineError>) -> String {
	match result {
		Err(EngineError::Ledger { message }) => message,
		other => panic!("expected a ledger error, got {other:?}"),
	}
}

// ---------------------------------------------------------------------------
// The pet
// ---------------------------------------------------------------------------

use keeta_pet::{Instruction as PetIx, Mood, PetView};
use keeta_pet_shop::{Instruction as ShopIx, Shop};

/// A second native token, standing in for a stablecoin (WUSD): what meals
/// are paid in.
fn wusd() -> String {
	generate_identifier_ref(91, KeyPairType::TOKEN, 0).to_string()
}

/// A pet, and the shop it buys food from (meals at 10 WUSD, 5 in stock),
/// both run by alice; alice and bob hold KTA and WUSD.
fn pet_world() -> (World, String, String) {
	let mut world = World::new();
	let shop = world.deploy("keeta-pet-shop");
	let pet = world.deploy("keeta-pet");
	let alice = world.alice.clone();
	let call = world.call(&alice);
	let open = ShopIx::Init { token: addr(&wusd()), price: 10, stock: 5 };
	world
		.execute(
			&call,
			&Instruction::new(&shop, vec![AccountMeta::writable(&shop, keeta_pet_shop::shop_id())], data(&open)),
		)
		.expect("open the shop");
	let call = world.call(&alice);
	let init = PetIx::Init { shop: addr(&shop) };
	world
		.execute(&call, &Instruction::new(&pet, vec![AccountMeta::writable(&pet, keeta_pet::config_id())], data(&init)))
		.expect("init");
	for who in [world.alice.clone(), world.bob.clone()] {
		world.host.credit(&who, &native_token(), 1_000u32);
		world.host.credit(&who, &wusd(), 1_000u32);
	}
	(world, pet, shop)
}

/// The accounts a pet instruction from `owner` needs.
fn pet_accounts(pet: &str, owner: &str) -> Vec<AccountMeta> {
	vec![
		AccountMeta::readonly(pet, keeta_pet::config_id()),
		AccountMeta::writable(pet, keeta_pet::pet_id(&addr(owner))),
	]
}

fn pet_ix(pet: &str, owner: &str, instruction: &PetIx) -> Instruction {
	Instruction::new(pet, pet_accounts(pet, owner), data(instruction))
}

/// Feeding `owner`'s pet: its accounts, and the shop's third, for the pet to pass on.
fn feed_ix(pet: &str, shop: &str, owner: &str) -> Instruction {
	let mut accounts = pet_accounts(pet, owner);
	accounts.push(AccountMeta::writable(shop, keeta_pet_shop::shop_id()));
	Instruction::new(pet, accounts, data(&PetIx::Feed))
}

fn shop_state(world: &World, shop: &str) -> Shop {
	world.view(&Instruction::new(
		shop,
		vec![AccountMeta::readonly(shop, keeta_pet_shop::shop_id())],
		data(&ShopIx::Info),
	))
}

fn pets(world: &World, pet: &str, owners: &[&str]) -> Vec<PetView> {
	let mut accounts = vec![AccountMeta::readonly(pet, keeta_pet::config_id())];
	accounts.extend(
		owners
			.iter()
			.map(|owner| AccountMeta::readonly(pet, keeta_pet::pet_id(&addr(owner)))),
	);
	world.view(&Instruction::new(pet, accounts, data(&PetIx::Pets)))
}

#[test]
fn a_pet_lives_in_its_owners_account() {
	let (mut world, pet, _shop) = pet_world();
	let (alice, bob) = (world.alice.clone(), world.bob.clone());

	let call = world.call(&bob);
	let adopted = world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("adopt");
	assert_eq!(adopted.events[0].contract, pet);
	assert_eq!(adopted.attribute("name"), Some("Pixel"));

	// The pet is bob's account in the contract's state, readable by anyone.
	let [view] = pets(&world, &pet, &[&bob]).try_into().unwrap();
	assert_eq!((view.name.as_str(), view.fullness, view.mood), ("Pixel", 50_000, Mood::Content));
	assert_eq!(view.owner, addr(&bob));

	// Time passes: block time drives decay. Twenty minutes later the pet is
	// hungry.
	world.advance(20 * 60 * 1000);
	let [view] = pets(&world, &pet, &[&bob]).try_into().unwrap();
	assert_eq!(view.mood, Mood::Hungry);
	assert_eq!(view.fullness, 50_000 - 20 * 60 * keeta_pet::HUNGER_PER_SECOND);

	// Bob can only reach his own pet: alice's account is not his to write.
	let call = world.call(&bob);
	let wrong = Instruction::new(&pet, pet_accounts(&pet, &alice), data(&PetIx::Play));
	let message = contract_error(world.execute(&call, &wrong));
	assert!(message.contains("not the one this instruction needs"), "{message}");
}

#[test]
fn a_pet_buys_its_meals_from_the_shop() {
	let (mut world, pet, shop) = pet_world();
	let (alice, bob) = (world.alice.clone(), world.bob.clone());
	let call = world.call(&bob);
	world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("adopt");

	// Feeding needs the meal's price attached, in the shop's token: the shop refuses anything else, and its refusal
	// fails the pet's call.
	let call = world.call(&bob);
	let message = contract_error(world.execute(&call, &feed_ix(&pet, &shop, &bob)));
	assert!(message.contains("attach the meal's price"), "{message}");
	let call = world.call(&bob).with_funds([Fund::new(wusd(), 9u32)]);
	let message = contract_error(world.execute(&call, &feed_ix(&pet, &shop, &bob)));
	assert_eq!(message, "pay the shop 10 of its token first (it has 9)");
	let call = world
		.call(&bob)
		.with_funds([Fund::new(native_token(), 10u32)]);
	let message = contract_error(world.execute(&call, &feed_ix(&pet, &shop, &bob)));
	assert!(message.contains("pay the shop 10"), "{message}");

	// With 10 WUSD the pet pays the shop, which sells it a meal: the money ends up with the shop, the stock goes down.
	let call = world.call(&bob).with_funds([Fund::new(wusd(), 10u32)]);
	let fed = world
		.execute(&call, &feed_ix(&pet, &shop, &bob))
		.expect("feed");
	assert_eq!(fed.attribute("paid"), Some("10"));
	assert_eq!(world.balance(&shop, &wusd()), big(10));
	assert_eq!(world.balance(&pet, &wusd()), big(0));
	assert_eq!(world.balance(&bob, &wusd()), big(990));
	let state = shop_state(&world, &shop);
	assert_eq!((state.stock, state.sold, state.accounted), (4, 1, 10));
	let [view] = pets(&world, &pet, &[&bob]).try_into().unwrap();
	// A meal adds 30,000 to the 50,000 it started with, less the few seconds of block time the calls took.
	assert_eq!(view.meals, 1);
	assert!(view.fullness > 79_000 && view.fullness <= 80_000, "{}", view.fullness);

	// WUSD is permissioned: once its issuer takes the pet's ACCESS away, the pet cannot pay the shop, and the call fails.
	world.host.set_access(&pet, &wusd(), false);
	let call = world.call(&bob).with_funds([Fund::new(wusd(), 10u32)]);
	let result = world.execute(&call, &feed_ix(&pet, &shop, &bob));
	assert!(result.is_err(), "fed without ACCESS");
	world.host.set_access(&pet, &wusd(), true);

	// People buy from the shop too, attaching the price to their own call.
	let shop_only = vec![AccountMeta::writable(&shop, keeta_pet_shop::shop_id())];
	let call = world.call(&alice).with_funds([Fund::new(wusd(), 20u32)]);
	world
		.execute(&call, &Instruction::new(&shop, shop_only.clone(), data(&ShopIx::Buy { quantity: 2 })))
		.expect("buy two");
	assert_eq!(shop_state(&world, &shop).stock, 2);
	let call = world.call(&alice).with_funds([Fund::new(wusd(), 30u32)]);
	let message = contract_error(
		world.execute(&call, &Instruction::new(&shop, shop_only.clone(), data(&ShopIx::Buy { quantity: 3 }))),
	);
	assert_eq!(message, "only 2 meals left");

	// Only the admin withdraws the takings, with a memo on the SEND.
	let withdraw = ShopIx::Withdraw { to: addr(&alice) };
	let call = world.call(&bob);
	let message = contract_error(world.execute(&call, &Instruction::new(&shop, shop_only.clone(), data(&withdraw))));
	assert!(message.contains("only the admin"), "{message}");
	let call = world.call(&alice);
	let paid = world
		.execute(&call, &Instruction::new(&shop, shop_only, data(&withdraw)))
		.expect("withdraw");
	assert!(matches!(
		paid.effects.as_slice(),
		[Effect::Send { from, to, amount, external: Some(memo), .. }]
			if *from == shop && *to == alice && *amount == big(30) && memo == "keeta pet shop takings"
	));
	assert_eq!(world.balance(&alice, &wusd()), big(1_000 - 20 + 30));
}

#[test]
fn a_starved_pet_runs_away() {
	let (mut world, pet, _shop) = pet_world();
	let bob = world.bob.clone();
	let call = world.call(&bob);
	world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Smoke".into() }))
		.expect("adopt");
	world.advance(5 * 60 * 60 * 1000);
	let [view] = pets(&world, &pet, &[&bob]).try_into().unwrap();
	assert_eq!(view.mood, Mood::RanAway);

	let call = world.call(&bob);
	let message = contract_error(world.execute(&call, &pet_ix(&pet, &bob, &PetIx::Play)));
	assert!(message.contains("ran away"), "{message}");
	let call = world.call(&bob);
	world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("a new pet");
}

#[test]
fn contract_sends_follow_the_ledgers_permissions() {
	let (mut world, pet, shop) = pet_world();
	let token = wusd();
	let (alice, bob) = (world.alice.clone(), world.bob.clone());
	let call = world.call(&bob);
	world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("adopt");
	let call = world.call(&bob).with_funds([Fund::new(&token, 10u32)]);
	world
		.execute(&call, &feed_ix(&pet, &shop, &bob))
		.expect("feed");

	let withdraw = |to: &str| {
		let accounts = vec![AccountMeta::writable(&shop, keeta_pet_shop::shop_id())];
		Instruction::new(&shop, accounts, data(&ShopIx::Withdraw { to: addr(to) }))
	};

	// The token's admin has not let bob hold it: the contract cannot send
	// it to him, and the whole call fails.
	world.host.set_access(&bob, &token, false);
	let call = world.call(&alice);
	let message = ledger_error(world.execute(&call, &withdraw(&bob)));
	assert!(message.contains("has no ACCESS"), "{message}");
	assert_eq!(world.balance(&shop, &token), big(10));

	// Nor into a storage account that does not let it hold tokens.
	let vault = generate_identifier_ref(7, KeyPairType::STORAGE, 0).to_string();
	let call = world.call(&alice);
	let message = ledger_error(world.execute(&call, &withdraw(&vault)));
	assert!(message.contains("does not let"), "{message}");

	world.host.set_access(&bob, &token, true);
	let call = world.call(&alice);
	world
		.execute(&call, &withdraw(&bob))
		.expect("withdraw once bob may hold the token");
	assert_eq!(world.balance(&bob, &token), big(1_000));
	assert_eq!(world.balance(&shop, &token), big(0));
}

// ---------------------------------------------------------------------------
// Native tokens
// ---------------------------------------------------------------------------

use keeta_escrow::{Escrow, Instruction as EscrowIx};

fn escrow_ix(escrow: &str, instruction: &EscrowIx) -> Instruction {
	Instruction::new(escrow, vec![AccountMeta::writable(escrow, keeta_escrow::escrow_id())], data(instruction))
}

/// An escrow alice opened with 400 of the native token: carol arbitrates,
/// bob receives, it expires in an hour.
fn escrow_world() -> (World, String) {
	let mut world = World::new();
	let kta = native_token();
	world.host.credit(&world.alice, &kta, 1_000u32);
	let escrow = world.deploy("keeta-escrow");
	let open = EscrowIx::Open {
		arbiter: addr(&world.carol),
		recipient: addr(&world.bob),
		expires_at: world.time_millis + 3_600_000,
	};
	let alice = world.alice.clone();
	let call = world.call(&alice).with_funds([Fund::new(&kta, 400u32)]);
	world
		.execute(&call, &escrow_ix(&escrow, &open))
		.expect("open");
	(world, escrow)
}

#[test]
fn escrow_releases_native_tokens_with_a_memo() {
	let (mut world, escrow) = escrow_world();
	let kta = native_token();
	let (bob, carol) = (world.bob.clone(), world.carol.clone());
	assert_eq!(world.balance(&escrow, &kta), big(400));

	let approve = EscrowIx::Approve { memo: Some("INVOICE 7".into()) };
	let call = world.call(&bob);
	let message = contract_error(world.execute(&call, &escrow_ix(&escrow, &approve)));
	assert!(message.contains("only the arbiter"), "{message}");

	let call = world.call(&carol);
	let approved = world
		.execute(&call, &escrow_ix(&escrow, &approve))
		.expect("approve");
	assert_eq!(world.balance(&bob, &kta), big(400));
	assert_eq!(world.balance(&escrow, &kta), big(0));
	assert!(approved.effects.iter().any(|effect| matches!(
		effect,
		Effect::Send { from, to, external: Some(memo), .. } if *from == escrow && *to == bob && memo == "INVOICE 7"
	)));

	let show = Instruction::new(
		&escrow,
		vec![AccountMeta::readonly(&escrow, keeta_escrow::escrow_id())],
		data(&EscrowIx::Show),
	);
	let state: Escrow = world.view(&show);
	assert!(state.closed);
	assert_eq!(state.holdings, vec![(addr(&kta), 400)]);
}

#[test]
fn escrow_refunds_only_after_expiry() {
	let (mut world, escrow) = escrow_world();
	let kta = native_token();
	let (alice, bob) = (world.alice.clone(), world.bob.clone());

	let call = world.call(&bob);
	let message = contract_error(world.execute(&call, &escrow_ix(&escrow, &EscrowIx::Refund)));
	assert!(message.contains("not expired"), "{message}");

	world.advance(2 * 3_600_000);
	let call = world.call(&bob);
	world
		.execute(&call, &escrow_ix(&escrow, &EscrowIx::Refund))
		.expect("refund");
	assert_eq!(world.balance(&alice, &kta), big(1_000));
}

// ---------------------------------------------------------------------------
// The account model
// ---------------------------------------------------------------------------

use keeta_probe::{Echo, Instruction as ProbeIx};

fn probe_ix(probe: &str, accounts: Vec<AccountMeta>, instruction: &ProbeIx) -> Instruction {
	Instruction::new(probe, accounts, data(instruction))
}

fn id(name: &str) -> StateId {
	keetanetwork_contract_engine::state_id(&[name.as_bytes()])
}

/// Give `probe` a non-empty account `name` holding a counter of 1.
fn seed_counter(world: &mut World, probe: &str, name: &str) {
	let alice = world.alice.clone();
	let call = world.call(&alice);
	world
		.execute(
			&call,
			&probe_ix(probe, vec![AccountMeta::writable(probe, id(name))], &ProbeIx::Increment { index: 0 }),
		)
		.expect("increment");
}

fn counter(world: &World, contract: &str, name: &str) -> u64 {
	let bytes = world
		.host
		.storage_of(contract)
		.remove(id(name).as_slice())
		.expect("counter exists");
	u64::from_le_bytes(bytes.try_into().expect("a u64"))
}

#[test]
fn a_contract_sees_its_caller_the_time_its_funds_and_its_accounts() {
	let mut world = World::new();
	let kta = native_token();
	let probe = world.deploy("keeta-probe");
	seed_counter(&mut world, &probe, "counter");
	let bob = world.bob.clone();
	world.host.credit(&bob, &kta, 10u32);

	let call = world.call(&bob).with_funds([Fund::new(&kta, 4u32)]);
	let echo = probe_ix(&probe, vec![AccountMeta::readonly(&probe, id("counter"))], &ProbeIx::Echo);
	let echoed = world.execute(&call, &echo).expect("echo");
	let (caller, contract, time, funds, accounts): Echo = borsh::from_slice(echoed.data.as_ref().unwrap()).unwrap();
	assert_eq!((caller, contract, time), (addr(&bob), addr(&probe), world.time_millis));
	assert_eq!(funds, vec![(addr(&kta), 4)]);
	assert_eq!(accounts, vec![1u64.to_le_bytes().to_vec()]);
	assert_eq!(echoed.logs[0].message, "echo");
	assert!(echoed.gas_used > 0);

	// The caller's block moved the funds; the contract's outcome does not move them again.
	assert!(echoed.effects.is_empty());
	assert_eq!((world.balance(&probe, &kta), world.balance(&bob, &kta)), (big(4), big(6)));
}

#[test]
fn a_call_reports_what_it_read_and_wrote() {
	let (mut world, pet, shop) = pet_world();
	let bob = world.bob.clone();

	// Adopting reads the config and bob's (empty) pet account, and writes only the pet.
	let call = world.call(&bob);
	let adopted = world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("adopt");
	let ids = |accesses: &[StateAccess]| accesses.iter().map(|access| access.id).collect::<Vec<_>>();
	let bob_pet = keeta_pet::pet_id(&addr(&bob));
	assert_eq!(ids(&adopted.writes), vec![bob_pet]);
	let mut read = ids(&adopted.reads);
	read.sort();
	let mut expected = vec![keeta_pet::config_id(), bob_pet];
	expected.sort();
	assert_eq!(read, expected);
	assert!(adopted
		.reads
		.iter()
		.any(|access| access.id == bob_pet && access.data.is_none()));
	assert!(adopted.effects.is_empty());

	// Feeding passes the shop's account on: the call reads and writes the
	// pet's and the shop's state, and the pet's SEND to the shop is its effect.
	let call = world.call(&bob).with_funds([Fund::new(wusd(), 10u32)]);
	let fed = world
		.execute(&call, &feed_ix(&pet, &shop, &bob))
		.expect("feed");
	let owners: Vec<&str> = fed
		.writes
		.iter()
		.map(|access| access.owner.as_str())
		.collect();
	let mut both = vec![pet.as_str(), shop.as_str()];
	both.sort();
	assert_eq!(owners, both);
	assert!(matches!(
		fed.effects.as_slice(),
		[Effect::Send { from, to, amount, external: Some(memo), .. }]
			if *from == pet && *to == shop && *amount == big(10) && memo == "keeta pet meal"
	));
	assert_eq!(fed.attribute("overfed"), Some("false"));
}

#[test]
fn contracts_change_only_their_own_writable_accounts() {
	let mut world = World::new();
	let (a, b) = (world.deploy("keeta-probe"), world.deploy("keeta-probe"));
	seed_counter(&mut world, &a, "counter");
	seed_counter(&mut world, &b, "counter");
	assert_eq!(counter(&world, &a, "counter"), 1);
	let alice = world.alice.clone();

	// A read-only account of its own, even written behind the SDK's back.
	let call = world.call(&alice);
	let readonly = vec![AccountMeta::readonly(&a, id("counter"))];
	let reason = account_error(world.execute(&call, &probe_ix(&a, readonly, &ProbeIx::ForceWrite { index: 0 })));
	assert!(reason.contains("changed read-only"), "{reason}");

	// Another contract's account, writable or not.
	let call = world.call(&alice);
	let foreign = vec![AccountMeta::writable(&b, id("counter"))];
	let reason = account_error(world.execute(&call, &probe_ix(&a, foreign, &ProbeIx::ForceWrite { index: 0 })));
	assert!(reason.contains("another contract's"), "{reason}");

	// A length past the room the engine reserved.
	let call = world.call(&alice);
	let own = vec![AccountMeta::writable(&a, id("counter"))];
	let past = (8 + keetanetwork_contract_std::abi::ACCOUNT_GROWTH + 1) as u64;
	let reason =
		account_error(world.execute(&call, &probe_ix(&a, own.clone(), &ProbeIx::ForceLength { index: 0, len: past })));
	assert!(reason.contains("beyond the capacity"), "{reason}");

	// Growing within it is fine, and an empty account no longer exists.
	let call = world.call(&alice);
	world
		.execute(&call, &probe_ix(&a, own.clone(), &ProbeIx::Store { index: 0, data: vec![7; 5_000] }))
		.expect("grow");
	let call = world.call(&alice);
	let cleared = world
		.execute(&call, &probe_ix(&a, own.clone(), &ProbeIx::Store { index: 0, data: Vec::new() }))
		.expect("clear");
	assert_eq!(cleared.writes, vec![StateAccess { owner: a.clone(), id: id("counter"), data: None }]);
	assert!(!world
		.host
		.storage_of(&a)
		.contains_key(id("counter").as_slice()));

	// Every account must be listed, once.
	let call = world.call(&alice);
	let message = contract_error(world.execute(&call, &probe_ix(&a, vec![], &ProbeIx::Increment { index: 0 })));
	assert!(message.contains("lists 0 accounts"), "{message}");
	let call = world.call(&alice);
	let twice = vec![AccountMeta::writable(&a, id("counter")), AccountMeta::readonly(&a, id("counter"))];
	let result = world.execute(&call, &probe_ix(&a, twice, &ProbeIx::Increment { index: 0 }));
	assert!(matches!(result, Err(EngineError::InvalidInstruction { .. })), "{result:?}");
}

/// A probe instruction that invokes `target` with `inner`.
fn invoke(target: &str, accounts: Vec<(u8, bool)>, inner: &ProbeIx, report: Option<u8>) -> ProbeIx {
	ProbeIx::Invoke { target: addr(target), accounts, data: data(inner), report }
}

#[test]
fn contracts_invoke_each_other_and_share_accounts() {
	let mut world = World::new();
	let (a, b) = (world.deploy("keeta-probe"), world.deploy("keeta-probe"));
	seed_counter(&mut world, &b, "counter");
	let alice = world.alice.clone();

	// A passes B's counter on; B increments it, and A sees the new value
	// as soon as B returns.
	let call = world.call(&alice);
	let accounts = vec![AccountMeta::writable(&b, id("counter"))];
	let outer = invoke(&b, vec![(0, true)], &ProbeIx::Increment { index: 0 }, Some(0));
	let outcome = world
		.execute(&call, &probe_ix(&a, accounts, &outer))
		.expect("invoke");
	let (child_return, after): (Vec<u8>, Vec<u8>) = borsh::from_slice(outcome.data.as_ref().unwrap()).unwrap();
	assert!(child_return.is_empty());
	assert_eq!(after, 2u64.to_le_bytes());
	assert_eq!(counter(&world, &b, "counter"), 2);
	// One event per invocation, outermost first; only B's state changed.
	let contracts: Vec<&str> = outcome
		.events
		.iter()
		.map(|event| event.contract.as_str())
		.collect();
	assert_eq!(contracts, [a.as_str(), b.as_str()]);
	assert_eq!(outcome.attribute("counter"), Some("2"));
	assert_eq!(
		outcome.writes,
		vec![StateAccess { owner: b.clone(), id: id("counter"), data: Some(2u64.to_le_bytes().to_vec()) }]
	);

	// A callee may create an account its caller passed on: the caller has room for it to grow.
	let call = world.call(&alice);
	let accounts = vec![AccountMeta::writable(&b, id("fresh"))];
	let outcome = world
		.execute(
			&call,
			&probe_ix(&a, accounts, &invoke(&b, vec![(0, true)], &ProbeIx::Increment { index: 0 }, Some(0))),
		)
		.expect("create through invoke");
	let (_, after): (Vec<u8>, Vec<u8>) = borsh::from_slice(outcome.data.as_ref().unwrap()).unwrap();
	assert_eq!(after, 1u64.to_le_bytes());
	assert_eq!(counter(&world, &b, "fresh"), 1);

	// The callee sees the invoking contract as its caller, and returns data.
	let call = world.call(&alice);
	let echo = invoke(&b, vec![], &ProbeIx::Echo, None);
	let outcome = world
		.execute(&call, &probe_ix(&a, vec![AccountMeta::readonly(&b, id("counter"))], &echo))
		.expect("echo");
	let (child_return, _): (Vec<u8>, Vec<u8>) = borsh::from_slice(outcome.data.as_ref().unwrap()).unwrap();
	let (caller, contract, ..): Echo = borsh::from_slice(&child_return).unwrap();
	assert_eq!((caller, contract), (addr(&a), addr(&b)));
	assert_eq!(outcome.logs[0].contract, b);

	// Privileges never grow: a read-only account cannot be passed on writable.
	let call = world.call(&alice);
	let escalate = invoke(&b, vec![(0, true)], &ProbeIx::Increment { index: 0 }, Some(0));
	let result = world.execute(&call, &probe_ix(&a, vec![AccountMeta::readonly(&b, id("counter"))], &escalate));
	assert!(
		matches!(&result, Err(EngineError::InvalidInstruction { reason }) if reason.contains("read-only")),
		"{result:?}"
	);
}

#[test]
fn contracts_cannot_be_reentered_or_nested_too_deeply() {
	let mut world = World::new();
	let probes: Vec<String> = (0..6).map(|_| world.deploy("keeta-probe")).collect();
	let alice = world.alice.clone();

	// A → B → A.
	let call = world.call(&alice);
	let back = invoke(&probes[0], vec![], &ProbeIx::Echo, None);
	let there = invoke(&probes[1], vec![], &back, None);
	let result = world.execute(&call, &probe_ix(&probes[0], vec![], &there));
	assert!(matches!(&result, Err(EngineError::Reentrancy { contract }) if *contract == probes[0]), "{result:?}");

	// Five contracts running at once is the limit; six is too many.
	let chain = |depth: usize| {
		let mut instruction = ProbeIx::Echo;
		for probe in probes[1..depth].iter().rev() {
			instruction = invoke(probe, vec![], &instruction, None);
		}
		instruction
	};
	let call = world.call(&alice);
	world
		.execute(&call, &probe_ix(&probes[0], vec![], &chain(5)))
		.expect("five deep");
	let call = world.call(&alice);
	let result = world.execute(&call, &probe_ix(&probes[0], vec![], &chain(6)));
	assert!(matches!(result, Err(EngineError::DepthExceeded { limit: 5 })), "{result:?}");
}

#[test]
fn panics_errors_and_endless_loops_fail_the_call() {
	let mut world = World::new();
	let probe = world.deploy("keeta-probe");
	let alice = world.alice.clone();

	let call = world.call(&alice);
	let message = contract_error(world.execute(&call, &probe_ix(&probe, vec![], &ProbeIx::Panic)));
	// The SDK reports the message, and the engine writes where the panic happened.
	assert!(message.starts_with("panicked at keeta-probe/src/lib.rs:"), "{message}");
	assert!(message.ends_with(": the probe panicked"), "{message}");

	// Numbers in messages are written by the engine (keeta_decimal), not by code in the contract.
	let call = world.call(&alice);
	let message = contract_error(world.execute(&call, &probe_ix(&probe, vec![], &ProbeIx::Increment { index: 9 })));
	assert_eq!(message, "the instruction lists 0 accounts, needs at least 10");

	let call = world.call(&alice);
	let message =
		contract_error(world.execute(&call, &probe_ix(&probe, vec![], &ProbeIx::Fail { message: "nope".into() })));
	assert_eq!(message, "nope");

	// Every instruction costs gas, so a loop runs out.
	let call = world.call(&alice).with_gas_limit(200_000);
	let result = world.execute(&call, &probe_ix(&probe, vec![], &ProbeIx::Spin));
	assert!(matches!(result, Err(EngineError::OutOfGas)), "{result:?}");

	// So does a failure deep inside an invocation.
	let other = world.deploy("keeta-probe");
	let call = world.call(&alice);
	let deep = invoke(&other, vec![], &ProbeIx::Fail { message: "deep".into() }, None);
	let message = contract_error(world.execute(&call, &probe_ix(&probe, vec![], &deep)));
	assert_eq!(message, "deep");
}

#[test]
fn a_failure_anywhere_fails_the_whole_call() {
	let mut world = World::new();
	let kta = native_token();
	let probe = world.deploy("keeta-probe");
	world.host.credit(&probe, &kta, 10u32);
	let (alice, bob) = (world.alice.clone(), world.bob.clone());
	let counter = vec![AccountMeta::writable(&probe, id("counter"))];
	let pay = |to: Address| ProbeIx::Send { to, token: addr(&kta), amount: 5 };

	// The probe pays bob and writes its counter, then fails: the call has
	// no outcome, so none of it happens.
	let steps = ProbeIx::Steps(vec![
		pay(addr(&bob)),
		ProbeIx::Increment { index: 0 },
		ProbeIx::Fail { message: "changed my mind".into() },
	]);
	let call = world.call(&alice);
	let message = contract_error(world.execute(&call, &probe_ix(&probe, counter.clone(), &steps)));
	assert_eq!(message, "changed my mind");

	// A host function failing fails it too: a bad address, after a good SEND.
	let mut bad = addr(&bob);
	bad.0[0] = 0x7f;
	let call = world.call(&alice);
	let result = world.execute(&call, &probe_ix(&probe, counter, &ProbeIx::Steps(vec![pay(addr(&bob)), pay(bad)])));
	assert!(matches!(result, Err(EngineError::InvalidAddress { .. })), "{result:?}");

	assert_eq!((world.balance(&probe, &kta), world.balance(&bob, &kta)), (big(10), big(0)));
	assert!(world.host.storage_of(&probe).is_empty());
}

#[test]
fn contracts_set_their_accounts_info_within_keetas_field_rules() {
	let mut world = World::new();
	let probe = world.deploy("keeta-probe");
	let alice = world.alice.clone();
	let set = |name: &str| {
		probe_ix(
			&probe,
			vec![],
			&ProbeIx::SetInfo { name: name.into(), description: "A probe".into(), metadata: String::new() },
		)
	};

	let call = world.call(&alice);
	let result = world.execute(&call, &set("not upper case"));
	assert!(matches!(result, Err(EngineError::InvalidField { field: "name", .. })), "{result:?}");

	let info = AccountInfo { name: "PROBE".into(), description: "A probe".into(), metadata: String::new() };
	let call = world.call(&alice);
	let named = world.execute(&call, &set("PROBE")).expect("name");
	assert_eq!(named.effects, vec![Effect::SetInfo { account: probe.clone(), info: info.clone() }]);
	assert_eq!(world.host.info_of(&probe), Some(info));

	// Setting the info it already has changes nothing, so it is no effect.
	let call = world.call(&alice);
	let again = world.execute(&call, &set("PROBE")).expect("name again");
	assert!(again.effects.is_empty());
}

#[test]
fn contracts_cannot_overspend() {
	let mut world = World::new();
	let kta = native_token();
	let probe = world.deploy("keeta-probe");
	world.host.credit(&probe, &kta, 10u32);
	let alice = world.alice.clone();
	let pay = |amount| ProbeIx::Send { to: addr(&alice), token: addr(&kta), amount };

	let call = world.call(&alice);
	let result = world.execute(&call, &probe_ix(&probe, vec![], &pay(11)));
	assert!(matches!(result, Err(EngineError::Ledger { .. })), "{result:?}");
	let call = world.call(&alice);
	world
		.execute(&call, &probe_ix(&probe, vec![], &pay(10)))
		.expect("send");
	assert_eq!(world.balance(&alice, &kta), big(10));
}

// ---------------------------------------------------------------------------
// Code, hosts and determinism
// ---------------------------------------------------------------------------

#[test]
fn only_sbpf_v3_contracts_are_stored() {
	let world = World::new();
	let result = world.engine.store_code(b"\x7fELF not really");
	assert!(matches!(result, Err(EngineError::Vm { .. })), "{result:?}");
	let mut truncated = elf("keeta-probe");
	truncated.truncate(truncated.len() / 2);
	let result = world.engine.store_code(&truncated);
	assert!(matches!(result, Err(EngineError::Vm { .. })), "{result:?}");
}

#[test]
fn code_size_is_capped_when_stored() {
	let probe = elf("keeta-probe");
	let pet = elf("keeta-pet");
	assert!(pet.len() > probe.len());

	// Code over the limit is refused before it is parsed.
	let world = World::with_config(EngineConfig { max_code_size: probe.len(), ..EngineConfig::default() });
	let result = world.engine.store_code(&vec![0; probe.len() + 1]);
	assert!(
		matches!(result, Err(EngineError::CodeTooLarge { size, limit }) if size == probe.len() + 1 && limit == probe.len()),
		"{result:?}"
	);
	let result = world.engine.store_code(&pet);
	assert!(matches!(result, Err(EngineError::CodeTooLarge { .. })), "{result:?}");
	world
		.engine
		.store_code(&probe)
		.expect("code at the limit is stored");

	// Lowering the limit leaves code already deployed running: an engine
	// that would refuse it still loads it from the host.
	let (mut world, pet, _shop) = pet_world();
	world.engine = Engine::new(EngineConfig { max_code_size: 1, ..EngineConfig::default() }).unwrap();
	let bob = world.bob.clone();
	let call = world.call(&bob);
	world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("adopt");
}

/// A host that fails balance reads when told to, and counts the code it
/// is asked for.
struct FlakyHost {
	inner: Arc<MemoryHost>,
	fail: AtomicBool,
	code_loads: AtomicUsize,
}

impl FlakyHost {
	fn new(inner: Arc<MemoryHost>) -> Arc<Self> {
		Arc::new(Self { inner, fail: AtomicBool::new(false), code_loads: AtomicUsize::new(0) })
	}
}

impl Host for FlakyHost {
	fn code_bytes(&self, hash: &CodeHash) -> HostResult<Option<Vec<u8>>> {
		self.code_loads.fetch_add(1, Ordering::SeqCst);
		self.inner.code_bytes(hash)
	}
	fn contract(&self, address: &str) -> HostResult<Option<ContractRecord>> {
		self.inner.contract(address)
	}
	fn storage_get(&self, contract: &str, key: &[u8]) -> HostResult<Option<Vec<u8>>> {
		self.inner.storage_get(contract, key)
	}
	fn balance(&self, account: &str, token: &str) -> HostResult<BigUint> {
		if self.fail.load(Ordering::SeqCst) {
			return Err(HostError::new("ledger unreachable"));
		}
		self.inner.balance(account, token)
	}
	fn token_supply(&self, token: &str) -> HostResult<Option<BigUint>> {
		self.inner.token_supply(token)
	}
	fn send_refusal(&self, from: &str, to: &str, token: &str) -> HostResult<Option<String>> {
		self.inner.send_refusal(from, to, token)
	}
}

#[test]
fn host_failures_abort_the_call() {
	let mut world = World::new();
	let kta = native_token();
	let probe = world.deploy("keeta-probe");
	world.host.credit(&probe, &kta, 10u32);
	let alice = world.alice.clone();
	let flaky = FlakyHost::new(world.host.clone());
	flaky.fail.store(true, Ordering::SeqCst);
	let call = world.call(&alice);
	let pay = world.ledger_call(
		&call,
		&probe_ix(&probe, vec![], &ProbeIx::Send { to: addr(&alice), token: addr(&kta), amount: 1 }),
	);

	let result = world.engine.run_ledger_call(flaky.clone(), &pay);
	assert!(
		matches!(&result, Err(EngineError::Host { source }) if source.message == "ledger unreachable"),
		"{result:?}"
	);

	flaky.fail.store(false, Ordering::SeqCst);
	world
		.engine
		.run_ledger_call(flaky, &pay)
		.expect("pays once the host recovers");
}

#[test]
fn a_restarted_engine_reloads_code_from_the_host() {
	let (mut world, pet, _shop) = pet_world();
	world.engine = Engine::new(EngineConfig::default()).unwrap();
	let bob = world.bob.clone();
	let call = world.call(&bob);
	world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("adopt with code fetched from the host");
}

#[test]
fn loaded_code_is_kept_within_its_budget() {
	let (mut world, pet, shop) = pet_world();
	let bob = world.bob.clone();
	let call = world.call(&bob);
	world
		.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
		.expect("adopt");
	let call = world.call(&bob).with_funds([Fund::new(wusd(), 10u32)]);
	let feed = world.ledger_call(&call, &feed_ix(&pet, &shop, &bob));
	// Feeding runs the pet, which invokes the shop. Returns how much code
	// the call loaded from the host.
	let feed_with = |engine: &Engine| {
		let host = FlakyHost::new(world.host.clone());
		engine.run_ledger_call(host.clone(), &feed).expect("feed");
		host.code_loads.load(Ordering::SeqCst)
	};

	// With the default budget both contracts stay loaded.
	let engine = Engine::new(EngineConfig::default()).unwrap();
	assert_eq!((feed_with(&engine), feed_with(&engine)), (2, 0));

	// With room for one contract they take turns: each feed loads both, and
	// the pet's code is dropped while the pet is still running.
	let room = elf("keeta-pet").len().max(elf("keeta-pet-shop").len());
	let engine = Engine::new(EngineConfig { max_cached_code_size: room, ..EngineConfig::default() }).unwrap();
	assert_eq!((feed_with(&engine), feed_with(&engine)), (2, 2));

	// With no room, nothing is kept.
	let engine = Engine::new(EngineConfig { max_cached_code_size: 0, ..EngineConfig::default() }).unwrap();
	engine.store_code(&elf("keeta-pet")).expect("store code");
	assert_eq!((feed_with(&engine), feed_with(&engine)), (2, 2));
}

#[test]
fn execution_is_deterministic() {
	let run = || {
		let (mut world, pet, shop) = pet_world();
		let bob = world.bob.clone();
		let call = world.call(&bob);
		world
			.execute(&call, &pet_ix(&pet, &bob, &PetIx::Adopt { name: "Pixel".into() }))
			.unwrap();
		let call = world.call(&bob).with_funds([Fund::new(wusd(), 10u32)]);
		let fed = world.execute(&call, &feed_ix(&pet, &shop, &bob)).unwrap();
		(fed.reads, fed.writes, fed.effects, fed.gas_used, fed.data)
	};
	assert_eq!(run(), run());
}
