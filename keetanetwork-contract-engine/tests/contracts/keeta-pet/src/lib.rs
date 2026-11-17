//! A virtual pet, one per account.
//!
//! A pet's fullness and happiness fall as block time passes. Its food comes
//! from a shop, another contract ([`keeta_pet_shop`]): to feed, the owner
//! attaches the meal's price in the shop's token, and the pet pays the shop
//! and buys the meal from it, all in the one call. If the shop refuses (the
//! wrong token or amount, no stock, or a token the pet or shop may not
//! hold), the whole call fails. Playing is free but makes the pet a little
//! hungry. A pet left at zero fullness for `RUN_AWAY_AFTER` seconds runs
//! away, and its owner can adopt another.
//!
//! Accounts (borsh-encoded):
//!
//! - `state_id(["config"])`: the [`Config`].
//! - `state_id(["pet", owner])`: the owner's [`Pet`].
//!
//! Every instruction lists the config first, then the pets it touches;
//! `Feed` lists the shop's account third. `Pets` is a view: it returns
//! borsh `Vec<PetView>` as of the block time, one per listed pet account
//! that holds a pet.
//!
//! Exercises: calling another contract (`invoke`) and reading what it
//! returns, paying it (`send` with an `external` memo), funds, block time,
//! `set_info`, and read-only views.

use borsh::{BorshDeserialize, BorshSerialize};
use keeta_pet_shop::{Instruction as ShopInstruction, Receipt};
use keetanetwork_contract_std::{
	attribute, bail, ensure, entrypoint, invoke, return_data, send, set_info, set_return_data, state_id, Address,
	Context, ContractResult, StateId,
};

/// Stats are kept in thousandths so decay stays exact in integers.
pub const MAX_STAT: u64 = 100_000;
/// Fullness lost per second: empty about an hour after a full meal.
pub const HUNGER_PER_SECOND: u64 = 28;
/// Happiness lost per second: bored about two hours after playing.
pub const BOREDOM_PER_SECOND: u64 = 14;
pub const MEAL: u64 = 30_000;
/// Feeding above this makes the pet overfed and grumpy.
pub const OVERFED_ABOVE: u64 = 90_000;
pub const OVERFED_PENALTY: u64 = 10_000;
pub const PLAY: u64 = 25_000;
pub const PLAY_HUNGER: u64 = 5_000;
/// Too hungry to play below this.
pub const PLAY_MIN_FULLNESS: u64 = 10_000;
pub const RUN_AWAY_AFTER: u64 = 2 * 60 * 60;
pub const MAX_NAME: usize = 24;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub struct Config {
	pub admin: Address,
	/// The shop contract the pet buys its food from
	pub shop: Address,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub struct Pet {
	pub owner: Address,
	pub name: String,
	pub born: u64,
	/// When `fullness` and `happiness` were last written, in seconds
	pub updated: u64,
	pub fullness: u64,
	pub happiness: u64,
	pub meals: u64,
	pub plays: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub enum Mood {
	Happy,
	Content,
	Hungry,
	Bored,
	Starving,
	RanAway,
}

/// A pet as it is at the block time.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub struct PetView {
	pub owner: Address,
	pub name: String,
	pub born: u64,
	pub age_seconds: u64,
	/// 0 to 100000 (thousandths of a percent point)
	pub fullness: u64,
	pub happiness: u64,
	pub mood: Mood,
	pub meals: u64,
	pub plays: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub enum Instruction {
	/// Accounts: config (writable). Name the shop; the caller becomes the
	/// admin. Only once.
	Init { shop: Address },
	/// Accounts: config, the caller's pet (writable). Allowed when you have
	/// no pet, or yours ran away.
	Adopt { name: String },
	/// Accounts: config, the caller's pet (writable), the shop's account
	/// (writable). Attach the meal's price in the shop's token: the pet buys
	/// the meal from the shop with it.
	Feed,
	/// Accounts: config, the caller's pet (writable).
	Play,
	/// Accounts: config (writable). Admin only: buy food from another shop.
	SetShop { shop: Address },
	/// Accounts: config, then any pet accounts. Returns `Vec<PetView>`.
	Pets,
}

/// The config account's id.
pub fn config_id() -> StateId {
	state_id(&[b"config"])
}

/// The id of `owner`'s pet account.
pub fn pet_id(owner: &Address) -> StateId {
	state_id(&[b"pet", &owner.0])
}

entrypoint!(process);

fn process(ctx: &mut Context) -> ContractResult {
	let instruction = Instruction::try_from_slice(ctx.data)?;
	let now = ctx.time_seconds();

	if let Instruction::Init { shop } = instruction {
		ctx.no_funds()?;
		let caller = ctx.caller;
		let config = ctx.own_account(0, &config_id())?;
		ensure!(config.is_empty(), "already initialized");
		config.store(&Config { admin: caller, shop })?;
		set_info("KEETA_PET", "A virtual pet contract", "");
		attribute("action", "init");
		return Ok(());
	}

	let Some(config) = ctx.own_account(0, &config_id())?.load::<Config>()? else {
		bail!("not initialized");
	};
	let caller = ctx.caller;

	match instruction {
		Instruction::Init { .. } => unreachable!("handled above"),
		Instruction::Adopt { name } => {
			ctx.no_funds()?;
			// Spaces trimmed (ASCII ones: Unicode's would bring their tables into the contract), and
			// characters counted by the bytes that start one (the name is valid UTF-8).
			let name = name.trim_ascii().to_string();
			let characters = name.bytes().filter(|byte| byte & 0xC0 != 0x80).count();
			ensure!(!name.is_empty() && characters <= MAX_NAME, "a name needs 1 to ", MAX_NAME, " characters");
			let account = ctx.own_account(1, &pet_id(&caller))?;
			if let Some(pet) = account.load::<Pet>()? {
				ensure!(view(&pet, now).mood == Mood::RanAway, "you already have a pet");
			}
			let pet = Pet {
				owner: caller,
				name: name.clone(),
				born: now,
				updated: now,
				fullness: MAX_STAT / 2,
				happiness: MAX_STAT / 2,
				meals: 0,
				plays: 0,
			};
			account.store(&pet)?;
			attribute("action", "adopt");
			attribute("name", name);
		}
		Instruction::Feed => {
			let &[fund] = ctx.funds.as_slice() else {
				bail!("attach the meal's price, in the shop's token");
			};
			let shop_listed = ctx
				.accounts
				.get(2)
				.is_some_and(|account| account.owner() == config.shop);
			ensure!(shop_listed, "list the shop's account third");
			let account = ctx.own_account(1, &pet_id(&caller))?;
			let mut pet = living_pet(account.load()?, now)?;
			// Buy the meal: pay the shop, then have it count the payment and sell. Either step failing fails the call.
			send(&config.shop, &fund.token, fund.amount, Some("keeta pet meal"));
			invoke(&config.shop, &[(2, true)], &borsh::to_vec(&ShopInstruction::Buy { quantity: 1 })?);
			let receipt = Receipt::try_from_slice(&return_data())?;
			let overfed = pet.fullness > OVERFED_ABOVE;
			pet.fullness = (pet.fullness + MEAL).min(MAX_STAT);
			if overfed {
				pet.happiness = pet.happiness.saturating_sub(OVERFED_PENALTY);
			}
			pet.meals += 1;
			account.store(&pet)?;
			attribute("action", "feed");
			attribute("paid", receipt.paid);
			attribute("overfed", overfed);
			attribute("fullness", pet.fullness);
		}
		Instruction::Play => {
			ctx.no_funds()?;
			let account = ctx.own_account(1, &pet_id(&caller))?;
			let mut pet = living_pet(account.load()?, now)?;
			ensure!(pet.fullness >= PLAY_MIN_FULLNESS, "your pet is too hungry to play");
			pet.happiness = (pet.happiness + PLAY).min(MAX_STAT);
			pet.fullness -= PLAY_HUNGER;
			pet.plays += 1;
			account.store(&pet)?;
			attribute("action", "play");
			attribute("happiness", pet.happiness);
		}
		Instruction::SetShop { shop } => {
			ctx.no_funds()?;
			ensure!(caller == config.admin, "only the admin can change the shop");
			ctx.own_account(0, &config_id())?
				.store(&Config { shop, ..config })?;
			attribute("action", "shop");
		}
		Instruction::Pets => {
			let mut views = Vec::new();
			for account in &ctx.accounts[1..] {
				if account.owner() != ctx.contract {
					continue;
				}
				if let Some(pet) = account.load::<Pet>()? {
					views.push(view(&pet, now));
				}
			}
			set_return_data(&borsh::to_vec(&views)?);
		}
	}
	Ok(())
}

/// The pet with decay applied up to `now`, unless it ran away.
fn living_pet(pet: Option<Pet>, now: u64) -> ContractResult<Pet> {
	let Some(pet) = pet else {
		bail!("you have no pet; adopt one first");
	};
	ensure!(view(&pet, now).mood != Mood::RanAway, "your pet ran away; adopt a new one");
	let (fullness, happiness) = decayed(&pet, now);
	Ok(Pet { updated: now.max(pet.updated), fullness, happiness, ..pet })
}

fn decayed(pet: &Pet, now: u64) -> (u64, u64) {
	let elapsed = now.saturating_sub(pet.updated);
	(
		pet.fullness
			.saturating_sub(elapsed.saturating_mul(HUNGER_PER_SECOND)),
		pet.happiness
			.saturating_sub(elapsed.saturating_mul(BOREDOM_PER_SECOND)),
	)
}

pub fn view(pet: &Pet, now: u64) -> PetView {
	let (fullness, happiness) = decayed(pet, now);
	let empty_at = pet.updated + pet.fullness.div_ceil(HUNGER_PER_SECOND);
	let mood = if fullness == 0 && now.saturating_sub(empty_at) >= RUN_AWAY_AFTER {
		Mood::RanAway
	} else if fullness == 0 {
		Mood::Starving
	} else if fullness < MAX_STAT / 4 {
		Mood::Hungry
	} else if happiness < MAX_STAT / 4 {
		Mood::Bored
	} else if fullness >= MAX_STAT * 7 / 10 && happiness >= MAX_STAT * 7 / 10 {
		Mood::Happy
	} else {
		Mood::Content
	};
	PetView {
		owner: pet.owner,
		name: pet.name.clone(),
		born: pet.born,
		age_seconds: now.saturating_sub(pet.born),
		fullness,
		happiness,
		mood,
		meals: pet.meals,
		plays: pet.plays,
	}
}

/// What the contract's instruction data, state accounts and views look
/// like, for explorers and other tools (off-chain only; see
/// `keetanetwork_contract_std::interface`).
#[cfg(not(target_os = "solana"))]
pub fn contract_interface() -> keetanetwork_contract_std::interface::Interface {
	use keetanetwork_contract_std::interface::{Interface, Seed};
	Interface::new("keeta-pet")
		.instruction::<Instruction>()
		.account::<Config>("config", &[Seed::bytes(b"config")])
		.account::<Pet>("pet", &[Seed::bytes(b"pet"), Seed::address("owner")])
		.view::<Vec<PetView>>("Pets")
}
