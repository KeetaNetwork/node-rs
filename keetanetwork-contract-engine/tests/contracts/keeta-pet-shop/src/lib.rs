//! A shop that sells pet food for a token, to people and to other
//! contracts.
//!
//! The admin opens the shop with a token, a price per meal and some stock,
//! and can restock, change the price and withdraw the takings. Anyone can
//! buy, an account or a contract: a buyer pays the shop first, and `Buy`
//! then counts the payment and sells.
//!
//! Payment is counted by the shop's balance: whatever the shop holds of its
//! token beyond what it has accounted for pays for the meals. An account
//! attaches the payment as funds to its `Buy`; a contract `send`s it to the
//! shop and then `invoke`s `Buy`, in the same call, as the pet does. (A
//! gift to the shop would pay for the next buyer's meals.)
//!
//! The token can be one whose holders need `ACCESS` (a permissioned token):
//! the shop and its buyers must have been granted it, or paying fails.
//!
//! Accounts (borsh-encoded):
//!
//! - `state_id(["shop"])`: the [`Shop`].
//!
//! Other contracts depend on this crate with its `no-entrypoint` feature to
//! use its [`Instruction`] and [`shop_id`].
//!
//! Exercises: being invoked by another contract, payment between contracts,
//! `balance`, `send` with a permissioned token, and return data.

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(not(feature = "no-entrypoint"))]
use keetanetwork_contract_std::entrypoint;
use keetanetwork_contract_std::{
	attribute, bail, balance, ensure, send, set_info, set_return_data, state_id, Address, Context, ContractResult,
	StateId,
};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub struct Shop {
	pub admin: Address,
	/// What meals are paid in
	pub token: Address,
	/// Per meal, in the token's atomic units
	pub price: u128,
	/// Meals left
	pub stock: u64,
	/// Meals sold
	pub sold: u64,
	/// How much of the shop's balance of `token` is already accounted for:
	/// anything above it pays for the next meals bought
	pub accounted: u128,
}

/// What `Buy` returns: the meals sold, and what they cost.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub struct Receipt {
	pub quantity: u64,
	pub paid: u128,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub enum Instruction {
	/// Accounts: shop (writable). Open the shop; the caller becomes the admin.
	/// Only once.
	Init { token: Address, price: u128, stock: u64 },
	/// Accounts: shop (writable). Buy `quantity` meals, paid beforehand
	/// (see the crate documentation). Returns a borsh [`Receipt`].
	Buy { quantity: u64 },
	/// Accounts: shop (writable). Admin only: add stock.
	Restock { quantity: u64 },
	/// Accounts: shop (writable). Admin only: change the price.
	SetPrice { price: u128 },
	/// Accounts: shop (writable). Admin only: send the takings to `to`.
	Withdraw { to: Address },
	/// Accounts: shop. Returns the borsh [`Shop`].
	Info,
}

/// The shop account's id.
pub fn shop_id() -> StateId {
	state_id(&[b"shop"])
}

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process);

#[cfg_attr(feature = "no-entrypoint", allow(dead_code))]
fn process(ctx: &mut Context) -> ContractResult {
	let instruction = Instruction::try_from_slice(ctx.data)?;
	let caller = ctx.caller;
	let contract = ctx.contract;

	if let Instruction::Init { token, price, stock } = instruction {
		ctx.no_funds()?;
		ensure!(price > 0, "the price must not be zero");
		let account = ctx.own_account(0, &shop_id())?;
		ensure!(account.is_empty(), "the shop is already open");
		// Anything the shop already holds is not a payment.
		let accounted = balance(&contract, &token);
		account.store(&Shop { admin: caller, token, price, stock, sold: 0, accounted })?;
		set_info("KEETA_PET_SHOP", "Sells pet food", "");
		attribute("action", "open");
		return Ok(());
	}

	let account = ctx.own_account(0, &shop_id())?;
	let Some(mut shop) = account.load::<Shop>()? else {
		bail!("the shop is not open");
	};

	match instruction {
		Instruction::Init { .. } => unreachable!("handled above"),
		Instruction::Buy { quantity } => {
			ensure!(quantity > 0, "buy at least one meal");
			ensure!(quantity <= shop.stock, "only ", shop.stock, " meals left");
			let due = shop.price * quantity as u128;
			let held = balance(&contract, &shop.token);
			let paid = held.saturating_sub(shop.accounted);
			ensure!(paid >= due, "pay the shop ", due, " of its token first (it has ", paid, ")");
			// Everything held is accounted for now: an overpayment is the shop's.
			shop.accounted = held;
			shop.stock -= quantity;
			shop.sold += quantity;
			account.store(&shop)?;
			set_return_data(&borsh::to_vec(&Receipt { quantity, paid })?);
			attribute("action", "buy");
			attribute("quantity", quantity);
			attribute("paid", paid);
		}
		Instruction::Restock { quantity } => {
			ensure!(caller == shop.admin, "only the admin can restock");
			shop.stock = shop.stock.saturating_add(quantity);
			account.store(&shop)?;
			attribute("action", "restock");
			attribute("stock", shop.stock);
		}
		Instruction::SetPrice { price } => {
			ensure!(caller == shop.admin, "only the admin can change the price");
			ensure!(price > 0, "the price must not be zero");
			shop.price = price;
			account.store(&shop)?;
			attribute("action", "price");
			attribute("price", price);
		}
		Instruction::Withdraw { to } => {
			ensure!(caller == shop.admin, "only the admin can withdraw");
			let held = balance(&contract, &shop.token);
			ensure!(held > 0, "nothing to withdraw");
			send(&to, &shop.token, held, Some("keeta pet shop takings"));
			shop.accounted = 0;
			account.store(&shop)?;
			attribute("action", "withdraw");
			attribute("amount", held);
		}
		Instruction::Info => set_return_data(&borsh::to_vec(&shop)?),
	}
	Ok(())
}

/// What the contract's instruction data, state accounts and views look
/// like, for explorers and other tools (off-chain only; see
/// `keetanetwork_contract_std::interface`).
#[cfg(not(target_os = "solana"))]
pub fn contract_interface() -> keetanetwork_contract_std::interface::Interface {
	use keetanetwork_contract_std::interface::{Interface, Seed};
	Interface::new("keeta-pet-shop")
		.instruction::<Instruction>()
		.account::<Shop>("shop", &[Seed::bytes(b"shop")])
		.view::<Receipt>("Buy")
		.view::<Shop>("Info")
}
