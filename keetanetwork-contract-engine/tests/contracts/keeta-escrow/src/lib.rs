//! Arbiter-released escrow of native Keeta tokens.
//!
//! Whoever opens the escrow funds it with the tokens attached; anyone can
//! add more. The arbiter releases everything to the recipient, with a memo;
//! after expiry anyone can refund everything to whoever opened it.
//!
//! Account: `state_id(["escrow"])` holds the [`Escrow`] (borsh).
//!
//! Exercises: funds of several tokens, `balance`, `send` with an
//! `external` memo, and block time.

use borsh::{BorshDeserialize, BorshSerialize};
use keetanetwork_contract_std::{
	attribute, bail, balance, ensure, entrypoint, send, set_return_data, state_id, Address, Context, ContractResult,
	StateId,
};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct Escrow {
	pub arbiter: Address,
	pub recipient: Address,
	pub source: Address,
	/// Milliseconds since the Unix epoch
	pub expires_at: i64,
	pub closed: bool,
	/// What the escrow holds, by token
	pub holdings: Vec<(Address, u128)>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum Instruction {
	/// Accounts: escrow (writable). Open it with the attached funds.
	Open { arbiter: Address, recipient: Address, expires_at: i64 },
	/// Accounts: escrow (writable). Add the attached funds.
	Deposit,
	/// Accounts: escrow (writable). Arbiter only: release to the recipient.
	Approve { memo: Option<String> },
	/// Accounts: escrow (writable). After expiry: return to the source.
	Refund,
	/// Accounts: escrow. Returns the borsh [`Escrow`].
	Show,
}

/// The escrow account's id.
pub fn escrow_id() -> StateId {
	state_id(&[b"escrow"])
}

entrypoint!(process);

fn process(ctx: &mut Context) -> ContractResult {
	let instruction = Instruction::try_from_slice(ctx.data)?;
	let (caller, now, contract) = (ctx.caller, ctx.time_millis, ctx.contract);
	let funds: Vec<(Address, u128)> = ctx
		.funds
		.iter()
		.map(|fund| (fund.token, fund.amount))
		.collect();
	let account = ctx.own_account(0, &escrow_id())?;

	if let Instruction::Open { arbiter, recipient, expires_at } = instruction {
		ensure!(account.is_empty(), "already open");
		ensure!(expires_at > now, "expiry must be in the future");
		let mut escrow = Escrow { arbiter, recipient, source: caller, expires_at, closed: false, holdings: Vec::new() };
		record(&mut escrow, &funds);
		account.store(&escrow)?;
		attribute("action", "open");
		return Ok(());
	}

	let Some(mut escrow) = account.load::<Escrow>()? else {
		bail!("no escrow here");
	};
	if let Instruction::Show = instruction {
		set_return_data(&borsh::to_vec(&escrow)?);
		return Ok(());
	}
	ensure!(!escrow.closed, "escrow is closed");

	match instruction {
		Instruction::Open { .. } | Instruction::Show => unreachable!("handled above"),
		Instruction::Deposit => {
			ensure!(!funds.is_empty(), "no funds attached");
			record(&mut escrow, &funds);
			attribute("action", "deposit");
		}
		Instruction::Approve { memo } => {
			ensure!(caller == escrow.arbiter, "only the arbiter can approve");
			release(&contract, &escrow, &escrow.recipient, memo.as_deref())?;
			escrow.closed = true;
			attribute("action", "approve");
		}
		Instruction::Refund => {
			ensure!(now >= escrow.expires_at, "escrow has not expired");
			release(&contract, &escrow, &escrow.source, Some("REFUND"))?;
			escrow.closed = true;
			attribute("action", "refund");
		}
	}
	account.store(&escrow)
}

fn record(escrow: &mut Escrow, funds: &[(Address, u128)]) {
	for (token, amount) in funds {
		match escrow.holdings.iter_mut().find(|(held, _)| held == token) {
			Some((_, held)) => *held += amount,
			None => escrow.holdings.push((*token, *amount)),
		}
	}
}

fn release(contract: &Address, escrow: &Escrow, to: &Address, memo: Option<&str>) -> ContractResult {
	for (token, amount) in &escrow.holdings {
		// Cross-check the escrow's own bookkeeping against the ledger.
		ensure!(balance(contract, token) >= *amount, "the ledger holds less than recorded");
		send(to, token, *amount, memo);
	}
	Ok(())
}
