//! A contract for testing the engine's rules rather than for use.
//!
//! Some instructions deliberately get around the SDK's own checks (writing
//! accounts through raw pointers), to show that the engine enforces the
//! rules itself.

#![allow(unsafe_code)]

use borsh::{BorshDeserialize, BorshSerialize};
use keetanetwork_contract_std::abi::layout;
use keetanetwork_contract_std::{
	attribute, bail, entrypoint, invoke, log, return_data, send, set_info, set_return_data, Address, Context,
	ContractResult,
};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum Instruction {
	/// Add one to the little-endian `u64` in account `index` (through the
	/// SDK, so only own writable accounts).
	Increment { index: u8 },
	/// Overwrite the first byte of account `index` through a raw pointer,
	/// whatever the account's permissions.
	ForceWrite { index: u8 },
	/// Set account `index`'s length to `len` through a raw pointer, past
	/// its capacity if asked.
	ForceLength { index: u8, len: u64 },
	/// Replace account `index`'s data (through the SDK).
	Store { index: u8, data: Vec<u8> },
	/// Invoke `target`, passing `(index, writable)` accounts, then return
	/// borsh `(child return data, account `report`'s data afterwards, or
	/// nothing)`.
	Invoke { target: Address, accounts: Vec<(u8, bool)>, data: Vec<u8>, report: Option<u8> },
	/// Return borsh `(caller, contract, time_millis, funds, account data)`,
	/// and log a line.
	Echo,
	/// Loop forever.
	Spin,
	/// Panic.
	Panic,
	/// Return an error.
	Fail { message: String },
	/// `SEND` from the contract.
	Send { to: Address, token: Address, amount: u128 },
	/// `SET_INFO` on the contract's account.
	SetInfo { name: String, description: String, metadata: String },
	/// Run each instruction in turn.
	Steps(Vec<Instruction>),
}

/// What [`Instruction::Echo`] returns.
pub type Echo = (Address, Address, i64, Vec<(Address, u128)>, Vec<Vec<u8>>);

entrypoint!(process);

fn data_pointer(ctx: &Context, index: u8) -> ContractResult<*mut u8> {
	let Some(account) = ctx.accounts.get(index as usize) else {
		bail!("no account ", index);
	};
	Ok(account.data().as_ptr() as *mut u8)
}

fn process(ctx: &mut Context) -> ContractResult {
	run(ctx, Instruction::try_from_slice(ctx.data)?)
}

fn run(ctx: &mut Context, instruction: Instruction) -> ContractResult {
	match instruction {
		Instruction::Increment { index } => {
			let account = ctx.account(index as usize)?;
			let next = account.load::<u64>()?.unwrap_or_default() + 1;
			account.store(&next)?;
			attribute("counter", next);
		}
		Instruction::ForceWrite { index } => {
			let data = data_pointer(ctx, index)?;
			// SAFETY: the account's data lives in the input region; the
			// engine decides whether this write is allowed.
			unsafe { *data ^= 0xff };
		}
		Instruction::ForceLength { index, len } => {
			let data = data_pointer(ctx, index)?;
			// SAFETY: the header sits just before the data in the input region.
			unsafe {
				let header = data.sub(layout::ACCOUNT_HEADER);
				core::ptr::write_unaligned(header.add(layout::ACCOUNT_DATA_LEN) as *mut u64, len);
			}
		}
		Instruction::Store { index, data } => ctx.account(index as usize)?.set(&data)?,
		Instruction::Invoke { target, accounts, data, report } => {
			let accounts: Vec<(usize, bool)> = accounts
				.into_iter()
				.map(|(index, writable)| (index as usize, writable))
				.collect();
			invoke(&target, &accounts, &data);
			let after = match report {
				Some(index) => ctx.account(index as usize)?.data().to_vec(),
				None => Vec::new(),
			};
			set_return_data(&borsh::to_vec(&(return_data(), after))?);
		}
		Instruction::Echo => {
			log("echo");
			let funds = ctx
				.funds
				.iter()
				.map(|fund| (fund.token, fund.amount))
				.collect();
			let accounts = ctx
				.accounts
				.iter()
				.map(|account| account.data().to_vec())
				.collect();
			let echo: Echo = (ctx.caller, ctx.contract, ctx.time_millis, funds, accounts);
			set_return_data(&borsh::to_vec(&echo)?);
		}
		Instruction::Spin => {
			let mut counter = 0u64;
			loop {
				counter = core::hint::black_box(counter.wrapping_add(1));
			}
		}
		Instruction::Panic => panic!("the probe panicked"),
		Instruction::Fail { message } => bail!(message),
		Instruction::Send { to, token, amount } => send(&to, &token, amount, None),
		Instruction::SetInfo { name, description, metadata } => set_info(&name, &description, &metadata),
		Instruction::Steps(steps) => {
			for step in steps {
				run(ctx, step)?;
			}
		}
	}
	Ok(())
}
