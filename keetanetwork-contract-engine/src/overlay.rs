//! A call's view of state: host reads, with the call's own writes on top.
//!
//! Reads are cached for the rest of the call, so a call sees one consistent
//! state and asks the host for each key at most once. A failed call is
//! simply dropped.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use num_bigint::BigUint;

use crate::engine::Effect;
use crate::error::{ledger, EngineError};
use crate::host::{AccountInfo, ContractRecord, Host, HostResult};

/// A state account: its contract and its id.
type StorageKey = (String, Vec<u8>);

/// Host reads made during the call: the state the call started from.
#[derive(Debug, Default)]
struct Reads {
	balances: BTreeMap<(String, String), BigUint>,
	supplies: BTreeMap<String, Option<BigUint>>,
	contracts: BTreeMap<String, Option<ContractRecord>>,
	storage: BTreeMap<StorageKey, Option<Vec<u8>>>,
	/// (from, to, token) → why the ledger would refuse that `SEND`
	send_refusals: BTreeMap<(String, String, String), Option<String>>,
}

/// A call's state.
#[derive(Debug, Default)]
pub(crate) struct Overlay {
	reads: Reads,
	balances: BTreeMap<(String, String), BigUint>,
	/// Account info contracts set during the call
	infos: BTreeMap<String, AccountInfo>,
	/// The call's writes, `None` for deleted
	storage: BTreeMap<StorageKey, Option<Vec<u8>>>,
	/// Contracts' `SEND`s, in order
	pub(crate) effects: Vec<Effect>,
}

impl Overlay {
	pub(crate) fn balance(&mut self, host: &dyn Host, account: &str, token: &str) -> HostResult<BigUint> {
		let key = (account.to_string(), token.to_string());
		if let Some(balance) = self.balances.get(&key) {
			return Ok(balance.clone());
		}
		Ok(match self.reads.balances.entry(key) {
			Entry::Occupied(entry) => entry.get().clone(),
			Entry::Vacant(entry) => entry.insert(host.balance(account, token)?).clone(),
		})
	}

	pub(crate) fn credit(
		&mut self,
		host: &dyn Host,
		account: &str,
		token: &str,
		amount: &BigUint,
	) -> Result<(), EngineError> {
		let balance = self.balance(host, account, token)? + amount;
		self.balances
			.insert((account.to_string(), token.to_string()), balance);
		Ok(())
	}

	pub(crate) fn debit(
		&mut self,
		host: &dyn Host,
		account: &str,
		token: &str,
		amount: &BigUint,
	) -> Result<(), EngineError> {
		let held = self.balance(host, account, token)?;
		if held < *amount {
			return Err(ledger(format!("{account} holds {held} of {token}, needs {amount}")));
		}
		self.balances
			.insert((account.to_string(), token.to_string()), held - amount);
		Ok(())
	}

	/// A `SEND` a contract makes: refused, failing the call, unless the
	/// ledger's permissions allow it ([`Host::send_refusal`]).
	pub(crate) fn send(
		&mut self,
		host: &dyn Host,
		from: &str,
		to: &str,
		token: &str,
		amount: &BigUint,
		external: Option<String>,
	) -> Result<(), EngineError> {
		if *amount == BigUint::ZERO {
			return Err(ledger("cannot send a zero amount"));
		}
		let refusal = match self
			.reads
			.send_refusals
			.entry((from.to_string(), to.to_string(), token.to_string()))
		{
			Entry::Occupied(entry) => entry.get().clone(),
			Entry::Vacant(entry) => entry.insert(host.send_refusal(from, to, token)?).clone(),
		};
		if let Some(reason) = refusal {
			return Err(ledger(format!("cannot send {token} from {from} to {to}: {reason}")));
		}
		self.debit(host, from, token, amount)?;
		self.credit(host, to, token, amount)?;
		self.effects.push(Effect::Send {
			from: from.to_string(),
			to: to.to_string(),
			token: token.to_string(),
			amount: amount.clone(),
			external,
		});
		Ok(())
	}

	pub(crate) fn supply(&mut self, host: &dyn Host, token: &str) -> HostResult<Option<BigUint>> {
		Ok(match self.reads.supplies.entry(token.to_string()) {
			Entry::Occupied(entry) => entry.get().clone(),
			Entry::Vacant(entry) => entry.insert(host.token_supply(token)?).clone(),
		})
	}

	pub(crate) fn contract(&mut self, host: &dyn Host, address: &str) -> Result<ContractRecord, EngineError> {
		let record = match self.reads.contracts.entry(address.to_string()) {
			Entry::Occupied(entry) => entry.get().clone(),
			Entry::Vacant(entry) => entry.insert(host.contract(address)?).clone(),
		};
		record.ok_or_else(|| EngineError::UnknownContract { address: address.to_string() })
	}

	pub(crate) fn set_info(&mut self, contract: &str, info: AccountInfo) {
		self.infos.insert(contract.to_string(), info);
	}

	/// The account info contracts set during the call that differs from
	/// what the call started from, by contract.
	pub(crate) fn changed_infos(&self) -> Vec<(String, AccountInfo)> {
		self.infos
			.iter()
			.filter(|(address, info)| {
				let before = self.reads.contracts.get(*address).cloned().flatten();
				before.map(|record| record.info).as_ref() != Some(*info)
			})
			.map(|(address, info)| (address.clone(), info.clone()))
			.collect()
	}

	pub(crate) fn storage_get(&mut self, host: &dyn Host, contract: &str, key: &[u8]) -> HostResult<Option<Vec<u8>>> {
		let entry = (contract.to_string(), key.to_vec());
		if let Some(value) = self.storage.get(&entry) {
			return Ok(value.clone());
		}
		Ok(match self.reads.storage.entry(entry) {
			Entry::Occupied(entry) => entry.get().clone(),
			Entry::Vacant(entry) => entry.insert(host.storage_get(contract, key)?).clone(),
		})
	}

	pub(crate) fn storage_set(&mut self, contract: &str, key: &[u8], value: Option<Vec<u8>>) {
		self.storage
			.insert((contract.to_string(), key.to_vec()), value);
	}

	/// Every account read from the host during the call, with the data it
	/// had: the call's read set.
	pub(crate) fn storage_reads(&self) -> Vec<(String, Vec<u8>, Option<Vec<u8>>)> {
		self.reads
			.storage
			.iter()
			.map(|((contract, key), value)| (contract.clone(), key.clone(), value.clone()))
			.collect()
	}

	/// Every account the call changed from the data it started with, with
	/// its new data, in (contract, key) order. Each was read before it was
	/// written, so the read set says what it had.
	pub(crate) fn storage_writes(&self) -> Vec<(StorageKey, Option<Vec<u8>>)> {
		self.storage
			.iter()
			.filter(|(entry, value)| self.reads.storage.get(*entry) != Some(*value))
			.map(|(entry, value)| (entry.clone(), value.clone()))
			.collect()
	}
}
