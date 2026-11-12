//! An in-memory [`Host`]: a minimal ledger, for tests.
//!
//! [`MemoryHost::apply`] applies a call's [`LedgerOutcome`] the way the
//! ledger does once the call's block is accepted: the caller's funds move
//! to the contract, the contract's state accounts take their new data, and
//! its `SEND`s and `SET_INFO` take effect. It checks that no balance goes
//! negative and that each `SEND` passes [`Host::send_refusal`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use keetanetwork_account::{AccountPublicKey, KeyPairType};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::address::parse_account;
use crate::engine::{Effect, LedgerCall, LedgerOutcome};
use crate::host::{AccountInfo, CodeHash, ContractRecord, Host, HostError, HostResult};

#[derive(Clone, Debug, Default)]
struct Inner {
	code: BTreeMap<CodeHash, Vec<u8>>,
	contracts: BTreeMap<String, ContractRecord>,
	storage: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
	balances: BTreeMap<(String, String), BigUint>,
	supplies: BTreeMap<String, BigUint>,
	/// (account, token) pairs without `ACCESS` on the token. Every other
	/// account has it, as with a token whose default permission grants it.
	no_access: BTreeSet<(String, String)>,
	/// Storage accounts that let anyone hold tokens in them: every contract
	/// unless [`MemoryHost::set_holdable`] says otherwise
	holdable: BTreeSet<String>,
}

impl Inner {
	fn balance(&self, account: &str, token: &str) -> BigUint {
		self.balances
			.get(&(account.to_string(), token.to_string()))
			.cloned()
			.unwrap_or_default()
	}

	fn transfer(&mut self, from: &str, to: &str, token: &str, amount: &BigUint) -> HostResult<()> {
		if let Some(reason) = self.send_refusal(from, to, token) {
			return Err(HostError::new(reason));
		}
		let held = self.balance(from, token);
		if held < *amount {
			return Err(HostError::new(format!("{from} holds {held} of {token}, needs {amount}")));
		}
		self.balances
			.insert((from.to_string(), token.to_string()), held - amount);
		let received = self.balance(to, token) + amount;
		self.balances
			.insert((to.to_string(), token.to_string()), received);
		Ok(())
	}

	/// Why Keeta would refuse this `SEND`: `ACCESS` on the token for both
	/// accounts, and a storage recipient that lets anyone hold tokens.
	fn send_refusal(&self, from: &str, to: &str, token: &str) -> Option<String> {
		for account in [from, to] {
			if account != token
				&& self
					.no_access
					.contains(&(account.to_string(), token.to_string()))
			{
				return Some(format!("{account} has no ACCESS on {token}"));
			}
		}
		let storage = parse_account(to).is_ok_and(|to| to.to_keypair_type() == KeyPairType::STORAGE);
		if storage && !self.holdable.contains(to) {
			return Some(format!("{to} does not let {from} hold tokens in it"));
		}
		None
	}
}

/// A [`Host`] that keeps a ledger in memory.
#[derive(Debug, Default)]
pub struct MemoryHost {
	inner: Mutex<Inner>,
}

impl MemoryHost {
	/// An empty ledger.
	pub fn new() -> Self {
		Self::default()
	}

	fn lock(&self) -> MutexGuard<'_, Inner> {
		self.inner.lock().expect("memory host lock")
	}

	/// Deploy `elf` at `address`, as the ledger does for a `CONTRACT_DEPLOY`.
	/// Check the code with [`Engine::store_code`](crate::Engine::store_code)
	/// first. Returns its hash.
	pub fn deploy(&self, address: &str, elf: Vec<u8>) -> CodeHash {
		let hash: CodeHash = Sha256::digest(&elf).into();
		let mut inner = self.lock();
		inner.code.insert(hash, elf);
		inner
			.contracts
			.insert(address.to_string(), ContractRecord { code_hash: hash, info: AccountInfo::default() });
		inner.holdable.insert(address.to_string());
		hash
	}

	/// Give `account` some of `token`.
	pub fn credit(&self, account: &str, token: &str, amount: impl Into<BigUint>) {
		let mut inner = self.lock();
		let balance = inner.balance(account, token) + amount.into();
		inner
			.balances
			.insert((account.to_string(), token.to_string()), balance);
	}

	/// Set a token's supply.
	pub fn set_supply(&self, token: &str, supply: impl Into<BigUint>) {
		self.lock()
			.supplies
			.insert(token.to_string(), supply.into());
	}

	/// Grant or revoke `account`'s `ACCESS` on `token`.
	pub fn set_access(&self, account: &str, token: &str, access: bool) {
		let key = (account.to_string(), token.to_string());
		let mut inner = self.lock();
		if access {
			inner.no_access.remove(&key);
		} else {
			inner.no_access.insert(key);
		}
	}

	/// Whether the storage account `account` lets anyone hold tokens in it.
	pub fn set_holdable(&self, account: &str, holdable: bool) {
		let mut inner = self.lock();
		if holdable {
			inner.holdable.insert(account.to_string());
		} else {
			inner.holdable.remove(account);
		}
	}

	/// Set some of a contract's state accounts directly.
	pub fn seed_storage(&self, contract: &str, records: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) {
		self.lock()
			.storage
			.entry(contract.to_string())
			.or_default()
			.extend(records);
	}

	/// Apply a call the engine ran, as the ledger does once the call's block
	/// is accepted. Nothing changes if any part of it fails.
	pub fn apply(&self, call: &LedgerCall, outcome: &LedgerOutcome) -> HostResult<()> {
		let mut inner = self.lock();
		let mut next = inner.clone();
		for fund in &call.funds {
			next.transfer(&call.caller, &call.instruction.contract, &fund.token, &fund.amount)?;
		}
		for write in &outcome.writes {
			let storage = next.storage.entry(write.owner.clone()).or_default();
			match &write.data {
				Some(data) => storage.insert(write.id.to_vec(), data.clone()),
				None => storage.remove(write.id.as_slice()),
			};
		}
		for effect in &outcome.effects {
			match effect {
				Effect::Send { from, to, token, amount, .. } => next.transfer(from, to, token, amount)?,
				Effect::SetInfo { account, info } => {
					let record = next
						.contracts
						.get_mut(account)
						.ok_or_else(|| HostError::new(format!("SET_INFO on {account}, which is not a contract")))?;
					record.info = info.clone();
				}
			}
		}
		*inner = next;
		Ok(())
	}

	/// `account`'s balance of `token`.
	pub fn balance_of(&self, account: &str, token: &str) -> BigUint {
		self.lock().balance(account, token)
	}

	/// A contract's account info.
	pub fn info_of(&self, contract: &str) -> Option<AccountInfo> {
		self.lock()
			.contracts
			.get(contract)
			.map(|record| record.info.clone())
	}

	/// A contract's state accounts, by id.
	pub fn storage_of(&self, contract: &str) -> BTreeMap<Vec<u8>, Vec<u8>> {
		self.lock()
			.storage
			.get(contract)
			.cloned()
			.unwrap_or_default()
	}
}

impl Host for MemoryHost {
	fn code_bytes(&self, hash: &CodeHash) -> HostResult<Option<Vec<u8>>> {
		Ok(self.lock().code.get(hash).cloned())
	}

	fn contract(&self, address: &str) -> HostResult<Option<ContractRecord>> {
		Ok(self.lock().contracts.get(address).cloned())
	}

	fn storage_get(&self, contract: &str, key: &[u8]) -> HostResult<Option<Vec<u8>>> {
		Ok(self
			.lock()
			.storage
			.get(contract)
			.and_then(|storage| storage.get(key))
			.cloned())
	}

	fn balance(&self, account: &str, token: &str) -> HostResult<BigUint> {
		Ok(self.lock().balance(account, token))
	}

	fn token_supply(&self, token: &str) -> HostResult<Option<BigUint>> {
		Ok(self.lock().supplies.get(token).cloned())
	}

	fn send_refusal(&self, from: &str, to: &str, token: &str) -> HostResult<Option<String>> {
		Ok(self.lock().send_refusal(from, to, token))
	}
}
