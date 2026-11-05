//! In-memory ledger and contract state.
//!
//! Stands in for both the Keeta ledger (balances, account info, tokens,
//! chain heads) and the sequencer's contract store. Every effect of a call
//! is applied here directly *and* recorded in [`ChainState::journal`] as a
//! [`LedgerOp`]; when the call commits, the journal becomes the Keeta
//! blocks the sequencer would publish. Rolling back is restoring a clone,
//! which also discards the journal entries made since.

use std::collections::BTreeMap;

use cosmwasm_std::Checksum;
use keetanetwork_crypto::hash::BlockHash;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::error::{ledger, EngineError};

/// `SET_INFO` fields of an account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountInfo {
	/// Account name
	pub name: String,
	/// Account description
	pub description: String,
	/// Base64 metadata
	pub metadata: String,
}

/// A token issued by a contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRecord {
	/// Contract that administers the token
	pub admin: String,
	/// Total supply
	pub supply: BigUint,
}

/// Stored code.
#[derive(Clone, Debug)]
pub struct CodeRecord {
	/// VM checksum (sha256) of the Wasm
	pub checksum: Checksum,
}

/// A contract instance.
#[derive(Clone, Debug, Default)]
pub struct ContractRecord {
	/// Code the contract runs
	pub code_id: u64,
	/// Who instantiated it
	pub creator: String,
	/// Who may migrate it (migration is not implemented in the spike)
	pub admin: Option<String>,
	/// Human-readable label
	pub label: String,
	/// The contract's key-value store
	pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// One ledger effect, attributed to the account whose chain it lands on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerOp {
	/// `SEND` from `from`.
	Send { from: String, to: String, token: String, amount: BigUint, external: Option<String> },
	/// `SET_INFO` on `account`.
	SetInfo { account: String, info: AccountInfo },
	/// `CREATE_IDENTIFIER` on `creator`'s chain.
	CreateIdentifier { creator: String, identifier: String },
	/// `TOKEN_ADMIN_SUPPLY` on the token's chain.
	TokenSupply { token: String, amount: BigUint, add: bool },
}

impl LedgerOp {
	/// The account whose chain carries this operation.
	pub fn account(&self) -> &str {
		match self {
			LedgerOp::Send { from, .. } => from,
			LedgerOp::SetInfo { account, .. } => account,
			LedgerOp::CreateIdentifier { creator, .. } => creator,
			LedgerOp::TokenSupply { token, .. } => token,
		}
	}
}

/// The whole state the engine operates on.
#[derive(Clone, Debug, Default)]
pub struct ChainState {
	/// account → token → balance
	pub(crate) balances: BTreeMap<String, BTreeMap<String, BigUint>>,
	pub(crate) accounts: BTreeMap<String, AccountInfo>,
	pub(crate) tokens: BTreeMap<String, TokenRecord>,
	/// (creator, subdenom) → token address
	pub(crate) token_registry: BTreeMap<(String, String), String>,
	/// code id `n` is `codes[n - 1]`
	pub(crate) codes: Vec<CodeRecord>,
	pub(crate) contracts: BTreeMap<String, ContractRecord>,
	/// account → hash of its latest block
	pub(crate) heads: BTreeMap<String, BlockHash>,
	/// Effects of the call in progress
	pub(crate) journal: Vec<LedgerOp>,
}

impl ChainState {
	pub(crate) fn balance(&self, account: &str, token: &str) -> BigUint {
		self.balances
			.get(account)
			.and_then(|tokens| tokens.get(token))
			.cloned()
			.unwrap_or_default()
	}

	pub(crate) fn credit(&mut self, account: &str, token: &str, amount: &BigUint) {
		*self
			.balances
			.entry(account.to_string())
			.or_default()
			.entry(token.to_string())
			.or_default() += amount;
	}

	pub(crate) fn debit(&mut self, account: &str, token: &str, amount: &BigUint) -> Result<(), EngineError> {
		let held = self.balance(account, token);
		if held < *amount {
			return Err(ledger(format!("{account} holds {held} of {token}, needs {amount}")));
		}
		let tokens = self.balances.entry(account.to_string()).or_default();
		let remaining = held - amount;
		if remaining == BigUint::ZERO {
			tokens.remove(token);
		} else {
			tokens.insert(token.to_string(), remaining);
		}
		Ok(())
	}

	/// Move tokens and journal the `SEND`.
	pub(crate) fn transfer(
		&mut self,
		from: &str,
		to: &str,
		token: &str,
		amount: &BigUint,
		external: Option<String>,
	) -> Result<(), EngineError> {
		if *amount == BigUint::ZERO {
			return Err(ledger("cannot send a zero amount"));
		}
		self.debit(from, token, amount)?;
		self.credit(to, token, amount);
		self.journal.push(LedgerOp::Send {
			from: from.to_string(),
			to: to.to_string(),
			token: token.to_string(),
			amount: amount.clone(),
			external,
		});
		Ok(())
	}

	pub(crate) fn checksum_of(&self, code_id: u64) -> Result<Checksum, EngineError> {
		code_id
			.checked_sub(1)
			.and_then(|index| self.codes.get(index as usize))
			.map(|code| code.checksum)
			.ok_or(EngineError::UnknownCode { code_id })
	}

	pub(crate) fn contract(&self, address: &str) -> Result<&ContractRecord, EngineError> {
		self.contracts
			.get(address)
			.ok_or_else(|| EngineError::UnknownContract { address: address.to_string() })
	}

	/// Commitment to everything except the in-progress journal.
	///
	/// A flat hash over a canonical encoding: enough to check that two
	/// engines agree. Phase 1 replaces it with a Merkle tree so a single
	/// key can be proven against the root.
	pub fn state_root(&self) -> [u8; 32] {
		let mut hasher = Sha256::new();
		let mut put = |bytes: &[u8]| {
			hasher.update((bytes.len() as u64).to_be_bytes());
			hasher.update(bytes);
		};

		put(b"balances");
		for (account, tokens) in &self.balances {
			for (token, amount) in tokens {
				put(account.as_bytes());
				put(token.as_bytes());
				put(&amount.to_bytes_be());
			}
		}
		put(b"accounts");
		for (account, info) in &self.accounts {
			put(account.as_bytes());
			put(info.name.as_bytes());
			put(info.description.as_bytes());
			put(info.metadata.as_bytes());
		}
		put(b"tokens");
		for (token, record) in &self.tokens {
			put(token.as_bytes());
			put(record.admin.as_bytes());
			put(&record.supply.to_bytes_be());
		}
		for ((creator, subdenom), token) in &self.token_registry {
			put(creator.as_bytes());
			put(subdenom.as_bytes());
			put(token.as_bytes());
		}
		put(b"codes");
		for code in &self.codes {
			put(code.checksum.as_slice());
		}
		put(b"contracts");
		for (address, contract) in &self.contracts {
			put(address.as_bytes());
			put(&contract.code_id.to_be_bytes());
			put(contract.creator.as_bytes());
			put(contract.admin.as_deref().unwrap_or("").as_bytes());
			put(contract.label.as_bytes());
			for (key, value) in &contract.storage {
				put(key);
				put(value);
			}
		}
		put(b"heads");
		for (account, head) in &self.heads {
			put(account.as_bytes());
			put(head.as_bytes());
		}

		hasher.finalize().into()
	}
}
