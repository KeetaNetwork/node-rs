//! JS `Builder`: accumulates operations into one or more signed blocks.

use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{BlockHash, BlockTime, IdentifierCreateArguments, MultisigCreateArguments, SetInfo};
use keetanetwork_client::TransactionBuilder;
use num_bigint::BigInt;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::block::Block;
use crate::certificate::CertificateChange;
use crate::convert::{
	client_error, coded_error, parse_adjust_method, parse_amount, parse_identifier_type, parse_purpose, JsResult,
};
use crate::pending::PendingAccount;
use crate::permissions::{PermissionChange, Permissions};

/// A fluent block builder. Operations accumulate against the active account;
/// `build` resolves and seals one signed block per account.
#[wasm_bindgen]
pub struct Builder {
	inner: TransactionBuilder,
}

#[wasm_bindgen]
impl Builder {
	/// Switch the active account to `account`, signed by itself.
	#[wasm_bindgen(js_name = forAccount)]
	pub fn for_account(&mut self, account: &Account) {
		self.inner.for_account(&account.inner());
	}

	/// Switch the active account to `account`, signed by `signer`.
	#[wasm_bindgen(js_name = forAccountWithSigner)]
	pub fn for_account_with_signer(&mut self, account: &Account, signer: &Account) {
		self.inner
			.for_account_with_signer(&account.inner(), &signer.inner());
	}

	/// Append a SEND of `amount` of `token` to `to`, optionally carrying
	/// `external` reference data.
	pub fn send(&mut self, to: &Account, amount: String, token: &Account, external: Option<String>) -> JsResult<()> {
		let amount = parse_amount(&amount)?;
		match external {
			Some(external) => self
				.inner
				.send_external(to.inner(), token.inner(), amount, external),
			None => self.inner.send(to.inner(), token.inner(), amount),
		};
		Ok(())
	}

	/// Append a RECEIVE claiming `amount` of `token` sent by `from`.
	pub fn receive(&mut self, from: &Account, amount: String, token: &Account) -> JsResult<()> {
		let amount = parse_amount(&amount)?;
		self.inner.receive(from.inner(), token.inner(), amount);
		Ok(())
	}

	/// Append a RECEIVE with `exact` matching and optional `forward` recipient.
	#[wasm_bindgen(js_name = receiveWith)]
	pub fn receive_with(
		&mut self,
		from: &Account,
		amount: String,
		token: &Account,
		exact: bool,
		forward: Option<Account>,
	) -> JsResult<()> {
		let amount = parse_amount(&amount)?;
		let forward = forward.map(|account| account.inner().into());
		self.inner
			.receive_with(from.inner(), token.inner(), amount, exact, forward);
		Ok(())
	}

	/// Append a block setting the originator's representative to `to`.
	#[wasm_bindgen(js_name = setRep)]
	pub fn set_rep(&mut self, to: &Account) {
		self.inner.set_rep(&to.inner());
	}

	/// Append a block setting the originator's on-chain info.
	/// `default_permission` is required for identifier accounts and rejected
	/// for keyed accounts.
	#[wasm_bindgen(js_name = setInfo)]
	pub fn set_info(
		&mut self,
		name: String,
		description: String,
		metadata: String,
		default_permission: Option<Permissions>,
	) {
		let info = SetInfo { name, description, metadata, default_permission: default_permission.map(|p| p.to_core()) };
		self.inner.set_info(info);
	}

	/// Append a block adjusting the originating token's supply. `method` is
	/// `"add"`, `"subtract"`, or `"set"`.
	#[wasm_bindgen(js_name = modifyTokenSupply)]
	pub fn modify_token_supply(&mut self, amount: String, method: String) -> JsResult<()> {
		let amount = parse_amount(&amount)?;
		self.inner
			.modify_token_supply(amount, parse_adjust_method(&method)?);
		Ok(())
	}

	/// Append a block adjusting the originator's balance of `token`. `method`
	/// is `"add"`, `"subtract"`, or `"set"`.
	#[wasm_bindgen(js_name = modifyTokenBalance)]
	pub fn modify_token_balance(&mut self, token: &Account, amount: String, method: String) -> JsResult<()> {
		let amount = parse_amount(&amount)?;
		self.inner
			.modify_token_balance(token.inner(), amount, parse_adjust_method(&method)?);
		Ok(())
	}

	/// Append a CREATE_IDENTIFIER of `kind` (`"network"`, `"token"`, or
	/// `"storage"`), returning a handle that resolves to the derived address
	/// once the builder is built.
	#[wasm_bindgen(js_name = generateIdentifier)]
	pub fn generate_identifier(&mut self, kind: String) -> JsResult<PendingAccount> {
		let handle = self
			.inner
			.generate_identifier(parse_identifier_type(&kind)?, None);
		Ok(PendingAccount::from(handle))
	}

	/// Append a CREATE_IDENTIFIER for a multisig identifier requiring `quorum`
	/// of `signers`, returning a handle to the derived address.
	#[wasm_bindgen(js_name = generateMultisigIdentifier)]
	pub fn generate_multisig_identifier(&mut self, signers: Vec<Account>, quorum: u32) -> PendingAccount {
		let signers = signers.iter().map(Account::inner).collect();
		let arguments =
			IdentifierCreateArguments::Multisig(MultisigCreateArguments { signers, quorum: BigInt::from(quorum) });
		let handle = self
			.inner
			.generate_identifier(KeyPairType::MULTISIG, Some(arguments));
		PendingAccount::from(handle)
	}

	/// Append a MODIFY_PERMISSIONS block from `change`.
	#[wasm_bindgen(js_name = updatePermissions)]
	pub fn update_permissions(&mut self, change: &PermissionChange) {
		self.inner.modify_permissions(change.to_core());
	}

	/// Append a MANAGE_CERTIFICATE block from `change`.
	#[wasm_bindgen(js_name = manageCertificate)]
	pub fn manage_certificate(&mut self, change: &CertificateChange) {
		self.inner.manage_certificate(change.to_core());
	}

	/// Seed the primary account's first block `previous` (hex), skipping its
	/// ledger head lookup.
	#[wasm_bindgen(js_name = withPrevious)]
	pub fn with_previous(&mut self, previous: String) -> JsResult<()> {
		let previous =
			BlockHash::from_str(&previous).map_err(|_| coded_error("INVALID_BLOCK_HASH", "block hash must be hex"))?;
		self.inner.with_previous(previous);
		Ok(())
	}

	/// Override every block's purpose: `"generic"` or `"fee"`.
	#[wasm_bindgen(js_name = withPurpose)]
	pub fn with_purpose(&mut self, purpose: String) -> JsResult<()> {
		self.inner.with_purpose(parse_purpose(&purpose)?);
		Ok(())
	}

	/// Override every block's timestamp (Unix milliseconds).
	#[wasm_bindgen(js_name = withDate)]
	pub fn with_date(&mut self, unix_millis: f64) -> JsResult<()> {
		let date = BlockTime::from_unix_millis(unix_millis as i64)
			.ok_or_else(|| coded_error("INVALID_DATE", "unix milliseconds out of range"))?;
		self.inner.with_date(date);
		Ok(())
	}

	/// Resolve and seal one signed block per account, in operation order.
	pub async fn build(&mut self) -> JsResult<Vec<Block>> {
		let blocks = self.inner.build().await.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}
}

impl Builder {
	pub(crate) fn new(inner: TransactionBuilder) -> Self {
		Self { inner }
	}
}
