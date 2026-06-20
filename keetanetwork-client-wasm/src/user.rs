//! JS `UserClient`: a signer-bound facade over [`KeetaClient`](crate::client).

use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{IdentifierCreateArguments, MultisigCreateArguments, SetInfo};
use keetanetwork_client::{
	AcceptSwapRequest, ChainQuery, CreateSwapRequest, HistoryQuery, KeetaClient as Core, Network,
	UserClient as CoreUser,
};
use num_bigint::BigInt;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::block::{Block, VoteStaple};
use crate::builder::Builder;
use crate::certificate::ManageCertificate;
use crate::client::KeetaClient;
use crate::convert::{
	amount_to_string, client_error, parse_adjust_method, parse_amount, parse_identifier_type, parse_ledger_side,
	JsResult,
};
use crate::dto::{AccountStateView, AclView, CertificateView, HistoryEntryView, TokenBalanceView};
use crate::options::TransmitOptions;
use crate::permissions::{PermissionChange, Permissions};
use crate::swap::SwapExpectation;
use crate::vote::VoteQuote;

/// A client bound to a signer (and optionally a distinct operating account),
/// exposing account-scoped reads and convenience writes. Constructed without a
/// signer it is read-only and rejects writes.
#[wasm_bindgen]
pub struct UserClient {
	inner: CoreUser,
}

#[wasm_bindgen]
impl UserClient {
	/// Connect to the node REST API at `base_url`, bound to `signer`.
	#[wasm_bindgen(constructor)]
	pub fn new(base_url: String, signer: &Account) -> UserClient {
		Self { inner: CoreUser::from_parts(Core::new(base_url), Some(signer.inner())) }
	}

	/// Connect to the node REST API at `base_url` without a signer; reads work
	/// but writes are rejected.
	#[wasm_bindgen(js_name = readOnly)]
	pub fn read_only(base_url: String) -> UserClient {
		Self { inner: CoreUser::from_parts(Core::new(base_url), None) }
	}

	/// Connect to a well-known network by name, bound to `signer`.
	#[wasm_bindgen(js_name = forNetwork)]
	pub fn for_network(name: String, signer: &Account) -> JsResult<UserClient> {
		let network = Network::from_str(&name).map_err(client_error)?;
		let inner = CoreUser::from_network(network, Some(signer.inner())).map_err(client_error)?;
		Ok(Self { inner })
	}

	/// Connect to a well-known network by name without a signer (read-only).
	#[wasm_bindgen(js_name = forNetworkReadOnly)]
	pub fn for_network_read_only(name: String) -> JsResult<UserClient> {
		let network = Network::from_str(&name).map_err(client_error)?;
		let inner = CoreUser::from_network(network, None).map_err(client_error)?;
		Ok(Self { inner })
	}

	/// Bind an existing [`KeetaClient`] to `signer`.
	#[wasm_bindgen(js_name = fromClient)]
	pub fn from_client(client: &KeetaClient, signer: &Account) -> UserClient {
		Self { inner: CoreUser::from_parts(client.inner(), Some(signer.inner())) }
	}

	/// Bind an existing [`KeetaClient`] without a signer; reads work but
	/// writes are rejected.
	#[wasm_bindgen(js_name = readOnlyFromClient)]
	pub fn read_only_from_client(client: &KeetaClient) -> UserClient {
		Self { inner: CoreUser::from_parts(client.inner(), None) }
	}

	/// Set a distinct operating account, used for reads and as the block
	/// originator while the signer still signs.
	#[wasm_bindgen(js_name = withAccount)]
	pub fn with_account(self, account: &Account) -> UserClient {
		Self { inner: self.inner.with_account(account.inner()) }
	}

	/// The underlying transport client.
	pub fn client(&self) -> KeetaClient {
		KeetaClient::from(self.inner.client().clone())
	}

	/// The operating account this client reads from and originates writes for.
	pub fn account(&self) -> JsResult<Account> {
		let account = self.inner.account().map_err(client_error)?;
		Ok(Account::from(account))
	}

	/// The bound signing account, or `undefined` when read-only.
	#[wasm_bindgen(js_name = signerAccount)]
	pub fn signer_account(&self) -> Option<Account> {
		self.inner
			.signer_account()
			.map(|signer| Account::from(signer.clone()))
	}

	/// Whether this client has no signer and therefore rejects writes.
	#[wasm_bindgen(getter, js_name = isReadOnly)]
	pub fn is_read_only(&self) -> bool {
		self.inner.is_read_only()
	}

	/// The settled balance of `token` for the operating account.
	pub async fn balance(&self, token: &Account) -> JsResult<String> {
		let amount = self
			.inner
			.balance(token.address())
			.await
			.map_err(client_error)?;
		Ok(amount_to_string(amount))
	}

	/// Every token balance held by the operating account.
	#[wasm_bindgen(js_name = allBalances)]
	pub async fn all_balances(&self) -> JsResult<Vec<TokenBalanceView>> {
		let balances = self.inner.all_balances().await.map_err(client_error)?;
		Ok(balances.iter().map(TokenBalanceView::from).collect())
	}

	/// A snapshot of the operating account's ledger state.
	pub async fn state(&self) -> JsResult<AccountStateView> {
		let state = self.inner.state().await.map_err(client_error)?;
		Ok(AccountStateView::from(&state))
	}

	/// The operating account's head block, or `undefined` when it has none.
	pub async fn head(&self) -> JsResult<Option<Block>> {
		let head = self.inner.head().await.map_err(client_error)?;
		Ok(head.map(Block::from))
	}

	/// Every block in the operating account's chain, oldest first.
	pub async fn chain(&self) -> JsResult<Vec<Block>> {
		let blocks = self.inner.chain().await.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}

	/// A single page of the operating account's chain, bounded by the optional
	/// `start`/`end` block-hash cursors and `limit`.
	#[wasm_bindgen(js_name = chainPage)]
	pub async fn chain_page(
		&self,
		start: Option<String>,
		end: Option<String>,
		limit: Option<u32>,
	) -> JsResult<Vec<Block>> {
		let query = ChainQuery { start, end, limit: limit.map(i64::from) };
		let blocks = self.inner.chain_page(query).await.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}

	/// Every block in the operating account's chain, fetched by paging
	/// `page_limit` blocks at a time.
	#[wasm_bindgen(js_name = chainAll)]
	pub async fn chain_all(&self, page_limit: u32) -> JsResult<Vec<Block>> {
		let blocks = self
			.inner
			.chain_all(page_limit)
			.await
			.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}

	/// The operating account's verified history.
	pub async fn history(&self) -> JsResult<Vec<HistoryEntryView>> {
		let entries = self.inner.history().await.map_err(client_error)?;
		Ok(entries.iter().map(HistoryEntryView::from).collect())
	}

	/// A single page of the operating account's history, bounded by `start`
	/// and `limit`.
	#[wasm_bindgen(js_name = historyPage)]
	pub async fn history_page(&self, start: Option<String>, limit: Option<u32>) -> JsResult<Vec<HistoryEntryView>> {
		let query = HistoryQuery { start, limit: limit.map(i64::from) };
		let entries = self.inner.history_page(query).await.map_err(client_error)?;
		Ok(entries.iter().map(HistoryEntryView::from).collect())
	}

	/// The next pending block for the operating account, if any.
	#[wasm_bindgen(js_name = pendingBlock)]
	pub async fn pending_block(&self) -> JsResult<Option<Block>> {
		let pending = self.inner.pending_block().await.map_err(client_error)?;
		Ok(pending.map(Block::from))
	}

	/// ACL entries where the operating account is the principal (grantee).
	pub async fn acls(&self) -> JsResult<Vec<AclView>> {
		let acls = self.inner.acls().await.map_err(client_error)?;
		Ok(acls.iter().map(AclView::from).collect())
	}

	/// ACL entries granted to the operating account as an entity.
	#[wasm_bindgen(js_name = aclsByEntity)]
	pub async fn acls_by_entity(&self) -> JsResult<Vec<AclView>> {
		let acls = self.inner.acls_by_entity().await.map_err(client_error)?;
		Ok(acls.iter().map(AclView::from).collect())
	}

	/// Every certificate held by the operating account.
	pub async fn certificates(&self) -> JsResult<Vec<CertificateView>> {
		let certificates = self.inner.certificates().await.map_err(client_error)?;
		Ok(certificates.iter().map(CertificateView::from).collect())
	}

	/// A single certificate on the operating account by its `hash`, if present.
	pub async fn certificate(&self, hash: String) -> JsResult<Option<CertificateView>> {
		let certificate = self.inner.certificate(hash).await.map_err(client_error)?;
		Ok(certificate.as_ref().map(CertificateView::from))
	}

	/// The block with hash `block_hash`, if the node has it. `side` selects the
	/// ledger to read (`"main"`, `"side"`, or `"both"`); the main ledger is
	/// used when omitted.
	pub async fn block(&self, block_hash: String, side: Option<String>) -> JsResult<Option<Block>> {
		let side = parse_ledger_side(side)?;
		let block = self
			.inner
			.block(block_hash, side)
			.await
			.map_err(client_error)?;
		Ok(block.map(Block::from))
	}

	/// The block carrying idempotency `key` on the operating account, if any.
	#[wasm_bindgen(js_name = blockFromIdempotent)]
	pub async fn block_from_idempotent(&self, key: String) -> JsResult<Option<Block>> {
		let block = self
			.inner
			.block_from_idempotent(key)
			.await
			.map_err(client_error)?;
		Ok(block.map(Block::from))
	}

	/// Fee quotes for `blocks` from every representative.
	pub async fn quotes(&self, blocks: Vec<Block>) -> JsResult<Vec<VoteQuote>> {
		let blocks: Vec<_> = blocks.iter().map(Block::inner).collect();
		let quotes = self.inner.quotes(&blocks).await.map_err(client_error)?;
		Ok(quotes.into_iter().map(VoteQuote::from).collect())
	}

	/// Recover the operating account's pending side block, optionally
	/// republishing. Returns the resulting staple, if any. `options` tunes the
	/// fee paid for the recovery block (fee-token preference, pre-fetched
	/// quotes); the bound signer pays the fee when none is set. Omit `options`
	/// to recover with the bound signer as fee signer.
	pub async fn recover(&self, publish: bool, options: Option<TransmitOptions>) -> JsResult<Option<VoteStaple>> {
		let staple = match options {
			None => self.inner.recover(publish).await,
			Some(options) => {
				let account = self.inner.account().map_err(client_error)?;
				let mut core = options.to_core();
				if core.fee_signer.is_none() {
					core.fee_signer = self.inner.signer_account().cloned();
				}
				self.inner
					.client()
					.recover_account(&account, publish, core)
					.await
			}
		}
		.map_err(client_error)?;
		Ok(staple.map(VoteStaple::from))
	}

	/// Reconstruct and optionally republish the operating account's settled
	/// head from representative votes. Returns the resulting staple, if any.
	pub async fn sync(&self, publish: bool) -> JsResult<Option<VoteStaple>> {
		let staple = self.inner.sync(publish).await.map_err(client_error)?;
		Ok(staple.map(VoteStaple::from))
	}

	/// Send `amount` of `token` to `to`, signed and fee-paid by the bound
	/// signer.
	pub async fn send(&self, to: &Account, amount: String, token: &Account) -> JsResult<bool> {
		let amount = parse_amount(&amount)?;
		self.inner
			.send(&to.inner(), &token.inner(), amount)
			.await
			.map_err(client_error)
	}

	/// Send `amount` of `token` to `to`, attaching opaque `external` reference
	/// data to the SEND operation. Signed and fee-paid by the bound signer.
	#[wasm_bindgen(js_name = sendExternal)]
	pub async fn send_external(
		&self,
		to: &Account,
		amount: String,
		token: &Account,
		external: String,
	) -> JsResult<bool> {
		let amount = parse_amount(&amount)?;
		self.inner
			.send_external(&to.inner(), &token.inner(), amount, external)
			.await
			.map_err(client_error)
	}

	/// Set the operating account's representative to `rep`.
	#[wasm_bindgen(js_name = setRep)]
	pub async fn set_rep(&self, rep: &Account) -> JsResult<bool> {
		self.inner.set_rep(&rep.inner()).await.map_err(client_error)
	}

	/// Set the operating account's on-chain info. `default_permission` is
	/// required for identifier accounts and rejected for keyed accounts.
	#[wasm_bindgen(js_name = setInfo)]
	pub async fn set_info(
		&self,
		name: String,
		description: String,
		metadata: String,
		default_permission: Option<Permissions>,
	) -> JsResult<bool> {
		let info = SetInfo { name, description, metadata, default_permission: default_permission.map(|p| p.to_core()) };
		self.inner.set_info(info).await.map_err(client_error)
	}

	/// Start a transaction originated by the operating account.
	#[wasm_bindgen(js_name = initBuilder)]
	pub fn init_builder(&self) -> JsResult<Builder> {
		let builder = self.inner.init_builder().map_err(client_error)?;
		Ok(Builder::new(builder))
	}

	/// Publish a single `block` under `options`, signed by the bound signer.
	pub async fn publish(&self, block: &Block, options: &TransmitOptions) -> JsResult<bool> {
		self.inner
			.publish(block.inner(), options.to_core())
			.await
			.map_err(client_error)
	}

	/// Publish `blocks` as one round under `options`, signed by the bound
	/// signer.
	pub async fn transmit(&self, blocks: Vec<Block>, options: &TransmitOptions) -> JsResult<bool> {
		let blocks: Vec<_> = blocks.iter().map(Block::inner).collect();
		self.inner
			.transmit(&blocks, options.to_core())
			.await
			.map_err(client_error)
	}

	/// Apply a MODIFY_PERMISSIONS `change` to the operating account.
	#[wasm_bindgen(js_name = updatePermissions)]
	pub async fn update_permissions(&self, change: &PermissionChange) -> JsResult<bool> {
		self.inner
			.update_permissions(change.to_core())
			.await
			.map_err(client_error)
	}

	/// Add or remove a certificate on the operating account via `change`.
	#[wasm_bindgen(js_name = modifyCertificate)]
	pub async fn modify_certificate(&self, change: &ManageCertificate) -> JsResult<bool> {
		self.inner
			.modify_certificate(change.to_core())
			.await
			.map_err(client_error)
	}

	/// Adjust `token`'s supply and a holder's balance of it in one block.
	/// `holder` defaults to the operating account when omitted. `method` is
	/// `"add"`, `"subtract"`, or `"set"`.
	#[wasm_bindgen(js_name = modifyTokenSupplyAndBalance)]
	pub async fn modify_token_supply_and_balance(
		&self,
		token: &Account,
		amount: String,
		method: String,
		holder: Option<Account>,
	) -> JsResult<bool> {
		let amount = parse_amount(&amount)?;
		let method = parse_adjust_method(&method)?;
		let holder = holder.map(|account| account.inner());
		self.inner
			.modify_token_supply_and_balance(&token.inner(), holder.as_ref(), amount, method)
			.await
			.map_err(client_error)
	}

	/// Create an identifier of `kind` (`"network"`, `"token"`, or `"storage"`)
	/// under the operating account, publish the creating block, and return the
	/// derived [`Account`].
	#[wasm_bindgen(js_name = generateIdentifier)]
	pub async fn generate_identifier(&self, kind: String) -> JsResult<Account> {
		let account = self
			.inner
			.generate_identifier(parse_identifier_type(&kind)?, None)
			.await
			.map_err(client_error)?;
		Ok(Account::from(account))
	}

	/// Create a multisig identifier requiring `quorum` of `signers`, publish
	/// the creating block, and return the derived [`Account`].
	#[wasm_bindgen(js_name = generateMultisigIdentifier)]
	pub async fn generate_multisig_identifier(&self, signers: Vec<Account>, quorum: u32) -> JsResult<Account> {
		let signers = signers.iter().map(Account::inner).collect();
		let arguments =
			IdentifierCreateArguments::Multisig(MultisigCreateArguments { signers, quorum: BigInt::from(quorum) });
		let account = self
			.inner
			.generate_identifier(KeyPairType::MULTISIG, Some(arguments))
			.await
			.map_err(client_error)?;
		Ok(Account::from(account))
	}

	/// Build a swap-request block: send `send_amount` of `send_token` and
	/// receive `receive_amount` of `receive_token` from `counterparty`, in a
	/// single unpublished block for the counterparty to accept.
	#[wasm_bindgen(js_name = createSwapRequest)]
	pub async fn create_swap_request(
		&self,
		counterparty: &Account,
		send_token: &Account,
		send_amount: String,
		receive_token: &Account,
		receive_amount: String,
		receive_exact: bool,
	) -> JsResult<Block> {
		let request = CreateSwapRequest {
			counterparty: counterparty.inner(),
			send_token: send_token.inner(),
			send_amount: parse_amount(&send_amount)?,
			receive_token: receive_token.inner(),
			receive_amount: parse_amount(&receive_amount)?,
			receive_exact,
		};
		let block = self
			.inner
			.create_swap_request(request)
			.await
			.map_err(client_error)?;
		Ok(Block::from(block))
	}

	/// Accept a maker's swap-request `block`, optionally asserting its legs via
	/// `expected`. Returns the taker's block(s) followed by the maker's block;
	/// transmit them together so the swap settles atomically.
	#[wasm_bindgen(js_name = acceptSwapRequest)]
	pub async fn accept_swap_request(&self, block: &Block, expected: Option<SwapExpectation>) -> JsResult<Vec<Block>> {
		let request = AcceptSwapRequest { block: block.inner(), expected: expected.map(|expected| expected.to_core()) };
		let blocks = self
			.inner
			.accept_swap_request(request)
			.await
			.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}
}
