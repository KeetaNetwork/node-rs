//! JS `KeetaClient`: representative-facing client over a node's REST API.

use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_client::{ChainQuery, HistoryQuery, KeetaClient as Core, Network};
use num_bigint::BigInt;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::block::{Block, VoteStaple};
use crate::builder::Builder;
use crate::convert::{amount_to_string, client_error, coded_error, parse_amount, parse_ledger_side, JsResult};
use crate::dto::{
	AccountStateView, AclView, CertificateView, HistoryEntryView, LedgerChecksumView, RepresentativeView,
	TokenBalanceView,
};
use crate::options::TransmitOptions;
use crate::rep::RepEndpoint;
use crate::vote::{Vote, VoteQuote};

/// A client bound to one or more node representatives.
#[wasm_bindgen]
pub struct KeetaClient {
	inner: Core,
}

#[wasm_bindgen]
impl KeetaClient {
	/// Connect to the node REST API at `base_url` (single representative).
	#[wasm_bindgen(constructor)]
	pub fn new(base_url: String) -> KeetaClient {
		Self { inner: Core::new(base_url) }
	}

	/// Connect to a well-known network by name: `"main"`, `"staging"`,
	/// `"test"`, or `"dev"`. Resolves the network's representatives and id.
	#[wasm_bindgen(js_name = forNetwork)]
	pub fn for_network(name: String) -> JsResult<KeetaClient> {
		let network = Network::from_str(&name).map_err(client_error)?;
		let inner = Core::try_from(network).map_err(client_error)?;
		Ok(Self { inner })
	}

	/// Connect to an explicit set of representatives, fanning votes and
	/// publishes across them.
	#[wasm_bindgen(js_name = forRepresentatives)]
	pub fn for_representatives(reps: Vec<RepEndpoint>) -> KeetaClient {
		let reps = reps.into_iter().map(RepEndpoint::into_inner);
		Self { inner: Core::with_representatives(reps, Default::default()) }
	}

	/// Stamp `network` (a decimal integer string) onto originated blocks.
	#[wasm_bindgen(js_name = withNetwork)]
	pub fn with_network(self, network: String) -> JsResult<KeetaClient> {
		let network = BigInt::from_str(&network)
			.map_err(|_| coded_error("INVALID_INTEGER", "network must be a decimal integer"))?;
		Ok(Self { inner: self.inner.with_network(network) })
	}

	/// Stamp `subnet` (a decimal integer string) onto originated blocks.
	#[wasm_bindgen(js_name = withSubnet)]
	pub fn with_subnet(self, subnet: String) -> JsResult<KeetaClient> {
		let subnet = BigInt::from_str(&subnet)
			.map_err(|_| coded_error("INVALID_INTEGER", "subnet must be a decimal integer"))?;
		Ok(Self { inner: self.inner.with_subnet(subnet) })
	}

	/// The node software version string.
	#[wasm_bindgen(js_name = nodeVersion)]
	pub async fn node_version(&self) -> JsResult<String> {
		self.inner.node_version().await.map_err(client_error)
	}

	/// The settled balance of `token` held by `account`, as a decimal string.
	pub async fn balance(&self, account: &Account, token: &Account) -> JsResult<String> {
		let amount = self
			.inner
			.balance(account.address(), token.address())
			.await
			.map_err(client_error)?;
		Ok(amount_to_string(amount))
	}

	/// Every token balance held by `account`.
	pub async fn balances(&self, account: &Account) -> JsResult<Vec<TokenBalanceView>> {
		let balances = self
			.inner
			.balances(account.address())
			.await
			.map_err(client_error)?;
		Ok(balances.iter().map(TokenBalanceView::from).collect())
	}

	/// A snapshot of `account`'s ledger state.
	pub async fn state(&self, account: &Account) -> JsResult<AccountStateView> {
		let state = self
			.inner
			.state(account.address())
			.await
			.map_err(client_error)?;
		Ok(AccountStateView::from(&state))
	}

	/// Snapshots of several accounts' ledger state, in input order.
	pub async fn states(&self, accounts: Vec<String>) -> JsResult<Vec<AccountStateView>> {
		let refs: Vec<&str> = accounts.iter().map(String::as_str).collect();
		let states = self.inner.states(&refs).await.map_err(client_error)?;
		Ok(states.iter().map(AccountStateView::from).collect())
	}

	/// The total supply of `token`, as a decimal string, when it is a token.
	#[wasm_bindgen(js_name = tokenSupply)]
	pub async fn token_supply(&self, token: &Account) -> JsResult<Option<String>> {
		let supply = self
			.inner
			.token_supply(token.address())
			.await
			.map_err(client_error)?;
		Ok(supply.map(amount_to_string))
	}

	/// The head block of `account`, or `undefined` when it has none.
	#[wasm_bindgen(js_name = headBlock)]
	pub async fn head_block(&self, account: &Account) -> JsResult<Option<Block>> {
		let head = self
			.inner
			.head_block(account.address())
			.await
			.map_err(client_error)?;
		Ok(head.map(Block::from))
	}

	/// The head block of `account` paired with its settled base-token balance.
	#[wasm_bindgen(js_name = accountHeadInfo)]
	pub async fn account_head_info(&self, account: &Account) -> JsResult<Option<AccountHead>> {
		let info = self
			.inner
			.account_head_info(account.address())
			.await
			.map_err(client_error)?;
		Ok(info.map(|(block, balance)| AccountHead { block: Block::from(block), balance: amount_to_string(balance) }))
	}

	/// The next pending (unreceived-driven) block for `account`, if any.
	#[wasm_bindgen(js_name = pendingBlock)]
	pub async fn pending_block(&self, account: &Account) -> JsResult<Option<Block>> {
		let pending = self
			.inner
			.pending_block(account.address())
			.await
			.map_err(client_error)?;
		Ok(pending.map(Block::from))
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

	/// The block that chains directly after `block_hash`, if any.
	#[wasm_bindgen(js_name = successorBlock)]
	pub async fn successor_block(&self, block_hash: String) -> JsResult<Option<Block>> {
		let block = self
			.inner
			.successor_block(block_hash)
			.await
			.map_err(client_error)?;
		Ok(block.map(Block::from))
	}

	/// The block carrying idempotency `key` on `account`, if any.
	#[wasm_bindgen(js_name = blockByIdempotent)]
	pub async fn block_by_idempotent(&self, account: &Account, key: String) -> JsResult<Option<Block>> {
		let block = self
			.inner
			.block_by_idempotent(account.address(), key)
			.await
			.map_err(client_error)?;
		Ok(block.map(Block::from))
	}

	/// The verified vote staple committing the block with hash `block_hash`.
	#[wasm_bindgen(js_name = voteStaple)]
	pub async fn vote_staple(&self, block_hash: String) -> JsResult<Option<VoteStaple>> {
		let staple = self
			.inner
			.vote_staple(block_hash)
			.await
			.map_err(client_error)?;
		Ok(staple.map(VoteStaple::from))
	}

	/// Every block in `account`'s chain, most recent first.
	pub async fn chain(&self, account: &Account) -> JsResult<Vec<Block>> {
		let blocks = self
			.inner
			.chain(account.address())
			.await
			.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}

	/// A single page of `account`'s chain, bounded by the optional `start`/
	/// `end` block-hash cursors and `limit`.
	#[wasm_bindgen(js_name = chainPage)]
	pub async fn chain_page(
		&self,
		account: &Account,
		start: Option<String>,
		end: Option<String>,
		limit: Option<u32>,
	) -> JsResult<Vec<Block>> {
		let query = ChainQuery { start, end, limit: limit.map(i64::from) };
		let blocks = self
			.inner
			.chain_page(account.address(), query)
			.await
			.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}

	/// Every block in `account`'s chain, fetched by paging `page_limit` at a
	/// time.
	#[wasm_bindgen(js_name = chainAll)]
	pub async fn chain_all(&self, account: &Account, page_limit: u32) -> JsResult<Vec<Block>> {
		let blocks = self
			.inner
			.chain_all(account.address(), page_limit)
			.await
			.map_err(client_error)?;
		Ok(blocks.into_iter().map(Block::from).collect())
	}

	/// `account`'s verified history.
	pub async fn history(&self, account: &Account) -> JsResult<Vec<HistoryEntryView>> {
		let entries = self
			.inner
			.history(account.address())
			.await
			.map_err(client_error)?;
		Ok(entries.iter().map(HistoryEntryView::from).collect())
	}

	/// A single page of `account`'s history, bounded by `start` and `limit`.
	#[wasm_bindgen(js_name = historyPage)]
	pub async fn history_page(
		&self,
		account: &Account,
		start: Option<String>,
		limit: Option<u32>,
	) -> JsResult<Vec<HistoryEntryView>> {
		let query = HistoryQuery { start, limit: limit.map(i64::from) };
		let entries = self
			.inner
			.history_page(account.address(), query)
			.await
			.map_err(client_error)?;
		Ok(entries.iter().map(HistoryEntryView::from).collect())
	}

	/// The node's global transaction history.
	#[wasm_bindgen(js_name = globalHistory)]
	pub async fn global_history(&self) -> JsResult<Vec<HistoryEntryView>> {
		let entries = self.inner.global_history().await.map_err(client_error)?;
		Ok(entries.iter().map(HistoryEntryView::from).collect())
	}

	/// A single page of the node's global history, bounded by `start`/`limit`.
	#[wasm_bindgen(js_name = globalHistoryPage)]
	pub async fn global_history_page(
		&self,
		start: Option<String>,
		limit: Option<u32>,
	) -> JsResult<Vec<HistoryEntryView>> {
		let query = HistoryQuery { start, limit: limit.map(i64::from) };
		let entries = self
			.inner
			.global_history_page(query)
			.await
			.map_err(client_error)?;
		Ok(entries.iter().map(HistoryEntryView::from).collect())
	}

	/// Vote staples committed at or after the ISO 8601 `start` moment.
	#[wasm_bindgen(js_name = voteStaplesAfter)]
	pub async fn vote_staples_after(&self, start: String) -> JsResult<Vec<VoteStaple>> {
		let staples = self
			.inner
			.vote_staples_after(start)
			.await
			.map_err(client_error)?;
		Ok(staples.into_iter().map(VoteStaple::from).collect())
	}

	/// A single page of vote staples committed at or after `start`, capped at
	/// `limit`.
	#[wasm_bindgen(js_name = voteStaplesAfterPage)]
	pub async fn vote_staples_after_page(&self, start: String, limit: Option<u32>) -> JsResult<Vec<VoteStaple>> {
		let staples = self
			.inner
			.vote_staples_after_page(start, limit.map(i64::from))
			.await
			.map_err(client_error)?;
		Ok(staples.into_iter().map(VoteStaple::from).collect())
	}

	/// The node's own representative and its weight.
	#[wasm_bindgen(js_name = nodeRepresentative)]
	pub async fn node_representative(&self) -> JsResult<RepresentativeView> {
		let rep = self
			.inner
			.node_representative()
			.await
			.map_err(client_error)?;
		Ok(RepresentativeView::from(&rep))
	}

	/// The weight of representative `rep`.
	pub async fn representative(&self, rep: &Account) -> JsResult<RepresentativeView> {
		let rep = self
			.inner
			.representative(rep.address())
			.await
			.map_err(client_error)?;
		Ok(RepresentativeView::from(&rep))
	}

	/// Every known representative and its weight.
	pub async fn representatives(&self) -> JsResult<Vec<RepresentativeView>> {
		let reps = self.inner.representatives().await.map_err(client_error)?;
		Ok(reps.iter().map(RepresentativeView::from).collect())
	}

	/// The current ledger checksum.
	#[wasm_bindgen(js_name = ledgerChecksum)]
	pub async fn ledger_checksum(&self) -> JsResult<LedgerChecksumView> {
		let checksum = self.inner.ledger_checksum().await.map_err(client_error)?;
		Ok(LedgerChecksumView::from(&checksum))
	}

	/// ACL entries where `account` is the principal (grantee).
	#[wasm_bindgen(js_name = aclsByPrincipal)]
	pub async fn acls_by_principal(&self, account: &Account) -> JsResult<Vec<AclView>> {
		let acls = self
			.inner
			.acls_by_principal(account.address())
			.await
			.map_err(client_error)?;
		Ok(acls.iter().map(AclView::from).collect())
	}

	/// ACL entries granted to `account` as an entity.
	#[wasm_bindgen(js_name = aclsByEntity)]
	pub async fn acls_by_entity(&self, account: &Account) -> JsResult<Vec<AclView>> {
		let acls = self
			.inner
			.acls_by_entity(account.address())
			.await
			.map_err(client_error)?;
		Ok(acls.iter().map(AclView::from).collect())
	}

	/// Every certificate held by `account`.
	pub async fn certificates(&self, account: &Account) -> JsResult<Vec<CertificateView>> {
		let certificates = self
			.inner
			.certificates(account.address())
			.await
			.map_err(client_error)?;
		Ok(certificates.iter().map(CertificateView::from).collect())
	}

	/// The certificate of `account` identified by `hash`, if present.
	pub async fn certificate(&self, account: &Account, hash: String) -> JsResult<Option<CertificateView>> {
		let certificate = self
			.inner
			.certificate(account.address(), hash)
			.await
			.map_err(client_error)?;
		Ok(certificate.as_ref().map(CertificateView::from))
	}

	/// Build, sign, and publish a SEND of `amount` of `token` from `from` to
	/// `to`. Returns whether the node accepted the staple.
	pub async fn send(&self, from: &Account, to: &Account, amount: String, token: &Account) -> JsResult<bool> {
		let amount = parse_amount(&amount)?;
		self.inner
			.send(&from.inner(), &to.inner(), &token.inner(), amount)
			.await
			.map_err(client_error)
	}

	/// Publish a single `block` under `options`.
	pub async fn publish(&self, block: &Block, options: &TransmitOptions) -> JsResult<bool> {
		self.inner
			.publish(block.inner(), options.to_core())
			.await
			.map_err(client_error)
	}

	/// Publish `blocks` as one round under `options`.
	pub async fn transmit(&self, blocks: Vec<Block>, options: &TransmitOptions) -> JsResult<bool> {
		let blocks: Vec<_> = blocks.iter().map(Block::inner).collect();
		self.inner
			.transmit(&blocks, options.to_core())
			.await
			.map_err(client_error)
	}

	/// Re-submit an already-voted `staple` to the representatives.
	#[wasm_bindgen(js_name = transmitStaple)]
	pub async fn transmit_staple(&self, staple: &VoteStaple) -> JsResult<bool> {
		self.inner
			.transmit_staple(staple.inner())
			.await
			.map_err(client_error)
	}

	/// Request a single representative's vote for `blocks`.
	#[wasm_bindgen(js_name = requestVote)]
	pub async fn request_vote(&self, blocks: Vec<Block>) -> JsResult<Vote> {
		let blocks: Vec<_> = blocks.iter().map(Block::inner).collect();
		let vote = self
			.inner
			.request_vote(&blocks)
			.await
			.map_err(client_error)?;
		Ok(Vote::from(vote))
	}

	/// Request a single representative's fee quote for `blocks`.
	#[wasm_bindgen(js_name = requestQuote)]
	pub async fn request_quote(&self, blocks: Vec<Block>) -> JsResult<VoteQuote> {
		let blocks: Vec<_> = blocks.iter().map(Block::inner).collect();
		let quote = self
			.inner
			.request_quote(&blocks)
			.await
			.map_err(client_error)?;
		Ok(VoteQuote::from(quote))
	}

	/// Request fee quotes for `blocks` from every representative.
	pub async fn quotes(&self, blocks: Vec<Block>) -> JsResult<Vec<VoteQuote>> {
		let blocks: Vec<_> = blocks.iter().map(Block::inner).collect();
		let quotes = self.inner.quotes(&blocks).await.map_err(client_error)?;
		Ok(quotes.into_iter().map(VoteQuote::from).collect())
	}

	/// Reconstruct and optionally republish `account`'s settled head from
	/// representative votes. Returns the resulting staple, if any.
	#[wasm_bindgen(js_name = syncAccount)]
	pub async fn sync_account(&self, account: &Account, publish: bool) -> JsResult<Option<VoteStaple>> {
		let staple = self
			.inner
			.sync_account(&account.inner(), publish)
			.await
			.map_err(client_error)?;
		Ok(staple.map(VoteStaple::from))
	}

	/// Recover `account`'s pending side block, optionally republishing, under
	/// `options`.
	#[wasm_bindgen(js_name = recoverAccount)]
	pub async fn recover_account(
		&self,
		account: &Account,
		publish: bool,
		options: &TransmitOptions,
	) -> JsResult<Option<VoteStaple>> {
		let staple = self
			.inner
			.recover_account(&account.inner(), publish, options.to_core())
			.await
			.map_err(client_error)?;
		Ok(staple.map(VoteStaple::from))
	}

	/// Start a transaction originated by `account`.
	pub fn builder(&self, account: &Account) -> Builder {
		Builder::new(self.inner.builder(&account.inner()))
	}

	/// Refresh the representative set from the configured nodes.
	#[wasm_bindgen(js_name = discoverRepresentatives)]
	pub async fn discover_representatives(&self) -> JsResult<()> {
		self.inner
			.discover_representatives()
			.await
			.map_err(client_error)
	}
}

impl KeetaClient {
	/// The wrapped core client, cloned for binding a [`UserClient`].
	pub(crate) fn inner(&self) -> Core {
		self.inner.clone()
	}
}

impl From<Core> for KeetaClient {
	fn from(inner: Core) -> Self {
		Self { inner }
	}
}

/// An account's head block paired with its settled base-token balance.
#[wasm_bindgen]
pub struct AccountHead {
	block: Block,
	balance: String,
}

#[wasm_bindgen]
impl AccountHead {
	/// The head block.
	#[wasm_bindgen(getter)]
	pub fn block(&self) -> Block {
		self.block.clone()
	}

	/// The settled base-token balance as a decimal string.
	#[wasm_bindgen(getter)]
	pub fn balance(&self) -> String {
		self.balance.clone()
	}
}
