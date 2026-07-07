//! wasmtime P2 component networked smoke test.
//!
//! The example drives the exported `node` and `user-client` resources over `wasi:http`.

use std::path::PathBuf;

use keetanetwork_utils::node_harness::E2eNode;
use wasmtime::component::{Component, Linker, ResourceAny, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

mod bindings {
	wasmtime::component::bindgen!({
		world: "keeta-client",
		path: "../wit",
		imports: { default: async | trappable },
		exports: { default: async },
	});
}

use bindings::exports::keeta::client::crypto::KeyAlgorithm;
use bindings::exports::keeta::client::node::{
	AdjustMethod, BasePermission, ChainQuery, CodedError, HistoryQuery, IdentifierKind, LedgerSide,
};
use bindings::KeetaClient;

/// Host state granting the component WASI + outbound `wasi:http`.
struct Host {
	ctx: WasiCtx,
	http: WasiHttpCtx,
	table: ResourceTable,
}

impl Default for Host {
	fn default() -> Self {
		let ctx = WasiCtx::builder().inherit_stdio().build();
		let http = WasiHttpCtx::new();
		let table = ResourceTable::new();
		Self { ctx, http, table }
	}
}

impl WasiView for Host {
	fn ctx(&mut self) -> WasiCtxView<'_> {
		WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
	}
}

impl WasiHttpView for Host {
	fn http(&mut self) -> WasiHttpCtxView<'_> {
		WasiHttpCtxView { ctx: &mut self.http, table: &mut self.table, hooks: Default::default() }
	}
}

/// Locate the prebuilt P2 component.
fn component_path() -> PathBuf {
	if let Ok(path) = std::env::var("WASI_P2_COMPONENT") {
		return PathBuf::from(path);
	}

	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let relative = "../../target/wasm32-wasip2/debug/keetanetwork_client_wasi.wasm";
	manifest_dir.join(relative)
}

/// A readiness field reported by the harness on startup.
fn ready_field(node: &E2eNode, field: &str) -> String {
	node.info()
		.get(field)
		.and_then(|value| value.as_str())
		.unwrap_or_default()
		.to_string()
}

/// Project a guest [`CodedError`] into a host error for `?`.
fn coded(error: CodedError) -> wasmtime::Error {
	wasmtime::Error::msg(format!("{}: {}", error.code, error.message))
}

/// Instantiate the P2 component with WASI + outbound `wasi:http` granted.
async fn instantiate() -> wasmtime::Result<(Store<Host>, KeetaClient)> {
	let engine = Engine::default();
	let component = Component::from_file(&engine, component_path())?;
	let mut linker: Linker<Host> = Linker::new(&engine);

	wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
	wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

	let mut store = Store::new(&engine, Host::default());
	let bindings = KeetaClient::instantiate_async(&mut store, &component, &linker).await?;
	Ok((store, bindings))
}

/// The harness's trusted (genesis) signer seed: 32 bytes of `0x77` as hex.
fn trusted_seed() -> String {
	"77".repeat(32)
}

/// Derive an `ed25519` `account` resource from `seed` at `index` via the
/// exported `crypto` interface, returning its host handle.
async fn account_from_seed(
	store: &mut Store<Host>,
	bindings: &KeetaClient,
	seed: &str,
	index: u32,
) -> wasmtime::Result<ResourceAny> {
	bindings
		.keeta_client_crypto()
		.account()
		.call_from_seed(&mut *store, seed, index, KeyAlgorithm::Ed25519)
		.await?
		.map_err(coded)
}

/// Parse a textual `keeta_…` address into an `account` resource via the
/// exported `crypto` interface, returning its host handle.
async fn account_from_address(
	store: &mut Store<Host>,
	bindings: &KeetaClient,
	address: &str,
) -> wasmtime::Result<ResourceAny> {
	bindings
		.keeta_client_crypto()
		.account()
		.call_from_address(&mut *store, address)
		.await?
		.map_err(coded)
}

#[tokio::test]
async fn p2_reads_against_e2e_node() -> wasmtime::Result<()> {
	let mut harness = E2eNode::start()?;
	let api = ready_field(&harness, "api");
	let trusted = ready_field(&harness, "trusted");
	let base_token = ready_field(&harness, "baseToken");

	assert!(!api.is_empty(), "the harness must advertise an api URL");

	// Mint a supply to the trusted account so it has a chain/balance to read; a
	// fresh harness publishes nothing on its own.
	const SUPPLY: &str = "1000000";
	harness.request("init_supply", serde_json::json!({ "amount": SUPPLY }))?;

	let (mut store, bindings) = instantiate().await?;
	let node = bindings.keeta_client_node();

	// Typed account resources for the harness's textual addresses.
	let trusted_account = account_from_address(&mut store, &bindings, &trusted).await?;
	let base_token_account = account_from_address(&mut store, &bindings, &base_token).await?;

	// `node` resource: anonymous client bound to the rep URL.
	let client = node.client().call_constructor(&mut store, &api).await?;
	let version = node
		.client()
		.call_node_version(&mut store, client)
		.await?
		.map_err(coded)?;
	assert!(!version.is_empty(), "the node must report a version");

	let balance = node
		.client()
		.call_account_balance(&mut store, client, trusted_account, base_token_account)
		.await?
		.map_err(coded)?;
	assert_eq!(balance, SUPPLY, "the trusted balance must equal the minted supply");

	// `account-state` must round-trip and agree with the scalar balance read.
	let state = node
		.client()
		.call_account_state(&mut store, client, trusted_account)
		.await?
		.map_err(coded)?;
	let state_balance = state
		.balances
		.iter()
		.find(|entry| entry.token == base_token)
		.map(|entry| entry.amount.clone())
		.unwrap_or_else(|| "0".to_string());
	assert_eq!(state_balance, balance, "account-state must agree with the scalar balance read");

	// A node always knows at least itself as a representative.
	let reps = node
		.client()
		.call_representatives(&mut store, client)
		.await?
		.map_err(coded)?;
	assert!(!reps.is_empty(), "the node must advertise at least one representative");

	// The minted supply gave the trusted account a chain (most recent first).
	let chain = node
		.client()
		.call_chain(&mut store, client, trusted_account)
		.await?
		.map_err(coded)?;
	assert!(!chain.is_empty(), "the seeded trusted account must have a chain");

	// `chain-page` must honor the limit and agree with the unpaged head.
	let page_limit = 5;
	let query = ChainQuery { start: None, end: None, limit: Some(page_limit) };
	let page = node
		.client()
		.call_chain_page(&mut store, client, trusted_account, &query)
		.await?
		.map_err(coded)?;

	let page_len = page.blocks.len();
	let bounded = !page.blocks.is_empty() && page_len <= page_limit as usize;
	assert!(bounded, "the first page must be non-empty and bounded");
	assert_eq!(page.blocks.first(), chain.first(), "the page head must match the unpaged chain head");

	// `account-head-info` must agree with the chain head and height. (`block` is
	// the serialized block here; `account-state.head` is its hash, a different
	// projection, so they are not directly comparable.)
	let head_info = node
		.client()
		.call_account_head_info(&mut store, client, trusted_account)
		.await?
		.map_err(coded)?
		.expect("a funded account must have a head block");
	assert_eq!(Some(&head_info.block), chain.first(), "head-info must match the chain head");
	assert!(
		head_info.height.parse::<u64>().is_ok(),
		"head-info height must be a decimal integer: {}",
		head_info.height
	);

	// `history` records the supply staple, each entry carrying a hex staple.
	let history = node
		.client()
		.call_history(&mut store, client, trusted_account)
		.await?
		.map_err(coded)?;
	assert!(!history.is_empty(), "the seeded account must have history");
	assert!(history.iter().all(|entry| !entry.staple.is_empty()), "every history entry must carry a staple");

	// A settled account has no half-published successor.
	let pending = node
		.client()
		.call_pending_block(&mut store, client, trusted_account)
		.await?
		.map_err(coded)?;
	assert!(pending.is_none(), "a settled account must have no pending block");

	// `user-client` resource: account-scoped reads without repeating the address.
	let user = node
		.user_client()
		.call_read_only(&mut store, &api, trusted_account)
		.await?
		.map_err(coded)?;
	let user_balance = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;
	assert_eq!(user_balance, balance, "the user-client must read the same balance as the node client");

	// Account-scoped reads must agree with the node-client reads of the same
	// account, without repeating the address.
	let user_chain = node
		.user_client()
		.call_chain(&mut store, user)
		.await?
		.map_err(coded)?;
	assert_eq!(user_chain, chain, "the user-client chain must match the node-client chain");

	let user_page = node
		.user_client()
		.call_chain_page(&mut store, user, &query)
		.await?
		.map_err(coded)?;
	assert_eq!(user_page.first(), chain.first(), "the user-client page head must match the chain head");
	assert!(user_page.len() <= page_limit as usize, "the user-client page must honor the limit");

	let user_history = node
		.user_client()
		.call_history(&mut store, user)
		.await?
		.map_err(coded)?;
	assert_eq!(user_history.len(), history.len(), "the user-client history must match the node-client history");

	let user_pending = node
		.user_client()
		.call_pending_block(&mut store, user)
		.await?
		.map_err(coded)?;
	assert!(user_pending.is_none(), "a settled account must have no pending block");

	// Batch state read returns one entry per requested account.
	let states = node
		.client()
		.call_account_states(&mut store, client, core::slice::from_ref(&trusted_account))
		.await?
		.map_err(coded)?;
	assert_eq!(states.len(), 1, "account-states must return one state per requested account");

	// The node always knows its own representative.
	let node_rep = node
		.client()
		.call_node_representative(&mut store, client)
		.await?
		.map_err(coded)?;
	assert!(!node_rep.account.is_empty(), "the node must report its own representative");

	// The head block has no successor.
	let head_hash = state
		.head
		.clone()
		.expect("a funded account must have a head hash");
	let head_successor = node
		.client()
		.call_successor_block(&mut store, client, &head_hash)
		.await?
		.map_err(coded)?;
	assert!(head_successor.is_none(), "the head block must have no successor");

	// An unknown idempotency key resolves to no block.
	let idempotent = node
		.client()
		.call_block_by_idempotent(&mut store, client, trusted_account, "no-such-key", None)
		.await?
		.map_err(coded)?;
	assert!(idempotent.is_none(), "an unknown idempotency key must resolve to no block");

	// The first history page (limit 1) must agree with the unpaged head.
	let history_query = HistoryQuery { start: None, limit: Some(1) };
	let history_first = node
		.client()
		.call_history_page(&mut store, client, trusted_account, &history_query)
		.await?
		.map_err(coded)?;
	assert!(history_first.len() <= 1, "history-page must honor the limit");

	// The node's global history is non-empty and its page honors the limit.
	let global = node
		.client()
		.call_global_history(&mut store, client)
		.await?
		.map_err(coded)?;
	assert!(!global.is_empty(), "the node must report a non-empty global history");
	let global_query = HistoryQuery { start: None, limit: Some(1) };
	let global_page = node
		.client()
		.call_global_history_page(&mut store, client, &global_query)
		.await?
		.map_err(coded)?;
	assert!(global_page.len() <= 1, "global-history-page must honor the limit");

	// Vote staples after an epoch moment (ISO 8601): the unpaged read includes
	// its page.
	let cursor = "1970-01-01T00:00:00.000Z".to_string();
	let staples_page = node
		.client()
		.call_vote_staples_after_page(&mut store, client, &cursor, Some(5))
		.await?
		.map_err(coded)?;
	assert!(staples_page.len() <= 5, "vote-staples-after-page must honor the limit");
	let staples_all = node
		.client()
		.call_vote_staples_after(&mut store, client, &cursor)
		.await?
		.map_err(coded)?;
	assert!(staples_all.len() >= staples_page.len(), "the unpaged staples must include at least the page");

	let first_staple = history_first.first().map(|entry| &entry.staple);
	assert_eq!(first_staple, history.first().map(|entry| &entry.staple), "the first history page must match the head");

	// `chain-all` / `history-all` walk the node's cursor to exhaustion: even
	// with a page limit of 1 they must cover the full chain/history.
	let chain_all = node
		.client()
		.call_chain_all(&mut store, client, trusted_account, 1)
		.await?
		.map_err(coded)?;
	assert_eq!(chain_all.first(), chain.first(), "chain-all must start at the chain head");
	assert!(chain_all.len() >= chain.len(), "chain-all must cover at least the unpaged chain");

	let history_all = node
		.client()
		.call_history_all(&mut store, client, trusted_account, 1)
		.await?
		.map_err(coded)?;
	assert!(history_all.len() >= history.len(), "history-all must cover at least the unpaged history");

	// Single-rep topology: heads trivially agree, so there is nothing to sync;
	// a settled account has nothing pending to recover.
	let synced = node
		.client()
		.call_sync_account(&mut store, client, trusted_account, false)
		.await?
		.map_err(coded)?;
	assert!(synced.is_none(), "a single-rep client must have nothing to sync");
	let recovered = node
		.client()
		.call_recover_account(&mut store, client, trusted_account, false)
		.await?
		.map_err(coded)?;
	assert!(recovered.is_none(), "a settled account must have nothing to recover");

	// The user-client mirrors of the new reads, scoped to the operating account.
	let user_chain_all = node
		.user_client()
		.call_chain_all(&mut store, user, 1)
		.await?
		.map_err(coded)?;
	assert_eq!(user_chain_all, chain_all, "the user-client chain-all must match the node-client chain-all");

	let user_history_page = node
		.user_client()
		.call_history_page(&mut store, user, &history_query)
		.await?
		.map_err(coded)?;
	assert!(user_history_page.len() <= 1, "the user-client history-page must honor the limit");

	let user_history_all = node
		.user_client()
		.call_history_all(&mut store, user, 1)
		.await?
		.map_err(coded)?;
	assert_eq!(
		user_history_all.len(),
		history_all.len(),
		"the user-client history-all must match the node-client history-all"
	);

	let user_head_block = node
		.user_client()
		.call_block(&mut store, user, &head_hash, None)
		.await?
		.map_err(coded)?;
	assert_eq!(user_head_block.as_ref(), chain.first(), "the user-client block lookup must return the head block");

	let user_idempotent = node
		.user_client()
		.call_block_from_idempotent(&mut store, user, "no-such-key", None)
		.await?
		.map_err(coded)?;
	assert!(user_idempotent.is_none(), "an unknown idempotency key must resolve to no block");

	let user_idempotent_both = node
		.user_client()
		.call_block_from_idempotent(&mut store, user, "no-such-key", Some(LedgerSide::Both))
		.await?
		.map_err(coded)?;
	assert!(user_idempotent_both.is_none(), "an unknown idempotency key must resolve to no block on both ledgers");

	// The operating account's own history, filtered for itself, must name it
	// in at least one operation (the genesis supply moves through it).
	let history_staples: Vec<String> = history.iter().map(|entry| entry.staple.clone()).collect();
	let staple_effects = node
		.user_client()
		.call_staple_effects(&mut store, user, &history_staples)
		.await?
		.map_err(coded)?;
	assert_eq!(staple_effects.len(), history_staples.len(), "every staple must be keyed in the effects list");

	let named_operations: usize = staple_effects
		.iter()
		.flat_map(|effects| &effects.blocks)
		.map(|block| block.operation_indexes.len())
		.sum();
	assert!(named_operations > 0, "the operating account's history must carry operations involving it");

	// Genesis grants the trusted account ACLs as principal on the base token
	// and network address, so the principal view must be non-empty, scoped
	// to the operating account, and agree with the node-client read.
	let user_acls = node
		.user_client()
		.call_acls(&mut store, user)
		.await?
		.map_err(coded)?;
	assert!(!user_acls.is_empty(), "the genesis account must hold ACLs as principal after network init");
	let scoped_as_principal = user_acls
		.iter()
		.all(|acl| acl.principal.as_deref() == Some(trusted.as_str()));
	assert!(scoped_as_principal, "every principal-scoped ACL must name the operating account as principal");
	let grants_base_token = user_acls
		.iter()
		.any(|acl| acl.entity.as_deref() == Some(base_token.as_str()));
	assert!(grants_base_token, "the genesis grants must include the base token as entity");
	let node_acls = node
		.client()
		.call_acls_by_principal(&mut store, client, trusted_account)
		.await?
		.map_err(coded)?;
	assert_eq!(user_acls.len(), node_acls.len(), "the user-client ACLs must match the node-client ACLs");

	// The entity view keys rows under the operating account. It must be scoped
	// to it and agree with the node-client read of the same entity.
	let user_entity_acls = node
		.user_client()
		.call_acls_by_entity(&mut store, user)
		.await?
		.map_err(coded)?;
	let scoped_as_entity = user_entity_acls
		.iter()
		.all(|acl| acl.entity.as_deref() == Some(trusted.as_str()));
	assert!(scoped_as_entity, "every entity-scoped ACL must name the operating account as entity");
	let node_entity_acls = node
		.client()
		.call_acls_by_entity(&mut store, client, trusted_account)
		.await?
		.map_err(coded)?;
	assert_eq!(
		user_entity_acls.len(),
		node_entity_acls.len(),
		"the user-client entity ACLs must match the node-client entity ACLs"
	);

	let user_certificates = node
		.user_client()
		.call_certificates(&mut store, user)
		.await?
		.map_err(coded)?;
	assert!(user_certificates.is_empty(), "a fresh account must hold no certificates");
	let user_certificate = node
		.user_client()
		.call_certificate(&mut store, user, &"00".repeat(32))
		.await?
		.map_err(coded)?;
	assert!(user_certificate.is_none(), "an unknown certificate hash must resolve to none");

	let user_synced = node
		.user_client()
		.call_sync(&mut store, user, false)
		.await?
		.map_err(coded)?;
	assert!(user_synced.is_none(), "a single-rep user-client must have nothing to sync");
	let user_recovered = node
		.user_client()
		.call_recover(&mut store, user, false)
		.await?
		.map_err(coded)?;
	assert!(user_recovered.is_none(), "a settled operating account must have nothing to recover");

	harness.shutdown()?;
	Ok(())
}

#[tokio::test]
async fn p2_writes_against_e2e_node() -> wasmtime::Result<()> {
	let mut harness = E2eNode::start()?;
	let api = ready_field(&harness, "api");
	let representative = ready_field(&harness, "representative");
	let base_token = ready_field(&harness, "baseToken");
	let network = ready_field(&harness, "network");

	// Fund the trusted signer so it can originate transactions.
	const SUPPLY: u128 = 1_000_000;
	const SEND: u128 = 1_000;
	const MINT: u128 = 500;
	harness.request("init_supply", serde_json::json!({ "amount": SUPPLY.to_string() }))?;

	let (mut store, bindings) = instantiate().await?;
	let node = bindings.keeta_client_node();

	// Typed account resources for the harness's textual addresses.
	let representative_account = account_from_address(&mut store, &bindings, &representative).await?;
	let base_token_account = account_from_address(&mut store, &bindings, &base_token).await?;

	// Bind a signing client to the trusted (genesis) seed; it is its own
	// operating account.
	let trusted_account = account_from_seed(&mut store, &bindings, &trusted_seed(), 0).await?;
	let user = node
		.user_client()
		.call_with_account(&mut store, &api, trusted_account, &network)
		.await?
		.map_err(coded)?;
	let before = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;
	assert_eq!(before, SUPPLY.to_string(), "the signer must start with the minted supply");

	// `send`: builds, signs, votes, staples, and publishes over wasi:http. The
	// sender's settled balance drops by exactly the amount (no fee configured).
	let sent = node
		.user_client()
		.call_send(&mut store, user, representative_account, base_token_account, &SEND.to_string())
		.await?
		.map_err(coded)?;
	assert!(sent, "the send must be accepted");

	let after = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;
	assert_eq!(after, (SUPPLY - SEND).to_string(), "the sender balance must drop by the sent amount");

	// `send-external`: a send carrying external reference data, never
	// aggregated; it must move value just like a plain send.
	let sent_external = node
		.user_client()
		.call_send_external(
			&mut store,
			user,
			representative_account,
			base_token_account,
			&SEND.to_string(),
			"invoice-42",
		)
		.await?
		.map_err(coded)?;
	assert!(sent_external, "the external send must be accepted");

	let after_external = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;
	assert_eq!(after_external, (SUPPLY - SEND - SEND).to_string(), "the external send must drop the balance again");

	// `set-rep` must take effect in the operating account's state.
	let set_rep = node
		.user_client()
		.call_set_rep(&mut store, user, representative_account)
		.await?
		.map_err(coded)?;
	assert!(set_rep, "the set-rep must be accepted");

	let state = node
		.user_client()
		.call_state(&mut store, user)
		.await?
		.map_err(coded)?;
	assert_eq!(
		state.representative.as_deref(),
		Some(representative.as_str()),
		"set-rep must update the representative"
	);

	// `set-info` must be reflected in the operating account's info.
	let set_info = node
		.user_client()
		.call_set_info(&mut store, user, Some("WASI"), None, None)
		.await?
		.map_err(coded)?;
	assert!(set_info, "the set-info must be accepted");

	let state = node
		.user_client()
		.call_state(&mut store, user)
		.await?
		.map_err(coded)?;
	let name = state.info.and_then(|info| info.name);
	assert_eq!(name.as_deref(), Some("WASI"), "set-info must update the account name");

	// `modify-token`: the trusted account is the base-token admin, so it can mint
	// additional supply.
	let client = node.client().call_constructor(&mut store, &api).await?;
	let supply_before = node
		.client()
		.call_token_supply(&mut store, client, base_token_account)
		.await?
		.map_err(coded)?;
	let minted = node
		.user_client()
		.call_modify_token(&mut store, user, base_token_account, None, &MINT.to_string(), AdjustMethod::Add)
		.await?
		.map_err(coded)?;
	assert!(minted, "the supply mint must be accepted");

	let supply_after = node
		.client()
		.call_token_supply(&mut store, client, base_token_account)
		.await?
		.map_err(coded)?;
	let supply_after_value = supply_after
		.and_then(|supply| supply.parse::<u128>().ok())
		.unwrap_or_default();
	let supply_before_value = supply_before
		.and_then(|supply| supply.parse::<u128>().ok())
		.unwrap_or_default();
	let delta = supply_after_value - supply_before_value;
	assert_eq!(delta, MINT, "token supply must grow by the minted amount");

	// Multi-op transaction: two operations (set-info + send) must seal into
	// exactly one block, proving atomic multi-operation transactions.
	let chain_before = node
		.user_client()
		.call_chain(&mut store, user)
		.await?
		.map_err(coded)?;
	let balance_before_tx = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;

	let tx = node
		.user_client()
		.call_begin(&mut store, user)
		.await?
		.map_err(coded)?;
	node.transaction()
		.call_set_info(&mut store, tx, Some("ATOMIC"), None, None)
		.await?
		.map_err(coded)?;
	node.transaction()
		.call_send(&mut store, tx, representative_account, base_token_account, &SEND.to_string())
		.await?
		.map_err(coded)?;
	let published = node
		.transaction()
		.call_commit(&mut store, tx)
		.await?
		.map_err(coded)?;
	assert_eq!(published.len(), 1, "a multi-op transaction must seal exactly one block");

	let chain_after = node
		.user_client()
		.call_chain(&mut store, user)
		.await?
		.map_err(coded)?;
	assert_eq!(chain_after.len(), chain_before.len() + 1, "two operations must advance the chain by exactly one block");
	assert_eq!(chain_after.first(), published.first(), "the published block must be the new chain head");

	let state = node
		.user_client()
		.call_state(&mut store, user)
		.await?
		.map_err(coded)?;
	let name = state.info.and_then(|info| info.name);
	assert_eq!(name.as_deref(), Some("ATOMIC"), "the atomic set-info must apply");

	let balance_after_tx = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;
	let expected = balance_before_tx.parse::<u128>().unwrap_or_default() - SEND;
	assert_eq!(balance_after_tx, expected.to_string(), "the atomic send must drop the balance by the sent amount");

	// `update-permissions`: grant a flag to the representative, then read it back
	// via the ACL surface.
	let granted = node
		.user_client()
		.call_update_permissions(
			&mut store,
			user,
			representative_account,
			AdjustMethod::Add,
			BasePermission::ACCESS,
			None,
		)
		.await?
		.map_err(coded)?;
	assert!(granted, "the permission grant must be accepted");
	let acls = node
		.client()
		.call_acls_by_principal(&mut store, client, representative_account)
		.await?
		.map_err(coded)?;
	let lists_representative = acls
		.iter()
		.any(|acl| acl.principal.as_deref() == Some(representative.as_str()));
	assert!(lists_representative, "the granted ACL must list the representative as principal");

	// `generate-multisig`: create a 1-of-2 multisig identifier on-chain.
	let multisig = node
		.user_client()
		.call_generate_multisig(&mut store, user, &[trusted_account, representative_account], 1)
		.await?
		.map_err(coded)?;
	assert!(!multisig.is_empty(), "the multisig identifier address must be returned");

	// `create-swap`: build (without publishing) a base-token-for-base-token
	// offer to the representative; it must yield a single offer block.
	let offer = node
		.user_client()
		.call_create_swap(
			&mut store,
			user,
			representative_account,
			base_token_account,
			&SEND.to_string(),
			base_token_account,
			&SEND.to_string(),
			false,
		)
		.await?
		.map_err(coded)?;
	assert!(!offer.is_empty(), "the swap offer block must be returned");

	// `accept-swap`: a self-directed offer (counterparty is the operating
	// account) must accept into the taker's and maker's settlement blocks.
	let self_offer = node
		.user_client()
		.call_create_swap(
			&mut store,
			user,
			trusted_account,
			base_token_account,
			&SEND.to_string(),
			base_token_account,
			&SEND.to_string(),
			true,
		)
		.await?
		.map_err(coded)?;
	let settlement = node
		.user_client()
		.call_accept_swap(&mut store, user, &self_offer, None)
		.await?
		.map_err(coded)?;
	assert!(!settlement.is_empty(), "accepting a swap must yield settlement blocks");

	// `add-certificate` / `remove-certificate`: malformed inputs must surface a
	// coded error rather than panic, proving the certificate path is wired.
	let bad_add = node
		.user_client()
		.call_add_certificate(&mut store, user, "zz", &[])
		.await?;
	assert!(bad_add.is_err(), "a non-hex certificate must be rejected with a coded error");

	let bad_remove = node
		.user_client()
		.call_remove_certificate(&mut store, user, &"abcd".to_string())
		.await?;
	assert!(bad_remove.is_err(), "a malformed certificate hash must be rejected with a coded error");

	// True two-party swap settlement: a distinct, funded taker validates the
	// maker's offer, appends its matching leg, and transmits both blocks as one
	// staple so neither settles alone.
	const SWAP_SEND: u128 = 400; // maker -> taker
	const SWAP_RECV: u128 = 150; // taker -> maker
	const FUND: u128 = 1_000; // seed the taker so it can pay its leg
	let taker_account = account_from_seed(&mut store, &bindings, &"55".repeat(32), 0).await?;
	let taker = node
		.user_client()
		.call_with_account(&mut store, &api, taker_account, &network)
		.await?
		.map_err(coded)?;
	node.user_client()
		.call_send(&mut store, user, taker_account, base_token_account, &FUND.to_string())
		.await?
		.map_err(coded)?;

	let maker_before = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;
	let taker_before = node
		.user_client()
		.call_balance(&mut store, taker, base_token_account)
		.await?
		.map_err(coded)?;

	let offer = node
		.user_client()
		.call_create_swap(
			&mut store,
			user,
			taker_account,
			base_token_account,
			&SWAP_SEND.to_string(),
			base_token_account,
			&SWAP_RECV.to_string(),
			true,
		)
		.await?
		.map_err(coded)?;
	let settlement = node
		.user_client()
		.call_accept_swap(&mut store, taker, &offer, None)
		.await?
		.map_err(coded)?;
	assert_eq!(settlement.len(), 2, "settlement must carry the taker's and maker's blocks");
	let settled = node
		.user_client()
		.call_transmit(&mut store, taker, &settlement)
		.await?
		.map_err(coded)?;
	assert!(settled, "the two-party swap must settle atomically");

	let maker_after = node
		.user_client()
		.call_balance(&mut store, user, base_token_account)
		.await?
		.map_err(coded)?;
	let taker_after = node
		.user_client()
		.call_balance(&mut store, taker, base_token_account)
		.await?
		.map_err(coded)?;
	let maker_before_value = maker_before.parse::<u128>().unwrap_or_default();
	let taker_before_value = taker_before.parse::<u128>().unwrap_or_default();
	// Both legs settle in the one staple
	assert_eq!(
		maker_after,
		(maker_before_value - SWAP_SEND + SWAP_RECV).to_string(),
		"the maker must net receive minus send"
	);
	assert_eq!(
		taker_after,
		(taker_before_value + SWAP_SEND - SWAP_RECV).to_string(),
		"the taker must net send minus receive"
	);

	harness.shutdown()?;
	Ok(())
}

/// Port of `accounts-multisig-signer.ts`: proves the low-level P2 surface the
/// high-level builder cannot reach — `derive-identifier`, generic
/// `generate-identifier`, and a `block-builder` block signed by a 2-of-3
/// `Signer::Multisig` that the node accepts on-chain.
#[tokio::test]
async fn p2_multisig_signer_against_e2e_node() -> wasmtime::Result<()> {
	let mut harness = E2eNode::start()?;
	let api = ready_field(&harness, "api");
	let network = ready_field(&harness, "network");

	// Give the node live ledger state to read; the harness charges no fee.
	harness.request("init_supply", serde_json::json!({ "amount": "1000000" }))?;

	let (mut store, bindings) = instantiate().await?;
	let node = bindings.keeta_client_node();
	let client = node.client().call_constructor(&mut store, &api).await?;

	// The component has no ambient clock; the host stamps each block.
	let now_millis = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_millis() as i64)
		.unwrap_or_default();

	let seed = "33".repeat(32);
	let account0 = account_from_seed(&mut store, &bindings, &seed, 0).await?;

	let user = node
		.user_client()
		.call_with_account(&mut store, &api, account0, &network)
		.await?
		.map_err(coded)?;
	let user_address = node
		.user_client()
		.call_address(&mut store, user)
		.await?
		.map_err(coded)?;
	let user_account = account_from_address(&mut store, &bindings, &user_address).await?;

	// Fund the user so it has a settled balance and a head to chain onto.
	let base_token = ready_field(&harness, "baseToken");
	let base_token_account = account_from_address(&mut store, &bindings, &base_token).await?;
	let trusted_account = account_from_seed(&mut store, &bindings, &trusted_seed(), 0).await?;
	let funder = node
		.user_client()
		.call_with_account(&mut store, &api, trusted_account, &network)
		.await?
		.map_err(coded)?;
	let funded = node
		.user_client()
		.call_send(&mut store, funder, user_account, base_token_account, &"1000".to_string())
		.await?
		.map_err(coded)?;
	assert!(funded, "the user funding send must settle");

	let mut signer_accounts = Vec::new();
	for index in 1..=3u32 {
		let account = account_from_seed(&mut store, &bindings, &seed, index).await?;
		signer_accounts.push(account);
	}

	// Local, deterministic multisig address (kind MULTISIG, op index 0).
	let multisig = node
		.call_derive_identifier(&mut store, account0, IdentifierKind::Multisig, None, 0)
		.await?
		.map_err(coded)?;
	assert!(!multisig.is_empty(), "the multisig identifier address must derive");
	let multisig_account = account_from_address(&mut store, &bindings, &multisig).await?;

	// User block: create the 2-of-3 multisig and grant it ADMIN over the user.
	let user_head = node
		.client()
		.call_account_state(&mut store, client, user_account)
		.await?
		.map_err(coded)?
		.head;
	let identifier_block = {
		let builder = node
			.block_builder()
			.call_new(&mut store, &network, user_account)
			.await?
			.map_err(coded)?;
		match &user_head {
			Some(head) => node
				.block_builder()
				.call_previous(&mut store, builder, head)
				.await?
				.map_err(coded)?,
			None => node
				.block_builder()
				.call_opening(&mut store, builder)
				.await?
				.map_err(coded)?,
		}
		node.block_builder()
			.call_date(&mut store, builder, now_millis)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_op_create_multisig(&mut store, builder, multisig_account, &signer_accounts, 2)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_op_modify_permissions(
				&mut store,
				builder,
				multisig_account,
				BasePermission::ADMIN,
				AdjustMethod::Set,
				None,
			)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_signer_single(&mut store, builder, account0)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_build_and_sign(&mut store, builder)
			.await?
			.map_err(coded)?
	};
	let published = node
		.user_client()
		.call_transmit(&mut store, user, &[identifier_block])
		.await?
		.map_err(coded)?;
	assert!(published, "the multisig-creation block must settle");

	// Generic identifier creation; the trusted client owns the token (see fn doc).
	let custom_token = node
		.user_client()
		.call_generate_identifier(&mut store, funder, IdentifierKind::Token)
		.await?
		.map_err(coded)?;
	assert!(!custom_token.is_empty(), "the custom token address must be returned");
	let custom_token_account = account_from_address(&mut store, &bindings, &custom_token).await?;

	// Grant the multisig ADMIN on the token's own chain (the entity whose ACL
	// changes), signed by the trusted creator.
	let grant_block = {
		let builder = node
			.block_builder()
			.call_new(&mut store, &network, custom_token_account)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_opening(&mut store, builder)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_date(&mut store, builder, now_millis)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_op_modify_permissions(
				&mut store,
				builder,
				multisig_account,
				BasePermission::ADMIN,
				AdjustMethod::Set,
				None,
			)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_signer_single(&mut store, builder, trusted_account)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_build_and_sign(&mut store, builder)
			.await?
			.map_err(coded)?
	};
	let granted = node
		.user_client()
		.call_transmit(&mut store, funder, &[grant_block])
		.await?
		.map_err(coded)?;
	assert!(granted, "the ADMIN grant on the custom token must settle");

	// The proof: SET_INFO on the token signed by a 2-of-3 quorum subset.
	let token_head = node
		.client()
		.call_account_state(&mut store, client, custom_token_account)
		.await?
		.map_err(coded)?
		.head;
	let multisig_block = {
		let builder = node
			.block_builder()
			.call_new(&mut store, &network, custom_token_account)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_version(&mut store, builder, 2)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_date(&mut store, builder, now_millis)
			.await?
			.map_err(coded)?;
		match token_head {
			Some(head) => node
				.block_builder()
				.call_previous(&mut store, builder, &head)
				.await?
				.map_err(coded)?,
			None => node
				.block_builder()
				.call_opening(&mut store, builder)
				.await?
				.map_err(coded)?,
		}
		node.block_builder()
			.call_op_set_info(
				&mut store,
				builder,
				"TKNM",
				"Test Multisig Token Example",
				"eyJkZWNpbWFsUGxhY2VzIjo2fQ==",
				Some(BasePermission::ACCESS),
			)
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_signer_multisig(&mut store, builder, multisig_account, &[signer_accounts[0], signer_accounts[1]])
			.await?
			.map_err(coded)?;
		node.block_builder()
			.call_build_and_sign(&mut store, builder)
			.await?
			.map_err(coded)?
	};
	let settled = node
		.user_client()
		.call_transmit(&mut store, funder, std::slice::from_ref(&multisig_block))
		.await?
		.map_err(coded)?;
	assert!(settled, "the 2-of-3 multisig-signed token block must settle");

	// The node accepted a multisig-signed block: it set the info and is the head.
	let token_state = node
		.client()
		.call_account_state(&mut store, client, custom_token_account)
		.await?
		.map_err(coded)?;
	let token_name = token_state.info.and_then(|info| info.name);
	assert_eq!(token_name.as_deref(), Some("TKNM"), "the multisig-signed SET_INFO must apply to the token");

	let token_head_block = node
		.client()
		.call_head_block(&mut store, client, custom_token_account)
		.await?
		.map_err(coded)?;
	assert_eq!(token_head_block.as_ref(), Some(&multisig_block), "the multisig-signed block must be the token's head");

	harness.shutdown()?;
	Ok(())
}
