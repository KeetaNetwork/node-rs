//! End-to-end tests driving [`KeetaClient`] against a live reference node.
//!
//! The TypeScript harness boots an in-memory reference node and reports its
//! REST API URL; the Rust client then exercises the API over HTTP.

use core::future::Future;
use core::pin::Pin;
use core::str::FromStr;
use core::time::Duration;
use std::sync::Arc;

use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_block::{AccountRef, Amount, Block, Hashable};
use keetanetwork_client::{
	ClientConfig, ClientError, InitializeNetwork, KeetaClient, KeetaNetError, NodeErrorType, RepEndpoint,
	TransmitOptions, UserClient,
};
use keetanetwork_utils::node_harness::E2eNode;
use num_bigint::BigInt;
use serde_json::{json, Value};

/// Base-token supply minted to the trusted account by the fixture.
const MINTED_SUPPLY: u64 = 1_000_000_000;

/// Send amount the fixture transfers from the trusted account.
const SEND_AMOUNT: u64 = 1_000;

/// Seed byte the harness uses for the trusted account (`Buffer.alloc(32,
/// 0x77)`); deriving from it client-side reproduces the trusted signer.
const TRUSTED_SEED_BYTE: u8 = 0x77;

/// Seed byte the harness uses for the representative account (`Buffer.alloc(32,
/// 0x5a)`); it doubles as the send recipient.
const REP_SEED_BYTE: u8 = 0x5a;

/// A booted reference node funded with an unpublished send block, paired with
/// a client bound to its API. The node is shut down when the fixture drops.
struct Fixture {
	node: E2eNode,
	client: KeetaClient,
	trusted: String,
	base_token: String,
	blocks: Vec<Block>,
}

impl Fixture {
	/// The recipient (representative) account from the ready payload.
	fn recipient(&self) -> String {
		ready_field(&self.node, "representative")
	}

	/// The trusted account's current head block hash, via the harness.
	fn head_hash(&mut self) -> String {
		let head = self
			.node
			.request("head", json!({ "account": self.trusted }))
			.expect("the head query must succeed");

		head["head"]
			.as_str()
			.expect("the head response must carry a hash")
			.to_string()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		// Best-effort graceful shutdown; `E2eNode`'s own `Drop` reaps the child.
		let _ = self.node.request("shutdown", json!({}));
	}
}

/// A fixture whose send block has been published, with its head captured for
/// round-trip assertions.
struct Published {
	fixture: Fixture,
	head: Block,
	head_hash: String,
}

/// The future a probe produces
type CaseError = Box<dyn core::error::Error>;
type CaseFuture<'a> = Pin<Box<dyn Future<Output = Result<(), CaseError>> + 'a>>;

/// A probe body: a higher-ranked closure over a borrowed context `C`.
type CaseRun<C> = Box<dyn for<'a> Fn(&'a C) -> CaseFuture<'a>>;

/// A named, self-asserting probe over a shared context `C`.
struct Case<C> {
	name: &'static str,
	run: CaseRun<C>,
}

/// Build a [`Case`] from a name and an async block over the context binding.
///
/// The closure parameter is annotated `&Ctx`, a type alias each test defines,
/// so the higher-ranked closure type can be inferred.
macro_rules! case {
	($name:expr, |$ctx:ident| $body:block) => {
		Case { name: $name, run: Box::new(|$ctx: &Ctx| Box::pin(async move $body)) }
	};
}

/// Run every probe against `ctx`, accumulating failures so a single bad probe
/// does not mask the rest.
async fn run_cases<C>(ctx: &C, cases: Vec<Case<C>>) {
	let mut failures = Vec::new();

	for case in &cases {
		if let Err(reason) = (case.run)(ctx).await {
			failures.push(format!("{}: {reason}", case.name));
		}
	}

	assert!(failures.is_empty(), "probe failures:\n{}", failures.join("\n"));
}

/// Require a boolean condition, yielding `reason` on failure.
fn require(condition: bool, reason: impl Into<CaseError>) -> Result<(), CaseError> {
	condition.then_some(()).ok_or_else(|| reason.into())
}

/// Read a required string field from the harness ready payload.
fn ready_field(node: &E2eNode, field: &str) -> String {
	node.info()
		.get(field)
		.and_then(Value::as_str)
		.unwrap_or_else(|| panic!("ready event must include `{field}`"))
		.to_string()
}

/// The signing accounts every test derives client-side from the harness's
/// deterministic seeds: the trusted (genesis) signer, the send recipient, and
/// the base-token identifier.
struct SigningAccounts {
	trusted: AccountRef,
	recipient: AccountRef,
	token: AccountRef,
}

/// Derive the [`SigningAccounts`] for a harness whose base token is `base_token`.
fn signing_accounts(base_token: &str) -> Result<SigningAccounts, Box<dyn core::error::Error>> {
	Ok(SigningAccounts {
		trusted: generate_ed25519_ref(TRUSTED_SEED_BYTE),
		recipient: generate_ed25519_ref(REP_SEED_BYTE),
		token: Arc::new(GenericAccount::from_str(base_token)?),
	})
}

/// Boot a node, fund the trusted account, and build+sign (without publishing)
/// a send block natively in Rust for the client to transmit.
///
/// The signing accounts are derived client-side from the harness's
/// deterministic seeds; asserting they match the node's reported addresses is
/// the interop anchor proving the blocks are genuinely client-built.
async fn fixture() -> Fixture {
	let mut node = E2eNode::start().expect("the reference node harness must start");

	let network = BigInt::from_str(&ready_field(&node, "network")).expect("the network id must parse");
	let client = KeetaClient::new(ready_field(&node, "api")).with_network(network);
	let recipient = ready_field(&node, "representative");
	let trusted = ready_field(&node, "trusted");
	let base_token = ready_field(&node, "baseToken");

	node.request("init_supply", json!({ "amount": MINTED_SUPPLY.to_string() }))
		.expect("the trusted account must be funded");

	let accounts = signing_accounts(&base_token).expect("the signing accounts must derive");
	assert_eq!(accounts.trusted.to_string(), trusted, "the derived trusted signer must match the node address");
	assert_eq!(accounts.recipient.to_string(), recipient, "the derived recipient must match the node address");

	let block = send_block(&client, &accounts, &accounts.recipient, SEND_AMOUNT)
		.await
		.expect("the client must build and sign a send block");

	Fixture { node, client, trusted, base_token, blocks: vec![block] }
}

/// Boot a fixture and publish its send block, capturing the resulting head.
async fn published() -> Published {
	let mut fixture = fixture().await;

	let accepted = fixture
		.client
		.transmit(&fixture.blocks, TransmitOptions::default())
		.await
		.expect("the transmit path must publish the staple");
	assert!(accepted, "the node must accept the published staple");

	let head = fixture
		.client
		.head_block(&fixture.trusted)
		.await
		.expect("the head query must succeed")
		.expect("the trusted account head must advance once the send is published");
	let head_hash = fixture.head_hash();

	Published { fixture, head, head_hash }
}

/// Read-only queries against a single freshly funded fixture.
#[tokio::test(flavor = "multi_thread")]
async fn test_read_only_queries() {
	type Ctx = Fixture;

	let fixture = fixture().await;

	let cases = vec![
		case!("node version is reported", |fx| {
			let version = fx.client.node_version().await?;
			require(!version.is_empty(), "version is empty")
		}),
		case!("balance reflects minted supply", |fx| {
			let balance = fx.client.balance(&fx.trusted, &fx.base_token).await?;
			require(balance == Amount::from(MINTED_SUPPLY), format!("got {balance:?}"))
		}),
		case!("balances include the base token", |fx| {
			let balances = fx.client.balances(&fx.trusted).await?;
			let base = balances.iter().find(|entry| entry.token == fx.base_token);
			require(
				base.is_some_and(|entry| entry.balance == Amount::from(MINTED_SUPPLY)),
				"base token balance mismatch",
			)
		}),
		case!("account state reports representative, head and balances", |fx| {
			let state = fx.client.state(&fx.trusted).await?;
			require(state.representative.as_deref() == Some(fx.recipient().as_str()), "representative mismatch")?;
			require(state.head.is_some(), "missing head block")?;
			let base = state
				.balances
				.iter()
				.find(|entry| entry.token == fx.base_token);
			require(base.is_some_and(|entry| entry.balance == Amount::from(MINTED_SUPPLY)), "base balance mismatch")
		}),
		case!("base token reports its minted supply", |fx| {
			let supply = fx.client.token_supply(&fx.base_token).await?;
			require(supply == Some(Amount::from(MINTED_SUPPLY)), format!("got {supply:?}"))
		}),
		case!("non-token account reports no supply", |fx| {
			let supply = fx.client.token_supply(&fx.trusted).await?;
			require(supply.is_none(), format!("unexpected supply {supply:?} for a non-token account"))
		}),
		case!("node stats is an object", |fx| {
			let stats = fx.client.node_stats().await?;
			require(stats.is_object(), "stats not an object")
		}),
		case!("peers is an object", |fx| {
			let peers = fx.client.node_peers().await?;
			require(peers.is_object(), "peers not an object")
		}),
		case!("ledger checksum carries a moment", |fx| {
			let checksum = fx.client.ledger_checksum().await?;
			require(checksum.moment.is_some(), "missing moment")
		}),
		case!("node representative matches ready payload", |fx| {
			let rep = fx.client.node_representative().await?;
			require(rep.account == fx.recipient(), "representative mismatch")
		}),
		case!("representative lookup echoes the account", |fx| {
			let rep = fx.client.representative(fx.recipient()).await?;
			require(rep.account == fx.recipient(), "representative mismatch")
		}),
		case!("representative set includes the node rep", |fx| {
			let all = fx.client.representatives().await?;
			require(all.iter().any(|rep| rep.account == fx.recipient()), "node rep absent")
		}),
		case!("principal ACLs carry permission bitmaps", |fx| {
			let acls = fx.client.acls_by_principal(&fx.trusted).await?;
			require(!acls.is_empty(), "no principal ACLs")?;
			require(acls.iter().all(|acl| !acl.permissions.is_empty()), "empty permissions")
		}),
		case!("granted ACL query succeeds", |fx| {
			fx.client.acls_by_entity(&fx.trusted).await?;
			Ok(())
		}),
		case!("additional ACL aggregate is an object", |fx| {
			let additional = fx.client.acls_by_principal_with_info(&fx.trusted).await?;
			require(additional.is_object(), "aggregate not an object")
		}),
		case!("vote covers at least one block", |fx| {
			let vote = fx.client.request_vote(&fx.blocks).await?;
			require(!vote.blocks().is_empty(), "vote covers no blocks")
		}),
		case!("quote query succeeds", |fx| {
			fx.client.request_quote(&fx.blocks).await?;
			Ok(())
		}),
		case!("batch account states return one entry per account", |fx| {
			let recipient = fx.recipient();
			let states = fx.client.states(&[&fx.trusted, &recipient]).await?;
			require(states.len() == 2, format!("got {} states", states.len()))?;
			require(states[0].representative.is_some(), "missing representative")
		}),
		case!("unknown block hash resolves to none", |fx| {
			let block = fx.client.block("0".repeat(64)).await?;
			require(block.is_none(), "unexpected block")
		}),
		case!("unknown idempotent key resolves to none", |fx| {
			let block = fx
				.client
				.block_by_idempotent(&fx.trusted, "unknown-idempotent-key")
				.await?;
			require(block.is_none(), "unexpected block")
		}),
		case!("unknown certificate hash resolves to none", |fx| {
			let certificate = fx.client.certificate(&fx.trusted, "0".repeat(64)).await?;
			require(certificate.is_none(), "unexpected certificate")
		}),
	];

	run_cases(&fixture, cases).await;
}

/// `getAccountPendingBlock` returns the side-ledger successor of the head.
///
/// This runs on a pristine fixture because requesting a vote stages the block
/// into the side ledger, which would otherwise leave a pending successor.
#[tokio::test(flavor = "multi_thread")]
async fn test_pending_block_absent_is_none() -> Result<(), Box<dyn core::error::Error>> {
	let fixture = fixture().await;

	let pending = fixture.client.pending_block(&fixture.trusted).await?;
	assert!(pending.is_none(), "an account with no staged side block must have no pending block");

	Ok(())
}

/// Queries that require a published send block, run against one shared fixture.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_transmit_queries() {
	type Ctx = Published;

	let context = published().await;

	let cases = vec![
		case!("trusted balance drops by the sent amount", |ctx| {
			let balance = ctx
				.fixture
				.client
				.balance(&ctx.fixture.trusted, &ctx.fixture.base_token)
				.await?;
			require(balance == Amount::from(MINTED_SUPPLY - SEND_AMOUNT), format!("got {balance:?}"))
		}),
		case!("chain contains blocks after the send", |ctx| {
			let chain = ctx.fixture.client.chain(&ctx.fixture.trusted).await?;
			require(!chain.is_empty(), "empty chain")
		}),
		case!("account history contains a staple after the send", |ctx| {
			let history = ctx.fixture.client.history(&ctx.fixture.trusted).await?;
			require(!history.is_empty(), "empty history")
		}),
		case!("global history contains a staple after the send", |ctx| {
			let history = ctx.fixture.client.global_history().await?;
			require(!history.is_empty(), "empty global history")
		}),
		case!("vote staples after the epoch include the staple", |ctx| {
			let staples = ctx
				.fixture
				.client
				.vote_staples_after("1970-01-01T00:00:00.000Z")
				.await?;
			require(!staples.is_empty(), "no staples")
		}),
		case!("head block round-trips by hash", |ctx| {
			let fetched = ctx
				.fixture
				.client
				.block(&ctx.head_hash)
				.await?
				.ok_or("head block not retrievable by hash")?;
			require(fetched.to_bytes() == ctx.head.to_bytes(), "block bytes mismatch")
		}),
		case!("account head info reports the head block and a nonzero height", |ctx| {
			let (block, height) = ctx
				.fixture
				.client
				.account_head_info(&ctx.fixture.trusted)
				.await?
				.ok_or("account head info must be present once the send is published")?;
			require(block.hash().to_string() == ctx.head_hash, "head info block mismatch")?;
			require(*height.as_bigint() > BigInt::from(0u8), format!("unexpected height {height:?}"))
		}),
		case!("vote staple round-trips by head hash", |ctx| {
			let staple = ctx
				.fixture
				.client
				.vote_staple(&ctx.head_hash)
				.await?
				.ok_or("a vote staple must be retrievable for the published head")?;
			require(
				staple
					.blocks()
					.iter()
					.any(|block| block.hash().to_string() == ctx.head_hash),
				"the vote staple must contain the head block",
			)
		}),
		case!("head block has no successor", |ctx| {
			let successor = ctx.fixture.client.successor_block(&ctx.head_hash).await?;
			require(successor.is_none(), "unexpected successor")
		}),
		case!("block votes endpoint returns the head's votes", |ctx| {
			let response = ctx
				.fixture
				.client
				.transport()
				.get_block_votes(&ctx.head_hash, None)
				.await?;
			let votes = response
				.into_inner()
				.votes
				.ok_or("no votes for the published head")?;
			require(!votes.is_empty(), "empty vote list")?;
			require(votes.iter().all(|vote| vote.binary.is_some()), "vote missing binary")
		}),
		case!("auto-paged chain returns the published blocks", |ctx| {
			let chain = ctx
				.fixture
				.client
				.chain_all(&ctx.fixture.trusted, 1)
				.await?;
			require(!chain.is_empty(), "empty auto-paged chain")
		}),
		case!("sync is a ignored when the only rep is in sync", |ctx| {
			let account: AccountRef = Arc::new(GenericAccount::from_str(&ctx.fixture.trusted)?);
			let synced = ctx.fixture.client.sync_account(&account, false).await?;
			require(synced.is_none(), "single in-sync rep should not produce a sync staple")
		}),
	];

	run_cases(&context, cases).await;
}

/// A conflicting second vote request surfaces a typed LEDGER node error.
#[tokio::test(flavor = "multi_thread")]
async fn test_conflicting_vote_request_is_typed_node_error() -> Result<(), Box<dyn core::error::Error>> {
	let fixture = fixture().await;

	fixture.client.request_vote(&fixture.blocks).await?;

	// A second binding vote for the same predecessor must conflict, and the
	// conflict must decode to a typed LEDGER node error.
	let result = fixture.client.request_vote(&fixture.blocks).await;
	assert!(
		matches!(&result, Err(ClientError::Node { source })
			if source.node_type() == Some(NodeErrorType::Ledger)
				&& matches!(source.as_ref(), KeetaNetError::Ledger { .. } | KeetaNetError::LedgerVote { .. })),
		"a conflicting vote must surface a typed LEDGER node error, got {result:?}"
	);

	Ok(())
}

/// Flat base-token fee a fee-enforcing node charges per transaction.
const FEE_AMOUNT: u64 = 10;

/// Boot a fee-enforcing node and fund the trusted account, returning the node,
/// a network-configured client, the derived signing accounts, and base token.
fn fee_fixture() -> (E2eNode, KeetaClient, SigningAccounts, String) {
	let mut node = E2eNode::start_with_fee(FEE_AMOUNT).expect("the fee-enforcing harness must start");

	let network = BigInt::from_str(&ready_field(&node, "network")).expect("the network id must parse");
	let client = KeetaClient::new(ready_field(&node, "api")).with_network(network);
	let base_token = ready_field(&node, "baseToken");

	node.request("init_supply", json!({ "amount": MINTED_SUPPLY.to_string() }))
		.expect("the trusted account must be funded");

	let accounts = signing_accounts(&base_token).expect("the signing accounts must derive");

	(node, client, accounts, base_token)
}

/// A native send against a fee-enforcing node must originate the required fee
/// block, be accepted, and debit the sender for the amount plus the fee.
#[tokio::test(flavor = "multi_thread")]
async fn test_send_with_required_fee_is_accepted() -> Result<(), Box<dyn core::error::Error>> {
	let (_node, client, accounts, base_token) = fee_fixture();
	let before = client
		.balance(accounts.trusted.to_string(), &base_token)
		.await?;

	let quote_block = send_block(&client, &accounts, &accounts.recipient, SEND_AMOUNT).await?;
	let quotes = client.quotes(&[quote_block]).await?;
	assert!(!quotes.is_empty(), "a fee-charging node must return a vote quote for the block");

	let accepted = client
		.send(&accounts.trusted, &accounts.recipient, &accounts.token, Amount::from(SEND_AMOUNT))
		.await?;
	assert!(accepted, "the node must accept a send carrying the required fee block");

	let after = client
		.balance(accounts.trusted.to_string(), &base_token)
		.await?;
	let debited = before.as_bigint() - after.as_bigint();
	assert_eq!(
		debited,
		BigInt::from(SEND_AMOUNT + FEE_AMOUNT),
		"the sender must be debited the send amount plus the fee"
	);

	Ok(())
}

/// Transmitting a fee-bearing block through the signer-less [`transmit`] path
/// must refuse with a typed [`ClientError::FeeRequired`] rather than submit a
/// staple the node would reject for a missing fee block.
#[tokio::test(flavor = "multi_thread")]
async fn test_transmit_without_signer_when_fee_required_errors() -> Result<(), Box<dyn core::error::Error>> {
	let (_node, client, accounts, _base_token) = fee_fixture();
	let block = send_block(&client, &accounts, &accounts.recipient, SEND_AMOUNT).await?;

	let result = client.transmit(&[block], TransmitOptions::default()).await;
	assert!(
		matches!(result, Err(ClientError::FeeRequired)),
		"a fee-required transmit without a signer must surface ClientError::FeeRequired, got {result:?}"
	);

	Ok(())
}

/// Number of peered representatives the multi-rep cluster boots.
const CLUSTER_REPS: usize = 2;

/// Decode the cluster's `reps` ready-payload array into client endpoints,
/// seeding each with a placeholder weight that the first weight refresh
/// replaces with the on-ledger voting power.
fn cluster_reps(node: &E2eNode) -> Result<Vec<RepEndpoint>, Box<dyn core::error::Error>> {
	let reps = node
		.info()
		.get("reps")
		.and_then(Value::as_array)
		.ok_or("the cluster ready payload must include a reps array")?;

	let mut endpoints = Vec::with_capacity(reps.len());
	for rep in reps {
		let api = rep
			.get("api")
			.and_then(Value::as_str)
			.ok_or("a rep entry must carry an api URL")?;
		let account_str = rep
			.get("account")
			.and_then(Value::as_str)
			.ok_or("a rep entry must carry an account")?;
		let account: AccountRef = Arc::new(GenericAccount::from_str(account_str)?);
		endpoints.push(RepEndpoint::new(api, account, 1u8));
	}

	Ok(endpoints)
}

/// Poll every node's head for `account` until they all report the same hash,
/// confirming the staple published to one rep has replicated over P2P.
async fn await_convergence(node: &mut E2eNode, account: &str) -> Result<(), Box<dyn core::error::Error>> {
	for _ in 0..50 {
		let response = node.request("head_all", json!({ "account": account }))?;
		let heads = response
			.get("heads")
			.and_then(Value::as_array)
			.ok_or("head_all must report a heads array")?;

		let first = heads.first().and_then(Value::as_str);
		let converged = first.is_some() && heads.iter().all(|head| head.as_str() == first);
		if converged {
			return Ok(());
		}

		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	Err("the cluster nodes did not converge on a common head".into())
}

/// Unwrap the sole block produced by a single-account builder render.
fn one_block(mut blocks: Vec<Block>) -> Block {
	assert_eq!(blocks.len(), 1, "a single-account builder must render exactly one block");
	blocks.remove(0)
}

/// Build and sign a single SEND block of `amount` base token from the trusted
/// account to `to`.
async fn send_block(
	client: &KeetaClient,
	accounts: &SigningAccounts,
	to: &AccountRef,
	amount: u64,
) -> Result<Block, Box<dyn core::error::Error>> {
	let blocks = client
		.builder(&accounts.trusted)
		.send(to, &accounts.token, Amount::from(amount))
		.build()
		.await?;
	Ok(one_block(blocks))
}

/// Hex-encode a block's transport bytes for the harness's ledger hooks, which parse
/// Rust-built blocks back into reference `Block` instances.
fn block_hex(block: &Block) -> String {
	block
		.to_bytes()
		.iter()
		.map(|byte| format!("{byte:02X}"))
		.collect()
}

/// Stage a side-ledger vote for `block` on one node, returning the vote's transport
/// bytes (hex). An empty `prior` yields a temporary vote; passing the gathered
/// temporary votes back escalates the same node to a permanent vote.
fn side_vote(
	node: &mut E2eNode,
	index: usize,
	block: &str,
	prior: &[String],
) -> Result<String, Box<dyn core::error::Error>> {
	let response = node.request("side_vote", json!({ "node": index, "block": block, "prior": prior }))?;
	let vote = response
		.get("vote")
		.and_then(Value::as_str)
		.ok_or("side_vote must return the sealed vote")?;
	Ok(vote.to_string())
}

/// Promote a staple assembled from `votes` and `block` onto one node's main
/// ledger, leaving its peers behind so the sync path has a divergence to heal.
fn ledger_add(
	node: &mut E2eNode,
	index: usize,
	votes: &[String],
	block: &str,
) -> Result<(), Box<dyn core::error::Error>> {
	node.request("ledger_add", json!({ "node": index, "votes": votes, "block": block }))?;
	Ok(())
}

/// Every node's head hash for `account`, indexed by node position.
fn head_hashes(node: &mut E2eNode, account: &str) -> Result<Vec<String>, Box<dyn core::error::Error>> {
	let response = node.request("head_all", json!({ "account": account }))?;
	let heads = response
		.get("heads")
		.and_then(Value::as_array)
		.ok_or("head_all must report a heads array")?;

	let mut hashes = Vec::with_capacity(heads.len());
	for head in heads {
		let hash = head
			.as_str()
			.ok_or("every live node must report a head hash")?;
		hashes.push(hash.to_string());
	}

	Ok(hashes)
}

/// A booted, funded, and converged peered cluster paired with a client bound
/// to every representative, weights already refreshed from the ledger.
struct ClusterFixture {
	node: E2eNode,
	client: KeetaClient,
	trusted: String,
	base_token: String,
	rep_accounts: Vec<String>,
}

impl ClusterFixture {
	/// Boot a `reps`-node P2P cluster, bind a client to every rep, fund and
	/// converge genesis, and refresh the client's view of voting weights.
	async fn start(reps: usize) -> Result<Self, Box<dyn core::error::Error>> {
		let mut node = E2eNode::start_cluster(reps)?;

		let network = BigInt::from_str(&ready_field(&node, "network"))?;
		let trusted = ready_field(&node, "trusted");
		let base_token = ready_field(&node, "baseToken");

		let endpoints = cluster_reps(&node)?;
		assert_eq!(endpoints.len(), reps, "the cluster must report one endpoint per representative");
		let rep_accounts = endpoints
			.iter()
			.map(|rep| rep.account().to_string())
			.collect();

		let client = KeetaClient::with_representatives(endpoints, ClientConfig::default()).with_network(network);

		node.request("init_supply", json!({ "amount": MINTED_SUPPLY.to_string() }))?;
		await_convergence(&mut node, &trusted).await?;
		client.discover_representatives().await?;

		Ok(Self { node, client, trusted, base_token, rep_accounts })
	}

	/// Block until every live node agrees on the trusted account's head.
	async fn converge(&mut self) -> Result<(), Box<dyn core::error::Error>> {
		await_convergence(&mut self.node, &self.trusted).await
	}

	/// The client-derived signing accounts for this cluster's base token.
	fn accounts(&self) -> Result<SigningAccounts, Box<dyn core::error::Error>> {
		signing_accounts(&self.base_token)
	}
}

impl Drop for ClusterFixture {
	fn drop(&mut self) {
		// Best-effort graceful shutdown; `E2eNode`'s own `Drop` reaps the child.
		let _ = self.node.request("shutdown", json!({}));
	}
}

/// Stage a temporary side-ledger vote for `block` on reps `0..reps`, then
/// escalate the primary rep to a permanent vote built over that quorum.
/// Returns the temporary votes and the permanent vote.
fn stage_quorum_side_votes(
	node: &mut E2eNode,
	reps: usize,
	block: &str,
) -> Result<(Vec<String>, String), Box<dyn core::error::Error>> {
	let mut temporary = Vec::with_capacity(reps);
	for index in 0..reps {
		temporary.push(side_vote(node, index, block, &[])?);
	}

	let permanent = side_vote(node, 0, block, &temporary)?;
	Ok((temporary, permanent))
}

/// Assert the primary rep's head is `block` while every peer still lags behind.
fn assert_heads_diverged(node: &mut E2eNode, account: &str, block: &Block) -> Result<(), Box<dyn core::error::Error>> {
	let heads = head_hashes(node, account)?;
	assert_eq!(heads[0], block.hash().to_string(), "the primary rep must hold the advanced head");
	assert!(
		heads[1..].iter().all(|head| *head != heads[0]),
		"the peer reps must lag behind the primary before the repair"
	);

	Ok(())
}

/// Converge the cluster, then assert `block` is the trusted head everywhere and
/// the send debited the trusted account by [`SEND_AMOUNT`].
async fn assert_converged_send(
	fixture: &mut ClusterFixture,
	block: &Block,
	trusted: &str,
	base_token: &str,
) -> Result<(), Box<dyn core::error::Error>> {
	fixture.converge().await?;

	let head = fixture
		.client
		.head_block(trusted)
		.await?
		.ok_or("the trusted account must have a head once the staple publishes")?;
	assert_eq!(
		head.hash().to_string(),
		block.hash().to_string(),
		"the published block must become the cluster-wide head"
	);

	let balance = fixture.client.balance(trusted, base_token).await?;
	assert_eq!(
		balance,
		Amount::from(MINTED_SUPPLY - SEND_AMOUNT),
		"the published send must debit the trusted account across the cluster"
	);

	Ok(())
}

/// A peered multi-rep cluster must vote to quorum, publish across every rep,
/// and replicate over P2P.
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_rep_quorum_publish_and_convergence() -> Result<(), Box<dyn core::error::Error>> {
	let mut fixture = ClusterFixture::start(CLUSTER_REPS).await?;
	let trusted = fixture.trusted.clone();
	let base_token = fixture.base_token.clone();

	// Reads dispatch across the cluster and endpoints decode from discovery.
	let balance = fixture.client.balance(&trusted, &base_token).await?;
	assert_eq!(balance, Amount::from(MINTED_SUPPLY), "every representative must report the minted supply");

	let all = fixture.client.representatives().await?;
	assert!(all.iter().any(|rep| rep.api_url.is_some()), "the representative set must advertise endpoints");

	// A client-built send must vote to quorum and publish across the cluster.
	let accounts = fixture.accounts()?;
	let block = send_block(&fixture.client, &accounts, &accounts.recipient, SEND_AMOUNT).await?;

	let accepted = fixture
		.client
		.transmit(&[block], TransmitOptions::default())
		.await?;
	assert!(accepted, "the cluster must accept the quorum-voted staple");
	fixture.converge().await?;

	let after = fixture.client.balance(&trusted, &base_token).await?;
	assert_eq!(
		after,
		Amount::from(MINTED_SUPPLY - SEND_AMOUNT),
		"the send must debit the trusted account across the cluster"
	);

	let synced = fixture
		.client
		.sync_account(&accounts.trusted, false)
		.await?;
	assert!(synced.is_none(), "representatives already in sync must not produce a sync staple");

	Ok(())
}

/// Representatives in the weighted cluster.
const WEIGHTED_REPS: usize = 3;

/// Base token delegated to each non-primary rep, leaving the primary below the
/// quorum threshold so no single rep can carry a vote alone.
const DISTRIBUTE_AMOUNT: u64 = 200_000_000;

/// Seed bytes for the two client-side accounts that receive the distributed
/// funds and delegate to the secondary representatives.
const ACCOUNT2_SEED_BYTE: u8 = 0x42;
const ACCOUNT3_SEED_BYTE: u8 = 0x43;

/// The voting weight a representative reports in `representatives()`, by account.
fn rep_weight(reps: &[keetanetwork_client::Representative], account: &str) -> Option<Amount> {
	reps.iter()
		.find(|rep| rep.account == account)
		.map(|rep| rep.weight.clone())
}

/// A full multi-node exercise
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_rep_weighted_quorum_and_rep_failure() -> Result<(), Box<dyn core::error::Error>> {
	let mut fixture = ClusterFixture::start(WEIGHTED_REPS).await?;
	let trusted = fixture.trusted.clone();
	let base_token = fixture.base_token.clone();
	let rep_accounts = fixture.rep_accounts.clone();

	// Distribute base token to two fresh accounts and delegate each to a
	// secondary rep, in one staple: a two-SEND block from the trusted account
	// plus an opening SET_REP block for each recipient.
	let accounts = fixture.accounts()?;
	let account2: AccountRef = generate_ed25519_ref(ACCOUNT2_SEED_BYTE);
	let account3: AccountRef = generate_ed25519_ref(ACCOUNT3_SEED_BYTE);
	let rep1_account: AccountRef = Arc::new(GenericAccount::from_str(&rep_accounts[1])?);
	let rep2_account: AccountRef = Arc::new(GenericAccount::from_str(&rep_accounts[2])?);

	let distribute = one_block(
		fixture
			.client
			.builder(&accounts.trusted)
			.send(&account2, &accounts.token, Amount::from(DISTRIBUTE_AMOUNT))
			.send(&account3, &accounts.token, Amount::from(DISTRIBUTE_AMOUNT))
			.build()
			.await?,
	);
	let set_rep2 = one_block(
		fixture
			.client
			.builder(&account2)
			.set_rep(&rep1_account)
			.build()
			.await?,
	);
	let set_rep3 = one_block(
		fixture
			.client
			.builder(&account3)
			.set_rep(&rep2_account)
			.build()
			.await?,
	);

	let accepted = fixture
		.client
		.transmit(&[distribute, set_rep2, set_rep3], TransmitOptions::default())
		.await?;
	assert!(accepted, "the cluster must accept the weight-distribution staple");
	fixture.converge().await?;

	// Weights now split 0.6 / 0.2 / 0.2 — no rep meets the 0.7 quorum alone.
	fixture.client.discover_representatives().await?;

	let all = fixture.client.representatives().await?;
	let primary = MINTED_SUPPLY - 2 * DISTRIBUTE_AMOUNT;
	assert_eq!(rep_weight(&all, &rep_accounts[0]), Some(Amount::from(primary)), "primary rep weight mismatch");
	assert_eq!(
		rep_weight(&all, &rep_accounts[1]),
		Some(Amount::from(DISTRIBUTE_AMOUNT)),
		"first secondary rep weight mismatch"
	);
	assert_eq!(
		rep_weight(&all, &rep_accounts[2]),
		Some(Amount::from(DISTRIBUTE_AMOUNT)),
		"second secondary rep weight mismatch"
	);
	assert!(all.iter().all(|rep| rep.api_url.is_some()), "every discovered rep must advertise an endpoint");

	// A send now requires aggregating the primary with at least one secondary
	// rep to clear quorum; acceptance proves the client gathered both.
	let send = send_block(&fixture.client, &accounts, &account2, SEND_AMOUNT).await?;
	let accepted = fixture
		.client
		.transmit(&[send], TransmitOptions::default())
		.await?;
	assert!(accepted, "the cluster must accept a staple that needed votes from more than one rep");
	fixture.converge().await?;

	let after_send = fixture.client.balance(&trusted, &base_token).await?;
	assert_eq!(
		after_send,
		Amount::from(primary - SEND_AMOUNT),
		"the multi-rep send must debit the trusted account across the cluster"
	);

	let synced = fixture
		.client
		.sync_account(&accounts.trusted, false)
		.await?;
	assert!(synced.is_none(), "representatives already in sync must not produce a sync staple");

	// Fail the second secondary rep. The primary plus the surviving secondary
	// still hold 0.8 of the weight, so transmit must reach a degraded quorum.
	fixture
		.node
		.request("stop_rep", json!({ "index": WEIGHTED_REPS - 1 }))?;

	let degraded = send_block(&fixture.client, &accounts, &account2, SEND_AMOUNT).await?;
	let accepted = fixture
		.client
		.transmit(&[degraded], TransmitOptions::default())
		.await?;
	assert!(accepted, "the cluster must reach a degraded quorum with one rep down");
	fixture.converge().await?;

	// Reads must still resolve, dispatching past the failed rep.
	let after_failure = fixture.client.balance(&trusted, &base_token).await?;
	assert_eq!(
		after_failure,
		Amount::from(primary - 2 * SEND_AMOUNT),
		"reads must dispatch past the downed rep and reflect the second send"
	);

	Ok(())
}

/// A half-published account — one whose successor block sits voted on the
/// representatives' side ledgers but never promoted to the main ledger — must
/// be recoverable: the client rebuilds the staple from the scattered side
/// votes and republishes it across the cluster.
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_rep_recover_publishes_pending_side_block() -> Result<(), Box<dyn core::error::Error>> {
	let mut fixture = ClusterFixture::start(WEIGHTED_REPS).await?;
	let trusted = fixture.trusted.clone();
	let base_token = fixture.base_token.clone();
	let accounts = fixture.accounts()?;

	// Build a send block but never transmit it; instead stage it on every
	// rep's side ledger so it becomes a pending, half-published successor.
	let block = send_block(&fixture.client, &accounts, &accounts.recipient, SEND_AMOUNT).await?;
	let block_bytes = block_hex(&block);

	// Stage temp votes on every rep, then escalate the primary to permanent.
	stage_quorum_side_votes(&mut fixture.node, WEIGHTED_REPS, &block_bytes)?;

	// The client must see the half-published block as the pending successor.
	let pending = fixture
		.client
		.pending_block(&trusted)
		.await?
		.ok_or("the staged side block must surface as the pending successor")?;
	assert_eq!(
		pending.hash().to_string(),
		block.hash().to_string(),
		"the pending block must be the block staged on the side ledger"
	);

	// Recovery rebuilds the staple from the side votes and republishes it.
	let recovered = fixture
		.client
		.recover_account(&accounts.trusted, true, TransmitOptions::default())
		.await?;
	assert!(recovered.is_some(), "recovery must produce a staple for the pending block");

	assert_converged_send(&mut fixture, &block, &trusted, &base_token).await?;

	Ok(())
}

/// A rep that already promoted the successor to its main ledger holds its vote
/// there, not on the side ledger. Recovery must read that main-ledger vote
/// (main-first), fold it in with the peers' still-pending side votes, and
/// republish so the lagging reps catch up.
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_rep_recover_reads_main_promoted_vote() -> Result<(), Box<dyn core::error::Error>> {
	let mut fixture = ClusterFixture::start(WEIGHTED_REPS).await?;
	let trusted = fixture.trusted.clone();
	let base_token = fixture.base_token.clone();
	let accounts = fixture.accounts()?;

	let block = send_block(&fixture.client, &accounts, &accounts.recipient, SEND_AMOUNT).await?;
	let block_bytes = block_hex(&block);

	// Stage temporary side votes on every rep, then escalate the primary to a
	// permanent vote built over that quorum.
	let (_temporary, permanent) = stage_quorum_side_votes(&mut fixture.node, WEIGHTED_REPS, &block_bytes)?;

	// Promote the staple onto the primary's main ledger only: its head now
	// holds the successor while the peers stay pending on their side ledgers.
	ledger_add(&mut fixture.node, 0, &[permanent], &block_bytes)?;

	assert_heads_diverged(&mut fixture.node, &trusted, &block)?;

	// The divergent head must not hide the pending successor: the majority of
	// reps still report it, so it remains recoverable.
	let pending = fixture
		.client
		.pending_block(&trusted)
		.await?
		.ok_or("the half-published successor must surface despite the primary's advanced head")?;
	assert_eq!(
		pending.hash().to_string(),
		block.hash().to_string(),
		"the majority of reps must agree on the pending successor"
	);

	// Recovery reads the primary's main-ledger vote, combines it with the
	// peers' side votes, and republishes to converge the cluster.
	let recovered = fixture
		.client
		.recover_account(&accounts.trusted, true, TransmitOptions::default())
		.await?;
	assert!(recovered.is_some(), "recovery must rebuild the staple from the main-promoted vote and the side votes");

	assert_converged_send(&mut fixture, &block, &trusted, &base_token).await?;

	Ok(())
}

/// When one rep's main ledger has advanced past its peers, the client must
/// detect the head-height divergence and publish the missing staple to the
/// lagging reps so the whole cluster converges.
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_rep_sync_repairs_lagging_rep() -> Result<(), Box<dyn core::error::Error>> {
	let mut fixture = ClusterFixture::start(WEIGHTED_REPS).await?;
	let trusted = fixture.trusted.clone();
	let base_token = fixture.base_token.clone();
	let accounts = fixture.accounts()?;

	// Build the successor and assemble a permanent staple from side votes.
	let block = send_block(&fixture.client, &accounts, &accounts.recipient, SEND_AMOUNT).await?;
	let block_bytes = block_hex(&block);

	let (_temporary, permanent) = stage_quorum_side_votes(&mut fixture.node, 2, &block_bytes)?;

	// Promote the staple onto the primary rep's main ledger only; the direct
	// ledger add does not broadcast, so the peers stay at the prior head.
	ledger_add(&mut fixture.node, 0, &[permanent], &block_bytes)?;

	assert_heads_diverged(&mut fixture.node, &trusted, &block)?;

	// Sync detects the divergence and publishes the staple to the lagging reps.
	let synced = fixture.client.sync_account(&accounts.trusted, true).await?;
	assert!(synced.is_some(), "sync must produce the repair staple while the reps diverge");

	assert_converged_send(&mut fixture, &block, &trusted, &base_token).await?;

	Ok(())
}

/// Queries that depend on mutating the node's ledger state.
#[tokio::test(flavor = "multi_thread")]
async fn test_certificates_after_add() -> Result<(), Box<dyn core::error::Error>> {
	let mut fixture = fixture().await;

	fixture.node.request("manage_cert_add", json!({}))?;

	let certificates = fixture.client.certificates(&fixture.trusted).await?;
	assert!(!certificates.is_empty(), "the trusted account must hold a certificate after adding one");
	assert!(!certificates[0].certificate.is_empty(), "the returned certificate must carry a PEM body");

	Ok(())
}

/// The multi-account builder must derive a pending identifier at build time and
/// the node must accept the creating block, proving the derived address matches
/// the node's own derivation from the operation index.
#[tokio::test(flavor = "multi_thread")]
async fn test_builder_creates_pending_identifier() -> Result<(), Box<dyn core::error::Error>> {
	let mut fixture = fixture().await;
	let accounts = signing_accounts(&fixture.base_token)?;

	let mut builder = fixture.client.builder(&accounts.trusted);
	let storage = builder.generate_identifier(KeyPairType::STORAGE, None);
	let blocks = builder.build().await?;
	assert_eq!(blocks.len(), 1, "a single originator must render exactly one block");

	let identifier = storage.get()?;
	assert!(identifier.to_keypair_type().is_identifier(), "the resolved handle must be an identifier");

	let accepted = fixture
		.client
		.transmit(&blocks, TransmitOptions::default())
		.await?;
	assert!(accepted, "the node must accept the create-identifier block, validating the derived address");

	let head = fixture.head_hash();
	assert_eq!(head, blocks[0].hash().to_string(), "the create-identifier block must become the trusted head");

	Ok(())
}

/// One builder spanning two originators must render one chained block each and
/// publish them in a single staple.
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_account_builder_staple() -> Result<(), Box<dyn core::error::Error>> {
	let fixture = fixture().await;
	let accounts = signing_accounts(&fixture.base_token)?;
	let account2 = generate_ed25519_ref(ACCOUNT2_SEED_BYTE);

	let mut builder = fixture.client.builder(&accounts.trusted);
	builder.send(&account2, &accounts.token, Amount::from(SEND_AMOUNT));
	builder.for_account(&account2).set_rep(&accounts.recipient);
	let blocks = builder.build().await?;
	assert_eq!(blocks.len(), 2, "two distinct originators must render two blocks");

	let accepted = fixture
		.client
		.transmit(&blocks, TransmitOptions::default())
		.await?;
	assert!(accepted, "the node must accept the multi-account staple");

	let head = fixture.client.head_block(account2.to_string()).await?;
	assert!(head.is_some(), "account2's opening set-rep block must become its head");

	let after = fixture
		.client
		.balance(&fixture.trusted, &fixture.base_token)
		.await?;
	assert_eq!(
		after,
		Amount::from(MINTED_SUPPLY - SEND_AMOUNT),
		"the trusted account must be debited by the bundled send"
	);

	Ok(())
}

/// A signer-bound [`UserClient`] must resolve account-scoped reads against its
/// signer and round-trip a convenience send.
#[tokio::test(flavor = "multi_thread")]
async fn test_user_client_send_round_trip() -> Result<(), Box<dyn core::error::Error>> {
	let mut node = E2eNode::start().expect("the reference node harness must start");
	let network = BigInt::from_str(&ready_field(&node, "network"))?;
	let api = ready_field(&node, "api");
	let base_token = ready_field(&node, "baseToken");
	node.request("init_supply", json!({ "amount": MINTED_SUPPLY.to_string() }))?;

	let accounts = signing_accounts(&base_token)?;
	let client = KeetaClient::new(&api).with_network(network);
	let user = UserClient::from_parts(client, Some(Arc::clone(&accounts.trusted)));

	let balance = user.balance(&base_token).await?;
	assert_eq!(balance, Amount::from(MINTED_SUPPLY), "the bound signer's balance must be the minted supply");

	let accepted = user
		.send(&accounts.recipient, &accounts.token, Amount::from(SEND_AMOUNT))
		.await?;
	assert!(accepted, "the user client send must publish");

	let after = user.balance(&base_token).await?;
	assert_eq!(after, Amount::from(MINTED_SUPPLY - SEND_AMOUNT), "the user client send must debit the bound signer");

	assert_eq!(
		user.account()?.to_string(),
		accounts.trusted.to_string(),
		"a signer-bound client must operate on the signer's account by default"
	);
	assert!(!user.is_read_only(), "a signer-bound client must accept writes");

	let head = user
		.head()
		.await?
		.expect("the operating account must have a head after a send");
	let fetched = user.block(head.hash().to_string()).await?;
	assert!(fetched.is_some(), "the head block must be fetchable by hash through the user client");

	let statuses = user.client().network_status().await?;
	assert!(
		statuses.iter().any(|status| status.online),
		"network status must report at least one online representative"
	);

	let read_only = UserClient::from_parts(user.client().clone(), None);
	assert!(read_only.is_read_only(), "a signerless client must be read-only");
	assert!(
		matches!(read_only.account(), Err(ClientError::SignerRequired)),
		"a signerless client must reject account-scoped operations"
	);

	let _ = node.request("shutdown", json!({}));
	Ok(())
}

/// Genesis: a Rust-built permanent staple bootstraps a fresh, uninitialized
/// network. The harness node starts empty (no `init_supply`), so the client's
/// own `initialize_network` mints the base-token supply, credits the recipient
/// (the bound signer), and delegates its weight to the representative.
#[tokio::test(flavor = "multi_thread")]
async fn test_initialize_network_bootstraps_fresh_chain() -> Result<(), Box<dyn core::error::Error>> {
	let mut node = E2eNode::start().expect("the reference node harness must start");
	let network = BigInt::from_str(&ready_field(&node, "network"))?;
	let api = ready_field(&node, "api");
	let base_token = ready_field(&node, "baseToken");
	let trusted_address = ready_field(&node, "trusted");
	let rep_address = ready_field(&node, "representative");

	let trusted = generate_ed25519_ref(TRUSTED_SEED_BYTE);
	let rep = generate_ed25519_ref(REP_SEED_BYTE);
	assert_eq!(trusted.to_string(), trusted_address, "the derived trusted signer must match the node address");
	assert_eq!(rep.to_string(), rep_address, "the derived representative must match the node address");

	let client =
		KeetaClient::with_representatives([RepEndpoint::new(&api, Arc::clone(&rep), 1u8)], ClientConfig::default())
			.with_network(network);
	let user = UserClient::from_parts(client, Some(Arc::clone(&trusted)));

	let accepted = user
		.initialize_network(InitializeNetwork { add_supply_amount: Amount::from(MINTED_SUPPLY), ..Default::default() })
		.await?;
	assert!(accepted, "the node must accept the genesis staple");

	let supply = user.client().token_supply(&base_token).await?;
	assert_eq!(supply, Some(Amount::from(MINTED_SUPPLY)), "genesis must mint the full base-token supply");

	let state = user.client().state(&trusted_address).await?;
	assert_eq!(
		state.representative.as_deref(),
		Some(rep_address.as_str()),
		"genesis must delegate the recipient's weight to the representative"
	);
	let base = state
		.balances
		.iter()
		.find(|entry| entry.token == base_token);
	assert!(
		base.is_some_and(|entry| entry.balance == Amount::from(MINTED_SUPPLY)),
		"genesis must credit the recipient with the minted supply"
	);

	let _ = node.request("shutdown", json!({}));
	Ok(())
}
