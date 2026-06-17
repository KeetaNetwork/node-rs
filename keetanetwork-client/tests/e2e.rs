//! End-to-end tests driving [`KeetaClient`] against a live reference node.
//!
//! The TypeScript harness boots an in-memory reference node and reports its
//! REST API URL; the Rust client then exercises the API over HTTP.

use core::future::Future;
use core::pin::Pin;
use core::str::FromStr;
use core::time::Duration;
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_block::{AccountRef, Amount, Block, Hashable};
use keetanetwork_client::{
	ClientConfig, ClientError, KeetaClient, KeetaNetError, NodeErrorType, RepEndpoint, TransmitOptions,
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

	let block = client
		.builder(&accounts.trusted)
		.send(&accounts.recipient, &accounts.token, Amount::from(SEND_AMOUNT))
		.build()
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
		case!("sync is a no-op when the only rep is in sync", |ctx| {
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
	let block = client
		.builder(&accounts.trusted)
		.send(&accounts.recipient, &accounts.token, Amount::from(SEND_AMOUNT))
		.build()
		.await?;

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

/// A peered multi-rep cluster must vote to quorum, publish across every rep,
/// replicate over P2P, and report a no-op sync once in agreement.
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
	let block = fixture
		.client
		.builder(&accounts.trusted)
		.send(&accounts.recipient, &accounts.token, Amount::from(SEND_AMOUNT))
		.build()
		.await?;

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

/// A full multi-node exercise: split voting weight across three peered reps so
/// no rep meets quorum alone, then prove the client aggregates votes to
/// quorum, replicates over P2P, reports a no-op sync, and survives a rep
/// failure by voting to a degraded quorum and dispatching past the dead rep.
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

	let distribute = fixture
		.client
		.builder(&accounts.trusted)
		.send(&account2, &accounts.token, Amount::from(DISTRIBUTE_AMOUNT))
		.send(&account3, &accounts.token, Amount::from(DISTRIBUTE_AMOUNT))
		.build()
		.await?;
	let set_rep2 = fixture
		.client
		.builder(&account2)
		.set_rep(&rep1_account)
		.build()
		.await?;
	let set_rep3 = fixture
		.client
		.builder(&account3)
		.set_rep(&rep2_account)
		.build()
		.await?;

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
	let send = fixture
		.client
		.builder(&accounts.trusted)
		.send(&account2, &accounts.token, Amount::from(SEND_AMOUNT))
		.build()
		.await?;
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

	let degraded = fixture
		.client
		.builder(&accounts.trusted)
		.send(&account2, &accounts.token, Amount::from(SEND_AMOUNT))
		.build()
		.await?;
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
	let block = fixture
		.client
		.builder(&accounts.trusted)
		.send(&accounts.recipient, &accounts.token, Amount::from(SEND_AMOUNT))
		.build()
		.await?;
	let block_bytes = block_hex(&block);

	let mut temporary = Vec::with_capacity(WEIGHTED_REPS);
	for index in 0..WEIGHTED_REPS {
		temporary.push(side_vote(&mut fixture.node, index, &block_bytes, &[])?);
	}
	// Escalate the primary rep to a permanent side-ledger vote.
	side_vote(&mut fixture.node, 0, &block_bytes, &temporary)?;

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
		.recover_account(&accounts.trusted, true, None)
		.await?;
	assert!(recovered.is_some(), "recovery must produce a staple for the pending block");
	fixture.converge().await?;

	let head = fixture
		.client
		.head_block(&trusted)
		.await?
		.ok_or("the trusted account must have a head once recovery publishes")?;
	assert_eq!(
		head.hash().to_string(),
		block.hash().to_string(),
		"the recovered block must become the main-ledger head"
	);
	let balance = fixture.client.balance(&trusted, &base_token).await?;
	assert_eq!(
		balance,
		Amount::from(MINTED_SUPPLY - SEND_AMOUNT),
		"the recovered send must debit the trusted account across the cluster"
	);

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
	let block = fixture
		.client
		.builder(&accounts.trusted)
		.send(&accounts.recipient, &accounts.token, Amount::from(SEND_AMOUNT))
		.build()
		.await?;
	let block_bytes = block_hex(&block);

	let temp_primary = side_vote(&mut fixture.node, 0, &block_bytes, &[])?;
	let temp_secondary = side_vote(&mut fixture.node, 1, &block_bytes, &[])?;
	let permanent = side_vote(&mut fixture.node, 0, &block_bytes, &[temp_primary, temp_secondary])?;

	// Promote the staple onto the primary rep's main ledger only; the direct
	// ledger add does not broadcast, so the peers stay at the prior head.
	ledger_add(&mut fixture.node, 0, &[permanent], &block_bytes)?;

	let heads = head_hashes(&mut fixture.node, &trusted)?;
	assert_eq!(heads[0], block.hash().to_string(), "the primary rep must hold the advanced head");
	assert!(heads[1..].iter().all(|head| *head != heads[0]), "the peer reps must lag behind the primary before sync");

	// Sync detects the divergence and publishes the staple to the lagging reps.
	let synced = fixture.client.sync_account(&accounts.trusted, true).await?;
	assert!(synced.is_some(), "sync must produce the repair staple while the reps diverge");
	fixture.converge().await?;

	let balance = fixture.client.balance(&trusted, &base_token).await?;
	assert_eq!(
		balance,
		Amount::from(MINTED_SUPPLY - SEND_AMOUNT),
		"the synced send must debit the trusted account across the cluster"
	);

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
