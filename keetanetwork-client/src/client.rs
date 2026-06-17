//! Ergonomic, domain-typed wrapper over the generated transport client.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use futures::future::{select, Either};
use futures::pin_mut;
use futures::stream::{FuturesUnordered, StreamExt};
use keetanetwork_account::{Account, GenericAccount, KeyNETWORK, KeyPairType};
use keetanetwork_block::{AccountRef, Amount, Block, BlockBuilder, BlockPurpose, BlockTime, Hashable, Send};
use keetanetwork_error::KeetaNetError;
use keetanetwork_vote::{Fee, ValidationConfig, Vote, VoteQuote, VoteStaple};
use num_bigint::BigInt;
use snafu::ResultExt;

use crate::builder::TransactionBuilder;
use crate::config::ClientConfig;
use crate::error::{AccountSnafu, ClientError, VoteSnafu};
use crate::math::{meets_quorum, most_common_hash, next_backoff, overlapping_moment};
use crate::model::{
	AccountState, Acl, Certificate, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum, Representative,
	TokenBalance, TransmitOptions,
};
use crate::rep::{RepBook, RepRecord, RepRef, SmallRng};
use crate::runtime::{Runtime, TaskHandle};
use crate::sync::{Mutex, RwLock};
use crate::transport::{LedgerSide, NodeTransport, TransportFactory};

#[cfg(feature = "std")]
use crate::generated::Client as Transport;
#[cfg(feature = "std")]
use crate::rep::RepEndpoint;
#[cfg(feature = "std")]
use crate::runtime::TokioRuntime;
#[cfg(feature = "std")]
use crate::transport::GeneratedTransportFactory;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// Bookkeeping for the background representative-refresh task.
#[derive(Debug, Default)]
struct RefreshState {
	started: bool,
	handle: Option<Box<dyn TaskHandle>>,
}

/// A selection target bound to its live transport: the scoring core yields a
/// [`RepRef`] (key + weight) which the client joins against its transport
/// registry to produce this.
#[derive(Clone, Debug)]
struct RepPick {
	key: String,
	weight: BigInt,
	transport: Arc<dyn NodeTransport>,
}

/// Shared client state behind an [`Arc`], so [`KeetaClient`] is cheap to
/// clone while all clones observe the same representative set, scores, and
/// background refresh task.
#[derive(Debug)]
struct Inner {
	/// Reliability scoring + selection core (`no_std`, internally locked).
	reps: RepBook,
	/// Live per-representative transports, keyed by the same key the scoring
	/// core uses. Read on every fan-out, written only on rep discovery.
	transports: RwLock<BTreeMap<String, Arc<dyn NodeTransport>>>,
	config: ClientConfig,
	/// Builds a transport for a representative discovered at runtime, keeping
	/// discovery transport-agnostic.
	factory: Arc<dyn TransportFactory>,
	runtime: Arc<dyn Runtime>,
	/// Per-pick counter mixed with the runtime clock to seed selection's
	/// [`SmallRng`] so successive picks differ.
	rng_counter: AtomicU64,
	network: RwLock<Option<BigInt>>,
	subnet: RwLock<Option<BigInt>>,
	/// `true` for the single anonymous-rep client built by [`KeetaClient::new`];
	/// disables weight refresh (no rep accounts to match) and the
	/// permanent-round issuer filter (its lone rep is always contacted).
	single_rep: bool,
	refresh: Mutex<RefreshState>,
}

impl Drop for Inner {
	fn drop(&mut self) {
		if let Some(handle) = self.refresh.get_mut().handle.take() {
			handle.abort();
		}
	}
}

/// Async, durable client for a KeetaNet network.
///
/// Talks to a set of representatives: reads pick one rep (power-of-two
/// choices, weighted by reliability) with retry, backoff, and timeout; votes,
/// quotes, and publishes fan out to every rep and aggregate by quorum weight.
/// Exposes the publish flow in domain types ([`Block`], [`Vote`],
/// [`VoteStaple`]) rather than base64 strings.
#[derive(Clone, Debug)]
pub struct KeetaClient {
	inner: Arc<Inner>,
}

impl KeetaClient {
	/// Create a single-representative client targeting `base_url`.
	/// Uses [`ClientConfig::default`].
	#[cfg(feature = "std")]
	pub fn new(base_url: impl AsRef<str>) -> Self {
		let http = reqwest::Client::new();
		Self::single(base_url.as_ref(), http, ClientConfig::default())
	}

	/// Create a single-representative client over a pre-configured
	/// [`reqwest::Client`], allowing custom timeouts, TLS, or proxy settings.
	#[cfg(feature = "std")]
	pub fn with_client(base_url: impl AsRef<str>, http: reqwest::Client) -> Self {
		Self::single(base_url.as_ref(), http, ClientConfig::default())
	}

	/// Create a multi-representative client over `reps`, fanning votes and
	/// publishes across them and selecting reps for reads by weighted
	/// reliability.
	#[cfg(feature = "std")]
	pub fn with_representatives(reps: impl IntoIterator<Item = RepEndpoint>, config: ClientConfig) -> Self {
		let http = reqwest::Client::new();
		let factory = Arc::new(GeneratedTransportFactory::new(http));
		let parts = reps
			.into_iter()
			.map(|rep| (rep.account().to_string(), rep.api_url().to_owned(), rep.weight().clone()));

		Self::with_parts(parts, factory, Arc::new(TokioRuntime), config, false)
	}

	#[cfg(feature = "std")]
	fn single(base_url: &str, http: reqwest::Client, config: ClientConfig) -> Self {
		let factory = Arc::new(GeneratedTransportFactory::new(http));
		let parts = [(base_url.to_owned(), base_url.to_owned(), BigInt::from(1u8))];

		Self::with_parts(parts, factory, Arc::new(TokioRuntime), config, true)
	}

	/// Construct a client from explicit `(key, url, weight)` representatives,
	/// an injected [`TransportFactory`] (used to bind each rep and any later
	/// discovered ones), and a [`Runtime`].
	pub fn with_parts(
		reps: impl IntoIterator<Item = (String, String, BigInt)>,
		factory: Arc<dyn TransportFactory>,
		runtime: Arc<dyn Runtime>,
		config: ClientConfig,
		single_rep: bool,
	) -> Self {
		let mut records = Vec::new();
		let mut transports = BTreeMap::new();
		for (key, url, weight) in reps {
			let transport = factory.create(&url);
			records.push(RepRecord::new(key.clone(), url, weight));
			transports.insert(key, transport);
		}

		Self {
			inner: Arc::new(Inner {
				reps: RepBook::new(records),
				transports: RwLock::new(transports),
				config,
				factory,
				runtime,
				rng_counter: AtomicU64::new(0),
				network: RwLock::new(None),
				subnet: RwLock::new(None),
				single_rep,
				refresh: Mutex::new(RefreshState::default()),
			}),
		}
	}

	/// Join scoring [`RepRef`]s against the transport registry, producing
	/// fan-out targets. A ref whose transport is missing is skipped.
	fn bind_transports(&self, refs: Vec<RepRef>) -> Vec<RepPick> {
		let transports = self.inner.transports.read();
		refs.into_iter()
			.filter_map(|rep| {
				transports.get(&rep.key).map(|transport| RepPick {
					key: rep.key,
					weight: rep.weight,
					transport: Arc::clone(transport),
				})
			})
			.collect()
	}

	/// Every representative as a fan-out target.
	fn snapshot_picks(&self) -> Vec<RepPick> {
		self.bind_transports(self.inner.reps.snapshot())
	}

	/// Select one representative bound to its transport.
	fn pick_target(&self) -> Option<RepPick> {
		let seed = self.inner.runtime.now_millis() ^ self.inner.rng_counter.fetch_add(1, Ordering::Relaxed);
		let chosen = self.inner.reps.pick(&mut SmallRng::seed_from_u64(seed))?;
		let transports = self.inner.transports.read();
		transports.get(&chosen.key).map(|transport| RepPick {
			key: chosen.key,
			weight: chosen.weight,
			transport: Arc::clone(transport),
		})
	}

	/// Set the network identifier stamped onto blocks this client
	/// originates. Required before [`builder`](Self::builder) or
	/// [`send`](Self::send).
	pub fn with_network(self, network: impl Into<BigInt>) -> Self {
		*self.inner.network.write() = Some(network.into());
		self
	}

	/// Set the subnet identifier stamped onto blocks this client
	/// originates.
	pub fn with_subnet(self, subnet: impl Into<BigInt>) -> Self {
		*self.inner.subnet.write() = Some(subnet.into());
		self
	}

	fn network(&self) -> Option<BigInt> {
		self.inner.network.read().clone()
	}

	fn subnet(&self) -> Option<BigInt> {
		self.inner.subnet.read().clone()
	}

	/// The current wall-clock moment from the runtime, falling back to the
	/// epoch if the clock is out of [`BlockTime`]'s representable range.
	fn now_moment(&self) -> BlockTime {
		BlockTime::from_unix_millis(self.inner.runtime.unix_millis()).unwrap_or_default()
	}

	/// Build a generated transport for the first representative, for endpoints
	/// not covered by this wrapper. Uses a fresh HTTP client (this escape hatch
	/// does not share the orchestrator's connection pool).
	#[cfg(feature = "std")]
	pub fn transport(&self) -> Transport {
		let url = self.inner.reps.first_url().unwrap_or_default();
		Transport::new_with_client(&url, reqwest::Client::new())
	}

	/// Abort the background representative-refresh task. Safe to call more
	/// than once; the task is also aborted automatically when the last clone
	/// is dropped.
	pub fn destroy(&self) {
		if let Some(handle) = self.inner.refresh.lock().handle.take() {
			handle.abort();
		}
	}

	/// Lazily start the periodic representative-weight refresh.
	fn ensure_refresh(&self) {
		if self.inner.single_rep {
			return;
		}

		let mut refresh = self.inner.refresh.lock();
		if refresh.started {
			return;
		}

		refresh.started = true;

		let weak = Arc::downgrade(&self.inner);
		let interval = Duration::from_millis(self.inner.config.update_reps_interval_ms.max(1));
		let runtime = Arc::clone(&self.inner.runtime);
		let handle = self.inner.runtime.spawn(Box::pin(async move {
			loop {
				// Scope the strong reference so it is dropped before sleeping
				{
					let Some(inner) = weak.upgrade() else {
						break;
					};
					let client = KeetaClient { inner };
					let _ = client.update_reps().await;
				}

				runtime.sleep(interval).await;
			}
		}));

		refresh.handle = Some(handle);
	}

	/// Refresh known representatives' voting weights from
	/// `GET /representatives`, matching by account.
	async fn update_reps(&self) -> Result<(), ClientError> {
		let signature = self.inner.reps.sorted_keys().join(",");
		let ttl = Duration::from_millis(self.inner.config.reps_cache_ttl_ms);

		let fetched = match cached_representatives(&self.inner.runtime, &signature, ttl) {
			Some(cached) => cached,
			None => {
				let entries = self.fetch_rep_entries().await?;
				store_representatives(&self.inner.runtime, &signature, &entries);
				entries
			}
		};

		self.apply_reps(&fetched, self.inner.config.discover_reps);
		Ok(())
	}

	/// Refresh weights *and* add any newly advertised representatives,
	/// bypassing the cache.
	pub async fn discover_representatives(&self) -> Result<(), ClientError> {
		let entries = self.fetch_rep_entries().await?;
		self.apply_reps(&entries, true);
		Ok(())
	}

	/// Fetch the representative set as `(key, weight, api_url)` entries.
	async fn fetch_rep_entries(&self) -> Result<Vec<RepEntry>, ClientError> {
		Ok(self
			.representatives()
			.await?
			.into_iter()
			.map(|rep| (rep.account, rep.weight.as_bigint().clone(), rep.api_url))
			.collect())
	}

	/// Apply fetched representative entries to the shared state: refresh the
	/// weights of known reps and, when `discover` is set, add reps that
	/// advertise an API URL and are not yet in the set.
	fn apply_reps(&self, fetched: &[RepEntry], discover: bool) {
		let weights: Vec<(String, BigInt)> = fetched
			.iter()
			.map(|(key, weight, _)| (key.clone(), weight.clone()))
			.collect();
		self.inner.reps.update_weights(&weights);

		if !discover {
			return;
		}

		for (key, weight, api_url) in fetched {
			let Some(api) = api_url else {
				continue;
			};
			if !self.inner.reps.contains(key) {
				self.inner
					.reps
					.add(RepRecord::new(key.clone(), api.clone(), weight.clone()));
				self.inner
					.transports
					.write()
					.insert(key.clone(), self.inner.factory.create(api));
			}
		}
	}

	/// Dispatch a single-representative call with weighted reliability
	/// selection, retry, exponential backoff, and per-request timeout.
	async fn dispatch_any<T, F, Fut>(&self, call: F) -> Result<T, ClientError>
	where
		F: Fn(Arc<dyn NodeTransport>) -> Fut,
		Fut: Future<Output = Result<T, ClientError>>,
	{
		self.ensure_refresh();

		let max_retries = self.inner.config.max_retries;
		let max_backoff = self.inner.config.max_backoff_ms;
		let mut delay = 1u64;
		let mut attempt = 0u32;

		loop {
			let Some(pick) = self.pick_target() else {
				return Err(ClientError::NoRepresentatives);
			};

			let error = match self.run_call(call(pick.transport)).await {
				Ok(Ok(response)) => {
					self.boost(&pick.key);
					return Ok(response);
				}
				Ok(Err(error)) => {
					if self.try_recover_on_error(&error).await {
						continue;
					}
					self.decay(&pick.key);
					error
				}
				Err(()) => {
					self.decay(&pick.key);
					ClientError::Timeout
				}
			};

			if attempt >= max_retries {
				return Err(error);
			}

			attempt += 1;
			self.inner.runtime.sleep(Duration::from_millis(delay)).await;
			delay = next_backoff(delay, max_backoff);
		}
	}

	/// Await a transport call, bounding it by the configured request timeout
	/// (`Err(())` on timeout); an unset timeout awaits indefinitely.
	async fn run_call<T>(
		&self,
		future: impl Future<Output = Result<T, ClientError>>,
	) -> Result<Result<T, ClientError>, ()> {
		let timeout_ms = self.inner.config.request_timeout_ms;
		if timeout_ms == 0 {
			return Ok(future.await);
		}

		let timer = self.inner.runtime.sleep(Duration::from_millis(timeout_ms));
		pin_mut!(future);
		pin_mut!(timer);

		match select(future, timer).await {
			Either::Left((result, _)) => Ok(result),
			Either::Right(((), _)) => Err(()),
		}
	}

	/// Auto-sync path for dispatched reads/calls: on a ledger-vote conflict
	/// (`LEDGER_NOT_SUCCESSOR`/`LEDGER_NOT_OPENING`), attempt to
	/// [`sync_account`](Self::sync_account) each contended account.
	async fn try_recover_on_error(&self, error: &ClientError) -> bool {
		let accounts = match error {
			ClientError::Node { source } => match source.as_ref() {
				KeetaNetError::LedgerVote { accounts, .. } => accounts.clone(),
				_ => return false,
			},
			_ => return false,
		};

		let mut synced = false;
		for account in accounts {
			let Ok(parsed) = account.parse::<GenericAccount>() else {
				continue;
			};

			let account_ref: AccountRef = Arc::new(parsed);
			if let Ok(Some(_)) = self.sync_account(&account_ref, true).await {
				synced = true;
			}
		}

		synced
	}

	/// Reward a representative for a successful response (AIMD increase).
	fn boost(&self, key: &str) {
		self.inner
			.reps
			.boost(key, self.inner.config.reliability_increment);
	}

	/// Penalize a representative for a failed response (AIMD decrease).
	fn decay(&self, key: &str) {
		let config = &self.inner.config;
		self.inner
			.reps
			.decay(key, config.reliability_decay, config.reliability_floor);
	}

	/// Publish an assembled vote staple to the node.
	pub async fn transmit_staple(&self, staple: &VoteStaple) -> Result<bool, ClientError> {
		self.ensure_refresh();
		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let mut requests = FuturesUnordered::new();
		for pick in picks {
			requests.push(async move { (pick.key, pick.transport.publish_staple(staple).await) });
		}

		let mut accepted = false;
		let mut last_error: Option<ClientError> = None;
		while let Some((key, result)) = requests.next().await {
			match result {
				// A fulfilled publish response counts as success regardless of
				// the returned `publish` flag, matching the reference.
				Ok(_) => {
					self.boost(&key);
					accepted = true;
				}
				Err(error) => {
					self.decay(&key);
					last_error = Some(error);
				}
			}
		}

		if !accepted {
			if let Some(error) = last_error {
				return Err(error);
			}
		}

		Ok(accepted)
	}

	/// Request a (temporary) vote for `blocks` from a representative.
	///
	/// Fans out to every representative and returns the first vote received;
	/// use the two-round [`transmit`](Self::transmit) for full quorum voting.
	pub async fn request_vote(&self, blocks: &[Block]) -> Result<Vote, ClientError> {
		let votes = self.request_votes(blocks, &[], &[]).await?;
		votes.into_iter().next().ok_or(ClientError::MissingVote)
	}

	/// Request votes for `blocks` from every representative concurrently,
	/// attaching `prior_votes` so reps escalate temporary votes into
	/// permanent ones (the second voting round). Returns every successful
	/// vote; errors only when no representative produced one.
	async fn request_votes(
		&self,
		blocks: &[Block],
		prior_votes: &[Vote],
		quotes: &[VoteQuote],
	) -> Result<Vec<Vote>, ClientError> {
		self.ensure_refresh();
		// In the permanent round, contact only the reps that issued a prior
		// (temporary) vote: the node refuses a permanent vote from a rep that
		// has no temporary vote of its own (`LEDGER_NO_PERM_WITHOUT_SELF_TEMP`).
		// A single-rep client keys its rep by URL rather than account, so it
		// always contacts its lone rep.
		let snapshot = self.snapshot_picks();
		let picks = if self.inner.single_rep {
			snapshot
		} else {
			contacts_for(snapshot, prior_votes)
		};
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let quotes_by_issuer = quotes_by_issuer(quotes);
		let mut requests = FuturesUnordered::new();
		for pick in picks {
			// Every contacted rep receives the full prior-vote set, including
			// its own temporary vote, which the node requires to escalate, plus
			// its own quote when the caller supplied one.
			let quote = quotes_by_issuer.get(&pick.key).cloned();
			requests.push(async move {
				let vote = pick
					.transport
					.create_vote(blocks, prior_votes, quote.as_ref())
					.await;
				(pick.key, pick.weight, vote)
			});
		}

		let mut votes = Vec::new();
		let mut highest_error: Option<(BigInt, ClientError)> = None;
		while let Some((key, weight, result)) = requests.next().await {
			match result {
				Ok(vote) => {
					self.boost(&key);
					votes.push(vote);
				}
				Err(error) => {
					self.decay(&key);
					let supersedes = highest_error
						.as_ref()
						.is_none_or(|(seen, _)| weight > *seen);
					if supersedes {
						highest_error = Some((weight, error));
					}
				}
			}
		}

		// Keep every vote the reps returned and let the node enforce voting
		// weight (`transmit` retries on the node's insufficient-weight error).
		if votes.is_empty() {
			return Err(highest_error
				.map(|(_, error)| error)
				.unwrap_or(ClientError::QuorumNotReached));
		}

		Ok(votes)
	}

	/// Request a non-binding vote quote for `blocks`, used during fee
	/// negotiation. Fans out to all reps and returns the first quote.
	pub async fn request_quote(&self, blocks: &[Block]) -> Result<VoteQuote, ClientError> {
		let quotes = self.request_quotes(blocks).await?;
		quotes.into_iter().next().ok_or(ClientError::MissingQuote)
	}

	/// Request vote quotes for `blocks` from every representative, returning
	/// each valid quote. Quorum-based early exit is not required because
	/// quotes do not process blocks.
	async fn request_quotes(&self, blocks: &[Block]) -> Result<Vec<VoteQuote>, ClientError> {
		self.ensure_refresh();
		let (refs, total_weight) = self.inner.reps.snapshot_with_total();
		let picks = self.bind_transports(refs);
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let threshold = self.inner.config.quorum_threshold;
		let mut requests = FuturesUnordered::new();
		for pick in picks {
			requests.push(async move {
				let quote = pick.transport.create_vote_quote(blocks).await;
				(pick.key, pick.weight, quote)
			});
		}

		let mut quotes = Vec::new();
		let mut accumulated = BigInt::from(0u8);
		let mut last_error: Option<ClientError> = None;
		while let Some((key, weight, result)) = requests.next().await {
			match result {
				Ok(quote) => {
					self.boost(&key);
					accumulated += weight;
					quotes.push(quote);
					if meets_quorum(&accumulated, &total_weight, threshold) {
						break;
					}
				}
				Err(error) => {
					self.decay(&key);
					last_error = Some(error);
				}
			}
		}

		if quotes.is_empty() {
			return Err(last_error.unwrap_or(ClientError::MissingQuote));
		}

		Ok(quotes)
	}

	/// Request permanent votes for `blocks`, assemble a canonical staple, and
	/// publish it.
	///
	/// The staple is validated as of the transmit moment with the default
	/// [`ValidationConfig`]; the votes are freshly minted in this call, so
	/// surfacing a moment to the caller would be both unknowable in advance and
	/// inert on the staple bytes.
	pub async fn transmit(&self, blocks: &[Block], options: TransmitOptions) -> Result<bool, ClientError> {
		self.transmit_with_optional_fee(blocks, &options).await
	}

	/// The two-round transmit flow, optionally originating a fee block,
	/// retried on insufficient voting weight.
	///
	/// After the temporary round, if the votes require a fee (a non-zero fee
	/// with no zero-amount option), `options.fee_signer` originates a
	/// [`BlockPurpose::Fee`] block that joins the permanent round and staple.
	async fn transmit_with_optional_fee(
		&self,
		blocks: &[Block],
		options: &TransmitOptions,
	) -> Result<bool, ClientError> {
		let mut attempt = 0u32;
		let mut delay = 1u64;
		loop {
			match self.transmit_round(blocks, options).await {
				Ok(accepted) => return Ok(accepted),
				Err(error) => {
					let retryable = is_ledger_code(&error, "LEDGER_INSUFFICIENT_VOTING_WEIGHT");
					if !retryable || attempt >= self.inner.config.max_retries {
						return Err(error);
					}

					attempt += 1;
					self.inner.runtime.sleep(Duration::from_millis(delay)).await;
					delay = next_backoff(delay, self.inner.config.max_backoff_ms);
				}
			}
		}
	}

	/// One temporary-then-permanent voting round, building a fee block when
	/// required, and publishing the assembled staple. Quotes attach only to the
	/// temporary round, matching the reference flow.
	async fn transmit_round(&self, blocks: &[Block], options: &TransmitOptions) -> Result<bool, ClientError> {
		let moment = self.now_moment();
		let temporary = self.request_votes(blocks, &[], &options.quotes).await?;

		let mut all = blocks.to_vec();
		if fees_required(&temporary) {
			let signer = options
				.fee_signer
				.as_ref()
				.ok_or(ClientError::FeeRequired)?;
			let fee_block = self
				.build_fee_block(signer, blocks, &temporary, moment)
				.await?;
			all.push(fee_block);
		}

		let permanent = self.request_votes(&all, &temporary, &[]).await?;
		let staple = VoteStaple::try_new(all.iter().cloned(), permanent, ValidationConfig::default(), moment)
			.context(VoteSnafu)?;

		self.transmit_staple(&staple).await
	}

	/// Synchronize an account whose head height differs across
	/// representatives: pull the missing successor staple from the highest
	/// rep and publish it to the lagging reps.
	pub async fn sync_account(&self, account: &AccountRef, publish: bool) -> Result<Option<VoteStaple>, ClientError> {
		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let account_key = account.to_string();

		let mut infos: Vec<(RepPick, Option<(String, Amount)>)> = Vec::with_capacity(picks.len());
		for pick in picks {
			let info = head_info(&pick.transport, &account_key).await;
			infos.push((pick, info));
		}

		infos.sort_by(|left, right| height_value(&left.1).cmp(&height_value(&right.1)));

		let lowest_height = height_value(&infos[0].1);
		let highest_index = infos.len() - 1;
		if lowest_height == height_value(&infos[highest_index].1) {
			return Ok(None);
		}

		let lowest_head = match &infos[0].1 {
			Some((head, _)) => head.clone(),
			None => account.to_opening_hash().to_string(),
		};

		let successor = match infos[highest_index]
			.0
			.transport
			.successor_block(&lowest_head)
			.await?
		{
			Some(block) => block,
			None => return Ok(None),
		};
		let staple = match self
			.compose_staple_on(&infos[highest_index].0.transport, &successor.hash().to_string())
			.await?
		{
			Some(staple) => staple,
			None => return Ok(None),
		};

		if publish {
			for (pick, info) in &infos {
				if height_value(info) == lowest_height {
					// Publish serially to every lagging rep; ignore conflicts
					// (e.g. LEDGER_BLOCK_ALREADY_EXISTS) and verify by height.
					let _ = pick.transport.publish_staple(&staple).await;
				}
			}

			let updated = head_info(&infos[0].0.transport, &account_key).await;
			if height_value(&updated) == lowest_height {
				return Err(ClientError::SyncPublishFailed);
			}
		}

		Ok(Some(staple))
	}

	/// Recover a half-published account by rebuilding the staple for its
	/// pending successor block from the votes scattered across reps, fetching
	/// the voted-on blocks, topping up votes, and republishing.
	///
	/// `options.fee_signer` originates a fee block if the recovered votes
	/// require a fee and no permanent votes exist yet. Returns the recovered
	/// staple, or `None` when there is nothing pending to recover.
	pub async fn recover_account(
		&self,
		account: &AccountRef,
		publish: bool,
		options: TransmitOptions,
	) -> Result<Option<VoteStaple>, ClientError> {
		self.ensure_refresh();
		let successor = match self.pending_block(account.to_string()).await? {
			Some(block) => block,
			None => return Ok(None),
		};

		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let successor_hash = successor.hash().to_string();
		let moment = self.now_moment();
		let config = ValidationConfig::default();

		let mut perm_votes: Vec<Vote> = Vec::new();
		let mut temp_votes: Vec<Vote> = Vec::new();
		let mut perm_keys: Vec<String> = Vec::new();
		let mut missing: Vec<RepPick> = Vec::new();

		for pick in &picks {
			let best = match pick
				.transport
				.block_votes(&successor_hash, LedgerSide::Side)
				.await
			{
				Ok(Some(list)) if !list.is_empty() => pick_best_vote(list),
				_ => None,
			};
			match best {
				Some(vote) if vote.validity().is_permanent_at(moment, config) => {
					perm_votes.push(vote);
					perm_keys.push(pick.key.clone());
				}
				Some(vote) => temp_votes.push(vote),
				None => missing.push(pick.clone()),
			}
		}

		let block_hashes: Vec<String> = {
			let Some(sample) = perm_votes.first().or_else(|| temp_votes.first()) else {
				return Ok(None);
			};
			sample
				.blocks()
				.iter()
				.map(|hash| hash.to_string())
				.collect()
		};

		let mut blocks: Vec<Block> = Vec::with_capacity(block_hashes.len());
		for hash in &block_hashes {
			let mut found = None;
			for pick in &picks {
				if let Some(block) = pick.transport.block(hash, Some(LedgerSide::Both)).await? {
					found = Some(block);
					break;
				}
			}
			match found {
				Some(block) => blocks.push(block),
				None => return Err(ClientError::RecoverFailed),
			}
		}

		if perm_votes.len() != picks.len() {
			if temp_votes.len() != picks.len() {
				let prior = if perm_votes.is_empty() {
					Vec::new()
				} else {
					perm_votes.clone()
				};
				if let Ok(mut more) = self.request_votes_on(&missing, &blocks, &prior).await {
					temp_votes.append(&mut more);
				}
			}

			if perm_votes.is_empty() && fees_required(&temp_votes) {
				let signer = options
					.fee_signer
					.as_ref()
					.ok_or(ClientError::FeeRequired)?;
				let fee_block = self
					.build_fee_block(signer, &blocks, &temp_votes, moment)
					.await?;
				blocks.push(fee_block);
			}

			let missing_perm: Vec<RepPick> = picks
				.iter()
				.filter(|pick| !perm_keys.contains(&pick.key))
				.cloned()
				.collect();
			let mut prior = temp_votes.clone();

			prior.extend(perm_votes.iter().cloned());

			if let Ok(mut more) = self.request_votes_on(&missing_perm, &blocks, &prior).await {
				perm_votes.append(&mut more);
			}
		}

		if perm_votes.is_empty() {
			return Err(ClientError::RecoverFailed);
		}

		let staple_at = staple_moment(&perm_votes, moment);
		let staple = VoteStaple::try_new(blocks, perm_votes.clone(), config, staple_at).context(VoteSnafu)?;
		if publish {
			self.transmit_staple(&staple).await?;
		}

		Ok(Some(staple))
	}

	/// Request votes from a specific subset of representatives, attaching
	/// `prior_votes`. Failures are scored and dropped; only successful votes
	/// are returned.
	async fn request_votes_on(
		&self,
		reps: &[RepPick],
		blocks: &[Block],
		prior_votes: &[Vote],
	) -> Result<Vec<Vote>, ClientError> {
		if reps.is_empty() {
			return Ok(Vec::new());
		}

		let mut requests = FuturesUnordered::new();
		for pick in reps {
			let key = pick.key.clone();
			let transport = Arc::clone(&pick.transport);
			requests.push(async move {
				let vote = transport.create_vote(blocks, prior_votes, None).await;
				(key, vote)
			});
		}

		let mut votes = Vec::new();
		while let Some((key, result)) = requests.next().await {
			match result {
				Ok(vote) => {
					self.boost(&key);
					votes.push(vote);
				}
				Err(_) => self.decay(&key),
			}
		}

		Ok(votes)
	}

	/// Assemble the staple covering `block_hash` from one rep's main-ledger
	/// votes and the blocks they cover.
	async fn compose_staple_on(
		&self,
		transport: &Arc<dyn NodeTransport>,
		block_hash: &str,
	) -> Result<Option<VoteStaple>, ClientError> {
		let votes = match transport.block_votes(block_hash, LedgerSide::Main).await? {
			Some(list) if !list.is_empty() => list,
			_ => return Ok(None),
		};

		let mut blocks = Vec::new();
		for hash in votes[0].blocks() {
			match transport
				.block(&hash.to_string(), Some(LedgerSide::Main))
				.await?
			{
				Some(block) => blocks.push(block),
				None => return Ok(None),
			}
		}

		let moment = staple_moment(&votes, self.now_moment());
		let staple = VoteStaple::try_new(blocks, votes, ValidationConfig::default(), moment).context(VoteSnafu)?;
		Ok(Some(staple))
	}

	/// Build and sign a [`BlockPurpose::Fee`] block paying the fees declared
	/// by `votes`, chained after `signer`'s block in `blocks`.
	async fn build_fee_block(
		&self,
		signer: &AccountRef,
		blocks: &[Block],
		votes: &[Vote],
		moment: BlockTime,
	) -> Result<Block, ClientError> {
		let previous = blocks
			.iter()
			.rev()
			.find(|block| block.data().account().to_string() == signer.to_string())
			.map(|block| block.hash())
			.ok_or(ClientError::FeeRequired)?;

		let mut builder = self
			.builder(signer)
			.with_purpose(BlockPurpose::Fee)
			.with_previous(previous)
			.with_date(moment);
		for operation in self.fee_operations(votes)? {
			builder = builder.with_operation(operation);
		}

		builder.build().await
	}

	/// Apply the configured network and subnet to `builder`, if set.
	pub(crate) fn apply_network(&self, mut builder: BlockBuilder) -> BlockBuilder {
		if let Some(network) = self.network() {
			builder = builder.with_network(network);
		}
		if let Some(subnet) = self.subnet() {
			builder = builder.with_subnet(subnet);
		}

		builder
	}

	/// Translate the fee schedule carried by `votes` into the `SEND`
	/// operations of a fee block, skipping votes that offer a zero-amount
	/// (optional) fee.
	fn fee_operations(&self, votes: &[Vote]) -> Result<Vec<Send>, ClientError> {
		let base_token = self.base_token()?;
		let mut operations = Vec::new();

		for vote in votes {
			let Some(fees) = vote.fees() else {
				continue;
			};
			if fees.entries().any(|fee| fee.amount == Amount::from(0u64)) {
				continue;
			}

			// Prefer an entry payable in the base token (implicit `None` or an
			// explicit match); otherwise fall back to the first entry.
			let Some(selected) = fees
				.entries()
				.find(|&fee| fee_pays_base_token(fee, &base_token))
				.or_else(|| fees.entries().next())
			else {
				continue;
			};

			let token = match &selected.token {
				Some(token) => Arc::clone(token),
				None => Arc::clone(&base_token),
			};
			let to = match &selected.pay_to {
				Some(pay_to) => Arc::clone(pay_to),
				None => Arc::clone(vote.issuer()),
			};

			operations.push(Send { to, amount: selected.amount.clone(), token, external: None });
		}

		Ok(operations)
	}

	/// Derive the network base token (the `TOKEN` identifier of the
	/// configured network), used as the implicit fee currency.
	fn base_token(&self) -> Result<AccountRef, ClientError> {
		let network = self.network().ok_or(ClientError::UnsupportedNetwork)?;
		let id = u64::try_from(&network).map_err(|_| ClientError::UnsupportedNetwork)?;
		let network_account = Account::<KeyNETWORK>::generate_network_address(id).context(AccountSnafu)?;
		let token = network_account
			.generate_identifier(KeyPairType::TOKEN, None, 0)
			.context(AccountSnafu)?;

		Ok(Arc::new(token))
	}

	/// Start a transaction originated by `account`.
	///
	/// The returned [`TransactionBuilder`] accumulates operations
	/// synchronously; [`build`](TransactionBuilder::build) then resolves the
	/// block context (`previous` from the ledger head, network/subnet from
	/// this client) and seals the block.
	pub fn builder(&self, account: &AccountRef) -> TransactionBuilder<'_> {
		TransactionBuilder::new(self, Arc::clone(account))
	}

	/// Publish a single block built via [`builder`](Self::builder).
	///
	/// `options.fee_signer` pays a fee when the node requires one (absent, a
	/// required fee fails with [`ClientError::FeeRequired`]) and drives
	/// recovery on a `LEDGER_SUCCESSOR_VOTE_EXISTS` conflict.
	pub async fn publish(&self, block: Block, options: TransmitOptions) -> Result<bool, ClientError> {
		let account = Arc::clone(block.data().account());
		let mut attempt = 0u32;
		loop {
			let result = self
				.transmit_with_optional_fee(core::slice::from_ref(&block), &options)
				.await;

			match result {
				Ok(accepted) => return Ok(accepted),
				Err(error) => {
					let recoverable = is_ledger_code(&error, "LEDGER_SUCCESSOR_VOTE_EXISTS");
					if !recoverable || attempt >= 2 {
						return Err(error);
					}
					attempt += 1;
					let _ = self.recover_account(&account, true, options.clone()).await;
				}
			}
		}
	}

	/// Build, sign, and [`publish`](Self::publish) a SEND of `amount` of
	/// `token` from `from` to `to`, paying any required fee with `from`.
	///
	/// Returns whether the node accepted the resulting staple.
	pub async fn send(
		&self,
		from: &AccountRef,
		to: &AccountRef,
		token: &AccountRef,
		amount: Amount,
	) -> Result<bool, ClientError> {
		let block = self.builder(from).send(to, token, amount).build().await?;
		let options = TransmitOptions { fee_signer: Some(Arc::clone(from)), ..Default::default() };
		self.publish(block, options).await
	}

	/// The node software version string.
	pub async fn node_version(&self) -> Result<String, ClientError> {
		self.dispatch_any(|t| async move { t.node_version().await })
			.await
	}

	/// The settled balance of `token` held by `account`.
	pub async fn balance(&self, account: impl AsRef<str>, token: impl AsRef<str>) -> Result<Amount, ClientError> {
		let account = account.as_ref().to_owned();
		let token = token.as_ref().to_owned();

		self.dispatch_any(move |t| {
			let account = account.clone();
			let token = token.clone();
			async move { t.balance(&account, &token).await }
		})
		.await
	}

	/// Every token balance held by `account`.
	pub async fn balances(&self, account: impl AsRef<str>) -> Result<Vec<TokenBalance>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.balances(&account).await }
		})
		.await
	}

	/// The full ledger state of `account`: representative, head, height, and
	/// balances.
	pub async fn state(&self, account: impl AsRef<str>) -> Result<AccountState, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.account_state(&account).await }
		})
		.await
	}

	/// The head block of `account`, or `None` when the account has no blocks.
	pub async fn head_block(&self, account: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.head_block(&account).await }
		})
		.await
	}

	/// The next pending (unreceived) block for `account`, if any.
	pub async fn pending_block(&self, account: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		self.ensure_refresh();
		let account = account.as_ref().to_owned();
		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let mut requests = FuturesUnordered::new();
		for pick in picks {
			let account = account.clone();
			requests.push(async move { (pick.key, pick.transport.pending_block(&account).await) });
		}

		// Tally candidate blocks by hash so the block seen on the most reps
		// wins, matching the reference's majority selection.
		let mut blocks_by_hash: BTreeMap<String, Block> = BTreeMap::new();
		let mut observed: Vec<String> = Vec::new();
		let mut any_success = false;
		let mut last_error: Option<ClientError> = None;
		while let Some((key, result)) = requests.next().await {
			match result {
				Ok(Some(block)) => {
					self.boost(&key);

					any_success = true;

					let hash = block.hash().to_string();
					blocks_by_hash.entry(hash.clone()).or_insert(block);
					observed.push(hash);
				}
				Ok(None) => {
					self.boost(&key);
					any_success = true;
				}
				Err(error) => {
					self.decay(&key);
					last_error = Some(error);
				}
			}
		}

		match most_common_hash(&observed).and_then(|hash| blocks_by_hash.remove(&hash)) {
			Some(block) => Ok(Some(block)),
			None if any_success => Ok(None),
			None => match last_error {
				Some(error) => Err(error),
				None => Ok(None),
			},
		}
	}

	/// The block identified by `blockhash`, if the node has it.
	pub async fn block(&self, blockhash: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		let blockhash = blockhash.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let blockhash = blockhash.clone();
			async move { t.block(&blockhash, None).await }
		})
		.await
	}

	/// The block following `blockhash`, if one exists.
	pub async fn successor_block(&self, blockhash: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		let blockhash = blockhash.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let blockhash = blockhash.clone();
			async move { t.successor_block(&blockhash).await }
		})
		.await
	}

	/// The block produced by `account` for the given idempotent `key`, if any.
	pub async fn block_by_idempotent(
		&self,
		account: impl AsRef<str>,
		key: impl AsRef<str>,
	) -> Result<Option<Block>, ClientError> {
		let account = account.as_ref().to_owned();
		let key = key.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			let key = key.clone();
			async move { t.block_by_idempotent(&account, &key).await }
		})
		.await
	}

	/// A prefix of `account`'s block chain, most recent first.
	pub async fn chain(&self, account: impl AsRef<str>) -> Result<Vec<Block>, ClientError> {
		self.chain_page(account, ChainQuery::default()).await
	}

	/// A single page of `account`'s block chain (most recent first), bounded
	/// by `query`.
	pub async fn chain_page(&self, account: impl AsRef<str>, query: ChainQuery) -> Result<Vec<Block>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			let query = query.clone();
			async move { t.chain_page(&account, &query).await }
		})
		.await
	}

	/// Every block in `account`'s chain (most recent first), fetched by
	/// paging with `page_limit` per request until a short page is returned.
	///
	/// Paging uses the last block hash of each page as the next `start`
	/// cursor and stops when the cursor stops advancing, guarding against a
	/// node whose cursor semantics differ from the expected contract.
	pub async fn chain_all(&self, account: impl AsRef<str>, page_limit: u32) -> Result<Vec<Block>, ClientError> {
		let account = account.as_ref();
		let limit = i64::from(page_limit.max(1));
		let mut blocks = Vec::new();
		let mut cursor: Option<String> = None;

		loop {
			let query = ChainQuery { start: cursor.clone(), end: None, limit: Some(limit) };
			let page = self.chain_page(account, query).await?;
			let page_len = page.len();

			let next_cursor = page.last().map(|block| block.hash().to_string());
			blocks.extend(page);

			match next_cursor {
				Some(hash) if Some(&hash) != cursor.as_ref() && page_len as i64 >= limit => {
					cursor = Some(hash);
				}
				_ => break,
			}
		}

		Ok(blocks)
	}

	/// `account`'s transaction history as verified vote staples.
	pub async fn history(&self, account: impl AsRef<str>) -> Result<Vec<HistoryEntry>, ClientError> {
		self.history_page(account, HistoryQuery::default()).await
	}

	/// A single page of `account`'s history, bounded by `query`.
	pub async fn history_page(
		&self,
		account: impl AsRef<str>,
		query: HistoryQuery,
	) -> Result<Vec<HistoryEntry>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			let query = query.clone();

			async move { t.history_page(&account, &query).await }
		})
		.await
	}

	/// The node's global transaction history as verified vote staples.
	pub async fn global_history(&self) -> Result<Vec<HistoryEntry>, ClientError> {
		self.global_history_page(HistoryQuery::default()).await
	}

	/// A single page of the node's global history, bounded by `query`.
	pub async fn global_history_page(&self, query: HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
		self.dispatch_any(move |t| {
			let query = query.clone();
			async move { t.global_history_page(&query).await }
		})
		.await
	}

	/// Vote staples committed at or after the ISO 8601 `start` moment.
	pub async fn vote_staples_after(&self, start: impl AsRef<str>) -> Result<Vec<VoteStaple>, ClientError> {
		self.vote_staples_after_page(start, None).await
	}

	/// A single page of vote staples committed at or after `start`, capped at
	/// `limit`.
	pub async fn vote_staples_after_page(
		&self,
		start: impl AsRef<str>,
		limit: Option<i64>,
	) -> Result<Vec<VoteStaple>, ClientError> {
		let start = start.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let start = start.clone();
			async move { t.vote_staples_after(&start, limit).await }
		})
		.await
	}

	/// The node's own representative and its weight.
	pub async fn node_representative(&self) -> Result<Representative, ClientError> {
		self.dispatch_any(|t| async move { t.node_representative().await })
			.await
	}

	/// The weight of representative `rep`.
	pub async fn representative(&self, rep: impl AsRef<str>) -> Result<Representative, ClientError> {
		let rep = rep.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let rep = rep.clone();
			async move { t.representative(&rep).await }
		})
		.await
	}

	/// Every known representative and its weight.
	pub async fn representatives(&self) -> Result<Vec<Representative>, ClientError> {
		self.dispatch_any(|t| async move { t.representatives().await })
			.await
	}

	/// The current ledger checksum.
	pub async fn ledger_checksum(&self) -> Result<LedgerChecksum, ClientError> {
		self.dispatch_any(|t| async move { t.ledger_checksum().await })
			.await
	}

	/// ACL entries where `account` is the principal (grantee).
	pub async fn acls_by_principal(&self, account: impl AsRef<str>) -> Result<Vec<Acl>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.acls_by_principal(&account).await }
		})
		.await
	}

	/// ACL entries granted to `account` as an entity.
	pub async fn acls_by_entity(&self, account: impl AsRef<str>) -> Result<Vec<Acl>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.acls_by_entity(&account).await }
		})
		.await
	}

	/// The aggregate ACL-with-info view for principal `account` (opaque JSON;
	/// std-only).
	#[cfg(feature = "std")]
	pub async fn acls_by_principal_with_info(
		&self,
		account: impl AsRef<str>,
	) -> Result<serde_json::Value, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.acls_by_principal_with_info(&account).await }
		})
		.await
	}

	/// Every certificate held by `account`.
	pub async fn certificates(&self, account: impl AsRef<str>) -> Result<Vec<Certificate>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.certificates(&account).await }
		})
		.await
	}

	/// The certificate of `account` identified by `hash`, if present.
	pub async fn certificate(
		&self,
		account: impl AsRef<str>,
		hash: impl AsRef<str>,
	) -> Result<Option<Certificate>, ClientError> {
		let account = account.as_ref().to_owned();
		let hash = hash.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			let hash = hash.clone();
			async move { t.certificate(&account, &hash).await }
		})
		.await
	}

	/// Node statistics (opaque ledger + switch metrics; std-only).
	#[cfg(feature = "std")]
	pub async fn node_stats(&self) -> Result<serde_json::Value, ClientError> {
		self.dispatch_any(|t| async move { t.node_stats().await })
			.await
	}

	/// Connected peers (opaque JSON; std-only).
	#[cfg(feature = "std")]
	pub async fn node_peers(&self) -> Result<serde_json::Value, ClientError> {
		self.dispatch_any(|t| async move { t.node_peers().await })
			.await
	}

	/// Ledger state for several `accounts` in one call.
	pub async fn states(&self, accounts: &[&str]) -> Result<Vec<AccountState>, ClientError> {
		let accounts = accounts.join(",");
		self.dispatch_any(move |t| {
			let accounts = accounts.clone();
			async move { t.account_states(&accounts).await }
		})
		.await
	}
}

/// A representative entry as cached/applied: account key, voting weight, and
/// advertised API URL (when the node provided one).
type RepEntry = (String, BigInt, Option<String>);

/// Process-shared representative cache, keyed by rep-set signature, so
/// concurrent clients/clones over the same reps refresh from one fetch. The
/// timestamp is the runtime's monotonic millisecond tick at storage time.
#[cfg(feature = "std")]
type RepsCache = BTreeMap<String, (u64, Vec<RepEntry>)>;

#[cfg(feature = "std")]
fn reps_cache() -> &'static Mutex<RepsCache> {
	static CACHE: OnceLock<Mutex<RepsCache>> = OnceLock::new();
	CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// A still-fresh cached rep set for `signature`, if one exists, measured
/// against the runtime clock.
#[cfg(feature = "std")]
fn cached_representatives(runtime: &Arc<dyn Runtime>, signature: &str, ttl: Duration) -> Option<Vec<RepEntry>> {
	let cache = reps_cache().lock();
	let (stored_at, reps) = cache.get(signature)?;
	if runtime.now_millis().saturating_sub(*stored_at) < ttl.as_millis() as u64 {
		return Some(reps.clone());
	}

	None
}

/// No-op cache lookup for `no_std`: every refresh fetches.
#[cfg(not(feature = "std"))]
fn cached_representatives(_runtime: &Arc<dyn Runtime>, _signature: &str, _ttl: Duration) -> Option<Vec<RepEntry>> {
	None
}

/// Store a freshly fetched rep set for `signature`, stamped with the runtime
/// clock.
#[cfg(feature = "std")]
fn store_representatives(runtime: &Arc<dyn Runtime>, signature: &str, reps: &[RepEntry]) {
	reps_cache()
		.lock()
		.insert(signature.to_owned(), (runtime.now_millis(), reps.to_vec()));
}

#[cfg(not(feature = "std"))]
fn store_representatives(_runtime: &Arc<dyn Runtime>, _signature: &str, _reps: &[RepEntry]) {}

/// Choose a moment that lies within every vote's validity window so a
/// reconstructed staple validates without rejecting near-expired votes.
fn staple_moment(votes: &[Vote], fallback: BlockTime) -> BlockTime {
	let windows = votes
		.iter()
		.map(|vote| (vote.validity().from.unix_millis(), vote.validity().to.unix_millis()));
	match overlapping_moment(windows) {
		Some(millis) => BlockTime::from_unix_millis(millis).unwrap_or(fallback),
		None => fallback,
	}
}

/// Index caller-supplied quotes by issuing-representative key, so each rep
/// receives only the quote it issued.
fn quotes_by_issuer(quotes: &[VoteQuote]) -> BTreeMap<String, VoteQuote> {
	quotes
		.iter()
		.map(|quote| (quote.as_vote().issuer().to_string(), quote.clone()))
		.collect()
}

/// Restrict `picks` to the reps that issued one of `prior_votes`. With no
/// prior votes (the temporary round) every rep is contacted.
fn contacts_for(picks: Vec<RepPick>, prior_votes: &[Vote]) -> Vec<RepPick> {
	if prior_votes.is_empty() {
		return picks;
	}

	let issuers: BTreeSet<String> = prior_votes
		.iter()
		.map(|vote| vote.issuer().to_string())
		.collect();
	picks
		.into_iter()
		.filter(|pick| issuers.contains(&pick.key))
		.collect()
}

/// Whether `error` is a node ledger error carrying the given `code`.
fn is_ledger_code(error: &ClientError, code: &str) -> bool {
	matches!(error, ClientError::Node { source } if source.code() == Some(code))
}

/// A specific rep's head block hash and height for `account`, treating any
/// error or absent head as "no head" so divergence detection can sort it low.
async fn head_info(transport: &Arc<dyn NodeTransport>, account: &str) -> Option<(String, Amount)> {
	let Ok(state) = transport.account_state(account).await else {
		return None;
	};
	match (state.head, state.height) {
		(Some(head), Some(height)) => Some((head, height)),
		_ => None,
	}
}

/// The head height carried by a rep's account info, treating a missing head as
/// `-1` so unopened reps sort below opened ones.
fn height_value(info: &Option<(String, Amount)>) -> BigInt {
	match info {
		Some((_, height)) => height.as_bigint().clone(),
		None => BigInt::from(-1),
	}
}

/// Choose the vote with the latest validity end, favouring permanent votes
/// when a rep returns both a permanent and a short vote.
fn pick_best_vote(mut votes: Vec<Vote>) -> Option<Vote> {
	votes.sort_by(|left, right| {
		right
			.validity()
			.to
			.unix_millis()
			.cmp(&left.validity().to.unix_millis())
	});
	votes.into_iter().next()
}

/// Whether a fee entry is payable in the network base token: an implicit
/// (`None`) token, or an explicit token matching `base_token`.
fn fee_pays_base_token(fee: &Fee, base_token: &AccountRef) -> bool {
	match &fee.token {
		None => true,
		Some(token) => token.to_string() == base_token.to_string(),
	}
}

/// Whether any vote requires a fee block: it carries a fee schedule with no
/// zero-amount (optional) entry, leaving the payer no way to opt out.
fn fees_required(votes: &[Vote]) -> bool {
	votes.iter().any(|vote| match vote.fees() {
		None => false,
		Some(fees) => !fees.entries().any(|fee| fee.amount == Amount::from(0u64)),
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	use keetanetwork_block::testing::{generate_ed25519_ref, generate_identifier_ref, validity_blocktime};
	use keetanetwork_block::BlockHash;
	use keetanetwork_vote::{Fees, VoteBuilder};

	use crate::transport::GeneratedTransport;

	const ISSUER_SEED: u8 = 0xA1;
	const TEST_NETWORK: u64 = 1;

	type TestResult = Result<(), Box<dyn core::error::Error>>;

	fn test_client() -> KeetaClient {
		KeetaClient::new("http://localhost").with_network(BigInt::from(TEST_NETWORK))
	}

	fn fee(amount: u64, pay_to: Option<AccountRef>, token: Option<AccountRef>) -> Fee {
		Fee { amount: Amount::from(amount), pay_to, token }
	}

	fn signed_vote(fees: Option<Fees>) -> Result<Vote, Box<dyn core::error::Error>> {
		let issuer = generate_ed25519_ref(ISSUER_SEED);
		let (from, to) = validity_blocktime(0, 60);
		let mut builder = VoteBuilder::new()
			.serial(1u8)
			.issuer(Arc::clone(&issuer))
			.validity(from, to)
			.add_block(BlockHash::from([7u8; 32]));
		if let Some(fees) = fees {
			builder = builder.fees(fees);
		}

		Ok(builder.build_signed(issuer.as_ref())?)
	}

	#[test]
	fn implicit_token_pays_base_token() {
		let base = generate_identifier_ref(1, KeyPairType::TOKEN, 0);
		assert!(fee_pays_base_token(&fee(1, None, None), &base));
	}

	#[test]
	fn matching_token_pays_base_token() {
		let base = generate_identifier_ref(1, KeyPairType::TOKEN, 0);
		assert!(fee_pays_base_token(&fee(1, None, Some(Arc::clone(&base))), &base));
	}

	#[test]
	fn divergent_token_does_not_pay_base_token() {
		let base = generate_identifier_ref(1, KeyPairType::TOKEN, 0);
		let other = generate_identifier_ref(2, KeyPairType::TOKEN, 0);
		assert!(!fee_pays_base_token(&fee(1, None, Some(other)), &base));
	}

	#[test]
	fn absent_fees_are_not_required() -> TestResult {
		assert!(!fees_required(&[signed_vote(None)?]));
		Ok(())
	}

	#[test]
	fn nonzero_fee_is_required() -> TestResult {
		let fees = Fees::from_entries(false, vec![fee(10, None, None)])?;
		assert!(fees_required(&[signed_vote(Some(fees))?]));
		Ok(())
	}

	#[test]
	fn zero_amount_entry_makes_fee_optional() -> TestResult {
		let fees = Fees::from_entries(false, vec![fee(10, None, None), fee(0, None, None)])?;
		assert!(!fees_required(&[signed_vote(Some(fees))?]));
		Ok(())
	}

	#[test]
	fn fee_operations_default_to_base_token_and_issuer() -> TestResult {
		let client = test_client();
		let base = client.base_token()?;
		let fees = Fees::from_entries(false, vec![fee(10, None, None)])?;

		let ops = client.fee_operations(&[signed_vote(Some(fees))?])?;
		assert_eq!(ops.len(), 1);
		assert_eq!(ops[0].amount, Amount::from(10u64));
		assert_eq!(ops[0].token.to_string(), base.to_string());
		assert_eq!(ops[0].to.to_string(), generate_ed25519_ref(ISSUER_SEED).to_string());
		Ok(())
	}

	#[test]
	fn fee_operations_skip_optional_zero_fee() -> TestResult {
		let client = test_client();
		let fees = Fees::from_entries(false, vec![fee(10, None, None), fee(0, None, None)])?;
		assert!(client
			.fee_operations(&[signed_vote(Some(fees))?])?
			.is_empty());

		Ok(())
	}

	#[test]
	fn fee_operations_honor_explicit_pay_to_and_token() -> TestResult {
		let client = test_client();
		let pay_to = generate_ed25519_ref(0xB2);
		let token = generate_identifier_ref(0xC3, KeyPairType::TOKEN, 0);
		let fees = Fees::from_entries(false, vec![fee(5, Some(Arc::clone(&pay_to)), Some(Arc::clone(&token)))])?;

		let ops = client.fee_operations(&[signed_vote(Some(fees))?])?;
		assert_eq!(ops[0].to.to_string(), pay_to.to_string());
		assert_eq!(ops[0].token.to_string(), token.to_string());
		Ok(())
	}

	#[test]
	fn fee_operations_prefer_base_token_entry() -> TestResult {
		let client = test_client();
		let base = client.base_token()?;
		let other = generate_identifier_ref(0xC4, KeyPairType::TOKEN, 0);
		let fees = Fees::from_entries(
			false,
			vec![fee(7, None, Some(Arc::clone(&other))), fee(9, None, Some(Arc::clone(&base)))],
		)?;

		let ops = client.fee_operations(&[signed_vote(Some(fees))?])?;
		assert_eq!(ops[0].token.to_string(), base.to_string());
		assert_eq!(ops[0].amount, Amount::from(9u64));
		Ok(())
	}

	#[test]
	fn ledger_code_matches_only_exact_code() {
		use keetanetwork_error::{NodeErrorParts, NodeErrorType};

		let parts = NodeErrorParts {
			kind: NodeErrorType::Ledger,
			code: "LEDGER_SUCCESSOR_VOTE_EXISTS".to_owned(),
			message: "exists".to_owned(),
			..Default::default()
		};

		let error = ClientError::Node { source: Box::new(KeetaNetError::from(parts)) };
		assert!(is_ledger_code(&error, "LEDGER_SUCCESSOR_VOTE_EXISTS"));
		assert!(!is_ledger_code(&error, "LEDGER_INSUFFICIENT_VOTING_WEIGHT"));
	}

	fn vote_by(issuer: &AccountRef, from_secs: i64, to_secs: i64) -> Result<Vote, Box<dyn core::error::Error>> {
		let (from, to) = validity_blocktime(from_secs, to_secs);
		Ok(VoteBuilder::new()
			.serial(1u8)
			.issuer(Arc::clone(issuer))
			.validity(from, to)
			.add_block(BlockHash::from([7u8; 32]))
			.build_signed(issuer.as_ref())?)
	}

	#[test]
	fn staple_moment_lands_within_the_vote_window() -> TestResult {
		let issuer = generate_ed25519_ref(ISSUER_SEED);
		let vote = vote_by(&issuer, 0, 60)?;
		let validity = *vote.validity();

		let chosen = staple_moment(&[vote], BlockTime::now());
		assert!(chosen.unix_millis() >= validity.from.unix_millis());
		assert!(chosen.unix_millis() <= validity.to.unix_millis());
		Ok(())
	}

	fn pick(key: &str) -> RepPick {
		RepPick {
			key: key.to_owned(),
			weight: BigInt::from(1u8),
			transport: Arc::new(GeneratedTransport::new("http://localhost", reqwest::Client::new())),
		}
	}

	#[test]
	fn contacts_include_every_rep_in_the_temporary_round() {
		let picks = vec![pick("a"), pick("b")];
		assert_eq!(contacts_for(picks, &[]).len(), 2);
	}

	#[test]
	fn contacts_in_permanent_round_map_to_prior_vote_issuers() -> TestResult {
		let rep_a = generate_ed25519_ref(0xA1);
		let rep_b = generate_ed25519_ref(0xB2);
		let picks = vec![pick(&rep_a.to_string()), pick(&rep_b.to_string())];

		let prior = vec![vote_by(&rep_a, 0, 60)?];
		let contacts = contacts_for(picks, &prior);
		assert_eq!(contacts.len(), 1);
		assert_eq!(contacts[0].key, rep_a.to_string());
		Ok(())
	}
}
