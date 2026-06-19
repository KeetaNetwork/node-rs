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

#[cfg(feature = "std")]
use core::str::FromStr;

use futures::future::{select, Either};
use futures::pin_mut;
use futures::stream::{FuturesUnordered, StreamExt};
use keetanetwork_account::{Account, GenericAccount, KeyNETWORK, KeyPairType};
use keetanetwork_block::{
	AccountRef, Amount, Block, BlockBuilder, BlockHash, BlockPurpose, BlockTime, Hashable, Operation, Send,
};
use keetanetwork_error::KeetaNetError;
use keetanetwork_vote::{Fee, Fees, ValidationConfig, Vote, VoteQuote, VoteStaple};
use num_bigint::BigInt;
use snafu::ResultExt;

use crate::builder::TransactionBuilder;
use crate::config::ClientConfig;
use crate::error::{AccountSnafu, BlockSnafu, ClientError, VoteSnafu};
use crate::math::{meets_quorum, most_common_hash, next_backoff, overlapping_moment};
use crate::model::{
	AccountState, Acl, Certificate, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum, Representative,
	TokenBalance, TransmitOptions,
};
use crate::rep::{RepBook, RepPart, RepRecord, RepRef, SmallRng};
use crate::runtime::{Runtime, TaskHandle};
use crate::sync::{Mutex, RwLock};
use crate::transport::{LedgerSide, NodeTransport, TransportFactory};

#[cfg(feature = "std")]
use {
	crate::generated::Client as Transport, crate::model::RepStatus, crate::network::Network, crate::rep::RepEndpoint,
	crate::runtime::TokioRuntime, crate::transport::GeneratedTransportFactory, std::sync::OnceLock,
};

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

/// A representative paired with the head block hash and height it reports for
/// an account, used to detect and reconcile divergence during a sync.
struct RepHead {
	pick: RepPick,
	head: Option<(String, Amount)>,
}

/// Representatives' own votes for a pending successor block, sorted into
/// permanent and temporary buckets plus the representatives that returned no
/// vote, as gathered during account recovery.
#[derive(Default)]
struct RecoveredVotes {
	perm_votes: Vec<Vote>,
	temp_votes: Vec<Vote>,
	perm_keys: Vec<String>,
	missing: Vec<RepPick>,
}

impl RecoveredVotes {
	/// The hashes of the blocks covered by a sample vote (permanent first,
	/// then temporary), or `None` when nothing was recovered.
	fn block_hashes(&self) -> Option<Vec<String>> {
		let sample = self
			.perm_votes
			.first()
			.or_else(|| self.temp_votes.first())?;
		Some(
			sample
				.blocks()
				.iter()
				.map(|hash| hash.to_string())
				.collect(),
		)
	}
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
///
/// See the [crate-level example](crate) for building and transmitting a block.
#[derive(Clone, Debug)]
pub struct KeetaClient {
	inner: Arc<Inner>,
}

/// Build a client for a well-known [`Network`], seeded with its default
/// representatives and network identifier.
///
/// # Errors
///
/// - [`ClientError::Account`] -- a representative key in the network registry
///   fails to parse.
///
/// # Examples
///
/// ```
/// use keetanetwork_client::{KeetaClient, Network};
///
/// let client = KeetaClient::try_from(Network::Test)?;
/// # let _ = client;
/// # Ok::<(), keetanetwork_client::ClientError>(())
/// ```
#[cfg(feature = "std")]
impl TryFrom<Network> for KeetaClient {
	type Error = ClientError;

	fn try_from(network: Network) -> Result<Self, Self::Error> {
		let config = network.config()?;
		let client = Self::with_representatives(config.representatives, ClientConfig::default());
		Ok(client.with_network(config.network_id))
	}
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
		let parts = reps.into_iter().map(|rep| RepPart {
			key: rep.account().to_string(),
			url: rep.api_url().to_owned(),
			weight: rep.weight().clone(),
		});

		Self::with_parts(parts, factory, Arc::new(TokioRuntime), config, false)
	}

	#[cfg(feature = "std")]
	fn single(base_url: &str, http: reqwest::Client, config: ClientConfig) -> Self {
		let factory = Arc::new(GeneratedTransportFactory::new(http));
		// An anonymous single-rep client has no account, so it keys the rep by
		// its API URL; the weight is moot with a single representative.
		let part = RepPart { key: base_url.to_owned(), url: base_url.to_owned(), weight: BigInt::from(1u8) };

		Self::with_parts([part], factory, Arc::new(TokioRuntime), config, true)
	}

	/// Construct a client from explicit [`RepPart`] representatives, an
	/// injected [`TransportFactory`] (used to bind each rep and any later
	/// discovered ones), and a [`Runtime`].
	pub fn with_parts(
		reps: impl IntoIterator<Item = RepPart>,
		factory: Arc<dyn TransportFactory>,
		runtime: Arc<dyn Runtime>,
		config: ClientConfig,
		single_rep: bool,
	) -> Self {
		let mut records = Vec::new();
		let mut transports = BTreeMap::new();
		for RepPart { key, url, weight } in reps {
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
		let now = self.inner.runtime.now_millis();
		let counter = self.inner.rng_counter.fetch_add(1, Ordering::Relaxed);
		let mut rng = SmallRng::seed_from_u64(now ^ counter);
		let chosen = self.inner.reps.pick(&mut rng)?;
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
		let millis = self.inner.runtime.unix_millis();
		BlockTime::from_unix_millis(millis).unwrap_or_default()
	}

	/// Build a generated transport for the first representative, for endpoints
	/// not covered by this wrapper.
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
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to query
	/// - [`ClientError::Transport`] -- the rep-listing request failed at the transport layer
	/// - [`ClientError::Node`] -- the node rejected the rep-listing request
	pub async fn discover_representatives(&self) -> Result<(), ClientError> {
		let entries = self.fetch_rep_entries().await?;
		self.apply_reps(&entries, true);
		Ok(())
	}

	/// Fetch the representative set as `(key, weight, api_url)` entries.
	async fn fetch_rep_entries(&self) -> Result<Vec<RepEntry>, ClientError> {
		let representatives = self.representatives().await?;
		let entries = representatives
			.into_iter()
			.map(|rep| (rep.account, rep.weight.as_bigint().clone(), rep.api_url))
			.collect();
		Ok(entries)
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
				Some(Ok(response)) => {
					self.boost(&pick.key);
					return Ok(response);
				}
				Some(Err(error)) => {
					if self.try_recover_on_error(&error).await {
						continue;
					}
					self.decay(&pick.key);
					error
				}
				None => {
					self.decay(&pick.key);
					ClientError::Timeout
				}
			};

			if attempt >= max_retries {
				return Err(error);
			}

			attempt += 1;

			let backoff = Duration::from_millis(delay);
			self.inner.runtime.sleep(backoff).await;

			delay = next_backoff(delay, max_backoff);
		}
	}

	/// Await a transport call, bounding it by the configured request timeout
	/// (`None` on timeout); an unset timeout awaits indefinitely.
	async fn run_call<T>(
		&self,
		future: impl Future<Output = Result<T, ClientError>>,
	) -> Option<Result<T, ClientError>> {
		let timeout_ms = self.inner.config.request_timeout_ms;
		if timeout_ms == 0 {
			return Some(future.await);
		}

		let duration = Duration::from_millis(timeout_ms);
		let timer = self.inner.runtime.sleep(duration);
		pin_mut!(future);
		pin_mut!(timer);

		match select(future, timer).await {
			Either::Left((result, _)) => Some(result),
			Either::Right(((), _)) => None,
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
	///
	/// Returns `true` once any representative accepts the staple.
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to publish to
	/// - [`ClientError::Transport`] -- every publish attempt failed at the transport layer
	/// - [`ClientError::Node`] -- every representative rejected the staple
	pub async fn transmit_staple(&self, staple: &VoteStaple) -> Result<bool, ClientError> {
		self.ensure_refresh();

		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let mut requests = FuturesUnordered::new();
		for pick in picks {
			let key = pick.key;
			let transport = pick.transport;

			requests.push(async move { (key, transport.publish_staple(staple).await) });
		}

		let mut accepted = false;
		let mut last_error: Option<ClientError> = None;
		while let Some((key, result)) = requests.next().await {
			match result {
				// A fulfilled publish response counts as success regardless of
				// the returned `publish` flag: the node accepted the staple, and
				// the flag only reports whether this node also voted on it.
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
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to query
	/// - [`ClientError::MissingVote`] -- a representative responded without a vote
	/// - [`ClientError::Node`] -- every representative rejected the vote request
	pub async fn request_vote(&self, blocks: &[Block]) -> Result<Vote, ClientError> {
		let votes = self.request_votes(blocks, &[], &[]).await?;
		let first = votes.into_iter().next();
		first.ok_or(ClientError::MissingVote)
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
			let key = pick.key;
			let weight = pick.weight;
			let transport = pick.transport;

			requests.push(async move {
				let vote = transport
					.create_vote(blocks, prior_votes, quote.as_ref())
					.await;
				(key, weight, vote)
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
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to query
	/// - [`ClientError::MissingQuote`] -- a representative responded without a quote
	/// - [`ClientError::Node`] -- every representative rejected the quote request
	pub async fn request_quote(&self, blocks: &[Block]) -> Result<VoteQuote, ClientError> {
		let quotes = self.request_quotes(blocks, false).await?;
		quotes.into_iter().next().ok_or(ClientError::MissingQuote)
	}

	/// Request vote quotes for `blocks` from every representative, returning
	/// one quote per responding rep without quorum early-exit.
	pub async fn quotes(&self, blocks: &[Block]) -> Result<Vec<VoteQuote>, ClientError> {
		self.request_quotes(blocks, true).await
	}

	/// Request vote quotes for `blocks` from every representative, returning
	/// each valid quote. With `collect_all` unset the collection stops once
	/// the responding weight reaches quorum; quotes do not process blocks, so
	/// a partial set still suffices for fee estimation.
	async fn request_quotes(&self, blocks: &[Block], collect_all: bool) -> Result<Vec<VoteQuote>, ClientError> {
		self.ensure_refresh();

		let (refs, total_weight) = self.inner.reps.snapshot_with_total();
		let picks = self.bind_transports(refs);
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let threshold = self.inner.config.quorum_threshold;
		let mut requests = FuturesUnordered::new();
		for pick in picks {
			let key = pick.key;
			let weight = pick.weight;
			let transport = pick.transport;
			requests.push(async move {
				let quote = transport.create_vote_quote(blocks).await;
				(key, weight, quote)
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
					if !collect_all && meets_quorum(&accumulated, &total_weight, threshold) {
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
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to vote
	/// - [`ClientError::QuorumNotReached`] -- the returned votes did not reach quorum weight
	/// - [`ClientError::FeeRequired`] -- the node requires a fee but no `fee_signer` was supplied
	/// - [`ClientError::Node`] -- a representative rejected the blocks or staple
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

					let backoff = Duration::from_millis(delay);
					self.inner.runtime.sleep(backoff).await;

					delay = next_backoff(delay, self.inner.config.max_backoff_ms);
				}
			}
		}
	}

	/// One temporary-then-permanent voting round, building a fee block when
	/// required, and publishing the assembled staple. Quotes attach only to the
	/// temporary round, since the permanent round votes on the finalized blocks.
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
				.build_fee_block(signer, blocks, &temporary, moment, &options.fee_token_priority)
				.await?;
			all.push(fee_block);
		}

		let permanent = self.request_votes(&all, &temporary, &[]).await?;

		let config = ValidationConfig::default();
		let staple = VoteStaple::try_new(all, permanent, config, moment).context(VoteSnafu)?;

		self.transmit_staple(&staple).await
	}

	/// Synchronize an account whose head height differs across
	/// representatives: pull the missing successor staple from the highest
	/// rep and publish it to the lagging reps.
	///
	/// Returns the staple used to reconcile the lagging reps, or `None` when
	/// the reps already agree or no successor staple is available.
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to query
	/// - [`ClientError::SyncPublishFailed`] -- the lagging reps did not advance after publishing
	/// - [`ClientError::Node`] -- a representative rejected a fetch or publish request
	pub async fn sync_account(&self, account: &AccountRef, publish: bool) -> Result<Option<VoteStaple>, ClientError> {
		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let account_key = account.to_string();

		let mut heads: Vec<RepHead> = Vec::with_capacity(picks.len());
		for pick in picks {
			let head = head_info(&pick.transport, &account_key).await;
			heads.push(RepHead { pick, head });
		}

		heads.sort_by_key(|entry| height_value(&entry.head));

		let highest_index = heads.len() - 1;
		let lowest_height = height_value(&heads[0].head);
		let highest_height = height_value(&heads[highest_index].head);
		if lowest_height == highest_height {
			return Ok(None);
		}

		let lowest_head = match &heads[0].head {
			Some((hash, _)) => hash.clone(),
			None => account.to_opening_hash().to_string(),
		};
		let highest_transport = Arc::clone(&heads[highest_index].pick.transport);

		let successor = match highest_transport.successor_block(&lowest_head).await? {
			Some(block) => block,
			None => return Ok(None),
		};
		let successor_hash = successor.hash().to_string();
		let staple = match self
			.compose_staple_on(&highest_transport, &successor_hash)
			.await?
		{
			Some(staple) => staple,
			None => return Ok(None),
		};

		if publish {
			for entry in &heads {
				if height_value(&entry.head) == lowest_height {
					// Publish serially to every lagging rep; ignore conflicts
					// (e.g. LEDGER_BLOCK_ALREADY_EXISTS) and verify by height.
					let _ = entry.pick.transport.publish_staple(&staple).await;
				}
			}

			let updated = head_info(&heads[0].pick.transport, &account_key).await;
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
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to query
	/// - [`ClientError::RecoverFailed`] -- the pending votes or blocks could not be reassembled
	/// - [`ClientError::FeeRequired`] -- a fee is required but `options.fee_signer` is absent
	/// - [`ClientError::Node`] -- a representative rejected a fetch or publish request
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
		let mut votes = self
			.collect_recover_votes(&picks, &successor_hash, moment, config)
			.await;

		let block_hashes = match votes.block_hashes() {
			Some(hashes) => hashes,
			None => return Ok(None),
		};

		let mut blocks = self.fetch_recover_blocks(&picks, &block_hashes).await?;

		if votes.perm_votes.len() != picks.len() {
			self.top_up_recover_votes(&picks, &mut votes, &mut blocks, moment, &options)
				.await?;
		}
		if votes.perm_votes.is_empty() {
			return Err(ClientError::RecoverFailed);
		}

		let staple_at = staple_moment(&votes.perm_votes, moment);
		let staple = VoteStaple::try_new(blocks, votes.perm_votes, config, staple_at).context(VoteSnafu)?;
		if publish {
			self.transmit_staple(&staple).await?;
		}

		Ok(Some(staple))
	}

	/// Gather each representative's own vote for `successor_hash`, sorting
	/// them into permanent, temporary, and missing buckets.
	async fn collect_recover_votes(
		&self,
		picks: &[RepPick],
		successor_hash: &str,
		moment: BlockTime,
		config: ValidationConfig,
	) -> RecoveredVotes {
		let mut votes = RecoveredVotes::default();
		for pick in picks {
			match self.rep_recover_vote(pick, successor_hash).await {
				Some(vote) if vote.validity().is_permanent_at(moment, config) => {
					votes.perm_votes.push(vote);
					votes.perm_keys.push(pick.key.clone());
				}
				Some(vote) => votes.temp_votes.push(vote),
				None => votes.missing.push(pick.clone()),
			}
		}

		votes
	}

	/// Fetch every voted-on block, trying each representative in turn and
	/// failing when no representative holds a required block.
	async fn fetch_recover_blocks(
		&self,
		picks: &[RepPick],
		block_hashes: &[String],
	) -> Result<Vec<Block>, ClientError> {
		let mut blocks = Vec::with_capacity(block_hashes.len());
		for hash in block_hashes {
			let block = self
				.first_block_on(picks, hash)
				.await?
				.ok_or(ClientError::RecoverFailed)?;
			blocks.push(block);
		}

		Ok(blocks)
	}

	/// The first representative that holds `hash` on either ledger side.
	async fn first_block_on(&self, picks: &[RepPick], hash: &str) -> Result<Option<Block>, ClientError> {
		for pick in picks {
			if let Some(block) = pick.transport.block(hash, Some(LedgerSide::Both)).await? {
				return Ok(Some(block));
			}
		}

		Ok(None)
	}

	/// Top up the recovered votes toward a full permanent quorum: request the
	/// missing temporary votes, originate a fee block when fees are required
	/// and no permanent votes exist, then request the missing permanent votes.
	async fn top_up_recover_votes(
		&self,
		picks: &[RepPick],
		votes: &mut RecoveredVotes,
		blocks: &mut Vec<Block>,
		moment: BlockTime,
		options: &TransmitOptions,
	) -> Result<(), ClientError> {
		if votes.temp_votes.len() != picks.len() {
			let prior = if votes.perm_votes.is_empty() {
				Vec::new()
			} else {
				votes.perm_votes.clone()
			};
			if let Ok(mut more) = self.request_votes_on(&votes.missing, blocks, &prior).await {
				votes.temp_votes.append(&mut more);
			}
		}

		if votes.perm_votes.is_empty() && fees_required(&votes.temp_votes) {
			let signer = options
				.fee_signer
				.as_ref()
				.ok_or(ClientError::FeeRequired)?;
			let fee_block = self
				.build_fee_block(signer, blocks, &votes.temp_votes, moment, &options.fee_token_priority)
				.await?;
			blocks.push(fee_block);
		}

		let missing_perm: Vec<RepPick> = picks
			.iter()
			.filter(|pick| !votes.perm_keys.contains(&pick.key))
			.cloned()
			.collect();

		let mut prior = votes.temp_votes.clone();
		prior.extend(votes.perm_votes.iter().cloned());

		if let Ok(mut more) = self.request_votes_on(&missing_perm, blocks, &prior).await {
			votes.perm_votes.append(&mut more);
		}

		Ok(())
	}

	/// Fetch a representative's own vote for `hash`, preferring the main
	/// ledger (the rep already promoted the staple) and falling back to the
	/// side ledger (the staple is still pending).
	async fn rep_recover_vote(&self, pick: &RepPick, hash: &str) -> Option<Vote> {
		for side in [LedgerSide::Main, LedgerSide::Side] {
			let list = match pick.transport.block_votes(hash, side).await {
				Ok(Some(list)) if !list.is_empty() => list,
				_ => continue,
			};
			if let Some(vote) = rep_vote(list, &pick.key, self.inner.single_rep) {
				return Some(vote);
			}
		}

		None
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
		let config = ValidationConfig::default();
		let staple = VoteStaple::try_new(blocks, votes, config, moment).context(VoteSnafu)?;
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
		priority: &[AccountRef],
	) -> Result<Block, ClientError> {
		let signer_key = signer.to_string();
		let previous = blocks
			.iter()
			.rev()
			.find(|block| block.data().account().to_string() == signer_key)
			.map(|block| block.hash())
			.ok_or(ClientError::FeeRequired)?;

		let mut builder = self.builder(signer);
		builder
			.with_purpose(BlockPurpose::Fee)
			.with_previous(previous)
			.with_date(moment);

		for operation in self.fee_operations(votes, priority)? {
			builder.with_operation(operation);
		}

		let mut blocks = builder.build().await?;
		blocks.pop().ok_or(ClientError::FeeRequired)
	}

	/// Translate the fee schedule carried by `votes` into the `SEND`
	/// operations of a fee block, skipping votes that offer a zero-amount
	/// (optional) fee.
	fn fee_operations(&self, votes: &[Vote], priority: &[AccountRef]) -> Result<Vec<Send>, ClientError> {
		let base_token = self.base_token()?;
		let mut operations = Vec::new();
		for vote in votes {
			let Some(fees) = vote.fees() else {
				continue;
			};
			if fees.entries().any(|fee| fee.amount == Amount::from(0u64)) {
				continue;
			}

			let Some(selected) = select_fee(fees, &base_token, priority) else {
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
		let (_network_address, base_token) = self.base_addresses()?;
		Ok(base_token)
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
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to vote
	/// - [`ClientError::FeeRequired`] -- the node requires a fee but no `fee_signer` was supplied
	/// - [`ClientError::QuorumNotReached`] -- the returned votes did not reach quorum weight
	/// - [`ClientError::Node`] -- a representative rejected the block or staple
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
	///
	/// # Errors
	///
	/// - [`ClientError::NoRepresentatives`] -- no representative is configured to vote
	/// - [`ClientError::QuorumNotReached`] -- the returned votes did not reach quorum weight
	/// - [`ClientError::Block`] -- the SEND block could not be assembled
	/// - [`ClientError::Node`] -- a representative rejected the block or staple
	pub async fn send(
		&self,
		from: &AccountRef,
		to: &AccountRef,
		token: &AccountRef,
		amount: Amount,
	) -> Result<bool, ClientError> {
		let mut builder = self.builder(from);
		builder.send(to, token, amount);
		let blocks = builder.build().await?;

		let options = TransmitOptions { fee_signer: Some(Arc::clone(from)), ..Default::default() };
		let mut accepted = true;
		for block in blocks {
			accepted = self.publish(block, options.clone()).await?;
		}

		Ok(accepted)
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

	/// The total supply of `token`, or `None` when the account reports no
	/// supply (it is not a token account).
	pub async fn token_supply(&self, token: impl AsRef<str>) -> Result<Option<Amount>, ClientError> {
		let state = self.state(token).await?;
		Ok(state.supply)
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

	/// The head block of `account` paired with its height, or `None` when the
	/// account has no blocks.
	pub async fn account_head_info(&self, account: impl AsRef<str>) -> Result<Option<(Block, Amount)>, ClientError> {
		let account = account.as_ref().to_owned();
		self.dispatch_any(move |t| {
			let account = account.clone();
			async move { t.account_head_info(&account).await }
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
			let key = pick.key;
			let transport = pick.transport;
			requests.push(async move { (key, transport.pending_block(&account).await) });
		}

		// Tally candidate blocks by hash so the block seen on the most reps
		// wins: reps may briefly disagree on the pending head, so majority
		// agreement is the safest single answer to return.
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

		let majority_hash = most_common_hash(&observed);
		let majority_block = majority_hash.and_then(|hash| blocks_by_hash.remove(&hash));

		match majority_block {
			Some(block) => Ok(Some(block)),
			None if any_success => Ok(None),
			None => match last_error {
				Some(error) => Err(error),
				None => Ok(None),
			},
		}
	}

	/// The vote staple covering `blockhash` on the main ledger, assembled from
	/// the first representative that holds votes for it, or `None` when no
	/// representative has the staple.
	pub async fn vote_staple(&self, blockhash: impl AsRef<str>) -> Result<Option<VoteStaple>, ClientError> {
		self.ensure_refresh();

		let blockhash = blockhash.as_ref();
		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let mut last_error: Option<ClientError> = None;
		for pick in &picks {
			match self.compose_staple_on(&pick.transport, blockhash).await {
				Ok(Some(staple)) => {
					self.boost(&pick.key);
					return Ok(Some(staple));
				}
				Ok(None) => self.boost(&pick.key),
				Err(error) => {
					self.decay(&pick.key);
					last_error = Some(error);
				}
			}
		}

		match last_error {
			Some(error) => Err(error),
			None => Ok(None),
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

			let Some(hash) = next_cursor else {
				break;
			};

			let advanced = Some(&hash) != cursor.as_ref();
			let full_page = page_len as i64 >= limit;
			if !advanced || !full_page {
				break;
			}

			cursor = Some(hash);
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

	/// Per-representative liveness: query each known rep's statistics once
	/// and report whether it answered, attaching its stats when it did.
	#[cfg(feature = "std")]
	pub async fn network_status(&self) -> Result<Vec<RepStatus>, ClientError> {
		self.ensure_refresh();
		let picks = self.snapshot_picks();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let mut requests = FuturesUnordered::new();
		for pick in picks {
			requests.push(async move {
				let stats = pick.transport.node_stats().await.ok();
				RepStatus { representative: pick.key, online: stats.is_some(), stats }
			});
		}

		let mut statuses = Vec::new();
		while let Some(status) = requests.next().await {
			statuses.push(status);
		}

		Ok(statuses)
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

	/// Derive the network address and its base token (the `TOKEN` identifier
	/// at operation index zero) for the configured network.
	pub(crate) fn base_addresses(&self) -> Result<(AccountRef, AccountRef), ClientError> {
		let network = self.network().ok_or(ClientError::UnsupportedNetwork)?;
		let id = u64::try_from(&network).map_err(|_| ClientError::UnsupportedNetwork)?;
		let network_account = Account::<KeyNETWORK>::generate_network_address(id).context(AccountSnafu)?;
		let token = network_account
			.generate_identifier(KeyPairType::TOKEN, None, 0)
			.context(AccountSnafu)?;

		let network_address = Arc::new(GenericAccount::Network(network_account));
		let base_token = Arc::new(token);
		Ok((network_address, base_token))
	}

	/// The account of the client's first representative, parsed from its
	/// published key; used as the default delegate at genesis.
	#[cfg(feature = "std")]
	pub(crate) fn first_rep_account(&self) -> Result<Option<AccountRef>, ClientError> {
		match self.inner.reps.snapshot().into_iter().next() {
			Some(rep) => {
				let account = GenericAccount::from_str(&rep.key).map_err(|source| ClientError::Account { source })?;
				Ok(Some(Arc::new(account)))
			}
			None => Ok(None),
		}
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

	/// Build and sign a single block over this client's network context:
	/// stamp the network/subnet, set account, operations, an optional distinct
	/// signer, an optional purpose/date, and either chain onto `previous` or
	/// open the chain.
	pub(crate) fn seal_block(
		&self,
		account: &AccountRef,
		signer: &AccountRef,
		previous: Option<BlockHash>,
		purpose: Option<BlockPurpose>,
		date: Option<BlockTime>,
		operations: Vec<Operation>,
	) -> Result<Block, ClientError> {
		let mut builder = self
			.apply_network(BlockBuilder::default())
			.with_account(Arc::clone(account))
			.with_operations(operations);

		if signer.to_string() != account.to_string() {
			builder = builder.with_signer(Arc::clone(signer));
		}
		if let Some(purpose) = purpose {
			builder = builder.with_purpose(purpose);
		}
		if let Some(date) = date {
			builder = builder.with_date(date);
		}

		builder = match previous {
			Some(prev) => builder.with_previous(prev),
			None => builder.as_opening(),
		};

		let unsigned = builder.build().context(BlockSnafu)?;
		unsigned.sign().context(BlockSnafu)
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
	let elapsed = runtime.now_millis().saturating_sub(*stored_at);
	let ttl_ms = ttl.as_millis() as u64;
	if elapsed < ttl_ms {
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
fn rep_vote(votes: Vec<Vote>, rep_key: &str, single_rep: bool) -> Option<Vote> {
	let own: Vec<Vote> = votes
		.iter()
		.filter(|vote| vote.issuer().to_string() == rep_key)
		.cloned()
		.collect();

	match (own.is_empty(), single_rep) {
		(true, true) => pick_best_vote(votes),
		_ => pick_best_vote(own),
	}
}

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

/// The token a fee entry is paid in, treating an implicit (`None`) token as
/// the network base token.
fn fee_token(fee: &Fee, base_token: &AccountRef) -> String {
	match &fee.token {
		Some(token) => token.to_string(),
		None => base_token.to_string(),
	}
}

/// Choose which fee entry to pay: the highest-ranked `priority` token wins
/// (an implicit `None` token counts as the base token); otherwise prefer the
/// base-token entry, then fall back to the first entry.
fn select_fee<'a>(fees: &'a Fees, base_token: &AccountRef, priority: &[AccountRef]) -> Option<&'a Fee> {
	priority
		.iter()
		.find_map(|wanted| {
			fees.entries()
				.find(|fee| fee_token(fee, base_token) == wanted.to_string())
		})
		.or_else(|| {
			fees.entries()
				.find(|&fee| fee_pays_base_token(fee, base_token))
		})
		.or_else(|| fees.entries().next())
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

		let ops = client.fee_operations(&[signed_vote(Some(fees))?], &[])?;
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
			.fee_operations(&[signed_vote(Some(fees))?], &[])?
			.is_empty());

		Ok(())
	}

	#[test]
	fn fee_operations_honor_explicit_pay_to_and_token() -> TestResult {
		let client = test_client();
		let pay_to = generate_ed25519_ref(0xB2);
		let token = generate_identifier_ref(0xC3, KeyPairType::TOKEN, 0);
		let fees = Fees::from_entries(false, vec![fee(5, Some(Arc::clone(&pay_to)), Some(Arc::clone(&token)))])?;

		let ops = client.fee_operations(&[signed_vote(Some(fees))?], &[])?;
		assert_eq!(ops[0].to.to_string(), pay_to.to_string());
		assert_eq!(ops[0].token.to_string(), token.to_string());
		Ok(())
	}

	#[test]
	fn fee_operations_select_the_payable_entry() -> TestResult {
		let client = test_client();
		let base = client.base_token()?;
		let a = generate_identifier_ref(0xC4, KeyPairType::TOKEN, 0);
		let b = generate_identifier_ref(0xC5, KeyPairType::TOKEN, 0);
		let absent = generate_identifier_ref(0xC6, KeyPairType::TOKEN, 0);

		let cases = [
			// base preferred when no priority is given
			(
				vec![fee(7, None, Some(Arc::clone(&a))), fee(9, None, Some(Arc::clone(&base)))],
				vec![],
				Arc::clone(&base),
				9u64,
			),
			// priority overrides the base default
			(
				vec![fee(7, None, Some(Arc::clone(&a))), fee(9, None, Some(Arc::clone(&base)))],
				vec![Arc::clone(&a)],
				Arc::clone(&a),
				7,
			),
			// priority is ranked highest first
			(
				vec![
					fee(7, None, Some(Arc::clone(&b))),
					fee(8, None, Some(Arc::clone(&a))),
					fee(9, None, Some(Arc::clone(&base))),
				],
				vec![Arc::clone(&a), Arc::clone(&b)],
				Arc::clone(&a),
				8,
			),
			// unmatched priority falls back to base
			(
				vec![fee(7, None, Some(Arc::clone(&a))), fee(9, None, Some(Arc::clone(&base)))],
				vec![Arc::clone(&absent)],
				Arc::clone(&base),
				9,
			),
			// priority matches the implicit (`None`) base entry
			(
				vec![fee(7, None, Some(Arc::clone(&a))), fee(9, None, None)],
				vec![Arc::clone(&base)],
				Arc::clone(&base),
				9,
			),
		];

		for (entries, priority, token, amount) in cases {
			let fees = Fees::from_entries(false, entries)?;
			let ops = client.fee_operations(&[signed_vote(Some(fees))?], &priority)?;
			assert_eq!(ops[0].token.to_string(), token.to_string());
			assert_eq!(ops[0].amount, Amount::from(amount));
		}

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
	fn rep_vote_keeps_only_the_reps_own_vote() -> TestResult {
		let rep_a = generate_ed25519_ref(0xA1);
		let rep_b = generate_ed25519_ref(0xB2);
		// rep_b's vote outlives rep_a's, yet rep_a must still get its own vote.
		let votes = vec![vote_by(&rep_a, 0, 60)?, vote_by(&rep_b, 0, 600)?];

		let chosen = rep_vote(votes, &rep_a.to_string(), false).ok_or("rep_a must have a vote")?;
		assert_eq!(chosen.issuer().to_string(), rep_a.to_string());
		Ok(())
	}

	#[test]
	fn rep_vote_absent_issuer_is_none_for_multi_rep() -> TestResult {
		let rep_a = generate_ed25519_ref(0xA1);
		let rep_b = generate_ed25519_ref(0xB2);

		let votes = vec![vote_by(&rep_b, 0, 60)?];
		assert!(rep_vote(votes, &rep_a.to_string(), false).is_none());
		Ok(())
	}

	#[test]
	fn rep_vote_single_rep_falls_back_to_latest() -> TestResult {
		let rep_a = generate_ed25519_ref(0xA1);
		let rep_b = generate_ed25519_ref(0xB2);
		let votes = vec![vote_by(&rep_a, 0, 60)?, vote_by(&rep_b, 0, 600)?];

		// A URL key matches no issuer; the single-rep client keeps the latest.
		let chosen = rep_vote(votes, "http://localhost", true).ok_or("single-rep must fall back to a vote")?;
		assert_eq!(chosen.issuer().to_string(), rep_b.to_string());
		Ok(())
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
