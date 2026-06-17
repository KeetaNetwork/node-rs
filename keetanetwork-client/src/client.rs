//! Ergonomic, domain-typed wrapper over the generated transport client.

use core::future::Future;
use core::str::FromStr;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::stream::{FuturesUnordered, StreamExt};
use keetanetwork_account::{Account, GenericAccount, KeyNETWORK, KeyPairType};
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, Block, BlockBuilder, BlockHash, BlockPurpose, BlockTime, CreateIdentifier,
	Hashable, IdentifierCreateArguments, ManageCertificate, ModifyPermissions, Operation, Receive, Send, SetInfo,
	SetRep, TokenAdminModifyBalance, TokenAdminSupply,
};
use keetanetwork_error::KeetaNetError;
use keetanetwork_vote::{Fee, ValidationConfig, Vote, VoteQuote, VoteStaple};
use num_bigint::BigInt;
use parking_lot::{Mutex, RwLock};
use progenitor_client::ResponseValue;
use snafu::ResultExt;
use tokio::task::JoinHandle;

use crate::config::ClientConfig;
use crate::error::{AccountSnafu, AmountSnafu, ApiError, BlockSnafu, ClientError, DecodeSnafu, VoteSnafu};
use crate::generated::{types, Client as Transport};
use crate::math::{meets_quorum, most_common_hash, next_backoff, overlapping_moment};
use crate::rep::{RepEndpoint, RepHandle, RepPick, RepState};

/// A token balance entry for an account.
#[derive(Debug, Clone)]
pub struct TokenBalance {
	/// Token account address.
	pub token: String,
	/// Settled balance.
	pub balance: Amount,
	/// Pending (unreceived) balance.
	pub pending: Amount,
}

/// A representative and its voting weight.
#[derive(Debug, Clone)]
pub struct Representative {
	/// Representative account address.
	pub account: String,
	/// Voting weight.
	pub weight: Amount,
	/// REST API base URL the representative can be reached at, when the node
	/// advertises it (the plural `representatives` endpoint includes this; the
	/// singular lookup does not).
	pub api_url: Option<String>,
}

/// A point-in-time ledger checksum.
#[derive(Debug, Clone)]
pub struct LedgerChecksum {
	/// XOR checksum of the ledger.
	pub checksum: Amount,
	/// Approximate moment the checksum was taken (ISO 8601).
	pub moment: Option<String>,
	/// Half the measurement window, in milliseconds.
	pub moment_range: Option<f64>,
}

/// A history entry: a verified vote staple with its id and timestamp.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
	/// The verified vote staple.
	pub staple: VoteStaple,
	/// Hexadecimal vote staple id.
	pub id: Option<String>,
	/// ISO 8601 timestamp.
	pub timestamp: Option<String>,
}

/// An access-control entry granting a principal permissions over a target.
#[derive(Debug, Clone)]
pub struct Acl {
	/// Principal the permissions are granted to.
	pub principal: Option<String>,
	/// Entity the ACL is keyed under.
	pub entity: Option<String>,
	/// Target the permissions apply to.
	pub target: Option<String>,
	/// Permission bitmaps as `0x`-prefixed hexadecimal values.
	pub permissions: Vec<String>,
}

/// A certificate and its intermediate chain.
#[derive(Debug, Clone)]
pub struct Certificate {
	/// PEM-encoded certificate.
	pub certificate: String,
	/// PEM-encoded intermediate certificates.
	pub intermediates: Vec<String>,
}

/// Pagination/range bounds for [`KeetaClient::chain_page`].
///
/// `start`/`end` are block-hash cursors; `limit` caps the page size (the node
/// enforces its own maximum).
#[derive(Debug, Clone, Default)]
pub struct ChainQuery {
	/// Start cursor (block hash) to page from.
	pub start: Option<String>,
	/// End cursor (block hash) to stop at.
	pub end: Option<String>,
	/// Maximum entries to return in the page.
	pub limit: Option<i64>,
}

/// Pagination/range bounds for [`KeetaClient::history_page`] and
/// [`KeetaClient::global_history_page`].
#[derive(Debug, Clone, Default)]
pub struct HistoryQuery {
	/// Start cursor (block hash) to page from.
	pub start: Option<String>,
	/// Maximum entries to return in the page.
	pub limit: Option<i64>,
}

/// A snapshot of an account's ledger state.
#[derive(Debug, Clone)]
pub struct AccountState {
	/// Representative account address, if one is set.
	pub representative: Option<String>,
	/// Head block hash (hex), if the account has any blocks.
	pub head: Option<String>,
	/// Head block height, if known.
	pub height: Option<Amount>,
	/// Per-token balances held by the account.
	pub balances: Vec<TokenBalance>,
}

/// Bookkeeping for the background representative-refresh task.
#[derive(Debug, Default)]
struct RefreshState {
	started: bool,
	handle: Option<JoinHandle<()>>,
}

/// Shared client state behind an [`Arc`], so [`KeetaClient`] is cheap to
/// clone while all clones observe the same representative set, scores, and
/// background refresh task.
#[derive(Debug)]
struct Inner {
	state: RwLock<RepState>,
	config: ClientConfig,
	http: reqwest::Client,
	network: RwLock<Option<BigInt>>,
	subnet: RwLock<Option<BigInt>>,
	/// `true` for the single anonymous-rep client built by [`KeetaClient::new`];
	/// disables weight refresh (no rep accounts to match) and quorum gating.
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
	/// Create a single-representative client targeting `base_url`, e.g.
	/// `http://localhost:8080/api`. Uses [`ClientConfig::default`].
	pub fn new(base_url: impl AsRef<str>) -> Self {
		let http = reqwest::Client::new();
		Self::single(base_url.as_ref(), http, ClientConfig::default())
	}

	/// Create a single-representative client over a pre-configured
	/// [`reqwest::Client`], allowing custom timeouts, TLS, or proxy settings.
	pub fn with_client(base_url: impl AsRef<str>, http: reqwest::Client) -> Self {
		Self::single(base_url.as_ref(), http, ClientConfig::default())
	}

	/// Create a multi-representative client over `reps`, fanning votes and
	/// publishes across them and selecting reps for reads by weighted
	/// reliability.
	pub fn with_representatives(reps: impl IntoIterator<Item = RepEndpoint>, config: ClientConfig) -> Self {
		let http = reqwest::Client::new();
		let handles = reps
			.into_iter()
			.map(|rep| RepHandle {
				key: rep.account().to_string(),
				weight: rep.weight().clone(),
				transport: Transport::new_with_client(rep.api_url(), http.clone()),
			})
			.collect();

		Self::from_parts(handles, http, config, false)
	}

	fn single(base_url: &str, http: reqwest::Client, config: ClientConfig) -> Self {
		let handle = RepHandle {
			key: base_url.to_owned(),
			weight: BigInt::from(1u8),
			transport: Transport::new_with_client(base_url, http.clone()),
		};

		Self::from_parts(vec![handle], http, config, true)
	}

	fn from_parts(reps: Vec<RepHandle>, http: reqwest::Client, config: ClientConfig, single_rep: bool) -> Self {
		Self {
			inner: Arc::new(Inner {
				state: RwLock::new(RepState::new(reps)),
				config,
				http,
				network: RwLock::new(None),
				subnet: RwLock::new(None),
				single_rep,
				refresh: Mutex::new(RefreshState::default()),
			}),
		}
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

	/// Clone the first representative's generated transport for endpoints not
	/// covered by this wrapper.
	pub fn transport(&self) -> Transport {
		self.inner
			.state
			.read()
			.first_transport()
			.unwrap_or_else(|| Transport::new_with_client("", self.inner.http.clone()))
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
		let interval_ms = self.inner.config.update_reps_interval_ms;
		let handle = tokio::spawn(async move {
			let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms.max(1)));
			loop {
				ticker.tick().await;
				let Some(inner) = weak.upgrade() else {
					break;
				};

				let client = KeetaClient { inner };
				let _ = client.update_reps().await;
			}
		});

		refresh.handle = Some(handle);
	}

	/// Refresh known representatives' voting weights from
	/// `GET /representatives`, matching by account.
	async fn update_reps(&self) -> Result<(), ClientError> {
		let signature = self.inner.state.read().sorted_keys().join(",");
		let ttl = Duration::from_millis(self.inner.config.reps_cache_ttl_ms);

		let fetched = match cached_representatives(&signature, ttl) {
			Some(cached) => cached,
			None => {
				let entries = self.fetch_rep_entries().await?;
				store_representatives(&signature, &entries);
				entries
			}
		};

		self.apply_reps(&fetched, self.inner.config.discover_reps);
		Ok(())
	}

	/// Refresh weights *and* add any newly advertised representatives,
	/// bypassing the cache. Mirrors the reference `updateReps(addNewReps =
	/// true)`: existing reps are never removed, only added.
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
		let mut state = self.inner.state.write();

		let weights: Vec<(String, BigInt)> = fetched
			.iter()
			.map(|(key, weight, _)| (key.clone(), weight.clone()))
			.collect();
		state.update_weights(&weights);

		if !discover {
			return;
		}

		for (key, weight, api_url) in fetched {
			let Some(api) = api_url else {
				continue;
			};
			if !state.contains(key) {
				state.add_rep(RepHandle {
					key: key.clone(),
					weight: weight.clone(),
					transport: Transport::new_with_client(api, self.inner.http.clone()),
				});
			}
		}
	}

	/// Dispatch a single-representative call with weighted reliability
	/// selection, retry, exponential backoff, and per-request timeout.
	async fn dispatch_any<T, F, Fut>(&self, call: F) -> Result<ResponseValue<T>, ClientError>
	where
		F: Fn(Transport) -> Fut,
		Fut: Future<Output = Result<ResponseValue<T>, ApiError>>,
	{
		self.ensure_refresh();

		let max_retries = self.inner.config.max_retries;
		let max_backoff = self.inner.config.max_backoff_ms;
		let mut delay = 1u64;
		let mut attempt = 0u32;

		loop {
			let pick = self.inner.state.read().pick();
			let Some(pick) = pick else {
				return Err(ClientError::NoRepresentatives);
			};

			let error = match self.run_call(call(pick.transport)).await {
				Ok(Ok(response)) => {
					self.boost(&pick.key);
					return Ok(response);
				}
				Ok(Err(api)) => {
					let error = ClientError::from(api);
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
			tokio::time::sleep(Duration::from_millis(delay)).await;
			delay = next_backoff(delay, max_backoff);
		}
	}

	/// Await a transport call, bounding it by the configured request timeout
	/// (`Err(())` on timeout); an unset timeout awaits indefinitely.
	async fn run_call<T>(
		&self,
		future: impl Future<Output = Result<ResponseValue<T>, ApiError>>,
	) -> Result<Result<ResponseValue<T>, ApiError>, ()> {
		let timeout_ms = self.inner.config.request_timeout_ms;
		if timeout_ms == 0 {
			return Ok(future.await);
		}

		tokio::time::timeout(Duration::from_millis(timeout_ms), future)
			.await
			.map_err(|_| ())
	}

	/// Auto-sync path for dispatched reads/calls: on a ledger-vote conflict
	/// (`LEDGER_NOT_SUCCESSOR`/`LEDGER_NOT_OPENING`), attempt to
	/// [`sync_account`](Self::sync_account) each contended account. Returns
	/// whether any account synced (the caller then retries without consuming
	/// a retry budget).
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
			.state
			.write()
			.boost(key, self.inner.config.reliability_increment);
	}

	/// Penalize a representative for a failed response (AIMD decrease).
	fn decay(&self, key: &str) {
		let config = &self.inner.config;
		self.inner
			.state
			.write()
			.decay(key, config.reliability_decay, config.reliability_floor);
	}

	/// Publish an assembled vote staple to the node.
	pub async fn transmit_staple(&self, staple: &VoteStaple) -> Result<bool, ClientError> {
		self.ensure_refresh();
		let body = types::PublishVoteStapleBody { votes_and_blocks: B64.encode(staple.as_bytes()) };
		let picks = self.inner.state.read().snapshot();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let mut requests = FuturesUnordered::new();
		for pick in picks {
			let body = body.clone();
			requests.push(async move { (pick.key, pick.transport.publish_vote_staple(&body).await) });
		}

		let mut accepted = false;
		let mut last_error: Option<ClientError> = None;
		while let Some((key, result)) = requests.next().await {
			match result {
				Ok(response) => {
					self.boost(&key);
					if response.into_inner().publish.unwrap_or(false) {
						accepted = true;
					}
				}
				Err(api) => {
					self.decay(&key);
					last_error = Some(ClientError::from(api));
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
		let votes = self.request_votes(blocks, &[]).await?;
		votes.into_iter().next().ok_or(ClientError::MissingVote)
	}

	/// Request votes for `blocks` from every representative concurrently,
	/// attaching `prior_votes` so reps escalate temporary votes into
	/// permanent ones (the second voting round). Returns every successful
	/// vote; errors only when no representative produced one.
	async fn request_votes(&self, blocks: &[Block], prior_votes: &[Vote]) -> Result<Vec<Vote>, ClientError> {
		self.ensure_refresh();
		// In the permanent round, contact only the reps that issued a prior
		// (temporary) vote: the node refuses a permanent vote from a rep that
		// has no temporary vote of its own (`LEDGER_NO_PERM_WITHOUT_SELF_TEMP`).
		// A single-rep client keys its rep by URL rather than account, so it
		// always contacts its lone rep.
		let snapshot = self.inner.state.read().snapshot();
		let picks = if self.inner.single_rep {
			snapshot
		} else {
			contacts_for(snapshot, prior_votes)
		};
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let total_weight: BigInt = picks.iter().map(|pick| pick.weight.clone()).sum();
		let blocks_encoded = encode_blocks(blocks);
		let prior_encoded = encode_votes(prior_votes);
		let mut requests = FuturesUnordered::new();
		for pick in picks {
			// Every contacted rep receives the full prior-vote set, including
			// its own temporary vote, which the node requires to escalate.
			let body =
				types::CreateVoteBody { blocks: blocks_encoded.clone(), votes: prior_encoded.clone(), quote: None };
			requests.push(async move { (pick.key, pick.weight, pick.transport.create_vote(&body).await) });
		}

		let mut votes = Vec::new();
		let mut accumulated = BigInt::from(0u8);
		let mut highest_error: Option<(BigInt, ClientError)> = None;
		while let Some((key, weight, result)) = requests.next().await {
			let outcome = match result {
				Ok(response) => decode_vote_binary(response.into_inner().vote.and_then(|vote| vote.binary)),
				Err(api) => Err(ClientError::from(api)),
			};
			match outcome {
				Ok(vote) => {
					self.boost(&key);
					accumulated += weight;
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

		// Surface the highest-weight failure when the responding reps fall
		// short of quorum.
		if !meets_quorum(&accumulated, &total_weight, self.inner.config.quorum_threshold) {
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
		let body = types::CreateVoteQuoteBody { blocks: encode_blocks(blocks) };
		let (picks, total_weight) = {
			let state = self.inner.state.read();
			(state.snapshot(), state.total_weight())
		};
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let threshold = self.inner.config.quorum_threshold;
		let mut requests = FuturesUnordered::new();
		for pick in picks {
			let body = body.clone();
			requests.push(async move { (pick.key, pick.weight, pick.transport.create_vote_quote(&body).await) });
		}

		let mut quotes = Vec::new();
		let mut accumulated = BigInt::from(0u8);
		let mut last_error: Option<ClientError> = None;
		while let Some((key, weight, result)) = requests.next().await {
			let outcome = match result {
				Ok(response) => decode_quote_binary(response.into_inner().quote.and_then(|quote| quote.binary)),
				Err(api) => Err(ClientError::from(api)),
			};
			match outcome {
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

	/// Request permanent votes for `blocks`, assemble a canonical staple at
	/// `moment`, and publish it.
	pub async fn transmit(
		&self,
		blocks: &[Block],
		config: ValidationConfig,
		moment: BlockTime,
	) -> Result<bool, ClientError> {
		self.transmit_with_optional_fee(blocks, None, config, moment)
			.await
	}

	/// The two-round transmit flow, optionally originating a fee block,
	/// retried on insufficient voting weight.
	///
	/// After the temporary round, if the votes require a fee (a non-zero fee
	/// with no zero-amount option), `fee_signer` originates a
	/// [`BlockPurpose::Fee`] block that joins the permanent round and staple.
	/// When a fee is required but no signer is available, this fails with
	/// [`ClientError::FeeRequired`]. `LEDGER_INSUFFICIENT_VOTING_WEIGHT` is
	/// retried with backoff up to [`ClientConfig::max_retries`].
	async fn transmit_with_optional_fee(
		&self,
		blocks: &[Block],
		fee_signer: Option<&AccountRef>,
		config: ValidationConfig,
		moment: BlockTime,
	) -> Result<bool, ClientError> {
		let mut attempt = 0u32;
		let mut delay = 1u64;
		loop {
			match self
				.transmit_round(blocks, fee_signer, config, moment)
				.await
			{
				Ok(accepted) => return Ok(accepted),
				Err(error) => {
					let retryable = is_ledger_code(&error, "LEDGER_INSUFFICIENT_VOTING_WEIGHT");
					if !retryable || attempt >= self.inner.config.max_retries {
						return Err(error);
					}

					attempt += 1;
					tokio::time::sleep(Duration::from_millis(delay)).await;
					delay = next_backoff(delay, self.inner.config.max_backoff_ms);
				}
			}
		}
	}

	/// One temporary-then-permanent voting round, building a fee block when
	/// required, and publishing the assembled staple.
	async fn transmit_round(
		&self,
		blocks: &[Block],
		fee_signer: Option<&AccountRef>,
		config: ValidationConfig,
		moment: BlockTime,
	) -> Result<bool, ClientError> {
		let temporary = self.request_votes(blocks, &[]).await?;

		let mut all = blocks.to_vec();
		if fees_required(&temporary) {
			let signer = fee_signer.ok_or(ClientError::FeeRequired)?;
			let fee_block = self
				.build_fee_block(signer, blocks, &temporary, moment)
				.await?;
			all.push(fee_block);
		}

		let permanent = self.request_votes(&all, &temporary).await?;
		let staple = VoteStaple::try_new(all.iter().cloned(), permanent, config, moment).context(VoteSnafu)?;

		self.transmit_staple(&staple).await
	}

	/// Synchronize an account whose head height differs across
	/// representatives: pull the missing successor staple from the highest
	/// rep and publish it to the lagging reps.
	pub async fn sync_account(&self, account: &AccountRef, publish: bool) -> Result<Option<VoteStaple>, ClientError> {
		let picks = self.inner.state.read().snapshot();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let account_key = account.to_string();

		let mut infos: Vec<(RepPick, Option<(String, Amount)>)> = Vec::with_capacity(picks.len());
		for pick in picks {
			let info = head_info_on(&pick.transport, &account_key)
				.await
				.unwrap_or(None);
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

		let successor = match successor_on(&infos[highest_index].0.transport, &lowest_head).await? {
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
					let _ = self.transmit_staple_on(&pick.transport, &staple).await;
				}
			}

			let updated = head_info_on(&infos[0].0.transport, &account_key)
				.await
				.unwrap_or(None);
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
	/// `fee_signer` originates a fee block if the recovered votes require a
	/// fee and no permanent votes exist yet. Returns the recovered staple, or
	/// `None` when there is nothing pending to recover.
	pub async fn recover_account(
		&self,
		account: &AccountRef,
		publish: bool,
		fee_signer: Option<&AccountRef>,
	) -> Result<Option<VoteStaple>, ClientError> {
		self.ensure_refresh();
		let successor = match self.pending_block(account.to_string()).await? {
			Some(block) => block,
			None => return Ok(None),
		};
		let successor_hash = successor.hash().to_string();

		let picks = self.inner.state.read().snapshot();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let moment = BlockTime::now();
		let config = ValidationConfig::default();

		let mut perm_votes: Vec<Vote> = Vec::new();
		let mut temp_votes: Vec<Vote> = Vec::new();
		let mut perm_keys: Vec<String> = Vec::new();
		let mut missing: Vec<RepPick> = Vec::new();

		for pick in &picks {
			let best = match votes_on(&pick.transport, &successor_hash, types::GetBlockVotesSide::Side).await {
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
				if let Some(block) = block_on(&pick.transport, hash, types::GetBlockSide::Both).await? {
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
				let signer = fee_signer.ok_or(ClientError::FeeRequired)?;
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

		let blocks_encoded = encode_blocks(blocks);
		let prior_encoded = encode_votes(prior_votes);
		let mut requests = FuturesUnordered::new();
		for pick in reps {
			let body =
				types::CreateVoteBody { blocks: blocks_encoded.clone(), votes: prior_encoded.clone(), quote: None };
			let key = pick.key.clone();
			let transport = pick.transport.clone();
			requests.push(async move { (key, transport.create_vote(&body).await) });
		}

		let mut votes = Vec::new();
		while let Some((key, result)) = requests.next().await {
			let outcome = match result {
				Ok(response) => decode_vote_binary(response.into_inner().vote.and_then(|vote| vote.binary)),
				Err(api) => Err(ClientError::from(api)),
			};
			match outcome {
				Ok(vote) => {
					self.boost(&key);
					votes.push(vote);
				}
				Err(_) => self.decay(&key),
			}
		}

		Ok(votes)
	}

	/// Publish a staple to one specific representative.
	async fn transmit_staple_on(&self, transport: &Transport, staple: &VoteStaple) -> Result<bool, ClientError> {
		let body = types::PublishVoteStapleBody { votes_and_blocks: B64.encode(staple.as_bytes()) };
		let response = transport.publish_vote_staple(&body).await?;
		Ok(response.into_inner().publish.unwrap_or(false))
	}

	/// Assemble the staple covering `block_hash` from one rep's main-ledger
	/// votes and the blocks they cover.
	async fn compose_staple_on(
		&self,
		transport: &Transport,
		block_hash: &str,
	) -> Result<Option<VoteStaple>, ClientError> {
		let votes = match votes_on(transport, block_hash, types::GetBlockVotesSide::Main).await? {
			Some(list) if !list.is_empty() => list,
			_ => return Ok(None),
		};

		let mut blocks = Vec::new();
		for hash in votes[0].blocks() {
			match block_on(transport, &hash.to_string(), types::GetBlockSide::Main).await? {
				Some(block) => blocks.push(block),
				None => return Ok(None),
			}
		}

		let moment = staple_moment(&votes, BlockTime::now());
		let staple = VoteStaple::try_new(blocks, votes, ValidationConfig::default(), moment).context(VoteSnafu)?;
		Ok(Some(staple))
	}

	/// Build and sign a [`BlockPurpose::Fee`] block paying the fees declared
	/// by `votes`, chained after `signer`'s block in `blocks`.
	///
	/// Each fee-bearing vote contributes one `SEND`: the selected fee's
	/// amount to `pay_to` (defaulting to the vote issuer) in `token`
	/// (defaulting to the network base token).
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
	fn apply_network(&self, mut builder: BlockBuilder) -> BlockBuilder {
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
		TransactionBuilder {
			client: self,
			account: Arc::clone(account),
			operations: Vec::new(),
			previous: None,
			purpose: None,
			date: None,
		}
	}

	/// Publish a single block built via [`builder`](Self::builder), paying a
	/// fee with `signer` when the node requires one.
	pub async fn publish(&self, block: Block, signer: &AccountRef) -> Result<bool, ClientError> {
		let account = Arc::clone(block.data().account());
		let mut attempt = 0u32;
		loop {
			let result = self
				.transmit_with_optional_fee(
					core::slice::from_ref(&block),
					Some(signer),
					ValidationConfig::default(),
					BlockTime::now(),
				)
				.await;

			match result {
				Ok(accepted) => return Ok(accepted),
				Err(error) => {
					let recoverable = is_ledger_code(&error, "LEDGER_SUCCESSOR_VOTE_EXISTS");
					if !recoverable || attempt >= 2 {
						return Err(error);
					}
					attempt += 1;
					let _ = self.recover_account(&account, true, Some(signer)).await;
				}
			}
		}
	}

	/// Build, sign, and [`publish`](Self::publish) a SEND of `amount` of
	/// `token` from `from` to `to`.
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
		self.publish(block, from).await
	}

	/// The node software version string.
	pub async fn node_version(&self) -> Result<String, ClientError> {
		let response = self
			.dispatch_any(|t| async move { t.get_node_version().await })
			.await?;

		response
			.into_inner()
			.node
			.ok_or(ClientError::MissingVersion)
	}

	/// The settled balance of `token` held by `account`.
	pub async fn balance(&self, account: impl AsRef<str>, token: impl AsRef<str>) -> Result<Amount, ClientError> {
		let account = account.as_ref().to_owned();
		let token = token.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				let token = token.clone();
				async move { t.get_account_balance(&account, &token).await }
			})
			.await?;

		decode_amount(response.into_inner().balance)
	}

	/// Every token balance held by `account`.
	pub async fn balances(&self, account: impl AsRef<str>) -> Result<Vec<TokenBalance>, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				async move { t.get_account_balances(&account).await }
			})
			.await?;

		decode_balances(response.into_inner().balances)
	}

	/// The full ledger state of `account`: representative, head, height, and
	/// balances.
	pub async fn state(&self, account: impl AsRef<str>) -> Result<AccountState, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				async move { t.get_account_state(&account).await }
			})
			.await?;
		let state = response.into_inner();

		decode_account_state(
			state.representative,
			state.current_head_block,
			state.current_head_block_height,
			state.balances,
		)
	}

	/// The head block of `account`, or `None` when the account has no blocks.
	pub async fn head_block(&self, account: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				async move { t.get_account_head(&account).await }
			})
			.await?;
		decode_block(response.into_inner().block)
	}

	/// The next pending (unreceived) block for `account`, if any.
	pub async fn pending_block(&self, account: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		self.ensure_refresh();
		let account = account.as_ref().to_owned();
		let picks = self.inner.state.read().snapshot();
		if picks.is_empty() {
			return Err(ClientError::NoRepresentatives);
		}

		let mut requests = FuturesUnordered::new();
		for pick in picks {
			let account = account.clone();
			requests.push(async move { (pick.key, pick.transport.get_pending_block(&account).await) });
		}

		// Tally candidate blocks by hash so the block seen on the most reps
		// wins, matching the reference's majority selection.
		let mut blocks_by_hash: HashMap<String, Block> = HashMap::new();
		let mut observed: Vec<String> = Vec::new();
		let mut any_success = false;
		let mut last_error: Option<ClientError> = None;
		while let Some((key, result)) = requests.next().await {
			match result {
				Ok(response) => {
					self.boost(&key);
					any_success = true;
					match decode_block(response.into_inner().block) {
						Ok(Some(block)) => {
							let hash = block.hash().to_string();
							blocks_by_hash.entry(hash.clone()).or_insert(block);
							observed.push(hash);
						}
						Ok(None) => {}
						Err(error) => last_error = Some(error),
					}
				}
				Err(api) => {
					self.decay(&key);
					last_error = Some(ClientError::from(api));
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
		let response = self
			.dispatch_any(move |t| {
				let blockhash = blockhash.clone();
				async move { t.get_block(&blockhash, None).await }
			})
			.await?;
		decode_block(response.into_inner().block)
	}

	/// The block following `blockhash`, if one exists.
	pub async fn successor_block(&self, blockhash: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		let blockhash = blockhash.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let blockhash = blockhash.clone();
				async move { t.get_successor_block(&blockhash).await }
			})
			.await?;

		decode_block(response.into_inner().successor_block)
	}

	/// The block produced by `account` for the given idempotent `key`, if any.
	pub async fn block_by_idempotent(
		&self,
		account: impl AsRef<str>,
		key: impl AsRef<str>,
	) -> Result<Option<Block>, ClientError> {
		let account = account.as_ref().to_owned();
		let key = key.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				let key = key.clone();
				async move { t.get_block_from_idempotent(&account, &key).await }
			})
			.await?;

		decode_block(response.into_inner().block)
	}

	/// A prefix of `account`'s block chain, most recent first.
	pub async fn chain(&self, account: impl AsRef<str>) -> Result<Vec<Block>, ClientError> {
		self.chain_page(account, ChainQuery::default()).await
	}

	/// A single page of `account`'s block chain (most recent first), bounded
	/// by `query`.
	pub async fn chain_page(&self, account: impl AsRef<str>, query: ChainQuery) -> Result<Vec<Block>, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				let query = query.clone();
				async move {
					t.get_account_chain(&account, query.end.as_deref(), query.limit, query.start.as_deref())
						.await
				}
			})
			.await?;

		response
			.into_inner()
			.blocks
			.into_iter()
			.filter_map(|entry| decode_block(entry.block).transpose())
			.collect()
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
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				let query = query.clone();
				async move {
					t.get_account_history(&account, query.limit, query.start.as_deref())
						.await
				}
			})
			.await?;

		decode_history(response.into_inner().history)
	}

	/// The node's global transaction history as verified vote staples.
	pub async fn global_history(&self) -> Result<Vec<HistoryEntry>, ClientError> {
		self.global_history_page(HistoryQuery::default()).await
	}

	/// A single page of the node's global history, bounded by `query`.
	pub async fn global_history_page(&self, query: HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
		let response = self
			.dispatch_any(move |t| {
				let query = query.clone();
				async move {
					t.get_global_history(query.limit, query.start.as_deref())
						.await
				}
			})
			.await?;

		decode_history(response.into_inner().history)
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
		let response = self
			.dispatch_any(move |t| {
				let start = start.clone();
				async move { t.get_vote_staples_after(limit, &start).await }
			})
			.await?;

		decode_staples(response.into_inner().vote_staples)
	}

	/// The node's own representative and its weight.
	pub async fn node_representative(&self) -> Result<Representative, ClientError> {
		let response = self
			.dispatch_any(|t| async move { t.get_node_representative().await })
			.await?;
		decode_representative(response.into_inner())
	}

	/// The weight of representative `rep`.
	pub async fn representative(&self, rep: impl AsRef<str>) -> Result<Representative, ClientError> {
		let rep = rep.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let rep = rep.clone();
				async move { t.get_representative(&rep).await }
			})
			.await?;
		decode_representative(response.into_inner())
	}

	/// Every known representative and its weight.
	pub async fn representatives(&self) -> Result<Vec<Representative>, ClientError> {
		let response = self
			.dispatch_any(|t| async move { t.get_all_representatives().await })
			.await?;
		response
			.into_inner()
			.representatives
			.into_iter()
			.map(decode_representative)
			.collect()
	}

	/// The current ledger checksum.
	pub async fn ledger_checksum(&self) -> Result<LedgerChecksum, ClientError> {
		let response = self
			.dispatch_any(|t| async move { t.get_ledger_checksum().await })
			.await?;
		let checksum = response.into_inner();

		Ok(LedgerChecksum {
			checksum: decode_amount(checksum.checksum)?,
			moment: checksum.moment,
			moment_range: checksum.moment_range,
		})
	}

	/// ACL entries where `account` is the principal (grantee).
	pub async fn acls_by_principal(&self, account: impl AsRef<str>) -> Result<Vec<Acl>, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				async move { t.list_acls_by_principal(&account).await }
			})
			.await?;

		let acls = response
			.into_inner()
			.permissions
			.into_iter()
			.map(decode_acl)
			.collect();

		Ok(acls)
	}

	/// ACL entries granted to `account` as an entity.
	pub async fn acls_by_entity(&self, account: impl AsRef<str>) -> Result<Vec<Acl>, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				async move { t.list_acls_by_entity(&account).await }
			})
			.await?;

		let acls = response
			.into_inner()
			.permissions
			.into_iter()
			.map(decode_acl)
			.collect();

		Ok(acls)
	}

	/// The aggregate ACL-with-info view for principal `account` (opaque).
	pub async fn acls_by_principal_with_info(
		&self,
		account: impl AsRef<str>,
	) -> Result<serde_json::Value, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				async move { t.list_acls_additional(&account).await }
			})
			.await?;

		Ok(serde_json::Value::Object(response.into_inner()))
	}

	/// Every certificate held by `account`.
	pub async fn certificates(&self, account: impl AsRef<str>) -> Result<Vec<Certificate>, ClientError> {
		let account = account.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				async move { t.get_account_certificates(&account).await }
			})
			.await?;

		let certificates = response
			.into_inner()
			.certificates
			.into_iter()
			.filter_map(decode_certificate)
			.collect();

		Ok(certificates)
	}

	/// The certificate of `account` identified by `hash`, if present.
	pub async fn certificate(
		&self,
		account: impl AsRef<str>,
		hash: impl AsRef<str>,
	) -> Result<Option<Certificate>, ClientError> {
		let account = account.as_ref().to_owned();
		let hash = hash.as_ref().to_owned();
		let response = self
			.dispatch_any(move |t| {
				let account = account.clone();
				let hash = hash.clone();
				async move { t.get_certificate_by_hash(&account, &hash).await }
			})
			.await?;

		let found = response.into_inner();

		Ok(decode_certificate(types::Certificate {
			certificate: found.certificate,
			intermediates: found.intermediates,
		}))
	}

	/// Node statistics (opaque ledger + switch metrics).
	pub async fn node_stats(&self) -> Result<serde_json::Value, ClientError> {
		let response = self
			.dispatch_any(|t| async move { t.get_node_stats().await })
			.await?;
		Ok(serde_json::Value::Object(response.into_inner()))
	}

	/// Connected peers (opaque).
	pub async fn node_peers(&self) -> Result<serde_json::Value, ClientError> {
		let response = self
			.dispatch_any(|t| async move { t.get_peers().await })
			.await?;
		Ok(serde_json::Value::Object(response.into_inner()))
	}

	/// Ledger state for several `accounts` in one call.
	pub async fn states(&self, accounts: &[&str]) -> Result<Vec<AccountState>, ClientError> {
		let accounts = accounts.join(",");
		let response = self
			.dispatch_any(move |t| {
				let accounts = accounts.clone();
				async move { t.get_account_states(&accounts).await }
			})
			.await?;

		response
			.into_inner()
			.into_iter()
			.map(|item| {
				decode_account_state(
					item.representative,
					item.current_head_block,
					item.current_head_block_height,
					item.balances,
				)
			})
			.collect()
	}
}

/// Fluent builder for a single account's block.
///
/// Operations are accumulated synchronously against one originating account;
/// [`build`](Self::build) then resolves the block context and seals the block.
/// Each operation has a convenience method covering its common shape, plus a
/// typed `*_op` variant (where the operation carries rarely-used optional
/// fields) and the generic [`with_operation`](Self::with_operation) escape
/// hatch.
///
/// Create one with [`KeetaClient::builder`].
#[must_use = "a TransactionBuilder does nothing until `build` is called"]
pub struct TransactionBuilder<'a> {
	client: &'a KeetaClient,
	account: AccountRef,
	operations: Vec<Operation>,
	previous: Option<BlockHash>,
	purpose: Option<BlockPurpose>,
	date: Option<BlockTime>,
}

impl TransactionBuilder<'_> {
	/// Append a SEND of `amount` of `token` to `to`.
	///
	/// For external reference data, pass a [`Send`] to
	/// [`with_operation`](Self::with_operation).
	pub fn send(self, to: &AccountRef, token: &AccountRef, amount: Amount) -> Self {
		self.with_operation(Send { to: Arc::clone(to), amount, token: Arc::clone(token), external: None })
	}

	/// Append a RECEIVE claiming `amount` of `token` sent by `from`.
	///
	/// For exact-match or forwarding, pass a [`Receive`] to
	/// [`with_operation`](Self::with_operation).
	pub fn receive(self, from: &AccountRef, token: &AccountRef, amount: Amount) -> Self {
		self.with_operation(Receive {
			amount,
			token: Arc::clone(token),
			from: Arc::clone(from),
			exact: false,
			forward: None,
		})
	}

	/// Append a block setting the originator's representative to `to`.
	pub fn set_rep(self, to: &AccountRef) -> Self {
		self.with_operation(SetRep { to: Arc::clone(to) })
	}

	/// Append a block setting the originator's on-chain info.
	pub fn set_info(self, info: SetInfo) -> Self {
		self.with_operation(info)
	}

	/// Append a block modifying the permissions granted by the originator.
	pub fn modify_permissions(self, permissions: ModifyPermissions) -> Self {
		self.with_operation(permissions)
	}

	/// Append a block creating `identifier` under the originator.
	pub fn create_identifier(
		self,
		identifier: &AccountRef,
		create_arguments: Option<IdentifierCreateArguments>,
	) -> Self {
		self.with_operation(CreateIdentifier { identifier: Arc::clone(identifier), create_arguments })
	}

	/// Append a block adjusting the supply of the originating token.
	pub fn modify_token_supply(self, amount: Amount, method: AdjustMethod) -> Self {
		self.with_operation(TokenAdminSupply { amount, method })
	}

	/// Append a block adjusting the originator's balance of `token`.
	pub fn modify_token_balance(self, token: &AccountRef, amount: Amount, method: AdjustMethod) -> Self {
		self.with_operation(TokenAdminModifyBalance { token: Arc::clone(token), amount, method })
	}

	/// Append a block adding or removing a certificate on the originator.
	pub fn manage_certificate(self, certificate: ManageCertificate) -> Self {
		self.with_operation(certificate)
	}

	/// Append an arbitrary operation. Escape hatch for operations without a
	/// dedicated convenience method.
	pub fn with_operation(mut self, operation: impl Into<Operation>) -> Self {
		self.operations.push(operation.into());
		self
	}

	/// Override the resolved `previous` hash, skipping the ledger head lookup.
	///
	/// Useful when chaining a block after another not-yet-published block.
	pub fn with_previous(mut self, previous: BlockHash) -> Self {
		self.previous = Some(previous);
		self
	}

	/// Override the block purpose (defaults to the [`BlockPurpose`] default).
	pub fn with_purpose(mut self, purpose: BlockPurpose) -> Self {
		self.purpose = Some(purpose);
		self
	}

	/// Override the block timestamp (defaults to the moment of [`build`](Self::build)).
	pub fn with_date(mut self, date: BlockTime) -> Self {
		self.date = Some(date);
		self
	}

	/// Resolve the block context and seal the block.
	///
	/// `previous` is the override from [`with_previous`](Self::with_previous)
	/// when set, otherwise the originator's current head (the account opening
	/// hash when it has no blocks yet); network/subnet come from the client
	/// configuration. The originator's key seals the block, which is then
	/// ready to [`transmit`](KeetaClient::transmit).
	pub async fn build(self) -> Result<Block, ClientError> {
		let mut builder = self
			.client
			.apply_network(BlockBuilder::default())
			.with_account(Arc::clone(&self.account))
			.with_operations(self.operations);

		if let Some(purpose) = self.purpose {
			builder = builder.with_purpose(purpose);
		}
		if let Some(date) = self.date {
			builder = builder.with_date(date);
		}

		match self.previous {
			Some(previous) => builder = builder.with_previous(previous),
			None => match self.client.head_block(self.account.to_string()).await? {
				Some(head) => builder = builder.with_previous(head.hash()),
				None => builder = builder.as_opening(),
			},
		}

		let unsigned = builder.build().context(BlockSnafu)?;
		unsigned.sign().context(BlockSnafu)
	}
}

/// A representative entry as cached/applied: account key, voting weight, and
/// advertised API URL (when the node provided one).
type RepEntry = (String, BigInt, Option<String>);

/// Process-shared representative cache, keyed by rep-set signature, so
/// concurrent clients/clones over the same reps refresh from one fetch.
type RepsCache = HashMap<String, (Instant, Vec<RepEntry>)>;

fn reps_cache() -> &'static Mutex<RepsCache> {
	static CACHE: OnceLock<Mutex<RepsCache>> = OnceLock::new();
	CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A still-fresh cached rep set for `signature`, if one exists.
fn cached_representatives(signature: &str, ttl: Duration) -> Option<Vec<RepEntry>> {
	let cache = reps_cache().lock();
	let (stored_at, reps) = cache.get(signature)?;
	if stored_at.elapsed() < ttl {
		return Some(reps.clone());
	}

	None
}

/// Store a freshly fetched rep set for `signature`.
fn store_representatives(signature: &str, reps: &[RepEntry]) {
	reps_cache()
		.lock()
		.insert(signature.to_owned(), (Instant::now(), reps.to_vec()));
}

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

/// Base64-encode a set of votes for a `createVote` request body.
fn encode_votes(votes: &[Vote]) -> Vec<String> {
	votes
		.iter()
		.map(|vote| B64.encode(vote.as_bytes()))
		.collect()
}

/// Restrict `picks` to the reps that issued one of `prior_votes`. With no
/// prior votes (the temporary round) every rep is contacted.
fn contacts_for(picks: Vec<RepPick>, prior_votes: &[Vote]) -> Vec<RepPick> {
	if prior_votes.is_empty() {
		return picks;
	}

	let issuers: HashSet<String> = prior_votes
		.iter()
		.map(|vote| vote.issuer().to_string())
		.collect();
	picks
		.into_iter()
		.filter(|pick| issuers.contains(&pick.key))
		.collect()
}

/// Decode and signature-verify a base64 vote from a node response, treating
/// an absent field as [`ClientError::MissingVote`].
fn decode_vote_binary(binary: Option<String>) -> Result<Vote, ClientError> {
	let encoded = binary.ok_or(ClientError::MissingVote)?;
	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	Vote::verify(bytes).context(VoteSnafu)
}

/// Decode and signature-verify a base64 vote quote from a node response,
/// treating an absent field as [`ClientError::MissingQuote`].
fn decode_quote_binary(binary: Option<String>) -> Result<VoteQuote, ClientError> {
	let encoded = binary.ok_or(ClientError::MissingQuote)?;
	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	VoteQuote::verify(bytes).context(VoteSnafu)
}

/// Whether `error` is a node ledger error carrying the given `code`.
fn is_ledger_code(error: &ClientError, code: &str) -> bool {
	matches!(error, ClientError::Node { source } if source.code() == Some(code))
}

/// Fetch and verify the votes a specific representative holds for `block_hash`
/// on the given ledger side. `None` means the rep holds no such votes.
async fn votes_on(
	transport: &Transport,
	block_hash: &str,
	side: types::GetBlockVotesSide,
) -> Result<Option<Vec<Vote>>, ClientError> {
	let response = transport.get_block_votes(block_hash, Some(side)).await?;
	let Some(list) = response.into_inner().votes else {
		return Ok(None);
	};

	let mut votes = Vec::with_capacity(list.len());
	for entry in list {
		votes.push(decode_vote_binary(entry.binary)?);
	}

	Ok(Some(votes))
}

/// Fetch and decode a block from a specific representative on the given side.
async fn block_on(
	transport: &Transport,
	block_hash: &str,
	side: types::GetBlockSide,
) -> Result<Option<Block>, ClientError> {
	let response = transport.get_block(block_hash, Some(side)).await?;
	decode_block(response.into_inner().block)
}

/// Fetch and decode the successor of `block_hash` from a specific rep.
async fn successor_on(transport: &Transport, block_hash: &str) -> Result<Option<Block>, ClientError> {
	let response = transport.get_successor_block(block_hash).await?;
	decode_block(response.into_inner().successor_block)
}

/// Fetch a specific rep's head block hash and height for `account`.
async fn head_info_on(transport: &Transport, account: &str) -> Result<Option<(String, Amount)>, ClientError> {
	let response = transport.get_account_state(account).await?;
	let state = response.into_inner();
	match (state.current_head_block, state.current_head_block_height) {
		(Some(head), Some(height)) => Ok(Some((head, decode_amount(Some(height))?))),
		_ => Ok(None),
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

/// Base64-encode each block's canonical bytes.
fn encode_blocks(blocks: &[Block]) -> Vec<String> {
	blocks
		.iter()
		.map(|block| B64.encode(block.to_bytes()))
		.collect()
}

/// Decode an optional transport block into a domain block.
fn decode_block(block: Option<types::Block>) -> Result<Option<Block>, ClientError> {
	let Some(encoded) = block.and_then(|block| block.binary) else {
		return Ok(None);
	};

	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	let decoded = Block::try_from(bytes.as_slice()).context(BlockSnafu)?;

	Ok(Some(decoded))
}

/// Decode and verify an optional transport vote staple.
fn decode_staple(staple: Option<types::VoteStaple>) -> Result<Option<VoteStaple>, ClientError> {
	let Some(encoded) = staple.and_then(|staple| staple.binary) else {
		return Ok(None);
	};

	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	let staple = VoteStaple::verify(bytes, ValidationConfig::default(), BlockTime::now()).context(VoteSnafu)?;

	Ok(Some(staple))
}

/// Decode and verify a list of transport vote staples.
fn decode_staples(staples: Vec<types::VoteStaple>) -> Result<Vec<VoteStaple>, ClientError> {
	staples
		.into_iter()
		.filter_map(|staple| decode_staple(Some(staple)).transpose())
		.collect()
}

/// Decode transport history entries into verified domain entries.
fn decode_history(entries: Vec<types::HistoryEntry>) -> Result<Vec<HistoryEntry>, ClientError> {
	entries
		.into_iter()
		.filter_map(|entry| match decode_staple(entry.vote_staple) {
			Ok(None) => None,
			Ok(Some(staple)) => Some(Ok(HistoryEntry { staple, id: entry.id, timestamp: entry.timestamp })),
			Err(error) => Some(Err(error)),
		})
		.collect()
}

/// Decode a transport representative entry.
fn decode_representative(rep: types::Representative) -> Result<Representative, ClientError> {
	Ok(Representative {
		account: rep.representative.unwrap_or_default(),
		weight: decode_amount(rep.weight)?,
		api_url: rep.endpoints.and_then(|endpoints| endpoints.api),
	})
}

/// Map a transport ACL row into a domain [`Acl`].
fn decode_acl(row: types::AclRow) -> Acl {
	Acl { principal: row.principal, entity: row.entity, target: row.target, permissions: row.permissions }
}

/// Map a transport certificate into a domain [`Certificate`], dropping entries
/// with no certificate body (the "not found" shape).
fn decode_certificate(cert: types::Certificate) -> Option<Certificate> {
	let certificate = cert.certificate?;
	Some(Certificate { certificate, intermediates: cert.intermediates.unwrap_or_default() })
}

/// Map transport balance entries into domain [`TokenBalance`]s.
fn decode_balances(entries: Vec<types::BalanceEntry>) -> Result<Vec<TokenBalance>, ClientError> {
	entries
		.into_iter()
		.map(|entry| {
			Ok(TokenBalance {
				token: entry.token.unwrap_or_default(),
				balance: decode_amount(entry.balance)?,
				pending: decode_amount(entry.pending)?,
			})
		})
		.collect()
}

/// Assemble an [`AccountState`] from the transport fields shared by the
/// single- and batch-account state endpoints.
fn decode_account_state(
	representative: Option<String>,
	head: Option<String>,
	height: Option<String>,
	balances: Vec<types::BalanceEntry>,
) -> Result<AccountState, ClientError> {
	Ok(AccountState {
		representative,
		head,
		height: height
			.map(|height| decode_amount(Some(height)))
			.transpose()?,
		balances: decode_balances(balances)?,
	})
}

/// Parse an optional `0x`-hex balance string into an [`Amount`], treating an
/// absent field as zero.
fn decode_amount(balance: Option<String>) -> Result<Amount, ClientError> {
	match balance {
		None => Ok(Amount::default()),
		Some(value) => Amount::from_str(&value).context(AmountSnafu),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use keetanetwork_block::testing::{generate_ed25519_ref, generate_identifier_ref, validity_blocktime};
	use keetanetwork_vote::{Fees, VoteBuilder};

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
		RepPick { key: key.to_owned(), weight: BigInt::from(1u8), transport: Transport::new("http://localhost") }
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
