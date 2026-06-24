//! Per-representative transport
//!
//! [`NodeTransport`] is the domain-typed request surface that the orchestrator
//! ([`KeetaClient`](crate::KeetaClient)) drives one representative at a time,
//! returning domain values such as [`Block`], [`Vote`], and [`VoteStaple`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use async_trait::async_trait;
use keetanetwork_block::{Amount, Block};
use keetanetwork_vote::{Vote, VoteQuote, VoteStaple};

use crate::error::ClientError;
use crate::marker::{MaybeSend, MaybeSync};
use crate::model::{
	AccountState, Acl, Certificate, ChainPage, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum, Representative,
	TokenBalance,
};

/// The ledger side a block/vote lookup targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerSide {
	/// The main ledger.
	Main,
	/// The side ledger (pending, not-yet-promoted staples).
	Side,
	/// Both ledgers.
	Both,
}

/// Domain-typed request surface for a single representative.
///
/// Every method maps to one node endpoint and yields decoded domain values.
/// The orchestrator fans these out, scores reps, and aggregates by quorum
/// without depending on the underlying transport.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait NodeTransport: core::fmt::Debug + MaybeSend + MaybeSync {
	/// The node software version string.
	async fn node_version(&self) -> Result<String, ClientError>;
	/// The settled balance of `token` held by `account`.
	async fn balance(&self, account: &str, token: &str) -> Result<Amount, ClientError>;
	/// Every token balance held by `account`.
	async fn balances(&self, account: &str) -> Result<Vec<TokenBalance>, ClientError>;
	/// The full ledger state of `account`.
	async fn account_state(&self, account: &str) -> Result<AccountState, ClientError>;
	/// Ledger state for several comma-joined `accounts` in one call.
	async fn account_states(&self, accounts: &str) -> Result<Vec<AccountState>, ClientError>;
	/// The head block of `account`, if any.
	async fn head_block(&self, account: &str) -> Result<Option<Block>, ClientError>;
	/// The head block of `account` paired with its height, if any.
	async fn account_head_info(&self, account: &str) -> Result<Option<(Block, Amount)>, ClientError>;
	/// The next pending (unreceived) block for `account`, if any.
	async fn pending_block(&self, account: &str) -> Result<Option<Block>, ClientError>;
	/// The block identified by `hash` on the given `side`, if present.
	async fn block(&self, hash: &str, side: Option<LedgerSide>) -> Result<Option<Block>, ClientError>;
	/// The block following `hash`, if one exists.
	async fn successor_block(&self, hash: &str) -> Result<Option<Block>, ClientError>;
	/// The block produced by `account` for the idempotent `key`, if any.
	async fn block_by_idempotent(&self, account: &str, key: &str) -> Result<Option<Block>, ClientError>;
	/// The verified votes a rep holds for `hash` on `side`. `None` when none.
	async fn block_votes(&self, hash: &str, side: LedgerSide) -> Result<Option<Vec<Vote>>, ClientError>;
	/// A single page of `account`'s block chain, bounded by `query`, including
	/// the cursor for the next page.
	async fn chain_page(&self, account: &str, query: &ChainQuery) -> Result<ChainPage, ClientError>;
	/// A single page of `account`'s staple history, bounded by `query`.
	async fn history_page(&self, account: &str, query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError>;
	/// A single page of global staple history, bounded by `query`.
	async fn global_history_page(&self, query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError>;
	/// Verified vote staples published after the `start` cursor.
	async fn vote_staples_after(&self, start: &str, limit: Option<i64>) -> Result<Vec<VoteStaple>, ClientError>;
	/// The node's own representative.
	async fn node_representative(&self) -> Result<Representative, ClientError>;
	/// The named representative `rep`.
	async fn representative(&self, rep: &str) -> Result<Representative, ClientError>;
	/// Every known representative.
	async fn representatives(&self) -> Result<Vec<Representative>, ClientError>;
	/// The current ledger checksum.
	async fn ledger_checksum(&self) -> Result<LedgerChecksum, ClientError>;
	/// ACL entries where `account` is the principal.
	async fn acls_by_principal(&self, account: &str) -> Result<Vec<Acl>, ClientError>;
	/// ACL entries where `account` is the entity.
	async fn acls_by_entity(&self, account: &str) -> Result<Vec<Acl>, ClientError>;
	/// Every certificate held by `account`.
	async fn certificates(&self, account: &str) -> Result<Vec<Certificate>, ClientError>;
	/// The certificate of `account` identified by `hash`, if present.
	async fn certificate(&self, account: &str, hash: &str) -> Result<Option<Certificate>, ClientError>;
	/// Request a vote for `blocks`, attaching `prior` votes and an optional
	/// `quote` issued by this representative.
	async fn create_vote(
		&self,
		blocks: &[Block],
		prior: &[Vote],
		quote: Option<&VoteQuote>,
	) -> Result<Vote, ClientError>;
	/// Request a non-binding vote quote for `blocks`.
	async fn create_vote_quote(&self, blocks: &[Block]) -> Result<VoteQuote, ClientError>;
	/// Publish `staple`. A fulfilled response counts as success regardless of
	/// the returned `publish` flag, which only reports whether this node also
	/// voted on the staple.
	async fn publish_staple(&self, staple: &VoteStaple) -> Result<bool, ClientError>;
	/// The aggregate ACL-with-info view for principal `account` (opaque JSON;
	/// std-only, as it returns a `serde_json::Value`).
	#[cfg(feature = "std")]
	async fn acls_by_principal_with_info(&self, account: &str) -> Result<serde_json::Value, ClientError>;
	/// Node statistics (opaque JSON; std-only).
	#[cfg(feature = "std")]
	async fn node_stats(&self) -> Result<serde_json::Value, ClientError>;
	/// Connected peers (opaque JSON; std-only).
	#[cfg(feature = "std")]
	async fn node_peers(&self) -> Result<serde_json::Value, ClientError>;
}

/// Builds a [`NodeTransport`] for a representative reachable at `url`. Lets the
/// orchestrator bind transports to representatives it discovers at runtime
/// without naming a concrete transport.
pub trait TransportFactory: core::fmt::Debug + MaybeSend + MaybeSync {
	/// Create a transport targeting the representative at `url`.
	fn create(&self, url: &str) -> Arc<dyn NodeTransport>;
}

#[cfg(feature = "http")]
pub use backend::{ApiError, GeneratedTransport, GeneratedTransportFactory};

#[cfg(all(feature = "wasi", target_os = "wasi"))]
pub use wasi_backend::{WasiTransport, WasiTransportFactory};

/// Production transport backend over the OpenAPI-generated `reqwest` client.
#[cfg(feature = "http")]
mod backend {
	use alloc::boxed::Box;
	use alloc::string::String;
	use alloc::sync::Arc;
	use alloc::vec::Vec;

	use async_trait::async_trait;
	use base64::engine::general_purpose::STANDARD as B64;
	use base64::Engine;
	use keetanetwork_block::{Amount, Block, BlockTime};
	use keetanetwork_vote::{Vote, VoteQuote, VoteStaple};

	use super::{LedgerSide, NodeTransport, TransportFactory};
	use crate::codec::{
		decode_account_state, decode_acl, decode_amount, decode_balances, decode_block, decode_certificate,
		decode_history, decode_node_error, decode_quote_binary, decode_representative, decode_staples,
		decode_vote_binary, encode_blocks, encode_votes,
	};
	use crate::error::ClientError;
	use crate::generated::{types, Client as Transport, Error as GeneratedError};
	use crate::model::{
		AccountState, Acl, Certificate, ChainPage, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum,
		Representative, TokenBalance,
	};

	/// Transport-layer error returned by the generated client: connection
	/// failures, non-2xx responses, and payload decoding problems.
	pub type ApiError = crate::generated::Error<types::Error>;

	impl From<ApiError> for ClientError {
		fn from(error: ApiError) -> Self {
			match error {
				GeneratedError::ErrorResponse(response) => {
					ClientError::Node { source: Box::new(decode_node_error(response.into_inner())) }
				}
				other => ClientError::Transport { source: Box::new(other) },
			}
		}
	}

	/// Production [`NodeTransport`] over the OpenAPI-generated client.
	#[derive(Clone, Debug)]
	pub struct GeneratedTransport {
		client: Transport,
	}

	impl GeneratedTransport {
		/// Wrap a base URL and shared HTTP client into a generated transport.
		pub(crate) fn new(base_url: &str, http: reqwest::Client) -> Self {
			Self { client: Transport::new_with_client(base_url, http) }
		}
	}

	/// [`TransportFactory`] that binds discovered representatives to
	/// [`GeneratedTransport`]s over a shared HTTP client.
	#[derive(Clone, Debug)]
	pub struct GeneratedTransportFactory {
		http: reqwest::Client,
	}

	impl GeneratedTransportFactory {
		/// A factory over the shared `http` client.
		pub fn new(http: reqwest::Client) -> Self {
			Self { http }
		}
	}

	impl TransportFactory for GeneratedTransportFactory {
		fn create(&self, url: &str) -> Arc<dyn NodeTransport> {
			Arc::new(GeneratedTransport::new(url, self.http.clone()))
		}
	}

	#[cfg_attr(not(target_family = "wasm"), async_trait)]
	#[cfg_attr(target_family = "wasm", async_trait(?Send))]
	impl NodeTransport for GeneratedTransport {
		async fn node_version(&self) -> Result<String, ClientError> {
			self.client
				.get_node_version()
				.await?
				.into_inner()
				.node
				.ok_or(ClientError::MissingVersion)
		}

		async fn balance(&self, account: &str, token: &str) -> Result<Amount, ClientError> {
			let response = self.client.get_account_balance(account, token).await?;
			decode_amount(response.into_inner().balance)
		}

		async fn balances(&self, account: &str) -> Result<Vec<TokenBalance>, ClientError> {
			let response = self.client.get_account_balances(account).await?;
			decode_balances(response.into_inner().balances)
		}

		async fn account_state(&self, account: &str) -> Result<AccountState, ClientError> {
			let state = self.client.get_account_state(account).await?.into_inner();
			decode_account_state(
				state.representative,
				state.current_head_block,
				state.current_head_block_height,
				state.info,
				state.balances,
			)
		}

		async fn account_states(&self, accounts: &str) -> Result<Vec<AccountState>, ClientError> {
			self.client
				.get_account_states(accounts)
				.await?
				.into_inner()
				.into_iter()
				.map(|item| {
					decode_account_state(
						item.representative,
						item.current_head_block,
						item.current_head_block_height,
						item.info,
						item.balances,
					)
				})
				.collect()
		}

		async fn head_block(&self, account: &str) -> Result<Option<Block>, ClientError> {
			let response = self.client.get_account_head(account).await?;
			decode_block(response.into_inner().block)
		}

		async fn account_head_info(&self, account: &str) -> Result<Option<(Block, Amount)>, ClientError> {
			let response = self.client.get_account_head(account).await?.into_inner();
			let Some(block) = decode_block(response.block)? else {
				return Ok(None);
			};
			let Some(height) = response.height else {
				return Ok(None);
			};

			Ok(Some((block, decode_amount(Some(height))?)))
		}

		async fn pending_block(&self, account: &str) -> Result<Option<Block>, ClientError> {
			let response = self.client.get_pending_block(account).await?;
			decode_block(response.into_inner().block)
		}

		async fn block(&self, hash: &str, side: Option<LedgerSide>) -> Result<Option<Block>, ClientError> {
			let response = self.client.get_block(hash, side.map(Into::into)).await?;
			decode_block(response.into_inner().block)
		}

		async fn successor_block(&self, hash: &str) -> Result<Option<Block>, ClientError> {
			let response = self.client.get_successor_block(hash).await?;
			decode_block(response.into_inner().successor_block)
		}

		async fn block_by_idempotent(&self, account: &str, key: &str) -> Result<Option<Block>, ClientError> {
			let response = self.client.get_block_from_idempotent(account, key).await?;
			decode_block(response.into_inner().block)
		}

		async fn block_votes(&self, hash: &str, side: LedgerSide) -> Result<Option<Vec<Vote>>, ClientError> {
			let response = self.client.get_block_votes(hash, Some(side.into())).await?;
			let Some(list) = response.into_inner().votes else {
				return Ok(None);
			};

			let mut votes = Vec::with_capacity(list.len());
			for entry in list {
				votes.push(decode_vote_binary(entry.binary)?);
			}

			Ok(Some(votes))
		}

		async fn chain_page(&self, account: &str, query: &ChainQuery) -> Result<ChainPage, ClientError> {
			let response = self
				.client
				.get_account_chain(account, query.end.as_deref(), query.limit, query.start.as_deref())
				.await?
				.into_inner();

			let blocks = response
				.blocks
				.into_iter()
				.filter_map(|entry| decode_block(entry.block).transpose())
				.collect::<Result<Vec<Block>, ClientError>>()?;

			Ok(ChainPage { blocks, next_key: response.next_key })
		}

		async fn history_page(&self, account: &str, query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
			let response = self
				.client
				.get_account_history(account, query.limit, query.start.as_deref())
				.await?;
			decode_history(response.into_inner().history, verify_moment())
		}

		async fn global_history_page(&self, query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
			let response = self
				.client
				.get_global_history(query.limit, query.start.as_deref())
				.await?;
			decode_history(response.into_inner().history, verify_moment())
		}

		async fn vote_staples_after(&self, start: &str, limit: Option<i64>) -> Result<Vec<VoteStaple>, ClientError> {
			let response = self.client.get_vote_staples_after(limit, start).await?;
			decode_staples(response.into_inner().vote_staples, verify_moment())
		}

		async fn node_representative(&self) -> Result<Representative, ClientError> {
			let response = self.client.get_node_representative().await?;
			decode_representative(response.into_inner())
		}

		async fn representative(&self, rep: &str) -> Result<Representative, ClientError> {
			let response = self.client.get_representative(rep).await?;
			decode_representative(response.into_inner())
		}

		async fn representatives(&self) -> Result<Vec<Representative>, ClientError> {
			self.client
				.get_all_representatives()
				.await?
				.into_inner()
				.representatives
				.into_iter()
				.map(decode_representative)
				.collect()
		}

		async fn ledger_checksum(&self) -> Result<LedgerChecksum, ClientError> {
			let checksum = self.client.get_ledger_checksum().await?.into_inner();
			Ok(LedgerChecksum {
				checksum: decode_amount(checksum.checksum)?,
				moment: checksum.moment,
				moment_range: checksum.moment_range,
			})
		}

		async fn acls_by_principal(&self, account: &str) -> Result<Vec<Acl>, ClientError> {
			let response = self.client.list_acls_by_principal(account).await?;
			Ok(response
				.into_inner()
				.permissions
				.into_iter()
				.map(decode_acl)
				.collect())
		}

		async fn acls_by_entity(&self, account: &str) -> Result<Vec<Acl>, ClientError> {
			let response = self.client.list_acls_by_entity(account).await?;
			Ok(response
				.into_inner()
				.permissions
				.into_iter()
				.map(decode_acl)
				.collect())
		}

		#[cfg(feature = "std")]
		async fn acls_by_principal_with_info(&self, account: &str) -> Result<serde_json::Value, ClientError> {
			let response = self.client.list_acls_additional(account).await?;
			Ok(serde_json::Value::Object(response.into_inner()))
		}

		async fn certificates(&self, account: &str) -> Result<Vec<Certificate>, ClientError> {
			let response = self.client.get_account_certificates(account).await?;
			Ok(response
				.into_inner()
				.certificates
				.into_iter()
				.filter_map(decode_certificate)
				.collect())
		}

		async fn certificate(&self, account: &str, hash: &str) -> Result<Option<Certificate>, ClientError> {
			let found = self
				.client
				.get_certificate_by_hash(account, hash)
				.await?
				.into_inner();
			Ok(decode_certificate(types::Certificate {
				certificate: found.certificate,
				intermediates: found.intermediates,
			}))
		}

		#[cfg(feature = "std")]
		async fn node_stats(&self) -> Result<serde_json::Value, ClientError> {
			let response = self.client.get_node_stats().await?;
			Ok(serde_json::Value::Object(response.into_inner()))
		}

		#[cfg(feature = "std")]
		async fn node_peers(&self) -> Result<serde_json::Value, ClientError> {
			let response = self.client.get_peers().await?;
			Ok(serde_json::Value::Object(response.into_inner()))
		}

		async fn create_vote(
			&self,
			blocks: &[Block],
			prior: &[Vote],
			quote: Option<&VoteQuote>,
		) -> Result<Vote, ClientError> {
			let body = types::CreateVoteBody {
				blocks: encode_blocks(blocks),
				votes: encode_votes(prior),
				quote: quote.map(|quote| B64.encode(quote.as_vote().as_bytes())),
			};
			let response = self.client.create_vote(&body).await?;
			decode_vote_binary(response.into_inner().vote.and_then(|vote| vote.binary))
		}

		async fn create_vote_quote(&self, blocks: &[Block]) -> Result<VoteQuote, ClientError> {
			let body = types::CreateVoteQuoteBody { blocks: encode_blocks(blocks) };
			let response = self.client.create_vote_quote(&body).await?;
			decode_quote_binary(response.into_inner().quote.and_then(|quote| quote.binary))
		}

		async fn publish_staple(&self, staple: &VoteStaple) -> Result<bool, ClientError> {
			let body = types::PublishVoteStapleBody { votes_and_blocks: B64.encode(staple.as_bytes()) };
			self.client.publish_vote_staple(&body).await?;
			Ok(true)
		}
	}

	/// The current moment used to bound staple temporal validity. `tokio`
	/// targets read the system clock; the browser reads `Date.now()`.
	#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
	fn verify_moment() -> BlockTime {
		BlockTime::now()
	}

	#[cfg(all(target_family = "wasm", target_os = "unknown"))]
	fn verify_moment() -> BlockTime {
		BlockTime::from_unix_millis(js_sys::Date::now() as i64).unwrap_or_default()
	}
}

/// WASI Preview 2 transport backend over `wstd`'s outbound `wasi:http` client.
#[cfg(all(feature = "wasi", target_os = "wasi"))]
mod wasi_backend {
	use alloc::boxed::Box;
	use alloc::format;
	use alloc::string::{String, ToString};
	use alloc::sync::Arc;
	use alloc::vec::Vec;
	use core::fmt::Write as _;

	use async_trait::async_trait;
	use base64::engine::general_purpose::STANDARD as B64;
	use base64::Engine;
	use keetanetwork_block::{Amount, Block, BlockTime};
	use keetanetwork_vote::{Vote, VoteQuote, VoteStaple};
	use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
	use serde::de::DeserializeOwned;
	use serde::Serialize;
	use wstd::http::{Body, Client, Method, Request};

	use super::{LedgerSide, NodeTransport, TransportFactory};
	use crate::codec::{
		decode_account_state, decode_acl, decode_amount, decode_balances, decode_block, decode_certificate,
		decode_history, decode_node_error, decode_quote_binary, decode_representative, decode_staples,
		decode_vote_binary, encode_blocks, encode_votes,
	};
	use crate::error::ClientError;
	use crate::generated::types;
	use crate::model::{
		AccountState, Acl, Certificate, ChainPage, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum,
		Representative, TokenBalance,
	};

	/// Bridges a foreign transport error (`wstd`/`http`, neither of which is a
	/// `core::error::Error` we can box directly in every case) into the
	/// [`ClientError::Transport`] source slot while preserving the original
	/// value.
	#[derive(Debug)]
	struct WasiHttpError<E>(E);

	impl<E: core::fmt::Display> core::fmt::Display for WasiHttpError<E> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			core::fmt::Display::fmt(&self.0, f)
		}
	}

	impl<E: core::fmt::Debug + core::fmt::Display> core::error::Error for WasiHttpError<E> {}

	fn transport_error<E: core::fmt::Debug + core::fmt::Display + 'static>(error: E) -> ClientError {
		ClientError::Transport { source: Box::new(WasiHttpError(error)) }
	}

	/// Percent-encode a single URL path segment.
	fn segment(value: &str) -> percent_encoding::PercentEncode<'_> {
		utf8_percent_encode(value, NON_ALPHANUMERIC)
	}

	/// Builds an optional `?k=v&...` query string with percent-encoded values.
	#[derive(Default)]
	struct Query {
		buffer: String,
		started: bool,
	}

	impl Query {
		fn push(&mut self, key: &str, value: &str) {
			self.buffer.push(if self.started {
				'&'
			} else {
				'?'
			});
			self.started = true;
			let _ = write!(self.buffer, "{key}={}", utf8_percent_encode(value, NON_ALPHANUMERIC));
		}

		fn push_opt(&mut self, key: &str, value: Option<&str>) {
			if let Some(value) = value {
				self.push(key, value);
			}
		}

		fn push_limit(&mut self, limit: Option<i64>) {
			if let Some(limit) = limit {
				self.push("limit", &limit.to_string());
			}
		}

		fn finish(self) -> String {
			self.buffer
		}
	}

	/// The transport value for a block `side` query (`main`/`side`/`both`).
	fn block_side(side: LedgerSide) -> &'static str {
		match side {
			LedgerSide::Main => "main",
			LedgerSide::Side => "side",
			LedgerSide::Both => "both",
		}
	}

	/// The transport value for a vote `side` query; votes have no `both`, so it
	/// collapses to the canonical `main`.
	fn block_votes_side(side: LedgerSide) -> &'static str {
		match side {
			LedgerSide::Side => "side",
			LedgerSide::Main | LedgerSide::Both => "main",
		}
	}

	/// The moment used to bound staple temporal validity, read from the wasip2
	/// clock via `std::time` (`BlockTime::now` is `std`-feature gated and
	/// the `wasi` feature deliberately omits that feature).
	fn now_moment() -> BlockTime {
		use std::time::{SystemTime, UNIX_EPOCH};

		let millis = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|elapsed| elapsed.as_millis() as i64)
			.unwrap_or_default();
		BlockTime::from_unix_millis(millis).unwrap_or_default()
	}

	/// WASI Preview 2 [`NodeTransport`] over `wstd`'s outbound `wasi:http`.
	#[derive(Clone, Debug)]
	pub struct WasiTransport {
		base_url: String,
		client: Client,
	}

	impl WasiTransport {
		fn new(base_url: &str) -> Self {
			Self { base_url: base_url.trim_end_matches('/').to_string(), client: Client::new() }
		}

		/// GET `path` (query string already appended) and decode the JSON body.
		async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
			self.request_json(Method::GET, path, Body::empty()).await
		}

		/// POST a JSON `body` to `path` and decode the JSON response.
		async fn post_json<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ClientError> {
			let body = Body::from_json(body).map_err(transport_error)?;
			self.request_json(Method::POST, path, body).await
		}

		/// Send a request and decode the JSON response, mapping a non-success
		/// status to a node error envelope when the body carries one.
		async fn request_json<T: DeserializeOwned>(
			&self,
			method: Method,
			path: &str,
			body: Body,
		) -> Result<T, ClientError> {
			let is_post = method == Method::POST;
			let mut builder = Request::builder()
				.method(method)
				.uri(format!("{}{path}", self.base_url))
				.header("accept", "application/json");
			// `wstd`'s `Body::from_json` serializes without stamping a media
			// type; a body sent without it is rejected by the node.
			if is_post {
				builder = builder.header("content-type", "application/json");
			}
			let request = builder.body(body).map_err(transport_error)?;

			let mut response = self.client.send(request).await.map_err(transport_error)?;
			let status = response.status();
			let body = response.body_mut();

			if status.is_success() {
				return body.json::<T>().await.map_err(transport_error);
			}

			match body.json::<types::Error>().await {
				Ok(envelope) => Err(ClientError::Node { source: Box::new(decode_node_error(envelope)) }),
				Err(error) => Err(transport_error(error)),
			}
		}
	}

	/// Builds [`WasiTransport`]s for representatives discovered at runtime.
	#[derive(Clone, Debug, Default)]
	pub struct WasiTransportFactory;

	impl TransportFactory for WasiTransportFactory {
		fn create(&self, url: &str) -> Arc<dyn NodeTransport> {
			Arc::new(WasiTransport::new(url))
		}
	}

	#[async_trait(?Send)]
	impl NodeTransport for WasiTransport {
		async fn node_version(&self) -> Result<String, ClientError> {
			let response: types::GetNodeVersionResponse = self.get_json("/node/version").await?;
			response.node.ok_or(ClientError::MissingVersion)
		}

		async fn balance(&self, account: &str, token: &str) -> Result<Amount, ClientError> {
			let path = format!("/node/ledger/account/{}/balance/{}", segment(account), segment(token));
			let response: types::GetAccountBalanceResponse = self.get_json(&path).await?;
			decode_amount(response.balance)
		}

		async fn balances(&self, account: &str) -> Result<Vec<TokenBalance>, ClientError> {
			let path = format!("/node/ledger/account/{}/balance", segment(account));
			let response: types::GetAccountBalancesResponse = self.get_json(&path).await?;
			decode_balances(response.balances)
		}

		async fn account_state(&self, account: &str) -> Result<AccountState, ClientError> {
			let path = format!("/node/ledger/account/{}", segment(account));
			let state: types::GetAccountStateResponse = self.get_json(&path).await?;
			decode_account_state(
				state.representative,
				state.current_head_block,
				state.current_head_block_height,
				state.info,
				state.balances,
			)
		}

		async fn account_states(&self, accounts: &str) -> Result<Vec<AccountState>, ClientError> {
			let path = format!("/node/ledger/accounts/{}", segment(accounts));
			let response: Vec<types::GetAccountStatesResponseItem> = self.get_json(&path).await?;
			response
				.into_iter()
				.map(|item| {
					decode_account_state(
						item.representative,
						item.current_head_block,
						item.current_head_block_height,
						item.info,
						item.balances,
					)
				})
				.collect()
		}

		async fn head_block(&self, account: &str) -> Result<Option<Block>, ClientError> {
			let path = format!("/node/ledger/account/{}/head", segment(account));
			let response: types::GetAccountHeadResponse = self.get_json(&path).await?;
			decode_block(response.block)
		}

		async fn account_head_info(&self, account: &str) -> Result<Option<(Block, Amount)>, ClientError> {
			let path = format!("/node/ledger/account/{}/head", segment(account));
			let response: types::GetAccountHeadResponse = self.get_json(&path).await?;
			let Some(block) = decode_block(response.block)? else {
				return Ok(None);
			};
			let Some(height) = response.height else {
				return Ok(None);
			};

			Ok(Some((block, decode_amount(Some(height))?)))
		}

		async fn pending_block(&self, account: &str) -> Result<Option<Block>, ClientError> {
			let path = format!("/node/ledger/account/{}/pending", segment(account));
			let response: types::GetPendingBlockResponse = self.get_json(&path).await?;
			decode_block(response.block)
		}

		async fn block(&self, hash: &str, side: Option<LedgerSide>) -> Result<Option<Block>, ClientError> {
			let mut query = Query::default();
			query.push_opt("side", side.map(block_side));
			let path = format!("/node/ledger/block/{}{}", segment(hash), query.finish());
			let response: types::GetBlockResponse = self.get_json(&path).await?;
			decode_block(response.block)
		}

		async fn successor_block(&self, hash: &str) -> Result<Option<Block>, ClientError> {
			let path = format!("/node/ledger/block/{}/successor", segment(hash));
			let response: types::GetSuccessorBlockResponse = self.get_json(&path).await?;
			decode_block(response.successor_block)
		}

		async fn block_by_idempotent(&self, account: &str, key: &str) -> Result<Option<Block>, ClientError> {
			let path = format!("/node/ledger/account/{}/idempotent/{}", segment(account), segment(key));
			let response: types::GetBlockFromIdempotentResponse = self.get_json(&path).await?;
			decode_block(response.block)
		}

		async fn block_votes(&self, hash: &str, side: LedgerSide) -> Result<Option<Vec<Vote>>, ClientError> {
			let mut query = Query::default();

			query.push("side", block_votes_side(side));

			let path = format!("/vote/{}{}", segment(hash), query.finish());
			let response: types::GetBlockVotesResponse = self.get_json(&path).await?;
			let Some(list) = response.votes else {
				return Ok(None);
			};

			let mut votes = Vec::with_capacity(list.len());
			for entry in list {
				votes.push(decode_vote_binary(entry.binary)?);
			}

			Ok(Some(votes))
		}

		async fn chain_page(&self, account: &str, query: &ChainQuery) -> Result<ChainPage, ClientError> {
			let mut params = Query::default();
			params.push_opt("end", query.end.as_deref());
			params.push_limit(query.limit);
			params.push_opt("start", query.start.as_deref());

			let path = format!("/node/ledger/account/{}/chain{}", segment(account), params.finish());
			let response: types::GetAccountChainResponse = self.get_json(&path).await?;
			let blocks = response
				.blocks
				.into_iter()
				.filter_map(|entry| decode_block(entry.block).transpose())
				.collect::<Result<Vec<Block>, ClientError>>()?;

			Ok(ChainPage { blocks, next_key: response.next_key })
		}

		async fn history_page(&self, account: &str, query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
			let mut params = Query::default();
			params.push_limit(query.limit);
			params.push_opt("start", query.start.as_deref());

			let path = format!("/node/ledger/account/{}/history{}", segment(account), params.finish());
			let response: types::GetAccountHistoryResponse = self.get_json(&path).await?;
			decode_history(response.history, now_moment())
		}

		async fn global_history_page(&self, query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
			let mut params = Query::default();
			params.push_limit(query.limit);
			params.push_opt("start", query.start.as_deref());

			let path = format!("/node/ledger/history{}", params.finish());
			let response: types::GetGlobalHistoryResponse = self.get_json(&path).await?;
			decode_history(response.history, now_moment())
		}

		async fn vote_staples_after(&self, start: &str, limit: Option<i64>) -> Result<Vec<VoteStaple>, ClientError> {
			let mut params = Query::default();
			params.push_limit(limit);
			params.push("start", start);

			let path = format!("/node/bootstrap/votes{}", params.finish());
			let response: types::GetVoteStaplesAfterResponse = self.get_json(&path).await?;
			decode_staples(response.vote_staples, now_moment())
		}

		async fn node_representative(&self) -> Result<Representative, ClientError> {
			let response: types::Representative = self.get_json("/node/ledger/representative").await?;
			decode_representative(response)
		}

		async fn representative(&self, rep: &str) -> Result<Representative, ClientError> {
			let path = format!("/node/ledger/representative/{}", segment(rep));
			let response: types::Representative = self.get_json(&path).await?;
			decode_representative(response)
		}

		async fn representatives(&self) -> Result<Vec<Representative>, ClientError> {
			let response: types::GetAllRepresentativesResponse = self.get_json("/node/ledger/representatives").await?;
			response
				.representatives
				.into_iter()
				.map(decode_representative)
				.collect()
		}

		async fn ledger_checksum(&self) -> Result<LedgerChecksum, ClientError> {
			let checksum: types::GetLedgerChecksumResponse = self.get_json("/node/ledger/checksum").await?;
			Ok(LedgerChecksum {
				checksum: decode_amount(checksum.checksum)?,
				moment: checksum.moment,
				moment_range: checksum.moment_range,
			})
		}

		async fn acls_by_principal(&self, account: &str) -> Result<Vec<Acl>, ClientError> {
			let path = format!("/node/ledger/account/{}/acl", segment(account));
			let response: types::ListAclsByPrincipalResponse = self.get_json(&path).await?;
			Ok(response.permissions.into_iter().map(decode_acl).collect())
		}

		async fn acls_by_entity(&self, account: &str) -> Result<Vec<Acl>, ClientError> {
			let path = format!("/node/ledger/account/{}/acl/granted", segment(account));
			let response: types::ListAclsByEntityResponse = self.get_json(&path).await?;
			Ok(response.permissions.into_iter().map(decode_acl).collect())
		}

		async fn certificates(&self, account: &str) -> Result<Vec<Certificate>, ClientError> {
			let path = format!("/node/ledger/account/{}/certificates", segment(account));
			let response: types::GetAccountCertificatesResponse = self.get_json(&path).await?;
			Ok(response
				.certificates
				.into_iter()
				.filter_map(decode_certificate)
				.collect())
		}

		async fn certificate(&self, account: &str, hash: &str) -> Result<Option<Certificate>, ClientError> {
			let path = format!("/node/ledger/account/{}/certificates/{}", segment(account), segment(hash));
			let found: types::GetCertificateByHashResponse = self.get_json(&path).await?;
			Ok(decode_certificate(types::Certificate {
				certificate: found.certificate,
				intermediates: found.intermediates,
			}))
		}

		async fn create_vote(
			&self,
			blocks: &[Block],
			prior: &[Vote],
			quote: Option<&VoteQuote>,
		) -> Result<Vote, ClientError> {
			let body = types::CreateVoteBody {
				blocks: encode_blocks(blocks),
				votes: encode_votes(prior),
				quote: quote.map(|quote| B64.encode(quote.as_vote().as_bytes())),
			};

			let response: types::CreateVoteResponse = self.post_json("/vote", &body).await?;
			decode_vote_binary(response.vote.and_then(|vote| vote.binary))
		}

		async fn create_vote_quote(&self, blocks: &[Block]) -> Result<VoteQuote, ClientError> {
			let body = types::CreateVoteQuoteBody { blocks: encode_blocks(blocks) };
			let response: types::CreateVoteQuoteResponse = self.post_json("/vote/quote", &body).await?;
			decode_quote_binary(response.quote.and_then(|quote| quote.binary))
		}

		async fn publish_staple(&self, staple: &VoteStaple) -> Result<bool, ClientError> {
			let body = types::PublishVoteStapleBody { votes_and_blocks: B64.encode(staple.as_bytes()) };
			let _: types::PublishVoteStapleResponse = self.post_json("/node/publish", &body).await?;
			Ok(true)
		}
	}
}
