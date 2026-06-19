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
	use keetanetwork_error::{KeetaNetError, NodeErrorParts, NodeErrorType};
	use keetanetwork_vote::{ValidationConfig, Vote, VoteQuote, VoteStaple};
	use snafu::ResultExt;

	use super::{LedgerSide, NodeTransport, TransportFactory};
	use crate::error::{AmountSnafu, BlockSnafu, ClientError, DecodeSnafu, VoteSnafu};
	use crate::generated::{types, Client as Transport, Error as GeneratedError};
	use crate::model::{
		AccountInfo, AccountState, Acl, Certificate, ChainPage, ChainQuery, HistoryEntry, HistoryQuery, LedgerChecksum,
		Representative, TokenBalance,
	};

	/// Transport-layer error returned by the generated client: connection
	/// failures, non-2xx responses, and payload decoding problems.
	pub type ApiError = crate::generated::Error<types::Error>;

	impl From<LedgerSide> for types::GetBlockSide {
		fn from(side: LedgerSide) -> Self {
			match side {
				LedgerSide::Main => types::GetBlockSide::Main,
				LedgerSide::Side => types::GetBlockSide::Side,
				LedgerSide::Both => types::GetBlockSide::Both,
			}
		}
	}

	impl From<LedgerSide> for types::GetBlockVotesSide {
		fn from(side: LedgerSide) -> Self {
			match side {
				LedgerSide::Side => types::GetBlockVotesSide::Side,
				// Vote lookups have no "both"; main is the canonical side.
				LedgerSide::Main | LedgerSide::Both => types::GetBlockVotesSide::Main,
			}
		}
	}

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

	/// Decode a node error envelope into the unified [`KeetaNetError`],
	/// promoting LEDGER errors to their typed variants and collapsing the rest
	/// to a coded carrier.
	fn decode_node_error(body: types::Error) -> KeetaNetError {
		let kind = body
			.type_
			.as_deref()
			.map(NodeErrorType::from)
			.unwrap_or_default();
		let idempotent_key = body.idempotent_key.and_then(|key| B64.decode(key).ok());

		NodeErrorParts {
			kind,
			code: body.code.unwrap_or_default(),
			message: body.message,
			should_retry: body.should_retry.unwrap_or(false),
			retry_delay: body.retry_delay.and_then(|delay| u64::try_from(delay).ok()),
			accounts: body.accounts.unwrap_or_default(),
			blockhash: body.blockhash,
			existing_blockhash: body.existing_blockhash,
			account: body.account,
			idempotent_key,
		}
		.into()
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
			decode_history(response.into_inner().history)
		}

		async fn global_history_page(&self, query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
			let response = self
				.client
				.get_global_history(query.limit, query.start.as_deref())
				.await?;
			decode_history(response.into_inner().history)
		}

		async fn vote_staples_after(&self, start: &str, limit: Option<i64>) -> Result<Vec<VoteStaple>, ClientError> {
			let response = self.client.get_vote_staples_after(limit, start).await?;
			decode_staples(response.into_inner().vote_staples)
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

	/// Base64-encode each block's canonical bytes.
	fn encode_blocks(blocks: &[Block]) -> Vec<String> {
		blocks
			.iter()
			.map(|block| B64.encode(block.to_bytes()))
			.collect()
	}

	/// Base64-encode a set of votes for a `createVote` request body.
	fn encode_votes(votes: &[Vote]) -> Vec<String> {
		votes
			.iter()
			.map(|vote| B64.encode(vote.as_bytes()))
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

	/// Decode an optional transport block into a domain block.
	fn decode_block(block: Option<types::Block>) -> Result<Option<Block>, ClientError> {
		let Some(encoded) = block.and_then(|block| block.binary) else {
			return Ok(None);
		};

		let bytes = B64.decode(encoded).context(DecodeSnafu)?;
		let decoded = Block::try_from(bytes.as_slice()).context(BlockSnafu)?;

		Ok(Some(decoded))
	}

	/// The current moment used to bound staple temporal validity. `tokio`
	/// targets read the system clock; the browser reads `Date.now()`.
	#[cfg(not(target_family = "wasm"))]
	fn verify_moment() -> BlockTime {
		BlockTime::now()
	}

	#[cfg(target_family = "wasm")]
	fn verify_moment() -> BlockTime {
		BlockTime::from_unix_millis(js_sys::Date::now() as i64).unwrap_or_default()
	}

	/// Decode and verify an optional transport vote staple.
	fn decode_staple(staple: Option<types::VoteStaple>) -> Result<Option<VoteStaple>, ClientError> {
		let Some(encoded) = staple.and_then(|staple| staple.binary) else {
			return Ok(None);
		};

		let bytes = B64.decode(encoded).context(DecodeSnafu)?;
		let staple = VoteStaple::verify(bytes, ValidationConfig::default(), verify_moment()).context(VoteSnafu)?;

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

	/// Map a transport certificate into a domain [`Certificate`], dropping
	/// entries with no certificate body (the "not found" shape).
	fn decode_certificate(cert: types::Certificate) -> Option<Certificate> {
		let certificate = cert.certificate?;
		Some(Certificate { certificate, intermediates: cert.intermediates.unwrap_or_default() })
	}

	/// Map transport balance entries into domain [`TokenBalance`]s.
	fn decode_balances(entries: Vec<types::BalanceEntry>) -> Result<Vec<TokenBalance>, ClientError> {
		entries
			.into_iter()
			.map(|entry| {
				Ok(TokenBalance { token: entry.token.unwrap_or_default(), balance: decode_amount(entry.balance)? })
			})
			.collect()
	}

	/// Map a transport account-info envelope into the domain [`AccountInfo`].
	fn decode_account_info(info: types::AccountInfo) -> AccountInfo {
		AccountInfo { name: info.name, description: info.description, metadata: info.metadata }
	}

	/// Assemble an [`AccountState`] from the transport fields shared by the
	/// single- and batch-account state endpoints.
	fn decode_account_state(
		representative: Option<String>,
		head: Option<String>,
		height: Option<String>,
		info: Option<types::AccountInfo>,
		balances: Vec<types::BalanceEntry>,
	) -> Result<AccountState, ClientError> {
		let supply = info
			.as_ref()
			.and_then(|info| info.supply.clone())
			.map(|supply| decode_amount(Some(supply)))
			.transpose()?;

		Ok(AccountState {
			representative,
			head,
			height: height
				.map(|height| decode_amount(Some(height)))
				.transpose()?,
			info: info.map(decode_account_info),
			supply,
			balances: decode_balances(balances)?,
		})
	}

	/// Parse an optional `0x`-hex balance string into an [`Amount`], treating
	/// an absent field as zero.
	fn decode_amount(balance: Option<String>) -> Result<Amount, ClientError> {
		use core::str::FromStr;

		match balance {
			None => Ok(Amount::default()),
			Some(value) => Amount::from_str(&value).context(AmountSnafu),
		}
	}
}
