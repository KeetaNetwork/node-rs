//! Error types surfaced by the client.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keetanetwork_account::AccountError;
use keetanetwork_block::BlockError;
use keetanetwork_error::{KeetaNetError, NodeErrorParts, NodeErrorType};
use keetanetwork_vote::VoteError;
use num_bigint::ParseBigIntError;
use snafu::Snafu;

use crate::generated::types;
use crate::generated::Error as GeneratedError;

/// Transport-layer error returned by the generated client: connection
/// failures, non-2xx responses, and payload decoding problems.
pub type ApiError = crate::generated::Error<types::Error>;

/// Failure modes of a client operation.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ClientError {
	/// The request failed at the HTTP/transport layer: connection, timeout,
	/// or response decoding problems.
	#[snafu(display("node request failed"))]
	Transport {
		/// Underlying transport error (boxed; the variant is large).
		#[snafu(source(from(ApiError, Box::new)))]
		source: Box<ApiError>,
	},

	/// The node returned a structured, coded error response.
	#[snafu(display("node returned an error"))]
	Node {
		/// The decoded node error (boxed; the variant is large).
		source: Box<KeetaNetError>,
	},

	/// A base64-encoded field in the response could not be decoded.
	#[snafu(display("malformed base64 in node response"))]
	Decode {
		/// Underlying base64 decoding error.
		source: base64::DecodeError,
	},

	/// A returned vote or staple failed domain decoding or validation.
	#[snafu(display("vote decoding or validation failed"))]
	Vote {
		/// Underlying vote error.
		source: VoteError,
	},

	/// A returned block failed domain decoding.
	#[snafu(display("block decoding failed"))]
	Block {
		/// Underlying block error.
		source: BlockError,
	},

	/// A `$bigint` amount field in the response could not be parsed.
	#[snafu(display("malformed amount in node response"))]
	Amount {
		/// Underlying parse error.
		source: ParseBigIntError,
	},

	/// The `/vote` response omitted the vote field.
	#[snafu(display("node response omitted the vote"))]
	MissingVote,

	/// The `/vote/quote` response omitted the quote field.
	#[snafu(display("node response omitted the vote quote"))]
	MissingQuote,

	/// The `/node/publish` response omitted the publish flag.
	#[snafu(display("node response omitted the publish result"))]
	MissingPublish,

	/// The `/node/version` response omitted the version.
	#[snafu(display("node response omitted the version"))]
	MissingVersion,

	/// The node's votes require a fee block but no signer was supplied to
	/// originate one (use [`send`](crate::KeetaClient::send) or another
	/// signer-bearing path).
	#[snafu(display("node votes require a fee block but no signer was supplied"))]
	FeeRequired,

	/// Deriving the network base token (the implicit fee currency) failed.
	#[snafu(display("network base token derivation failed"))]
	Account {
		/// Underlying account error.
		source: AccountError,
	},

	/// The configured network id is unset or out of range for base-token
	/// derivation.
	#[snafu(display("network id is unset or unsupported for fee token derivation"))]
	UnsupportedNetwork,

	/// The client has no representatives to dispatch to.
	#[snafu(display("no representatives available"))]
	NoRepresentatives,

	/// A request exceeded the configured per-request timeout.
	#[snafu(display("request timed out"))]
	Timeout,

	/// Votes could not reach the configured quorum threshold.
	#[snafu(display("could not reach voting quorum"))]
	QuorumNotReached,

	/// A sync found a missing staple but could not publish it.
	#[snafu(display("sync found a missing staple but could not publish it"))]
	SyncPublishFailed,

	/// Recovery could not assemble or fetch the blocks it needed.
	#[snafu(display("account recovery failed"))]
	RecoverFailed,
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

/// Decode a node error envelope into the unified [`KeetaNetError`], promoting
/// LEDGER errors to their typed variants and collapsing the rest to a coded carrier.
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
