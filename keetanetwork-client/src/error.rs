//! Error types surfaced by the client.

use alloc::boxed::Box;

use keetanetwork_account::AccountError;
use keetanetwork_block::BlockError;
use keetanetwork_error::KeetaNetError;
use keetanetwork_vote::VoteError;
use num_bigint::ParseBigIntError;
use snafu::Snafu;

/// Failure modes of a client operation.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ClientError {
	/// The request failed at the HTTP/transport layer: connection, timeout,
	/// or response decoding problems. The concrete error is supplied by the
	/// active transport backend, so the orchestrator stays transport-agnostic
	/// (and `no_std`).
	#[snafu(display("node request failed"))]
	Transport {
		/// Underlying transport error from the backend.
		source: Box<dyn core::error::Error + Send + Sync>,
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
