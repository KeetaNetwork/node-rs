//! Deterministic issuer / validity factories shared by every test in the
//! vote crate (unit + integration).

use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::doc_utils::{
	create_ed25519_test_keys, create_secp256k1_test_keys, create_secp256r1_test_keys,
};
use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_block::testing::padded_seed;
use keetanetwork_block::{AccountRef, Amount, BlockTime, Hashable};
use keetanetwork_crypto::hash::BlockHash as CryptoBlockHash;
use num_bigint::BigInt;

use crate::error::VoteError;
use crate::fee::{Fee, Fees};
use crate::validity::Validity;
use crate::vote::{UnsignedVote, Vote};

/// A deterministic ed25519 issuer derived from `seed` (any length up to
/// the 64-byte buffer the reference helpers expect).
pub fn ed25519_issuer(seed: impl AsRef<[u8]>) -> AccountRef {
	let (_, _, account) = create_ed25519_test_keys(Some(&padded_seed(seed.as_ref())));
	Arc::new(GenericAccount::Ed25519(account))
}

/// A deterministic secp256k1 issuer derived from `seed`.
pub fn secp256k1_issuer(seed: impl AsRef<[u8]>) -> AccountRef {
	let (_, _, account) = create_secp256k1_test_keys(Some(&padded_seed(seed.as_ref())));
	Arc::new(GenericAccount::EcdsaSecp256k1(account))
}

/// A deterministic secp256r1 issuer derived from `seed`.
pub fn secp256r1_issuer(seed: impl AsRef<[u8]>) -> AccountRef {
	let (_, _, account) = create_secp256r1_test_keys(Some(&padded_seed(seed.as_ref())));
	Arc::new(GenericAccount::EcdsaSecp256r1(account))
}

/// A [`BlockTime`] from unix milliseconds; panics on the (test-only)
/// out-of-range case.
pub fn moment(ms: i64) -> BlockTime {
	BlockTime::from_unix_millis(ms).expect("test moment must be representable")
}

/// A [`Validity`] from unix-second offsets.
pub fn validity_seconds(from_secs: i64, to_secs: i64) -> Validity {
	validity_millis(from_secs * 1_000, to_secs * 1_000)
}

/// A [`Validity`] from unix-millisecond offsets.
pub fn validity_millis(from_ms: i64, to_ms: i64) -> Validity {
	Validity::try_new(moment(from_ms), moment(to_ms)).expect("validity range must be well-formed")
}

/// A validity range anchored at the current wall clock - 60s of slack
/// before now, 24h after - sized so live-node tests stay valid even on
/// slow runners.
pub fn future_validity() -> Validity {
	let now_ms = chrono::Utc::now().timestamp_millis();
	validity_millis(now_ms - 60_000, now_ms + 24 * 60 * 60 * 1_000)
}

/// Locate the first occurrence of the X.509 `[0] EXPLICIT INTEGER` version
/// tag (`A0 03 02 01 ..`) inside a wire buffer. Used by tests that corrupt
/// the version byte to force a decode failure.
pub fn find_version_tag(buf: &[u8]) -> Result<usize, VoteError> {
	buf.iter()
		.zip(buf.iter().skip(1))
		.position(|(a, b)| *a == 0xa0 && *b == 0x03)
		.ok_or(VoteError::MalformedVoteContent)
}

// -- Wall-clock --------------------------------------------------------------

/// Current wall clock as a [`BlockTime`]. For tests that need a moment
/// "now" against the live system clock.
pub fn now_blocktime() -> BlockTime {
	let millis = chrono::Utc::now().timestamp_millis();
	BlockTime::from_unix_millis(millis).expect("now must map to BlockTime")
}

// -- Fee constructors --------------------------------------------------------

/// A minimal [`Fee`] with the supplied amount and no `pay_to` / `token`.
pub fn simple_fee(amount: u64) -> Fee {
	Fee { amount: Amount::from(amount), pay_to: None, token: None }
}

/// A non-quote single-entry [`Fees::Single`] of the supplied amount.
pub fn single_fees(amount: u64) -> Fees {
	Fees::Single { quote: false, fee: simple_fee(amount) }
}

/// A quote-flagged single-entry [`Fees::Single`] of the supplied amount.
pub fn quote_fees(amount: u64) -> Fees {
	Fees::Single { quote: true, fee: simple_fee(amount) }
}

/// A [`Fees::Multiple`] populated from `amounts`, each entry minimal
/// (no `pay_to` / `token`).
pub fn multi_fees(quote: bool, amounts: impl IntoIterator<Item = u64>) -> Fees {
	Fees::Multiple { quote, fees: amounts.into_iter().map(simple_fee).collect() }
}

// -- Account derivations -----------------------------------------------------

/// A deterministic TOKEN identifier suitable for use in `Fee::token`.
pub fn token_account(seed: impl AsRef<[u8]>) -> AccountRef {
	let signer = ed25519_issuer(seed);
	let block_hash = CryptoBlockHash::from([7u8; 32]);
	Arc::new(
		signer
			.generate_identifier(KeyPairType::TOKEN, Some(&block_hash), 0)
			.expect("token identifier generation must succeed"),
	)
}

/// A deterministic STORAGE identifier suitable for use in `Fee::pay_to`.
pub fn storage_account(seed: impl AsRef<[u8]>) -> AccountRef {
	let signer = ed25519_issuer(seed);
	let block_hash = CryptoBlockHash::from([3u8; 32]);
	Arc::new(
		signer
			.generate_identifier(KeyPairType::STORAGE, Some(&block_hash), 0)
			.expect("storage identifier generation must succeed"),
	)
}

// -- Vote construction -------------------------------------------------------

/// Build and sign a vote with the supplied parameters using only Rust
/// code paths.
pub fn sign_simple_vote(
	issuer: &AccountRef,
	serial: u64,
	validity: Validity,
	blocks: impl IntoIterator<Item = keetanetwork_block::BlockHash>,
	fees: Option<Fees>,
) -> Vote {
	let blocks: Vec<keetanetwork_block::BlockHash> = blocks.into_iter().collect();
	let unsigned = UnsignedVote::try_new(BigInt::from(serial), issuer.clone(), validity, blocks, fees)
		.expect("UnsignedVote must build");
	unsigned
		.sign(issuer.as_ref())
		.expect("signing must succeed")
}

// -- Block construction ------------------------------------------------------

/// A minimal opening block with the supplied owner and representative.
pub fn opening_block(owner: &AccountRef, representative: &AccountRef) -> keetanetwork_block::Block {
	keetanetwork_block::BlockBuilder::default()
		.with_network(0u8)
		.with_account(owner.clone())
		.as_opening()
		.with_operation(keetanetwork_block::SetRep { to: representative.clone() })
		.build()
		.expect("opening block must build")
		.sign()
		.expect("opening block must sign")
}

/// Hash a block; convenience for callers that don't want to import the
/// [`Hashable`] trait.
pub fn block_hash(block: &keetanetwork_block::Block) -> keetanetwork_block::BlockHash {
	block.hash()
}
