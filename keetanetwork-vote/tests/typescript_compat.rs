//! Live byte-exact compatibility tests against the reference TypeScript.

mod support;

use keetanetwork_block::{AccountRef, BlockHash};
use keetanetwork_vote::testing::{multi_fees, simple_fee, single_fees};
use keetanetwork_vote::{Fees, Vote, VoteError, VoteQuoteBuilder};

use support::{
	assert_rust_decodes_ts_minted, assert_ts_agrees_with_rust, ed25519_issuer, future_validity, rust_sign_vote,
	secp256k1_issuer, secp256r1_issuer, token_identifier, FeeEntry, KeyKind, MintSpec, TestResult,
};

const ED25519_SEED: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const ECDSA_SEED: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";

// -- Rust -> TypeScript ------------------------------------------------------

/// One Rust→TypeScript round-trip case. `build` mints a vote (or quote)
/// using deterministic Rust factories; the harness then asserts the
/// reference parser decodes it byte-exact.
struct RustToTsCase {
	name: &'static str,
	build: fn() -> Result<Vote, VoteError>,
}

const RUST_TO_TS_CASES: &[RustToTsCase] = &[
	RustToTsCase { name: "ed25519-no-fees", build: build_ed25519_simple },
	RustToTsCase { name: "secp256k1-no-fees", build: build_secp256k1_simple },
	RustToTsCase { name: "secp256r1-no-fees", build: build_secp256r1_simple },
	RustToTsCase { name: "ed25519-multi-block", build: build_ed25519_multi_block },
	RustToTsCase { name: "ed25519-single-fee", build: build_ed25519_single_fee },
	RustToTsCase { name: "ed25519-fee-with-pay-to-and-token", build: build_ed25519_fee_pay_to_and_token },
	RustToTsCase { name: "ed25519-multi-fees", build: build_ed25519_multi_fees },
	RustToTsCase { name: "ed25519-quote", build: build_ed25519_quote },
];

#[test]
fn test_rust_minted_votes_parse_in_typescript() -> TestResult {
	for case in RUST_TO_TS_CASES {
		let vote = (case.build)().unwrap_or_else(|err| panic!("case `{}`: build failed: {err:?}", case.name));
		assert_ts_agrees_with_rust(&vote);
	}
	Ok(())
}

fn ed25519() -> AccountRef {
	ed25519_issuer(ED25519_SEED)
}

fn build_signed(issuer: &AccountRef, serial: u64, blocks: &[BlockHash], fees: Option<Fees>) -> Result<Vote, VoteError> {
	Ok(rust_sign_vote(issuer, serial, future_validity(), blocks, fees))
}

fn build_ed25519_simple() -> Result<Vote, VoteError> {
	build_signed(&ed25519(), 17, &[BlockHash::from([1u8; 32]), BlockHash::from([2u8; 32])], None)
}

fn build_secp256k1_simple() -> Result<Vote, VoteError> {
	build_signed(&secp256k1_issuer(ECDSA_SEED), 21, &[BlockHash::from([3u8; 32])], None)
}

fn build_secp256r1_simple() -> Result<Vote, VoteError> {
	build_signed(&secp256r1_issuer(ECDSA_SEED), 22, &[BlockHash::from([4u8; 32])], None)
}

fn build_ed25519_multi_block() -> Result<Vote, VoteError> {
	let blocks = [BlockHash::from([0xAA; 32]), BlockHash::from([0xBB; 32]), BlockHash::from([0xCC; 32])];
	build_signed(&ed25519(), 23, &blocks, None)
}

fn build_ed25519_single_fee() -> Result<Vote, VoteError> {
	build_signed(&ed25519(), 33, &[BlockHash::from([5u8; 32])], Some(single_fees(1234)))
}

fn build_ed25519_fee_pay_to_and_token() -> Result<Vote, VoteError> {
	let fee = keetanetwork_vote::Fee {
		amount: keetanetwork_block::Amount::from(99u64),
		pay_to: Some(secp256k1_issuer(ECDSA_SEED)),
		token: Some(token_identifier(0xDD)),
	};
	let fees = Fees::Single { quote: false, fee };
	build_signed(&ed25519(), 34, &[BlockHash::from([7u8; 32])], Some(fees))
}

fn build_ed25519_multi_fees() -> Result<Vote, VoteError> {
	build_signed(&ed25519(), 41, &[BlockHash::from([8u8; 32])], Some(multi_fees(false, [11, 22])))
}

fn build_ed25519_quote() -> Result<Vote, VoteError> {
	let issuer = ed25519();
	let validity = future_validity();
	let quote = VoteQuoteBuilder::new()
		.serial(99u64)
		.issuer(issuer.clone())
		.validity(validity.from, validity.to)
		.add_blocks([BlockHash::from([9u8; 32])])
		.fees(Fees::Single { quote: true, fee: simple_fee(7) })
		.build(issuer.as_ref())?;
	Ok(quote.into_vote())
}

// -- TypeScript -> Rust ------------------------------------------------------

/// One TypeScript→Rust round-trip case. `build` produces a [`MintSpec`]
/// understood by `ts_vote_mint`; the harness mints, decodes in Rust,
/// and asserts every field matches the originating spec.
struct TsToRustCase {
	name: &'static str,
	build: fn() -> MintSpec,
}

const TS_TO_RUST_CASES: &[TsToRustCase] = &[
	TsToRustCase { name: "ed25519-single-block", build: spec_ed25519_single_block },
	TsToRustCase { name: "secp256k1-single-block", build: spec_secp256k1_single_block },
	TsToRustCase { name: "secp256r1-single-block", build: spec_secp256r1_single_block },
	TsToRustCase { name: "ed25519-multi-block", build: spec_ed25519_multi_block },
	TsToRustCase { name: "ed25519-single-fee", build: spec_ed25519_single_fee },
	TsToRustCase { name: "ed25519-fee-with-pay-to-and-token", build: spec_ed25519_fee_pay_to_and_token },
	TsToRustCase { name: "ed25519-multi-fees", build: spec_ed25519_multi_fees },
	TsToRustCase { name: "ed25519-quote", build: spec_ed25519_quote },
];

#[test]
fn test_typescript_minted_votes_parse_in_rust() -> TestResult {
	for case in TS_TO_RUST_CASES {
		let spec = (case.build)();
		assert_rust_decodes_ts_minted(&spec).unwrap_or_else(|err| panic!("case `{}`: {err}", case.name));
	}
	Ok(())
}

fn spec_ed25519_single_block() -> MintSpec {
	MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 42)
		.add_block("0606060606060606060606060606060606060606060606060606060606060606")
}

fn spec_secp256k1_single_block() -> MintSpec {
	MintSpec::new(KeyKind::Secp256k1, ECDSA_SEED, 43)
		.add_block("1111111111111111111111111111111111111111111111111111111111111111")
}

fn spec_secp256r1_single_block() -> MintSpec {
	MintSpec::new(KeyKind::Secp256r1, ECDSA_SEED, 44)
		.add_block("2222222222222222222222222222222222222222222222222222222222222222")
}

fn spec_ed25519_multi_block() -> MintSpec {
	MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 45).add_blocks([
		"3333333333333333333333333333333333333333333333333333333333333333",
		"4444444444444444444444444444444444444444444444444444444444444444",
		"5555555555555555555555555555555555555555555555555555555555555555",
	])
}

fn spec_ed25519_single_fee() -> MintSpec {
	MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 46)
		.add_block("6767676767676767676767676767676767676767676767676767676767676767")
		.fee(FeeEntry::new(2_500))
}

fn spec_ed25519_fee_pay_to_and_token() -> MintSpec {
	let pay_to = secp256k1_issuer(ECDSA_SEED).to_string();
	let token = token_identifier(0xEE).to_string();
	MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 47)
		.add_block("8989898989898989898989898989898989898989898989898989898989898989")
		.fee(FeeEntry::new(500).pay_to(pay_to).token(token))
}

fn spec_ed25519_multi_fees() -> MintSpec {
	MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 48)
		.add_block("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB")
		.fees(vec![FeeEntry::new(10), FeeEntry::new(20)])
}

fn spec_ed25519_quote() -> MintSpec {
	MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 49)
		.add_block("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD")
		.fee(FeeEntry::new(7))
		.quote()
}
