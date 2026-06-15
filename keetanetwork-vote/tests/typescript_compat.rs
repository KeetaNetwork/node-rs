//! Live byte-exact compatibility tests against the reference TypeScript.

mod support;

use keetanetwork_block::{Amount, BlockHash};
use keetanetwork_vote::{Fee, Fees, VoteQuoteBuilder};

use support::{
	assert_rust_decodes_ts_minted, assert_ts_agrees_with_rust, ed25519_issuer, future_validity, rust_sign_vote,
	secp256k1_issuer, secp256r1_issuer, token_identifier, FeeEntry, KeyKind, MintSpec, TestResult,
};

const ED25519_SEED: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const ECDSA_SEED: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";

// -- Rust -> TypeScript ------------------------------------------------------

#[test]
fn test_rust_minted_vote_parses_in_typescript_ed25519() {
	let issuer = ed25519_issuer(ED25519_SEED);
	let blocks = [BlockHash::from([1u8; 32]), BlockHash::from([2u8; 32])];
	let vote = rust_sign_vote(&issuer, 17, future_validity(), &blocks, None);
	assert_ts_agrees_with_rust(&vote);
}

#[test]
fn test_rust_minted_vote_parses_in_typescript_secp256k1() {
	let issuer = secp256k1_issuer(ECDSA_SEED);
	let blocks = [BlockHash::from([3u8; 32])];
	let vote = rust_sign_vote(&issuer, 21, future_validity(), &blocks, None);
	assert_ts_agrees_with_rust(&vote);
}

#[test]
fn test_rust_minted_vote_parses_in_typescript_secp256r1() {
	let issuer = secp256r1_issuer(ECDSA_SEED);
	let blocks = [BlockHash::from([4u8; 32])];
	let vote = rust_sign_vote(&issuer, 22, future_validity(), &blocks, None);
	assert_ts_agrees_with_rust(&vote);
}

#[test]
fn test_rust_minted_multi_block_vote_parses_in_typescript() {
	let issuer = ed25519_issuer(ED25519_SEED);
	let blocks = [BlockHash::from([0xAA; 32]), BlockHash::from([0xBB; 32]), BlockHash::from([0xCC; 32])];
	let vote = rust_sign_vote(&issuer, 23, future_validity(), &blocks, None);
	assert_ts_agrees_with_rust(&vote);
}

#[test]
fn test_rust_minted_vote_with_single_fee_parses_in_typescript() {
	let issuer = ed25519_issuer(ED25519_SEED);
	let blocks = [BlockHash::from([5u8; 32])];
	let fees = Fees::Single { quote: false, fee: Fee { amount: Amount::from(1234u64), pay_to: None, token: None } };
	let vote = rust_sign_vote(&issuer, 33, future_validity(), &blocks, Some(fees));
	assert_ts_agrees_with_rust(&vote);
}

#[test]
fn test_rust_minted_vote_with_pay_to_and_token_parses_in_typescript() {
	let issuer = ed25519_issuer(ED25519_SEED);
	let blocks = [BlockHash::from([7u8; 32])];
	let pay_to = secp256k1_issuer(ECDSA_SEED);
	let token = token_identifier(0xDD);
	let fees = Fees::Single {
		quote: false,
		fee: Fee { amount: Amount::from(99u64), pay_to: Some(pay_to.clone()), token: Some(token.clone()) },
	};
	let vote = rust_sign_vote(&issuer, 34, future_validity(), &blocks, Some(fees));
	assert_ts_agrees_with_rust(&vote);
}

#[test]
fn test_rust_minted_vote_with_multiple_fees_parses_in_typescript() {
	let issuer = ed25519_issuer(ED25519_SEED);
	let blocks = [BlockHash::from([8u8; 32])];
	let fees = Fees::Multiple {
		quote: false,
		fees: vec![
			Fee { amount: Amount::from(11u64), pay_to: None, token: None },
			Fee { amount: Amount::from(22u64), pay_to: None, token: None },
		],
	};
	let vote = rust_sign_vote(&issuer, 41, future_validity(), &blocks, Some(fees));
	assert_ts_agrees_with_rust(&vote);
}

#[test]
fn test_rust_minted_vote_quote_parses_in_typescript() -> TestResult {
	let issuer = ed25519_issuer(ED25519_SEED);
	let validity = future_validity();
	let blocks = [BlockHash::from([9u8; 32])];
	let fees = Fees::Single { quote: true, fee: Fee { amount: Amount::from(7u64), pay_to: None, token: None } };
	let quote = VoteQuoteBuilder::new()
		.serial(99u64)
		.issuer(issuer.clone())
		.validity(validity.from, validity.to)
		.add_blocks(blocks.iter().copied())
		.fees(fees)
		.build(issuer.as_ref())?;

	assert_ts_agrees_with_rust(quote.as_vote());
	Ok(())
}

// -- TypeScript -> Rust ------------------------------------------------------

#[test]
fn test_typescript_minted_vote_parses_in_rust() -> TestResult {
	let spec = MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 42)
		.add_block("0606060606060606060606060606060606060606060606060606060606060606");
	assert_rust_decodes_ts_minted(&spec)
}

#[test]
fn test_typescript_minted_secp256k1_vote_parses_in_rust() -> TestResult {
	let spec = MintSpec::new(KeyKind::Secp256k1, ECDSA_SEED, 43)
		.add_block("1111111111111111111111111111111111111111111111111111111111111111");
	assert_rust_decodes_ts_minted(&spec)
}

#[test]
fn test_typescript_minted_secp256r1_vote_parses_in_rust() -> TestResult {
	let spec = MintSpec::new(KeyKind::Secp256r1, ECDSA_SEED, 44)
		.add_block("2222222222222222222222222222222222222222222222222222222222222222");
	assert_rust_decodes_ts_minted(&spec)
}

#[test]
fn test_typescript_minted_multi_block_vote_parses_in_rust() -> TestResult {
	let spec = MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 45).add_blocks([
		"3333333333333333333333333333333333333333333333333333333333333333",
		"4444444444444444444444444444444444444444444444444444444444444444",
		"5555555555555555555555555555555555555555555555555555555555555555",
	]);
	assert_rust_decodes_ts_minted(&spec)
}

#[test]
fn test_typescript_minted_vote_with_single_fee_parses_in_rust() -> TestResult {
	let spec = MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 46)
		.add_block("6767676767676767676767676767676767676767676767676767676767676767")
		.fee(FeeEntry::new(2_500));
	assert_rust_decodes_ts_minted(&spec)
}

#[test]
fn test_typescript_minted_vote_with_pay_to_and_token_parses_in_rust() -> TestResult {
	let pay_to = secp256k1_issuer(ECDSA_SEED).to_string();
	let token = token_identifier(0xEE).to_string();
	let spec = MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 47)
		.add_block("8989898989898989898989898989898989898989898989898989898989898989")
		.fee(FeeEntry::new(500).pay_to(pay_to).token(token));
	assert_rust_decodes_ts_minted(&spec)
}

#[test]
fn test_typescript_minted_vote_with_multiple_fees_parses_in_rust() -> TestResult {
	let spec = MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 48)
		.add_block("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB")
		.fees(vec![FeeEntry::new(10), FeeEntry::new(20)]);
	assert_rust_decodes_ts_minted(&spec)
}

#[test]
fn test_typescript_minted_vote_quote_parses_in_rust() -> TestResult {
	let spec = MintSpec::new(KeyKind::Ed25519, ED25519_SEED, 49)
		.add_block("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD")
		.fee(FeeEntry::new(7))
		.quote();
	assert_rust_decodes_ts_minted(&spec)
}
