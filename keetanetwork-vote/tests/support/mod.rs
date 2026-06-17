//! Shared helpers for vote integration tests.
//!
//! Bundles harness-script invocation, deterministic issuer factories,
//! reusable JSON parsing, and the round-trip assertions used to prove
//! cross-implementation interoperability with the reference TypeScript
//! node.
#![allow(dead_code)] // each integration test binary uses a subset

use std::error::Error;
use std::path::PathBuf;

use chrono::{DateTime, FixedOffset};
use keetanetwork_asn1::testing;
use keetanetwork_block::Hashable;
use keetanetwork_block::{AccountRef, BlockHash};
use keetanetwork_utils::node_harness::{run_node_script, script_path};
use keetanetwork_vote::{Fee, Fees, Validity, Vote, VoteHash, VoteQuote, VoteStaple};
use num_bigint::BigInt;
use serde_json::{Map, Value};

pub use keetanetwork_vote::testing::{
	ed25519_issuer as ed25519_issuer_raw, future_validity, secp256k1_issuer as secp256k1_issuer_raw,
	secp256r1_issuer as secp256r1_issuer_raw, sign_simple_vote, token_account as token_identifier_raw,
};

pub type TestResult = Result<(), Box<dyn Error>>;

// -- issuer factories --------------------------------------------------------

fn decode_seed(seed_hex: &str) -> Vec<u8> {
	hex::decode(seed_hex).expect("seed must be valid hex")
}

/// A deterministic ed25519 issuer derived from a hex-encoded seed.
pub fn ed25519_issuer(seed_hex: &str) -> AccountRef {
	ed25519_issuer_raw(decode_seed(seed_hex))
}

/// A deterministic secp256k1 issuer derived from a hex-encoded seed.
pub fn secp256k1_issuer(seed_hex: &str) -> AccountRef {
	secp256k1_issuer_raw(decode_seed(seed_hex))
}

/// A deterministic secp256r1 issuer derived from a hex-encoded seed.
pub fn secp256r1_issuer(seed_hex: &str) -> AccountRef {
	secp256r1_issuer_raw(decode_seed(seed_hex))
}

/// A deterministic TOKEN identifier suitable for use in fee `token`
/// fields. Mirrors the helper in [`keetanetwork_vote::testing`] but
/// keyed by a single byte for legibility in test tables.
pub fn token_identifier(seed_byte: u8) -> AccountRef {
	token_identifier_raw([seed_byte; 32])
}

// -- json helpers ------------------------------------------------------------

/// Read a string field from a JSON value or panic with a helpful message.
pub fn json_str(value: &Value, key: &str) -> String {
	value[key]
		.as_str()
		.unwrap_or_else(|| panic!("response must include {key}"))
		.to_string()
}

/// Read an array field from a JSON value or panic with a helpful message.
pub fn json_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
	value[key]
		.as_array()
		.unwrap_or_else(|| panic!("response field `{key}` must be an array"))
		.as_slice()
}

/// Decode a hex string, panicking with the underlying error if malformed.
pub fn hex_decode(value: &str) -> Vec<u8> {
	hex::decode(value).unwrap_or_else(|err| panic!("response field must be hex-encoded: {err}"))
}

// -- harness scripts ---------------------------------------------------------

fn script(name: &str) -> PathBuf {
	script_path(name).expect("harness scripts must be built (run `make node-harness`)")
}

/// Run a node-harness script with `stdin` and parse its first stdout
/// line as JSON.
pub fn run_script(name: &str, stdin: &[u8]) -> Value {
	let output = run_node_script(script(name), [] as [&str; 0], Some(stdin)).expect("the harness script must run");
	let stdout = String::from_utf8(output.stdout).expect("node output must be UTF-8");
	let line = stdout
		.lines()
		.next()
		.expect("the harness script must produce output");
	serde_json::from_str(line).expect("the harness script must produce JSON")
}

/// Hand the supplied bytes to the TypeScript verifier and return its
/// JSON view of the certificate.
pub fn ts_vote_verify(vote_bytes_hex: &str) -> Value {
	run_script("ts_vote_verify", format!("{vote_bytes_hex}\n").as_bytes())
}

/// Ask the TypeScript minter to produce a certificate matching `spec`
/// and return its `{ bytes, hash }` response.
pub fn ts_vote_mint(spec: &MintSpec) -> Value {
	let bytes = serde_json::to_vec(&spec.to_value()).expect("the spec must serialize");
	run_script("ts_vote_mint", &bytes)
}

// -- rust signing helper -----------------------------------------------------

/// Sign a vote with the supplied issuer using only Rust code paths.
///
/// Adapter over [`keetanetwork_vote::testing::sign_simple_vote`] that
/// accepts blocks as a slice (matching the integration-test call sites).
pub fn rust_sign_vote(
	issuer: &AccountRef,
	serial: u64,
	validity: Validity,
	blocks: &[BlockHash],
	fees: Option<Fees>,
) -> Vote {
	sign_simple_vote(issuer, serial, validity, blocks.iter().copied(), fees)
}

// -- mint spec ---------------------------------------------------------------

/// Issuer key family understood by the TypeScript minter.
#[derive(Clone, Copy)]
pub enum KeyKind {
	Ed25519,
	Secp256k1,
	Secp256r1,
}

impl KeyKind {
	fn wire_name(self) -> &'static str {
		match self {
			Self::Ed25519 => "ed25519",
			Self::Secp256k1 => "ecdsa-secp256k1",
			Self::Secp256r1 => "ecdsa-secp256r1",
		}
	}
}

/// One fee entry as understood by the TypeScript mint script.
#[derive(Clone, Debug)]
pub struct FeeEntry {
	pub amount: u64,
	pub pay_to: Option<String>,
	pub token: Option<String>,
}

impl FeeEntry {
	pub fn new(amount: u64) -> Self {
		Self { amount, pay_to: None, token: None }
	}

	pub fn pay_to(mut self, account: impl Into<String>) -> Self {
		self.pay_to = Some(account.into());
		self
	}

	pub fn token(mut self, account: impl Into<String>) -> Self {
		self.token = Some(account.into());
		self
	}

	fn to_json(&self) -> Value {
		let mut obj = Map::new();
		obj.insert("amount".to_string(), Value::String(self.amount.to_string()));
		if let Some(pay_to) = &self.pay_to {
			obj.insert("payTo".to_string(), Value::String(pay_to.clone()));
		}
		if let Some(token) = &self.token {
			obj.insert("token".to_string(), Value::String(token.clone()));
		}
		Value::Object(obj)
	}
}

/// Either a single fee or a list of fees
#[derive(Clone, Debug)]
pub enum FeeSchedule {
	Single(FeeEntry),
	Multiple(Vec<FeeEntry>),
}

/// A self-describing minting request that doubles as the source of
/// truth for round-trip assertions.
pub struct MintSpec {
	pub key_kind: KeyKind,
	pub issuer_seed_hex: String,
	pub issuer_index: u32,
	pub serial: u64,
	pub blocks: Vec<String>,
	pub validity_from_ms: i64,
	pub validity_to_ms: i64,
	pub fees: Option<FeeSchedule>,
	pub quote: bool,
}

impl MintSpec {
	/// Build a spec with a wide future validity window so live tests
	/// stay valid even on slow runners.
	pub fn new(key_kind: KeyKind, seed_hex: impl Into<String>, serial: u64) -> Self {
		let now_ms = chrono::Utc::now().timestamp_millis();
		Self {
			key_kind,
			issuer_seed_hex: seed_hex.into(),
			issuer_index: 0,
			serial,
			blocks: Vec::new(),
			validity_from_ms: now_ms - 60_000,
			validity_to_ms: now_ms + 24 * 60 * 60 * 1_000,
			fees: None,
			quote: false,
		}
	}

	pub fn add_block(mut self, hash_hex: impl Into<String>) -> Self {
		self.blocks.push(hash_hex.into());
		self
	}

	pub fn add_blocks<S: Into<String>>(mut self, hashes: impl IntoIterator<Item = S>) -> Self {
		self.blocks.extend(hashes.into_iter().map(Into::into));
		self
	}

	pub fn fee(mut self, entry: FeeEntry) -> Self {
		self.fees = Some(FeeSchedule::Single(entry));
		self
	}

	pub fn fees(mut self, entries: Vec<FeeEntry>) -> Self {
		self.fees = Some(FeeSchedule::Multiple(entries));
		self
	}

	pub fn quote(mut self) -> Self {
		self.quote = true;
		self
	}

	fn to_value(&self) -> Value {
		let mut obj = Map::new();
		obj.insert("issuerSeed".to_string(), Value::String(self.issuer_seed_hex.clone()));
		obj.insert("issuerKeyType".to_string(), Value::String(self.key_kind.wire_name().to_string()));
		obj.insert("issuerIndex".to_string(), Value::Number(self.issuer_index.into()));
		obj.insert("serial".to_string(), Value::String(self.serial.to_string()));
		obj.insert("blocks".to_string(), Value::Array(self.blocks.iter().cloned().map(Value::String).collect()));
		obj.insert("validityFromMs".to_string(), Value::Number(self.validity_from_ms.into()));
		obj.insert("validityToMs".to_string(), Value::Number(self.validity_to_ms.into()));
		if let Some(schedule) = &self.fees {
			let value = match schedule {
				FeeSchedule::Single(entry) => entry.to_json(),
				FeeSchedule::Multiple(entries) => Value::Array(entries.iter().map(FeeEntry::to_json).collect()),
			};
			obj.insert("fee".to_string(), value);
		}
		if self.quote {
			obj.insert("quote".to_string(), Value::Bool(true));
		}
		Value::Object(obj)
	}
}

// -- assertions --------------------------------------------------------------

/// Hand `vote` to TypeScript and assert every parsed field round-trips.
///
/// Proves wire-format, hash, and semantic interpretation parity: the
/// reference parser must agree on the bytes (re-encode equality), the
/// certificate hash, every scalar field (serial, issuer, validity), and
/// the full block / fee shape.
pub fn assert_ts_agrees_with_rust(vote: &Vote) {
	let bytes_hex = hex::encode_upper(vote.as_bytes());
	let parsed = ts_vote_verify(&bytes_hex);

	assert_eq!(parsed["bytes"].as_str(), Some(bytes_hex.as_str()), "TS must re-encode the Rust bytes verbatim");
	assert_eq!(parsed["hash"].as_str(), Some(vote.hash().to_string().as_str()), "TS hash must match Rust hash");
	assert_eq!(parsed["serial"].as_str(), Some(vote.serial().to_string().as_str()), "TS serial must match");
	assert_eq!(parsed["issuer"].as_str(), Some(vote.issuer().to_string().as_str()), "TS issuer must match");

	let expected_blocks: Vec<String> = vote.blocks().iter().map(BlockHash::to_string).collect();
	let actual_blocks = collect_strings(json_array(&parsed, "blocks"), "blocks");
	assert_eq!(actual_blocks, expected_blocks, "TS block list must match Rust");

	assert_eq!(
		iso_to_unix_millis(&json_str(&parsed, "validityFrom")),
		vote.validity().from.unix_millis(),
		"TS validityFrom must match Rust",
	);
	assert_eq!(
		iso_to_unix_millis(&json_str(&parsed, "validityTo")),
		vote.validity().to.unix_millis(),
		"TS validityTo must match Rust",
	);

	assert_fees_agree(&parsed["fee"], vote.fees(), "TS");
	assert_eq!(parsed["quote"].as_bool().unwrap_or(false), vote.is_quote(), "TS quote flag must match Rust",);
}

/// Mint a certificate via TypeScript, decode it in Rust, and assert
/// every field round-trips against the original spec.
pub fn assert_rust_decodes_ts_minted(spec: &MintSpec) -> TestResult {
	let minted = ts_vote_mint(spec);
	let bytes = hex_decode(&json_str(&minted, "bytes"));

	let vote = if spec.quote {
		VoteQuote::verify(bytes.clone())?.into_vote()
	} else {
		Vote::verify(bytes.clone())?
	};

	assert_eq!(vote.serial(), &BigInt::from(spec.serial), "Rust serial must match spec");
	assert_eq!(vote.validity().from.unix_millis(), spec.validity_from_ms, "Rust validityFrom must match spec");
	assert_eq!(vote.validity().to.unix_millis(), spec.validity_to_ms, "Rust validityTo must match spec");

	let expected_blocks: Vec<String> = spec.blocks.iter().map(|hex| hex.to_uppercase()).collect();
	let actual_blocks: Vec<String> = vote.blocks().iter().map(BlockHash::to_string).collect();
	assert_eq!(actual_blocks, expected_blocks, "Rust block list must match spec");

	// The TS minter authoritatively reports the issuer it derived from
	// `(seed, index, algorithm)`; comparing Rust's decoded view against
	// that proves wire-format agreement on the issuer field without
	// reproducing the seed→account derivation here.
	assert_eq!(vote.issuer().to_string(), json_str(&minted, "issuer"), "Rust issuer must match TS-reported issuer",);

	assert_eq!(vote.is_quote(), spec.quote, "Rust quote flag must match spec");
	assert_fees_match_schedule(vote.fees(), spec.fees.as_ref());

	let expected_hash = parse_vote_hash(&json_str(&minted, "hash"))?;
	assert_eq!(vote.hash(), expected_hash, "Rust hash must match TS-reported hash");

	Ok(())
}

/// Compare every block / vote hash in the TypeScript `verify_staple`
/// response against the Rust-parsed staple.
pub fn assert_ts_staple_matches_rust(rust: &VoteStaple, ts_response: &Value) {
	assert_eq!(json_str(ts_response, "stapleHash"), rust.hash().to_string(), "TS staple hash must match Rust",);

	let ts_blocks = collect_strings(json_array(ts_response, "blockHashes"), "block hash");
	let rust_blocks: Vec<String> = rust
		.blocks()
		.iter()
		.map(|block| block.hash().to_string())
		.collect();
	assert_eq!(ts_blocks, rust_blocks, "TS block hash list must match Rust");

	let ts_votes = collect_strings(json_array(ts_response, "voteHashes"), "vote hash");
	let rust_votes: Vec<String> = rust
		.votes()
		.iter()
		.map(|vote| vote.hash().to_string())
		.collect();
	assert_eq!(ts_votes, rust_votes, "TS vote hash list must match Rust");
}

// -- internal helpers --------------------------------------------------------

fn collect_strings(values: &[Value], context: &str) -> Vec<String> {
	values
		.iter()
		.map(|value| {
			value
				.as_str()
				.unwrap_or_else(|| panic!("{context} entry must be a string"))
				.to_string()
		})
		.collect()
}

fn iso_to_unix_millis(iso: &str) -> i64 {
	DateTime::<FixedOffset>::parse_from_rfc3339(iso)
		.unwrap_or_else(|err| panic!("validity {iso} must be RFC3339: {err}"))
		.timestamp_millis()
}

fn parse_vote_hash(s: &str) -> Result<VoteHash, Box<dyn Error>> {
	let bytes = hex::decode(s.trim_start_matches("0x"))?;
	Ok(VoteHash::try_from(bytes.as_slice())?)
}

fn assert_fees_agree(fee_json: &Value, vote_fees: Option<&Fees>, label: &str) {
	match vote_fees {
		None => assert!(fee_json.is_null(), "{label}: expected no fee, got {fee_json:?}"),
		Some(Fees::Single { fee, .. }) => {
			assert_fee_entry_matches(fee_json, fee, &format!("{label} single fee"));
		}
		Some(Fees::Multiple { fees, .. }) => {
			let entries = fee_json
				.as_array()
				.unwrap_or_else(|| panic!("{label}: multi-fee must be an array, got {fee_json:?}"));
			assert_eq!(entries.len(), fees.len(), "{label}: fee count must match");
			for (i, (entry, expected)) in entries.iter().zip(fees.iter()).enumerate() {
				assert_fee_entry_matches(entry, expected, &format!("{label} fees[{i}]"));
			}
		}
	}
}

fn assert_fee_entry_matches(entry: &Value, fee: &Fee, ctx: &str) {
	assert_eq!(entry["amount"].as_str(), Some(fee.amount.to_string().as_str()), "{ctx}: amount mismatch");
	assert_eq!(
		entry["payTo"].as_str().map(str::to_string),
		fee.pay_to.as_ref().map(|account| account.to_string()),
		"{ctx}: payTo mismatch",
	);
	assert_eq!(
		entry["token"].as_str().map(str::to_string),
		fee.token.as_ref().map(|account| account.to_string()),
		"{ctx}: token mismatch",
	);
}

fn assert_fees_match_schedule(vote_fees: Option<&Fees>, schedule: Option<&FeeSchedule>) {
	match (vote_fees, schedule) {
		(None, None) => {}
		(Some(Fees::Single { fee, .. }), Some(FeeSchedule::Single(spec))) => {
			assert_spec_fee_matches(fee, spec, "single fee");
		}
		(Some(Fees::Multiple { fees, .. }), Some(FeeSchedule::Multiple(specs))) => {
			assert_eq!(fees.len(), specs.len(), "fee count must match spec");
			for (i, (fee, spec)) in fees.iter().zip(specs.iter()).enumerate() {
				assert_spec_fee_matches(fee, spec, &format!("fees[{i}]"));
			}
		}
		(rust, spec) => panic!("Rust fee shape {rust:?} does not match spec {spec:?}"),
	}
}

// -- wire surgery ------------------------------------------------------------
//
// Helpers for table-driven corruption tests that mutate a single TLV
// inside a known-good DER encoding and re-emit the wire form.

/// Split the TLV(s) inside a SEQUENCE into owned, individually-encoded
/// pieces - i.e. given the bytes of `SEQUENCE { x, y, z }`, return the
/// bytes of `[x, y, z]`. Each output element is a complete TLV blob.
pub fn split_seq(bytes: &[u8]) -> Vec<Vec<u8>> {
	testing::split_sequence(bytes).expect("split SEQUENCE")
}

/// Build a SEQUENCE whose body is the concatenation of the supplied
/// pre-encoded TLV blobs.
pub fn join_seq<I, B>(parts: I) -> Vec<u8>
where
	I: IntoIterator<Item = B>,
	B: AsRef<[u8]>,
{
	testing::sequence_tlv(parts).expect("join SEQUENCE")
}

/// Build an `[N] EXPLICIT` constructed TLV whose body is the
/// concatenation of the supplied pre-encoded TLV blobs.
pub fn join_explicit_context<I, B>(number: u8, parts: I) -> Vec<u8>
where
	I: IntoIterator<Item = B>,
	B: AsRef<[u8]>,
{
	testing::explicit_context_tlv(number, parts).expect("explicit context tlv")
}

/// Encode an `INTEGER 0` TLV - a convenient "obviously wrong" blob to
/// substitute for a SEQUENCE / context-tagged slot.
pub fn integer_zero_tlv() -> Vec<u8> {
	testing::integer_zero_tlv().expect("integer 0")
}

/// Encode an `OCTET STRING` TLV with empty content.
pub fn empty_octet_tlv() -> Vec<u8> {
	testing::empty_octet_string_tlv().expect("empty octet")
}

/// Encode an `OCTET STRING` TLV with the supplied content.
pub fn octet_string_tlv(content: &[u8]) -> Vec<u8> {
	testing::octet_string_tlv(content).expect("octet string tlv")
}

/// Sign and return the wire bytes of a minimal one-block ed25519 vote
/// suitable as a baseline for surgery.
pub fn baseline_vote_bytes(serial: u64) -> Vec<u8> {
	let issuer = ed25519_issuer("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
	let blocks = [BlockHash::from([0xCA; 32])];
	let vote = rust_sign_vote(&issuer, serial, future_validity(), &blocks, None);
	vote.as_bytes().to_vec()
}

fn assert_spec_fee_matches(fee: &Fee, spec: &FeeEntry, ctx: &str) {
	assert_eq!(fee.amount.to_string(), spec.amount.to_string(), "{ctx}: amount mismatch");
	assert_eq!(fee.pay_to.as_ref().map(|account| account.to_string()), spec.pay_to.clone(), "{ctx}: payTo mismatch",);
	assert_eq!(fee.token.as_ref().map(|account| account.to_string()), spec.token.clone(), "{ctx}: token mismatch",);
}
