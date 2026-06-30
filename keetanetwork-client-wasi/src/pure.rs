//! Shared, target-agnostic operations behind both WASI ABIs (`p1` flat ABI and
//! `p2` component). Every function is pure.

use core::str::FromStr;
use std::sync::Arc;

use num_bigint::BigInt;

use keetanetwork_account::KeyPairType;
use keetanetwork_bindings::error::CodedError;
use keetanetwork_bindings::parse::{adjust_method, base_flag, bigint_hex, purpose};
use keetanetwork_bindings::permissions as bindings_permissions;
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, Block, BlockBuilder, BlockHash, BlockPurpose, BlockTime, BlockVersion,
	CertificateDer, CertificateOrHash, CreateIdentifier, Hashable, IdentifierCreateArguments, IntermediateCertificates,
	ManageCertificate, ModifyPermissions, ModifyPermissionsPrincipal, MultisigCreateArguments, Operation, Permissions,
	Receive, Send, SetInfo, SetRep, Signer, TokenAdminModifyBalance, TokenAdminSupply, UnsignedBlock,
};
use keetanetwork_vote::{ValidationConfig, Vote, VoteQuote, VoteStaple};

/// The account primitive operations live in the shared `keetanetwork-bindings`
/// crate so every binding boundary reuses a single definition.
pub use keetanetwork_bindings::account::{
	account_address, account_algorithm, account_decrypt, account_encrypt, account_from_address,
	account_from_passphrase, account_from_private_key, account_from_public_key, account_from_seed, account_public_key,
	account_sign, account_verify, generate_passphrase, generate_seed, DEFAULT_ALGORITHM,
};

/// The base X.509 certificate primitive operations also live in the shared
/// `keetanetwork-bindings` crate, re-exported so the WASI ABIs call them as
/// `pure::*`.
pub use keetanetwork_bindings::x509::{
	certificate_der, certificate_from_der, certificate_from_pem, certificate_issuer, certificate_not_after,
	certificate_not_before, certificate_pem, certificate_serial, certificate_subject, certificate_subject_public_key,
	certificate_valid_at,
};

/// Derive an identifier account (`network`/`token`/`storage`) relative to
/// `account`, an optional previous block hash (the opening hash when absent),
/// and an operation `index`.
pub fn generate_identifier(
	account: &AccountRef,
	kind: KeyPairType,
	previous: Option<[u8; 32]>,
	index: u32,
) -> Result<AccountRef, CodedError> {
	let previous = previous.map(BlockHash::from);
	let identifier = account
		.generate_identifier(kind, previous.as_ref(), index)
		.map_err(|error| CodedError::new("IDENTIFIER", error.as_ref()))?;

	Ok(Arc::new(identifier))
}

/// Decode a block from its hex transport encoding.
pub fn block_from_hex(value: &str) -> Result<Block, CodedError> {
	let bytes = hex::decode(value).map_err(|_| CodedError::new("INVALID_BLOCK", "block must be hex"))?;
	Ok(Block::try_from(bytes.as_slice())?)
}

/// The block hash as a hex string.
pub fn block_hash(block: &Block) -> String {
	block.hash().to_string()
}

/// The block's hex transport encoding.
pub fn block_to_hex(block: &Block) -> String {
	hex::encode(block.to_bytes())
}

/// The block's originating account.
pub fn block_account(block: &Block) -> AccountRef {
	block.data().account().clone()
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// Build a permission set from snake_case base flag names and external bit
/// `offsets`.
pub fn permissions_from_flags(flags: &[String], offsets: &[u8]) -> Result<Permissions, CodedError> {
	let flags = flags
		.iter()
		.map(|flag| base_flag(flag).map_err(CodedError::from))
		.collect::<Result<Vec<_>, _>>()?;
	bindings_permissions::from_flags(&flags, offsets)
}

/// Decode a permission set from the on-chain `[base, external]` hex bitmaps.
pub fn permissions_from_bitmaps(base: &str, external: &str) -> Result<Permissions, CodedError> {
	let base = bigint_hex(base, "base")?;
	let external = bigint_hex(external, "external")?;
	bindings_permissions::from_bigints(base, external)
}

/// The base flag names present, after normalization.
pub fn permissions_flag_names(permissions: &Permissions) -> Vec<String> {
	bindings_permissions::flag_names(permissions)
}

/// The external bit offsets present, ascending.
pub fn permissions_offsets(permissions: &Permissions) -> Vec<u8> {
	bindings_permissions::offsets(permissions)
}

/// The `[base, external]` bitmaps as `0x`-prefixed hex.
pub fn permissions_bitmaps(permissions: &Permissions) -> Vec<String> {
	bindings_permissions::bitmaps(permissions)
}

// ---------------------------------------------------------------------------
// Vote / staple projections (sources are networked; encoders only)
// ---------------------------------------------------------------------------

/// The vote hash as a hex string.
pub fn vote_hash(vote: &Vote) -> String {
	vote.hash().to_string()
}

/// The vote's DER hex encoding.
pub fn vote_to_hex(vote: &Vote) -> String {
	hex::encode(vote.as_bytes())
}

/// The quote hash as a hex string.
pub fn quote_hash(quote: &VoteQuote) -> String {
	quote.hash().to_string()
}

/// The quote's DER hex encoding.
pub fn quote_to_hex(quote: &VoteQuote) -> String {
	hex::encode(quote.as_vote().as_bytes())
}

/// The fee-paying `SEND` operation `vote` requires.
pub fn fee_send(vote: &Vote, base_token: &AccountRef, priority: &[AccountRef]) -> Option<Operation> {
	vote.fee_send(base_token, priority).map(Operation::from)
}

/// The staple hash as a hex string.
pub fn staple_hash(staple: &VoteStaple) -> String {
	staple.hash().to_string()
}

/// The staple's compressed hex transport encoding.
pub fn staple_to_hex(staple: &VoteStaple) -> String {
	hex::encode(staple.as_bytes())
}

/// Verify and decode a representative [`Vote`] from its wire `bytes`. The host
/// sources these over its own transport.
pub fn vote_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Vote, CodedError> {
	Vote::verify(bytes).map_err(CodedError::from)
}

/// Assemble a publishable [`VoteStaple`] from signed `blocks` and the `votes`
/// endorsing them, enforcing the staple invariants at `moment_millis`.
pub fn vote_staple_build(blocks: Vec<Block>, votes: Vec<Vote>, moment_millis: i64) -> Result<Vec<u8>, CodedError> {
	let staple = VoteStaple::try_new(blocks, votes, ValidationConfig::default(), block_time(moment_millis)?)
		.map_err(CodedError::from)?;

	Ok(staple.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Block building (the `p1` host-transmit path). The networked
// `TransactionBuilder` lives in the `p2` component.
// ---------------------------------------------------------------------------

/// A single-account signer.
pub fn signer_single(account: AccountRef) -> Signer {
	Signer::Single(account)
}

/// A multisig signer: the multisig `address` plus the member accounts actually
/// producing signatures (which may be a quorum subset).
pub fn signer_multisig(address: AccountRef, signers: Vec<AccountRef>) -> Signer {
	let signers = signers.into_iter().map(Signer::Single).collect();
	Signer::Multisig { address, signers }
}

/// A `CREATE_IDENTIFIER` operation for a plain (non-multisig) identifier such
/// as a token, storage, or network address.
pub fn op_create_identifier(identifier: AccountRef) -> Operation {
	CreateIdentifier { identifier, create_arguments: None }.into()
}

/// A `CREATE_IDENTIFIER` operation for a multisig identifier requiring `quorum`
/// of `signers`.
pub fn op_create_multisig(multisig: AccountRef, signers: Vec<AccountRef>, quorum: u32) -> Operation {
	CreateIdentifier {
		identifier: multisig,
		create_arguments: Some(IdentifierCreateArguments::Multisig(MultisigCreateArguments {
			signers,
			quorum: BigInt::from(quorum),
		})),
	}
	.into()
}

/// A `MODIFY_PERMISSIONS` operation for an account `principal`.
pub fn op_modify_permissions(
	principal: AccountRef,
	permissions: Permissions,
	method: AdjustMethod,
	target: Option<AccountRef>,
) -> Operation {
	ModifyPermissions {
		principal: ModifyPermissionsPrincipal::Account(principal),
		method,
		permissions: Some(permissions),
		target,
	}
	.into()
}

/// Parse a transfer amount accepting either a decimal or `0x`-prefixed hex
/// integer (the latter matching the reference balance encoding).
fn parse_amount(amount: &str) -> Result<Amount, CodedError> {
	Amount::from_str(amount)
		.map_err(|_| CodedError::new("INVALID_AMOUNT", "amount must be a decimal or 0x-hex integer"))
}

/// A `SEND` operation transferring `amount` of `token` to `to`. An empty
/// `external` is treated as no reference, so every ABI can forward its raw
/// optional-string argument without repeating that policy.
pub fn op_send(to: AccountRef, amount: &str, token: AccountRef, external: &str) -> Result<Operation, CodedError> {
	let external = (!external.is_empty()).then(|| external.to_string());

	Ok(Send { to, amount: parse_amount(amount)?, token, external }.into())
}

/// A `RECEIVE` operation crediting `amount` of `token` from `from`, optionally
/// requiring an `exact` match and forwarding to `forward`.
pub fn op_receive(
	from: AccountRef,
	amount: &str,
	token: AccountRef,
	exact: bool,
	forward: Option<AccountRef>,
) -> Result<Operation, CodedError> {
	Ok(Receive { amount: parse_amount(amount)?, token, from, exact, forward }.into())
}

/// A `TOKEN_ADMIN_SUPPLY` operation adjusting the block token's total supply by
/// `amount` using `method` (`add`/`subtract`; `set` is rejected on validation).
pub fn op_token_admin_supply(amount: &str, method: &str) -> Result<Operation, CodedError> {
	Ok(TokenAdminSupply { amount: parse_amount(amount)?, method: adjust_method(method)? }.into())
}

/// A `TOKEN_ADMIN_MODIFY_BALANCE` operation adjusting the block account's
/// balance of `token` by `amount` using `method`.
pub fn op_token_admin_modify_balance(token: AccountRef, amount: &str, method: &str) -> Result<Operation, CodedError> {
	Ok(TokenAdminModifyBalance { token, amount: parse_amount(amount)?, method: adjust_method(method)? }.into())
}

/// A `SET_REP` operation delegating voting weight to representative `to`.
pub fn op_set_rep(to: AccountRef) -> Operation {
	SetRep { to }.into()
}

/// A `SET_INFO` operation.
pub fn op_set_info(
	name: String,
	description: String,
	metadata: String,
	default_permission: Option<Permissions>,
) -> Operation {
	SetInfo { name, description, metadata, default_permission }.into()
}

/// Build a block timestamp from Unix milliseconds.
pub fn block_time(unix_millis: i64) -> Result<BlockTime, CodedError> {
	BlockTime::from_unix_millis(unix_millis)
		.ok_or_else(|| CodedError::new("INVALID_DATE", "unix milliseconds out of range"))
}

/// Parse a block version (`1` or `2`).
pub fn block_version(version: u32) -> Result<BlockVersion, CodedError> {
	match version {
		1 => Ok(BlockVersion::V1),
		2 => Ok(BlockVersion::V2),
		_ => Err(CodedError::new("INVALID_BLOCK_VERSION", "block version must be 1 or 2")),
	}
}

/// Parse a block purpose (`generic` or `fee`).
pub fn block_purpose(value: &str) -> Result<BlockPurpose, CodedError> {
	Ok(purpose(value)?)
}

/// Build and validate the unsigned block, consuming the builder.
pub fn build_unsigned(builder: BlockBuilder) -> Result<UnsignedBlock, CodedError> {
	builder.build().map_err(CodedError::from)
}

/// Sign the block with the private keys held by its required signer accounts
/// and seal it, consuming the unsigned block.
pub fn sign_unsigned(unsigned: UnsignedBlock) -> Result<Block, CodedError> {
	unsigned.sign().map_err(CodedError::from)
}

/// The unsigned block hash as a hex string.
pub fn unsigned_hash(unsigned: &UnsignedBlock) -> String {
	unsigned.hash().to_string()
}

/// The signed block's raw transport bytes.
pub fn block_to_bytes(block: &Block) -> Vec<u8> {
	block.to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// X.509 / certificate management (MANAGE_CERTIFICATE)
// ---------------------------------------------------------------------------

/// The `SHA3-256` hash (hex) of a hex-DER `certificate`, as used to reference
/// or remove it on-chain.
pub fn certificate_hash(certificate: &str) -> Result<String, CodedError> {
	Ok(hex::encode(decode_certificate_der(certificate)?.hash()))
}

/// A `MANAGE_CERTIFICATE` add operation for a hex-DER `certificate` plus
/// optional hex-DER `intermediates`.
pub fn op_manage_certificate_add(certificate: &str, intermediates: &[String]) -> Result<Operation, CodedError> {
	let certificate = decode_certificate_der(certificate)?;
	// An add with no intermediates is canonically encoded as NULL, not as an
	// empty SEQUENCE; the two ASN.1 forms hash differently and an empty bundle
	// would not match the bytes the network signs over.
	let intermediates = if intermediates.is_empty() {
		IntermediateCertificates::None
	} else {
		let bundle = intermediates
			.iter()
			.map(|der| decode_certificate_der(der))
			.collect::<Result<Vec<_>, _>>()?;

		IntermediateCertificates::Bundle(bundle)
	};

	Ok(ManageCertificate {
		method: AdjustMethod::Add,
		certificate_or_hash: CertificateOrHash::Certificate(certificate),
		intermediate_certificates: Some(intermediates),
	}
	.into())
}

/// A `MANAGE_CERTIFICATE` remove operation identified by a 32-byte hex `hash`.
pub fn op_manage_certificate_remove(hash: &str) -> Result<Operation, CodedError> {
	let mut digest = [0u8; 32];
	hex::decode_to_slice(hash, &mut digest)
		.map_err(|_| CodedError::new("INVALID_CERTIFICATE_HASH", "certificate hash must be 32-byte hex"))?;

	Ok(ManageCertificate {
		method: AdjustMethod::Subtract,
		certificate_or_hash: CertificateOrHash::Hash(digest),
		intermediate_certificates: None,
	}
	.into())
}

fn decode_certificate_der(certificate: &str) -> Result<CertificateDer, CodedError> {
	hex::decode(certificate)
		.map(CertificateDer::from)
		.map_err(|_| CodedError::new("INVALID_CERTIFICATE", "certificate must be hex DER"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn permissions_round_trip_through_bitmaps() {
		let flags = [String::from("admin")];
		let permissions = permissions_from_flags(&flags, &[]).expect("flags must build");
		let bitmaps = permissions_bitmaps(&permissions);
		let decoded = permissions_from_bitmaps(&bitmaps[0], &bitmaps[1]).expect("bitmaps must decode");
		assert!(permissions_flag_names(&decoded)
			.iter()
			.any(|name| name == "admin"));
	}

	#[test]
	fn unknown_permission_flag_is_rejected() {
		let flags = [String::from("not_a_flag")];
		let error = permissions_from_flags(&flags, &[]).expect_err("unknown flag must fail");
		assert_eq!(error.code, "INVALID_PERMISSION_FLAG");
	}

	#[test]
	fn opening_block_builds_signs_and_serializes() {
		let seed = generate_seed().expect("seed generation must succeed");
		let user = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let rep = account_from_seed(&seed, 1, DEFAULT_ALGORITHM).expect("derivation must succeed");

		let set_rep = op_set_rep(rep);
		let date = block_time(1_700_000_000_000).expect("timestamp must be in range");
		let builder = BlockBuilder::default()
			.with_network(0u64)
			.with_account(user.clone())
			.with_signer(signer_single(user))
			.with_date(date)
			.as_opening()
			.with_operation(set_rep);

		let unsigned = build_unsigned(builder).expect("the unsigned block must build");
		assert_eq!(unsigned_hash(&unsigned).len(), 64);

		let signed = sign_unsigned(unsigned).expect("signing must succeed");
		assert_eq!(block_hash(&signed).len(), 64);
		assert!(!block_to_bytes(&signed).is_empty());
	}

	#[test]
	fn multisig_operation_constructors_assemble() {
		let seed = generate_seed().expect("seed generation must succeed");
		let derive = |index| account_from_seed(&seed, index, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let (user, s1, s2, s3) = (derive(0), derive(1), derive(2), derive(3));
		let multisig = generate_identifier(&user, KeyPairType::MULTISIG, None, 0).expect("identifier must derive");

		// Construction must not panic; signing validity is exercised end-to-end
		// in the host example (which supplies real ledger heads).
		let _ = op_create_multisig(multisig.clone(), vec![s1.clone(), s2.clone(), s3.clone()], 2);
		let _ = signer_multisig(multisig, vec![s1, s2]);
	}

	#[test]
	fn plain_identifier_create_operation_assembles() {
		let seed = generate_seed().expect("seed generation must succeed");
		let owner = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let token = generate_identifier(&owner, KeyPairType::TOKEN, None, 0).expect("identifier must derive");

		let operation = op_create_identifier(token);
		assert!(matches!(operation, Operation::CreateIdentifier(_)));
	}

	#[test]
	fn certificate_hash_is_deterministic_and_drives_remove() {
		let certificate = "30030101ff";
		let hash = certificate_hash(certificate).expect("der must hash");
		assert_eq!(hash.len(), 64);
		assert_eq!(certificate_hash(certificate).expect("der must hash"), hash);

		op_manage_certificate_add(certificate, &[]).expect("add must build");
		op_manage_certificate_remove(&hash).expect("remove must accept a 32-byte hash");
	}

	#[test]
	fn certificate_remove_rejects_a_short_hash() {
		let error = op_manage_certificate_remove("abcd").expect_err("short hash must fail");
		assert_eq!(error.code, "INVALID_CERTIFICATE_HASH");
	}

	#[test]
	fn send_and_receive_operations_assemble() {
		let seed = generate_seed().expect("seed generation must succeed");
		let derive = |index| account_from_seed(&seed, index, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let (sender, recipient) = (derive(0), derive(1));
		let token = generate_identifier(&sender, KeyPairType::TOKEN, None, 0).expect("identifier must derive");

		let send = op_send(recipient.clone(), "1000", token.clone(), "memo").expect("send must build");
		assert!(matches!(send, Operation::Send(operation) if operation.external.as_deref() == Some("memo")));

		let receive = op_receive(sender, "0x3e8", token, false, None).expect("receive must build");
		assert!(matches!(receive, Operation::Receive(_)));
	}

	#[test]
	fn send_treats_an_empty_external_as_absent() {
		let seed = generate_seed().expect("seed generation must succeed");
		let derive = |index| account_from_seed(&seed, index, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let token = generate_identifier(&derive(0), KeyPairType::TOKEN, None, 0).expect("identifier must derive");

		let send = op_send(derive(1), "1", token, "").expect("send must build");
		assert!(matches!(send, Operation::Send(operation) if operation.external.is_none()));
	}

	#[test]
	fn send_rejects_a_malformed_amount() {
		let seed = generate_seed().expect("seed generation must succeed");
		let derive = |index| account_from_seed(&seed, index, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let token = generate_identifier(&derive(0), KeyPairType::TOKEN, None, 0).expect("identifier must derive");

		let error = op_send(derive(1), "not-a-number", token, "").expect_err("amount must be rejected");
		assert_eq!(error.code, "INVALID_AMOUNT");
	}

	#[test]
	fn token_admin_operations_assemble() {
		let seed = generate_seed().expect("seed generation must succeed");
		let derive = |index| account_from_seed(&seed, index, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let token = generate_identifier(&derive(0), KeyPairType::TOKEN, None, 0).expect("identifier must derive");

		let supply = op_token_admin_supply("1000", "add").expect("supply must build");
		assert!(matches!(supply, Operation::TokenAdminSupply(_)));

		let modify = op_token_admin_modify_balance(token, "0x10", "subtract").expect("modify must build");
		assert!(matches!(modify, Operation::TokenAdminModifyBalance(_)));
	}

	#[test]
	fn token_admin_supply_rejects_an_unknown_method() {
		let error = op_token_admin_supply("1", "multiply").expect_err("method must be rejected");
		assert!(!error.code.is_empty());
	}

	#[test]
	fn malformed_vote_bytes_are_rejected() {
		let error = vote_from_bytes([0u8, 1, 2, 3]).expect_err("garbage must not decode");
		assert!(!error.code.is_empty());
	}

	#[test]
	fn staple_without_votes_is_rejected() {
		let result = vote_staple_build(Vec::new(), Vec::new(), 1_700_000_000_000);
		assert!(matches!(result, Err(error) if !error.code.is_empty()));
	}

	#[test]
	fn staple_with_an_out_of_range_moment_is_rejected() {
		let error = vote_staple_build(Vec::new(), Vec::new(), i64::MAX).expect_err("moment must be in range");
		assert_eq!(error.code, "INVALID_DATE");
	}

	#[test]
	fn signed_block_round_trips_through_hex() {
		let seed = generate_seed().expect("seed generation must succeed");
		let user = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let rep = account_from_seed(&seed, 1, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let date = block_time(1_700_000_000_000).expect("timestamp must be in range");
		let builder = BlockBuilder::default()
			.with_network(0u64)
			.with_account(user.clone())
			.with_signer(signer_single(user))
			.with_date(date)
			.as_opening()
			.with_operation(op_set_rep(rep));

		let signed = sign_unsigned(build_unsigned(builder).expect("block must build")).expect("signing must succeed");
		let decoded = block_from_hex(&block_to_hex(&signed)).expect("hex must decode");
		assert_eq!(block_hash(&decoded), block_hash(&signed));
	}

	#[test]
	fn identifier_accounts_report_the_other_algorithm() {
		let seed = generate_seed().expect("seed generation must succeed");
		let owner = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let token = generate_identifier(&owner, KeyPairType::TOKEN, None, 0).expect("identifier must derive");
		assert_eq!(account_algorithm(&token), "other");
	}

	#[test]
	fn permissions_round_trip_external_offsets() {
		let permissions = permissions_from_flags(&[], &[3, 7]).expect("offsets must build");
		assert_eq!(permissions_offsets(&permissions), [3, 7]);
	}

	#[test]
	fn permission_and_info_operations_assemble() {
		let seed = generate_seed().expect("seed generation must succeed");
		let principal = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("derivation must succeed");
		let permissions = permissions_from_flags(&[String::from("access")], &[]).expect("flags must build");

		let modify = op_modify_permissions(principal, permissions, AdjustMethod::Set, None);
		assert!(matches!(modify, Operation::ModifyPermissions(_)));

		let info = op_set_info(String::from("TKN"), String::from("Token"), String::new(), None);
		assert!(matches!(info, Operation::SetInfo(_)));
	}

	#[test]
	fn block_versions_parse_and_reject() {
		assert!(matches!(block_version(1), Ok(BlockVersion::V1)));
		assert!(matches!(block_version(2), Ok(BlockVersion::V2)));
		assert_eq!(block_version(3).expect_err("version 3 must fail").code, "INVALID_BLOCK_VERSION");
	}

	#[test]
	fn malformed_block_hex_is_rejected_with_a_stable_code() {
		assert_eq!(block_from_hex("zz").expect_err("bad block must fail").code, "INVALID_BLOCK");
	}

	#[test]
	fn block_purposes_parse_and_reject() {
		assert!(matches!(block_purpose("generic"), Ok(BlockPurpose::Generic)));
		assert!(matches!(block_purpose("fee"), Ok(BlockPurpose::Fee)));
		assert_eq!(
			block_purpose("other")
				.expect_err("unknown purpose must fail")
				.code,
			"INVALID_PURPOSE"
		);
	}
}
