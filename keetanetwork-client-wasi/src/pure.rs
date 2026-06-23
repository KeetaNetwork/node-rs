//! Shared, target-agnostic operations behind both WASI ABIs (`p1` flat ABI and
//! `p2` component). Every function is pure/offline.

use std::str::FromStr;
use std::sync::Arc;

use num_bigint::BigInt;

use keetanetwork_account::account::AccountSigner;
use keetanetwork_account::{Account, GenericAccount, KeyED25519, KeyPairType, Keyable};
use keetanetwork_bindings::account::{algorithm_name, from_keyable};
use keetanetwork_bindings::error::CodedError;
use keetanetwork_bindings::parse::{base_flag, bigint_hex};
use keetanetwork_bindings::permissions as bindings_permissions;
use keetanetwork_block::{
	AccountRef, AdjustMethod, Block, BlockBuilder, BlockHash, BlockTime, BlockVersion, CertificateDer,
	CertificateOrHash, CreateIdentifier, Hashable, IdentifierCreateArguments, IntermediateCertificates,
	ManageCertificate, ModifyPermissions, ModifyPermissionsPrincipal, MultisigCreateArguments, Operation, Permissions,
	SetInfo, SetRep, Signer, UnsignedBlock,
};
use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret};
use keetanetwork_vote::{Vote, VoteQuote, VoteStaple};

/// The default signing algorithm, matching the browser binding.
pub const DEFAULT_ALGORITHM: &str = "ecdsa_secp256k1";

/// Generate a fresh random 32-byte seed as hex.
pub fn generate_seed() -> Result<String, CodedError> {
	let seed = Account::<KeyED25519>::generate_random_seed().map_err(|error| CodedError::new("RNG", error.as_ref()))?;
	Ok(hex::encode(seed.expose_secret()))
}

/// Generate a fresh BIP39 mnemonic.
pub fn generate_passphrase() -> Result<Vec<String>, CodedError> {
	let passphrase =
		Account::<KeyED25519>::generate_passphrase().map_err(|error| CodedError::new("RNG", error.as_ref()))?;
	Ok(passphrase.expose_secret().clone())
}

/// Derive an account from a 32-byte hex `seed` at derivation `index`.
pub fn account_from_seed(seed: &str, index: u32, algorithm: &str) -> Result<AccountRef, CodedError> {
	let mut bytes = [0u8; 32];
	hex::decode_to_slice(seed, &mut bytes).map_err(|_| CodedError::new("INVALID_SEED", "seed must be 32-byte hex"))?;
	keyable_account(Keyable::Seed((bytes.into_secret(), index)), algorithm)
}

/// Build an account from a hex-encoded private `key`.
pub fn account_from_private_key(key: &str, algorithm: &str) -> Result<AccountRef, CodedError> {
	let bytes = hex::decode(key).map_err(|_| CodedError::new("INVALID_PRIVATE_KEY", "private key must be hex"))?;
	keyable_account(Keyable::PrivateKey(bytes), algorithm)
}

/// Derive an account from a BIP39 mnemonic `words` at derivation `index`.
pub fn account_from_passphrase(words: Vec<String>, index: u32, algorithm: &str) -> Result<AccountRef, CodedError> {
	keyable_account(Keyable::from((words, index)), algorithm)
}

/// Build a read-only account from a hex-encoded public `key`.
pub fn account_from_public_key(key: &str, algorithm: &str) -> Result<AccountRef, CodedError> {
	let bytes = hex::decode(key).map_err(|_| CodedError::new("INVALID_PUBLIC_KEY", "public key must be hex"))?;
	keyable_account(Keyable::PublicKey(bytes), algorithm)
}

/// Build a read-only account from its textual `address`.
pub fn account_from_address(address: &str) -> Result<AccountRef, CodedError> {
	let account =
		GenericAccount::from_str(address).map_err(|_| CodedError::new("INVALID_ADDRESS", "invalid account address"))?;
	Ok(Arc::new(account))
}

/// The textual account address.
pub fn account_address(account: &AccountRef) -> String {
	account.to_string()
}

/// The signing algorithm name, or `"other"` for identifier accounts.
pub fn account_algorithm(account: &AccountRef) -> String {
	String::from(algorithm_name(account.to_keypair_type()))
}

/// The type-prefixed public key transport bytes, hex-encoded.
pub fn account_public_key(account: &AccountRef) -> String {
	hex::encode(account.to_public_key_with_type())
}

/// Sign `message`, returning the raw signature bytes.
pub fn account_sign(account: &AccountRef, message: &[u8]) -> Result<Vec<u8>, CodedError> {
	AccountSigner::sign(account.as_ref(), message, None).map_err(|error| CodedError::new("SIGN", error.as_ref()))
}

/// Whether `signature` is a valid signature of `message` by this account.
pub fn account_verify(account: &AccountRef, message: &[u8], signature: &[u8]) -> bool {
	account.verify(message, signature, None).is_ok()
}

/// Encrypt `plaintext` to the account's public key.
pub fn account_encrypt(account: &AccountRef, plaintext: &[u8]) -> Result<Vec<u8>, CodedError> {
	account
		.encrypt(plaintext)
		.map_err(|error| CodedError::new("ENCRYPT", error.as_ref()))
}

/// Decrypt `ciphertext` with the account's private key.
pub fn account_decrypt(account: &AccountRef, ciphertext: &[u8]) -> Result<Vec<u8>, CodedError> {
	account
		.decrypt(ciphertext)
		.map_err(|error| CodedError::new("DECRYPT", error.as_ref()))
}

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

fn keyable_account(keyable: Keyable, algorithm: &str) -> Result<AccountRef, CodedError> {
	let account = from_keyable(keyable, algorithm)?;
	Ok(Arc::new(account))
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

/// The staple hash as a hex string.
pub fn staple_hash(staple: &VoteStaple) -> String {
	staple.hash().to_string()
}

/// The staple's compressed hex transport encoding.
pub fn staple_to_hex(staple: &VoteStaple) -> String {
	hex::encode(staple.as_bytes())
}

// ---------------------------------------------------------------------------
// Offline block building (the `p1` host-transmit path). The networked
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
	let bundle = intermediates
		.iter()
		.map(|der| decode_certificate_der(der))
		.collect::<Result<Vec<_>, _>>()?;

	Ok(ManageCertificate {
		method: AdjustMethod::Add,
		certificate_or_hash: CertificateOrHash::Certificate(certificate),
		intermediate_certificates: Some(IntermediateCertificates::Bundle(bundle)),
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
	fn generated_seed_is_32_byte_hex() {
		let seed = generate_seed().expect("seed generation must succeed");
		assert_eq!(seed.len(), 64);
		assert!(hex::decode(&seed).is_ok());
	}

	#[test]
	fn account_round_trips_through_seed_and_address() {
		let seed = generate_seed().expect("seed generation must succeed");
		let account = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("account derivation must succeed");
		let address = account_address(&account);
		let reopened = account_from_address(&address).expect("address must parse");
		assert_eq!(account_address(&reopened), address);
		assert_eq!(account_algorithm(&account), DEFAULT_ALGORITHM);
	}

	#[test]
	fn signatures_verify_against_the_signing_account() {
		let seed = generate_seed().expect("seed generation must succeed");
		let account = account_from_seed(&seed, 0, DEFAULT_ALGORITHM).expect("account derivation must succeed");
		let message = b"keeta multisig";
		let signature = account_sign(&account, message).expect("signing must succeed");
		assert!(account_verify(&account, message, &signature));
		assert!(!account_verify(&account, b"tampered", &signature));
	}

	#[test]
	fn invalid_seed_is_rejected_with_a_stable_code() {
		let error = account_from_seed("not-hex", 0, DEFAULT_ALGORITHM).expect_err("invalid seed must fail");
		assert_eq!(error.code, "INVALID_SEED");
	}

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
		// in the host capstone (which supplies real ledger heads).
		let _ = op_create_multisig(multisig.clone(), vec![s1.clone(), s2.clone(), s3.clone()], 2);
		let _ = signer_multisig(multisig, vec![s1, s2]);
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
}
