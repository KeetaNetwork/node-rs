//! Genesis bootstrap for a brand-new network.
//!
//! The initial trusted account (the bound signer) seals the network-address
//! and base-token blocks, optionally mints supply to a recipient and delegates
//! the recipient's voting weight, then self-issues a permanent vote binding the
//! whole set into a single staple ready to transmit.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use base64::Engine;
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, BaseFlag, Block, BlockHash, BlockTime, Hashable, ModifyPermissions,
	ModifyPermissionsPrincipal, Operation, Permissions, SetInfo, SetRep, TokenAdminModifyBalance, TokenAdminSupply,
};
use keetanetwork_vote::{Vote, VoteBuilder, VoteStaple, VoteStapleBuilder};

use crate::client::KeetaClient;
use crate::error::ClientError;

/// Span by which a genesis vote's `validity_to` exceeds its `validity_from`,
/// far past the permanence threshold so the vote is treated as permanent.
const PERMANENT_SPAN_MS: i64 = 200 * 365 * 86_400 * 1000;

/// The base-token metadata and default permission for a genesis network.
#[derive(Clone, Debug)]
pub struct BaseTokenInfo {
	/// Human-readable token name (stored as the token's description).
	pub name: String,
	/// Short currency code (stored as the token's name).
	pub currency_code: String,
	/// Number of decimal places (encoded into the token's metadata).
	pub decimal_places: u32,
	/// Default permission granted to holders; defaults to `ACCESS`.
	pub default_permission: Option<Permissions>,
}

/// Overrides for the network-address account's info at genesis.
#[derive(Clone, Debug, Default)]
pub struct BaseNetworkInfo {
	/// Network name; defaults to `KEETANET`.
	pub name: Option<String>,
	/// Network description; defaults to `Network Address For KeetaNet`.
	pub description: Option<String>,
	/// Network metadata; defaults to empty.
	pub metadata: Option<String>,
	/// Default permission; defaults to `STORAGE_CREATE`.
	pub default_permission: Option<Permissions>,
}

/// Inputs to [`UserClient::initialize_network`](crate::UserClient::initialize_network).
#[derive(Clone, Debug, Default)]
pub struct InitializeNetwork {
	/// Supply minted on the base token and credited to the recipient.
	pub add_supply_amount: Amount,
	/// Representative to delegate the recipient's voting weight to; defaults
	/// to the client's first representative.
	pub delegate_to: Option<AccountRef>,
	/// Serial of the self-issued genesis vote (default zero).
	pub vote_serial: Option<num_bigint::BigInt>,
	/// Base-token info; absent leaves the token's info blank.
	pub base_token_info: Option<BaseTokenInfo>,
	/// Network-address info overrides.
	pub base_network_info: Option<BaseNetworkInfo>,
}

/// Build the initial vote staple for a fresh network.
///
/// `trusted` is the initial trusted account (and signer); `recipient` receives
/// the minted supply and delegates its weight.
///
/// # Errors
///
/// - [`ClientError::UnsupportedNetwork`] -- the client has no network set.
/// - [`ClientError::Block`] / [`ClientError::Vote`] -- a genesis block,
///   vote, or staple cannot be built.
pub(crate) fn generate_initial_vote_staple(
	client: &KeetaClient,
	trusted: &AccountRef,
	recipient: &AccountRef,
	delegate_to: &AccountRef,
	options: &InitializeNetwork,
) -> Result<VoteStaple, ClientError> {
	let (network_address, base_token) = client.base_addresses()?;

	let network_operations = network_address_ops(trusted, options)?;
	let network_block = seal(client, &network_address, trusted, None, network_operations)?;

	let token_operations = base_token_ops(trusted, options)?;
	let base_token_block = seal(client, &base_token, trusted, None, token_operations)?;

	let balance_operations = balance_ops(&base_token, options);
	let balance_block = seal(client, recipient, trusted, None, balance_operations)?;

	let balance_hash = balance_block.hash();
	let rep_operations = set_rep_ops(delegate_to);
	let set_rep_block = seal(client, recipient, recipient, Some(balance_hash), rep_operations)?;

	let blocks = alloc::vec![network_block, base_token_block, balance_block, set_rep_block];
	let hashes: Vec<BlockHash> = blocks.iter().map(Block::hash).collect();

	let vote = permanent_vote(trusted, hashes, options)?;

	VoteStapleBuilder::new()
		.add_blocks(blocks)
		.add_vote(vote)
		.build()
		.map_err(|source| ClientError::Vote { source })
}

/// Seal a genesis block (no purpose or date) over `client`'s network context.
fn seal(
	client: &KeetaClient,
	account: &AccountRef,
	signer: &AccountRef,
	previous: Option<BlockHash>,
	operations: Vec<Operation>,
) -> Result<Block, ClientError> {
	client.seal_block(account, signer, previous, None, None, operations)
}

/// Self-issue the permanent vote binding the genesis `hashes` into a staple.
fn permanent_vote(
	trusted: &AccountRef,
	hashes: Vec<BlockHash>,
	options: &InitializeNetwork,
) -> Result<Vote, ClientError> {
	let serial = options
		.vote_serial
		.clone()
		.unwrap_or_else(|| num_bigint::BigInt::from(0u8));

	let from = BlockTime::now();
	let span_end = from.unix_millis().saturating_add(PERMANENT_SPAN_MS);
	let to = BlockTime::from_unix_millis(span_end).unwrap_or(from);

	VoteBuilder::new()
		.issuer(Arc::clone(trusted))
		.serial(serial)
		.validity(from, to)
		.add_blocks(hashes)
		.build_signed(trusted.as_ref())
		.map_err(|source| ClientError::Vote { source })
}

/// The network-address account's genesis operations.
fn network_address_ops(trusted: &AccountRef, options: &InitializeNetwork) -> Result<Vec<Operation>, ClientError> {
	let info = options.base_network_info.clone().unwrap_or_default();
	let default_permission = match info.default_permission {
		Some(permission) => permission,
		None => permission_of(&[BaseFlag::StorageCreate])?,
	};

	let owner = owner_permission(trusted)?;
	let name = info.name.unwrap_or_else(|| "KEETANET".into());
	let description = info
		.description
		.unwrap_or_else(|| "Network Address For KeetaNet".into());
	let metadata = info.metadata.unwrap_or_default();
	let set_info = SetInfo { name, description, metadata, default_permission: Some(default_permission) };

	Ok(alloc::vec![owner, set_info.into()])
}

/// The base-token account's genesis operations.
fn base_token_ops(trusted: &AccountRef, options: &InitializeNetwork) -> Result<Vec<Operation>, ClientError> {
	let token = options.base_token_info.as_ref();
	let default_permission = match token.and_then(|info| info.default_permission.clone()) {
		Some(permission) => permission,
		None => permission_of(&[BaseFlag::Access])?,
	};

	let owner = owner_permission(trusted)?;
	let name = token
		.map(|info| info.currency_code.clone())
		.unwrap_or_default();
	let description = token.map(|info| info.name.clone()).unwrap_or_default();
	let metadata = token.map(token_metadata).unwrap_or_default();
	let set_info = SetInfo { name, description, metadata, default_permission: Some(default_permission) };

	let supply = TokenAdminSupply { amount: options.add_supply_amount.clone(), method: AdjustMethod::Add };

	Ok(alloc::vec![owner, set_info.into(), supply.into()])
}

/// The recipient's supply-minting operation, crediting `base_token`.
fn balance_ops(base_token: &AccountRef, options: &InitializeNetwork) -> Vec<Operation> {
	let mint = TokenAdminModifyBalance {
		token: Arc::clone(base_token),
		amount: options.add_supply_amount.clone(),
		method: AdjustMethod::Add,
	};

	alloc::vec![mint.into()]
}

/// The recipient's delegation operation, assigning its weight to `delegate_to`.
fn set_rep_ops(delegate_to: &AccountRef) -> Vec<Operation> {
	let set_rep = SetRep { to: Arc::clone(delegate_to) };
	alloc::vec![set_rep.into()]
}

/// Encode a token's decimal places as the base64 JSON the ledger stores in
/// token metadata.
fn token_metadata(info: &BaseTokenInfo) -> String {
	let json = format!("{{\"decimalPlaces\":{}}}", info.decimal_places);
	base64::engine::general_purpose::STANDARD.encode(json)
}

/// A MODIFY_PERMISSIONS operation granting `OWNER` to `principal`.
fn owner_permission(principal: &AccountRef) -> Result<Operation, ClientError> {
	let permissions = permission_of(&[BaseFlag::Owner])?;
	let modify = ModifyPermissions {
		principal: ModifyPermissionsPrincipal::Account(Arc::clone(principal)),
		method: AdjustMethod::Set,
		permissions: Some(permissions),
		target: None,
	};

	Ok(modify.into())
}

/// Build a permission set from `flags` (no external offsets).
fn permission_of(flags: &[BaseFlag]) -> Result<Permissions, ClientError> {
	Permissions::from_flags(flags, &[]).map_err(|source| ClientError::Block { source })
}
