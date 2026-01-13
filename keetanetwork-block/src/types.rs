//! Keeta Network Block Types
//!
//! Type definitions for Keeta blockchain blocks and operations.
//! Zero-copy types with lifetime parameters for efficient parsing in `no_std` environments.
//!
//! ## Operation Tags
//!
//! | Tag  | Operation           |
//! |------|---------------------|
//! | [0]  | Send                |
//! | [1]  | SetRep              |
//! | [2]  | SetInfo             |
//! | [3]  | ModifyPermissions   |
//! | [4]  | CreateIdentifier    |
//! | [5]  | TokenAdminSupply    |
//! | [6]  | TokenModifyBalance  |
//! | [7]  | Receive             |
//! | [8]  | ManageCertificate   |
//! | [9]  | MatchSwap           |
//! | [10] | CancelSwap          |

// Use alloc for Vec when not using std
#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

// ============================================================================
// Block Types
// ============================================================================

/// Block version
///
/// - V1: Plain SEQUENCE with internal version field = 0
/// - V2: Wrapped in [1] EXPLICIT context tag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockVersion {
	V1 = 1,
	V2 = 2,
}

impl BlockVersion {
	/// V1 blocks have version field 0 internally, V2 blocks use [1] context tag
	pub fn from_version_field(version: u8) -> Option<Self> {
		match version {
			0 => Some(BlockVersion::V1),
			_ => None,
		}
	}

	/// Create from context tag (for V2)
	pub fn from_context_tag(tag: u8) -> Option<Self> {
		match tag {
			1 => Some(BlockVersion::V2),
			_ => None,
		}
	}
}

/// Block purpose (V2 only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockPurpose {
	Generic,
	Fee,
}

impl TryFrom<u8> for BlockPurpose {
	type Error = u8;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(BlockPurpose::Generic),
			1 => Ok(BlockPurpose::Fee),
			n => Err(n),
		}
	}
}

/// Block header information
#[derive(Debug, Clone)]
pub struct BlockHeader<'a> {
	/// Network ID
	pub network: u64,
	/// Subnet ID (optional)
	pub subnet: Option<u64>,
	/// Idempotent key for deduplication (optional)
	pub idempotent: Option<&'a [u8]>,
	/// Date as GeneralizedTime raw bytes
	pub date: &'a [u8],
	/// Block purpose (V2 only, defaults to Generic for V1)
	pub purpose: BlockPurpose,
	/// Account public key with type prefix
	pub account: &'a [u8],
	/// Signer public key with type prefix (may be same as account)
	pub signer: &'a [u8],
	/// Previous block hash (32 bytes)
	pub previous: &'a [u8],
}

/// Parsed Keeta block (unified view for both V1 and V2)
///
/// Requires the `alloc` or `std` feature (uses Vec for operations).
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct KeetaBlock<'a> {
	/// Block version
	pub version: BlockVersion,
	/// Block header/metadata
	pub header: BlockHeader<'a>,
	/// Operations in the block
	pub operations: Vec<Operation<'a>>,
}

/// Builder for constructing KeetaBlock instances
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct KeetaBlockBuilder<'a> {
	version: BlockVersion,
	header: BlockHeader<'a>,
	operations: Vec<Operation<'a>>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<'a> KeetaBlockBuilder<'a> {
	/// Create a new builder with the specified block version and header
	pub fn new(version: BlockVersion, header: BlockHeader<'a>) -> Self {
		Self { version, header, operations: Vec::new() }
	}

	/// Set the operations
	pub fn operations(mut self, operations: Vec<Operation<'a>>) -> Self {
		self.operations = operations;
		self
	}

	/// Add a single operation
	pub fn operation(mut self, operation: Operation<'a>) -> Self {
		self.operations.push(operation);
		self
	}

	/// Build the KeetaBlock
	pub fn build(self) -> KeetaBlock<'a> {
		KeetaBlock { version: self.version, header: self.header, operations: self.operations }
	}
}

// ============================================================================
// Enum Types
// ============================================================================

/// Adjust method for supply/balance/permissions operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjustMethod {
	Add,
	Subtract,
	Set,
}

impl TryFrom<u8> for AdjustMethod {
	type Error = u8;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(AdjustMethod::Add),
			1 => Ok(AdjustMethod::Subtract),
			2 => Ok(AdjustMethod::Set),
			n => Err(n),
		}
	}
}

/// Adjust method for relative operations (add/subtract only, no set)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjustMethodRelative {
	Add,
	Subtract,
}

impl TryFrom<u8> for AdjustMethodRelative {
	type Error = u8;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(AdjustMethodRelative::Add),
			1 => Ok(AdjustMethodRelative::Subtract),
			n => Err(n),
		}
	}
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Token and value pair (used in swap operations)
#[derive(Debug, Clone, Copy)]
pub struct TokenValue<'a> {
	/// Token public key
	pub token: &'a [u8],
	/// Value (rate or amount)
	pub value: &'a [u8],
}

/// Fee details for swap operations
#[derive(Debug, Clone, Copy)]
pub struct FeeDetails<'a> {
	/// Fee token (None means use sell token)
	pub token: Option<&'a [u8]>,
	/// Fee value
	pub value: &'a [u8],
}

/// Fee details with recipient for match swap
#[derive(Debug, Clone, Copy)]
pub struct FeeDetailsWithRecipient<'a> {
	/// Fee token (None means use sell token)
	pub token: Option<&'a [u8]>,
	/// Fee value
	pub value: &'a [u8],
	/// Fee recipient
	pub recipient: &'a [u8],
}

/// Permission value (base and external)
#[derive(Debug, Clone, Copy)]
pub struct Permission {
	/// Base permissions
	pub base: u64,
	/// External permissions
	pub external: u64,
}

// ============================================================================
// Operation Structures
// ============================================================================

/// [0] SEND operation - Transfer tokens to another account
#[derive(Debug, Clone)]
pub struct SendOp<'a> {
	/// Destination account
	pub to: &'a [u8],
	/// Amount to send
	pub amount: &'a [u8],
	/// Token ID to send
	pub token: &'a [u8],
	/// External reference (optional)
	pub external: Option<&'a [u8]>,
}

/// [1] SET_REP operation - Set representative for delegation
#[derive(Debug, Clone)]
pub struct SetRepOp<'a> {
	/// Representative to delegate to
	pub to: &'a [u8],
}

/// [2] SET_INFO operation - Set account information
#[derive(Debug, Clone)]
pub struct SetInfoOp<'a> {
	/// Account name
	pub name: &'a [u8],
	/// Account description
	pub description: &'a [u8],
	/// Account metadata
	pub metadata: &'a [u8],
	/// Default permission (optional)
	pub default_permission: Option<Permission>,
}

/// [3] MODIFY_PERMISSIONS operation - Modify account permissions
#[derive(Debug, Clone)]
pub struct ModifyPermissionsOp<'a> {
	/// Principal to modify permissions for
	pub principal: &'a [u8],
	/// Method to modify (add/subtract/set)
	pub method: AdjustMethod,
	/// Permissions to modify (None = null/clear)
	pub permissions: Option<Permission>,
	/// Target account (optional)
	pub target: Option<&'a [u8]>,
}

/// Identifier creation arguments
#[derive(Debug, Clone)]
pub enum CreateIdentifierArgs<'a> {
	/// Multisig creation arguments [7]
	Multisig {
		signers: &'a [u8], // Raw sequence of octet strings
		quorum: u64,
	},
	/// Swap creation arguments [8]
	Swap {
		sell_token_rate: TokenValue<'a>,
		buy_token_rate: TokenValue<'a>,
		fee_token_rate: Option<FeeDetails<'a>>,
		quantity: &'a [u8],
	},
}

/// [4] CREATE_IDENTIFIER operation - Create token, multisig, or swap
#[derive(Debug, Clone)]
pub struct CreateIdentifierOp<'a> {
	/// Identifier to create
	pub identifier: &'a [u8],
	/// Creation arguments (optional, depends on identifier type)
	pub create_arguments: Option<CreateIdentifierArgs<'a>>,
}

/// [5] TOKEN_ADMIN_SUPPLY operation - Modify token supply
#[derive(Debug, Clone, Copy)]
pub struct TokenAdminSupplyOp<'a> {
	/// Amount to modify
	pub amount: &'a [u8],
	/// Method (add/subtract/set)
	pub method: AdjustMethod,
}

/// [6] TOKEN_ADMIN_MODIFY_BALANCE operation - Modify account token balance
#[derive(Debug, Clone)]
pub struct TokenAdminModifyBalanceOp<'a> {
	/// Token to modify balance of
	pub token: &'a [u8],
	/// Amount to modify
	pub amount: &'a [u8],
	/// Method (add/subtract/set)
	pub method: AdjustMethod,
}

/// [7] RECEIVE operation - Receive tokens from another account
#[derive(Debug, Clone)]
pub struct ReceiveOp<'a> {
	/// Amount to receive
	pub amount: &'a [u8],
	/// Token to receive
	pub token: &'a [u8],
	/// Sender account
	pub from: &'a [u8],
	/// Whether amount must match exactly
	pub exact: bool,
	/// Forward to another account (optional)
	pub forward: Option<&'a [u8]>,
}

/// [8] MANAGE_CERTIFICATE operation - Add or subtract certificates
#[derive(Debug, Clone)]
pub struct ManageCertificateOp<'a> {
	/// Method (add/subtract)
	pub method: AdjustMethodRelative,
	/// Certificate (if adding) or certificate hash (if removing)
	pub certificate_or_hash: &'a [u8],
	/// Intermediate certificates (required if adding, must be None if removing)
	pub intermediates: Option<&'a [u8]>,
}

/// [9] MATCH_SWAP operation - Match two swap orders
#[derive(Debug, Clone)]
pub struct MatchSwapOp<'a> {
	/// Swap account being used
	pub swap: &'a [u8],
	/// Other swap account to match against
	pub other: &'a [u8],
	/// Token being sold and value
	pub sell: TokenValue<'a>,
	/// Token being bought and value
	pub buy: TokenValue<'a>,
	/// Fee details with recipient (optional)
	pub fee: Option<FeeDetailsWithRecipient<'a>>,
}

/// [10] CANCEL_SWAP operation - Cancel a swap order
#[derive(Debug, Clone)]
pub struct CancelSwapOp<'a> {
	/// Swap account to cancel
	pub swap: &'a [u8],
	/// Sell token and value being returned
	pub sell: TokenValue<'a>,
	/// Fee details (optional)
	pub fee: Option<FeeDetails<'a>>,
}

// ============================================================================
// Operation Enum
// ============================================================================

/// Keeta blockchain operation
#[derive(Debug, Clone)]
pub enum Operation<'a> {
	/// [0] Send tokens
	Send(SendOp<'a>),
	/// [1] Set representative
	SetRep(SetRepOp<'a>),
	/// [2] Set account info
	SetInfo(SetInfoOp<'a>),
	/// [3] Modify permissions
	ModifyPermissions(ModifyPermissionsOp<'a>),
	/// [4] Create identifier (token, multisig, swap)
	CreateIdentifier(CreateIdentifierOp<'a>),
	/// [5] Token admin supply
	TokenAdminSupply(TokenAdminSupplyOp<'a>),
	/// [6] Token modify balance
	TokenModifyBalance(TokenAdminModifyBalanceOp<'a>),
	/// [7] Receive tokens
	Receive(ReceiveOp<'a>),
	/// [8] Manage certificate
	ManageCertificate(ManageCertificateOp<'a>),
	/// [9] Match swap
	MatchSwap(MatchSwapOp<'a>),
	/// [10] Cancel swap
	CancelSwap(CancelSwapOp<'a>),
}
