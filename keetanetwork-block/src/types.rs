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
//! | [6]  | TokenAdminModifyBalance |
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
/// - V1: Unwrapped format with internal version field = 0
/// - V2: Tagged format (explicit context tag 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockVersion {
	V1 = 1,
	V2 = 2,
}

impl BlockVersion {
	/// V1 blocks have internal version field 0, V2 blocks use tag 1
	pub fn from_version_field(version: u8) -> Option<Self> {
		match version {
			0 => Some(BlockVersion::V1),
			_ => None,
		}
	}

	/// Create from tag value (for V2 blocks)
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
	/// Block timestamp as raw bytes
	pub date: &'a [u8],
	/// Block purpose (V2 only, defaults to Generic for V1)
	pub purpose: BlockPurpose,
	/// Account public key with type prefix
	pub account: &'a [u8],
	/// Signer information (V1: always Single, V2: can be Single/Multisig/AccountIsSigner)
	pub signer: SignerField<'a>,
	/// Previous block hash (32 bytes)
	pub previous: &'a [u8],
}

/// Parsed Keeta block (unified view for both V1 and V2)
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct KeetaBlock<'a> {
	/// Block version
	pub version: BlockVersion,
	/// Block header/metadata
	pub header: BlockHeader<'a>,
	/// Operations in the block
	pub operations: Vec<Operation<'a>>,
	/// Signatures (V1: single, V2: one or more)
	pub signatures: Vec<&'a [u8]>,
}

/// Builder for constructing KeetaBlock instances
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct KeetaBlockBuilder<'a> {
	version: BlockVersion,
	header: BlockHeader<'a>,
	operations: Vec<Operation<'a>>,
	signatures: Vec<&'a [u8]>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<'a> KeetaBlockBuilder<'a> {
	/// Create a new builder with the specified block version and header
	pub fn new(version: BlockVersion, header: BlockHeader<'a>) -> Self {
		Self { version, header, operations: Vec::new(), signatures: Vec::new() }
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

	/// Set the signatures
	pub fn signatures(mut self, signatures: Vec<&'a [u8]>) -> Self {
		self.signatures = signatures;
		self
	}

	/// Add a single signature
	pub fn signature(mut self, signature: &'a [u8]) -> Self {
		self.signatures.push(signature);
		self
	}

	/// Build the KeetaBlock
	pub fn build(self) -> KeetaBlock<'a> {
		KeetaBlock {
			version: self.version,
			header: self.header,
			operations: self.operations,
			signatures: self.signatures,
		}
	}
}

// ============================================================================
// Signer Types
// ============================================================================

/// Individual signer in a multisig (can be nested)
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub enum MultiSigSigner<'a> {
	/// Nested multisig signer info
	Nested(Box<MultiSigSignerInfo<'a>>),
	/// Single key signer (public key with type prefix)
	Key(&'a [u8]),
}

/// Multisig signer information for V2 blocks
#[derive(Debug, Clone)]
#[cfg_attr(not(any(feature = "alloc", feature = "std")), derive(Copy))]
pub struct MultiSigSignerInfo<'a> {
	/// Public key of the multisig account
	pub multisig_pub_key: &'a [u8],
	/// signers (can be nested multisig or single keys)
	#[cfg(any(feature = "alloc", feature = "std"))]
	pub signers: Vec<MultiSigSigner<'a>>,
	/// Raw DER bytes of the signers sequence
	#[cfg(not(any(feature = "alloc", feature = "std")))]
	pub signers_raw: &'a [u8],
}

/// Signer field for blocks
///
/// V1 blocks always use Single. V2 blocks can use any variant.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(feature = "alloc", feature = "std")), derive(Copy))]
pub enum SignerField<'a> {
	/// Single signer (public key with type prefix)
	Single(&'a [u8]),
	/// Multisig signer info (V2 only)
	Multisig(MultiSigSignerInfo<'a>),
	/// Account is signer (null case, V2 only)
	AccountIsSigner,
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

/// Token and rate pair (used in CREATE_IDENTIFIER swap arguments)
#[derive(Debug, Clone, Copy)]
pub struct TokenRate<'a> {
	/// Token public key
	pub token: &'a [u8],
	/// Rate
	pub rate: &'a [u8],
}

/// Fee rate for CREATE_IDENTIFIER swap arguments
#[derive(Debug, Clone, Copy)]
pub struct FeeRate<'a> {
	/// Fee token (None means use sell token)
	pub token: Option<&'a [u8]>,
	/// Fee rate
	pub rate: &'a [u8],
}

/// Token and value pair (used in MATCH_SWAP/CANCEL_SWAP operations)
#[derive(Debug, Clone, Copy)]
pub struct TokenValue<'a> {
	/// Token public key
	pub token: &'a [u8],
	/// Value
	pub value: &'a [u8],
}

/// Fee value for CANCEL_SWAP operation
#[derive(Debug, Clone, Copy)]
pub struct FeeValue<'a> {
	/// Fee token (None means use sell token)
	pub token: Option<&'a [u8]>,
	/// Fee value
	pub value: &'a [u8],
}

/// Fee value with recipient for MATCH_SWAP operation
#[derive(Debug, Clone, Copy)]
pub struct FeeValueWithRecipient<'a> {
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
		/// Signer public keys (raw byte strings)
		signers: &'a [u8],
		/// Required number of signatures
		quorum: u64,
	},
	/// Swap creation arguments [8]
	Swap {
		sell_token_rate: TokenRate<'a>,
		buy_token_rate: TokenRate<'a>,
		fee_token_rate: Option<FeeRate<'a>>,
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
	pub intermediate_certificates: Option<&'a [u8]>,
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
	/// Fee value with recipient (optional)
	pub fee: Option<FeeValueWithRecipient<'a>>,
}

/// [10] CANCEL_SWAP operation - Cancel a swap order
#[derive(Debug, Clone)]
pub struct CancelSwapOp<'a> {
	/// Swap account to cancel
	pub swap: &'a [u8],
	/// Sell token and value being returned
	pub sell: TokenValue<'a>,
	/// Fee value (optional)
	pub fee: Option<FeeValue<'a>>,
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
	/// [6] Token admin modify balance
	TokenAdminModifyBalance(TokenAdminModifyBalanceOp<'a>),
	/// [7] Receive tokens
	Receive(ReceiveOp<'a>),
	/// [8] Manage certificate
	ManageCertificate(ManageCertificateOp<'a>),
	/// [9] Match swap
	MatchSwap(MatchSwapOp<'a>),
	/// [10] Cancel swap
	CancelSwap(CancelSwapOp<'a>),
}

// ============================================================================
// Vote Types (X.509 Certificate)
// ============================================================================

/// Algorithm identifier (used in certificates)
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, Copy)]
pub struct AlgorithmIdentifier<'a> {
	/// Algorithm identifier
	pub algorithm: &'a [u8],
	/// Optional parameters (e.g., curve identifier for ECDSA)
	pub parameters: Option<&'a [u8]>,
}

/// Validity period for certificates
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, Copy)]
pub struct Validity<'a> {
	/// Certificate validity start time
	pub not_before: &'a str,
	/// Certificate validity end time
	pub not_after: &'a str,
}

/// Subject public key info
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, Copy)]
pub struct SubjectPublicKeyInfo<'a> {
	/// Algorithm identifier
	pub algorithm: AlgorithmIdentifier<'a>,
	/// Public key as raw bytes
	pub public_key: &'a [u8],
}

/// Certificate extension wrapper
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, Copy)]
pub struct CertificateExtensionWrapper<'a> {
	/// Extension identifier
	pub extension_id: &'a [u8],
	/// Critical flag
	pub critical: bool,
	/// Extension data (contains HashData or FeeData)
	pub data: &'a [u8],
}

/// Hash data extension content (OID: 2.16.840.1.101.3.3.1.3)
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct HashData<'a> {
	/// Hash algorithm identifier
	pub hash_algorithm: &'a [u8],
	/// Block hashes
	pub hashes: Vec<&'a [u8]>,
}

/// Fee data extension content (OID: 1.3.6.1.4.1.62675.0.1.0)
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, Copy)]
pub struct FeeData<'a> {
	/// Whether this is a quote (`true`) or a vote (`false`)
	pub quote: bool,
	/// Amount
	pub amount: &'a [u8],
	/// Pay to account (optional)
	pub pay_to: Option<&'a [u8]>,
	/// Token account (optional)
	pub token: Option<&'a [u8]>,
}

/// TBS (To Be Signed) Certificate data
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct TbsCertificate<'a> {
	/// Version (always 2 for v3 certificates)
	pub version: u8,
	/// Serial number
	pub serial: &'a [u8],
	/// Signature algorithm
	pub signature_algorithm: AlgorithmIdentifier<'a>,
	/// Issuer common name
	pub issuer_cn: &'a str,
	/// Validity period
	pub validity: Validity<'a>,
	/// Subject serial number
	pub subject_serial: &'a str,
	/// Subject public key info
	pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
	/// Extensions
	pub extensions: Vec<CertificateExtensionWrapper<'a>>,
}

/// Vote (X.509v3 Certificate for blockchain voting)
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct Vote<'a> {
	/// TBS Certificate (data to be signed)
	pub tbs_certificate: TbsCertificate<'a>,
	/// Signature algorithm
	pub signature_algorithm: AlgorithmIdentifier<'a>,
	/// Signature as raw bytes
	pub signature: &'a [u8],
}

/// Vote staple - bundles blocks with their votes
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
pub struct VoteStaple<'a> {
	/// Blocks
	pub blocks: Vec<KeetaBlock<'a>>,
	/// Votes (X.509 certificates)
	pub votes: Vec<Vote<'a>>,
}
