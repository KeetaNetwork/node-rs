//! Keeta Network Block Types
//!
//! Type definitions for Keeta blockchain blocks and operations.
//! Zero-copy types with lifetime parameters for efficient parsing in `no_std` environments.
//!
//! ## Operation Tags
//!
//! | Tag  | Operation               |
//! |------|-------------------------|
//! | [0]  | Send                    |
//! | [1]  | SetRep                  |
//! | [2]  | SetInfo                 |
//! | [3]  | ModifyPermissions       |
//! | [4]  | CreateIdentifier        |
//! | [5]  | TokenAdminSupply        |
//! | [6]  | TokenAdminModifyBalance |
//! | [7]  | Receive                 |
//! | [8]  | ManageCertificate       |
//! | [9]  | MatchSwap               |
//! | [10] | CancelSwap              |

// Use alloc for Vec when not using std
#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

// DER encoding/decoding support
use der::{
	asn1::{IntRef, Null, OctetStringRef, Utf8StringRef},
	Choice, Decode, DecodeValue, Encode, EncodeValue, Enumerated, Header, Length, Reader, Sequence, Tag, Writer,
};

// Type aliases for DER types
pub type Bytes<'a> = OctetStringRef<'a>;
pub type Int<'a> = IntRef<'a>;
pub type Str<'a> = Utf8StringRef<'a>;

// ============================================================================
// NullOr Type
// ============================================================================

/// Either a value of type `T` or an explicit "none" marker.
///
/// Used for fields where `None` has a specific meaning (e.g., "use sell token
/// as fee token") rather than just being absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullOr<T> {
	/// NULL - represents none/default
	Null,
	/// Value present
	Value(T),
}

impl<T> NullOr<T> {
	/// Get the value if present, None if NULL
	pub fn value(&self) -> Option<&T> {
		match self {
			NullOr::Null => None,
			NullOr::Value(v) => Some(v),
		}
	}
}

// Implement Decode for NullOr<T>
impl<'a, T: Decode<'a>> Decode<'a> for NullOr<T> {
	fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
		let tag = reader.peek_tag()?;
		if tag == Tag::Null {
			let _: Null = reader.decode()?;
			Ok(NullOr::Null)
		} else {
			Ok(NullOr::Value(T::decode(reader)?))
		}
	}
}

// Implement Encode for NullOr<T>
impl<T: Encode> Encode for NullOr<T> {
	fn encoded_len(&self) -> der::Result<Length> {
		match self {
			NullOr::Null => Null.encoded_len(),
			NullOr::Value(v) => v.encoded_len(),
		}
	}

	fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
		match self {
			NullOr::Null => Null.encode(writer),
			NullOr::Value(v) => v.encode(writer),
		}
	}
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enumerated)]
#[repr(u8)]
pub enum AdjustMethod {
	Add = 0,
	Subtract = 1,
	Set = 2,
}

/// Adjust method for relative operations (add/subtract only, no set)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enumerated)]
#[repr(u8)]
pub enum AdjustMethodRelative {
	Add = 0,
	Subtract = 1,
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Token and rate pair (used in CREATE_IDENTIFIER swap arguments)
#[derive(Debug, Clone, Copy, Sequence)]
pub struct TokenRate<'a> {
	/// Token public key
	pub token: Bytes<'a>,
	/// Rate
	pub rate: Int<'a>,
}

/// Fee rate for CREATE_IDENTIFIER swap arguments
#[derive(Debug, Clone, Copy, Sequence)]
pub struct FeeRate<'a> {
	/// Fee token (NULL means use sell token)
	pub token: NullOr<Bytes<'a>>,
	/// Fee rate
	pub rate: Int<'a>,
}

/// Token and value pair (used in MATCH_SWAP/CANCEL_SWAP operations)
#[derive(Debug, Clone, Copy, Sequence)]
pub struct TokenValue<'a> {
	/// Token public key
	pub token: Bytes<'a>,
	/// Value
	pub value: Int<'a>,
}

/// Fee value for CANCEL_SWAP operation
#[derive(Debug, Clone, Copy, Sequence)]
pub struct FeeValue<'a> {
	/// Fee token (NULL means use sell token)
	pub token: NullOr<Bytes<'a>>,
	/// Fee value
	pub value: Int<'a>,
}

/// Fee value with recipient for MATCH_SWAP operation
#[derive(Debug, Clone, Copy, Sequence)]
pub struct FeeValueWithRecipient<'a> {
	/// Fee token (NULL means use sell token)
	pub token: NullOr<Bytes<'a>>,
	/// Fee value
	pub value: Int<'a>,
	/// Fee recipient
	pub recipient: Bytes<'a>,
}

/// Permission value (base and external)
#[derive(Debug, Clone, Copy, Sequence)]
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
#[derive(Debug, Clone, Sequence)]
pub struct SendOp<'a> {
	/// Destination account
	pub to: Bytes<'a>,
	/// Amount to send
	pub amount: Int<'a>,
	/// Token ID to send
	pub token: Bytes<'a>,
	/// External reference (optional)
	pub external: Option<Str<'a>>,
}

/// [1] SET_REP operation - Set representative for delegation
#[derive(Debug, Clone, Sequence)]
pub struct SetRepOp<'a> {
	/// Representative to delegate to
	pub to: Bytes<'a>,
}

/// [2] SET_INFO operation - Set account information
#[derive(Debug, Clone, Sequence)]
pub struct SetInfoOp<'a> {
	/// Account name
	pub name: Str<'a>,
	/// Account description
	pub description: Str<'a>,
	/// Account metadata
	pub metadata: Str<'a>,
	/// Default permission (optional)
	#[asn1(optional = "true")]
	pub default_permission: Option<Permission>,
}

/// [3] MODIFY_PERMISSIONS operation - Modify account permissions
#[derive(Debug, Clone, Sequence)]
pub struct ModifyPermissionsOp<'a> {
	/// Principal to modify permissions for
	pub principal: Bytes<'a>,
	/// Method to modify (add/subtract/set)
	pub method: AdjustMethod,
	/// Permissions to modify (NULL = clear)
	pub permissions: NullOr<Permission>,
	/// Target account (optional)
	#[asn1(optional = "true")]
	pub target: Option<Bytes<'a>>,
}

/// Multisig creation arguments
///
/// Note: The `signers` field contains raw DER-encoded bytes representing
/// a sequence of public keys. For `no_std`/`no_alloc` environments, manual
/// parsing is required.
#[derive(Debug, Clone, Sequence)]
pub struct MultisigArgs<'a> {
	/// Signer public keys (raw DER-encoded bytes)
	pub signers: Bytes<'a>,
	/// Required number of signatures
	pub quorum: u64,
}

/// Swap creation arguments
#[derive(Debug, Clone, Sequence)]
pub struct SwapArgs<'a> {
	/// Token being sold and rate
	pub sell_token_rate: TokenRate<'a>,
	/// Token being bought and rate
	pub buy_token_rate: TokenRate<'a>,
	/// Fee token and rate (NULL = no fee)
	pub fee_token_rate: NullOr<FeeRate<'a>>,
	/// Quantity
	pub quantity: Int<'a>,
}

/// Identifier creation arguments
#[derive(Debug, Clone, Choice)]
pub enum CreateIdentifierArgs<'a> {
	/// Multisig creation arguments [7]
	#[asn1(context_specific = "7", tag_mode = "EXPLICIT", constructed = "true")]
	Multisig(MultisigArgs<'a>),
	/// Swap creation arguments [8]
	#[asn1(context_specific = "8", tag_mode = "EXPLICIT", constructed = "true")]
	Swap(SwapArgs<'a>),
}

/// [4] CREATE_IDENTIFIER operation - Create token, multisig, or swap
#[derive(Debug, Clone, Sequence)]
pub struct CreateIdentifierOp<'a> {
	/// Identifier to create
	pub identifier: Bytes<'a>,
	/// Creation arguments (optional, depends on identifier type)
	#[asn1(optional = "true")]
	pub create_arguments: Option<CreateIdentifierArgs<'a>>,
}

/// [5] TOKEN_ADMIN_SUPPLY operation - Modify token supply
#[derive(Debug, Clone, Copy, Sequence)]
pub struct TokenAdminSupplyOp<'a> {
	/// Amount to modify
	pub amount: Int<'a>,
	/// Method (add/subtract/set)
	pub method: AdjustMethod,
}

/// [6] TOKEN_ADMIN_MODIFY_BALANCE operation - Modify account token balance
#[derive(Debug, Clone, Sequence)]
pub struct TokenAdminModifyBalanceOp<'a> {
	/// Token to modify balance of
	pub token: Bytes<'a>,
	/// Amount to modify
	pub amount: Int<'a>,
	/// Method (add/subtract/set)
	pub method: AdjustMethod,
}

/// [7] RECEIVE operation - Receive tokens from another account
#[derive(Debug, Clone, Sequence)]
pub struct ReceiveOp<'a> {
	/// Amount to receive
	pub amount: Int<'a>,
	/// Token to receive
	pub token: Bytes<'a>,
	/// Sender account
	pub from: Bytes<'a>,
	/// Whether amount must match exactly
	pub exact: bool,
	/// Forward to another account (optional)
	#[asn1(optional = "true")]
	pub forward: Option<Bytes<'a>>,
}

/// [8] MANAGE_CERTIFICATE operation - Add or subtract certificates
///
/// Implemented manually because `Option<NullOr<T>>` doesn't implement `Decode`
/// (the `Option<T>` impl requires `T: FixedTag`, but `NullOr` has no fixed tag).
#[derive(Debug, Clone)]
pub struct ManageCertificateOp<'a> {
	/// Method (add/subtract)
	pub method: AdjustMethodRelative,
	/// Certificate (if adding) or certificate hash (if removing)
	pub certificate_or_hash: Bytes<'a>,
	/// Intermediate certificates (either raw bytes or explicit none)
	/// Required when adding a certificate, optional overall
	pub intermediate_certificates: Option<NullOr<Bytes<'a>>>,
}

impl<'a> DecodeValue<'a> for ManageCertificateOp<'a> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
		let method = reader.decode()?;
		let certificate_or_hash = reader.decode()?;

		// Handle optional field that can be either bytes or explicit none
		let intermediate_certificates = if reader.is_finished() {
			None
		} else {
			Some(reader.decode()?)
		};

		Ok(ManageCertificateOp { method, certificate_or_hash, intermediate_certificates })
	}
}

impl EncodeValue for ManageCertificateOp<'_> {
	fn value_len(&self) -> der::Result<Length> {
		self.method.encoded_len()?
			+ self.certificate_or_hash.encoded_len()?
			+ self
				.intermediate_certificates
				.as_ref()
				.map(|v| v.encoded_len())
				.transpose()?
				.unwrap_or(Length::ZERO)
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		self.method.encode(writer)?;
		self.certificate_or_hash.encode(writer)?;
		if let Some(ref certs) = self.intermediate_certificates {
			certs.encode(writer)?;
		}
		Ok(())
	}
}

impl<'a> Sequence<'a> for ManageCertificateOp<'a> {}

/// [9] MATCH_SWAP operation - Match two swap orders
#[derive(Debug, Clone, Sequence)]
pub struct MatchSwapOp<'a> {
	/// Swap account being used
	pub swap: Bytes<'a>,
	/// Other swap account to match against
	pub other: Bytes<'a>,
	/// Token being sold and value
	pub sell: TokenValue<'a>,
	/// Token being bought and value
	pub buy: TokenValue<'a>,
	/// Fee value with recipient (NULL = no fee)
	pub fee: NullOr<FeeValueWithRecipient<'a>>,
}

/// [10] CANCEL_SWAP operation - Cancel a swap order
#[derive(Debug, Clone, Sequence)]
pub struct CancelSwapOp<'a> {
	/// Swap account to cancel
	pub swap: Bytes<'a>,
	/// Sell token and value being returned
	pub sell: TokenValue<'a>,
	/// Fee value (NULL = no fee)
	pub fee: NullOr<FeeValue<'a>>,
}

// ============================================================================
// Operation Enum
// ============================================================================

/// Keeta blockchain operation
#[derive(Debug, Clone, Choice)]
pub enum Operation<'a> {
	/// [0] Send tokens
	#[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
	Send(SendOp<'a>),
	/// [1] Set representative
	#[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
	SetRep(SetRepOp<'a>),
	/// [2] Set account info
	#[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
	SetInfo(SetInfoOp<'a>),
	/// [3] Modify permissions
	#[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
	ModifyPermissions(ModifyPermissionsOp<'a>),
	/// [4] Create identifier (token, multisig, swap)
	#[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
	CreateIdentifier(CreateIdentifierOp<'a>),
	/// [5] Token admin supply
	#[asn1(context_specific = "5", tag_mode = "EXPLICIT", constructed = "true")]
	TokenAdminSupply(TokenAdminSupplyOp<'a>),
	/// [6] Token admin modify balance
	#[asn1(context_specific = "6", tag_mode = "EXPLICIT", constructed = "true")]
	TokenAdminModifyBalance(TokenAdminModifyBalanceOp<'a>),
	/// [7] Receive tokens
	#[asn1(context_specific = "7", tag_mode = "EXPLICIT", constructed = "true")]
	Receive(ReceiveOp<'a>),
	/// [8] Manage certificate
	#[asn1(context_specific = "8", tag_mode = "EXPLICIT", constructed = "true")]
	ManageCertificate(ManageCertificateOp<'a>),
	/// [9] Match swap
	#[asn1(context_specific = "9", tag_mode = "EXPLICIT", constructed = "true")]
	MatchSwap(MatchSwapOp<'a>),
	/// [10] Cancel swap
	#[asn1(context_specific = "10", tag_mode = "EXPLICIT", constructed = "true")]
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
