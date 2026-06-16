//! Keeta Network Block Types
//!
//! Type definitions for Keeta blockchain blocks and operations.
//! Zero-copy types with lifetime parameters for efficient parsing in `no_std` environments.
//!
//! ## Operation Tags
//!
//! | Tag  | Operation               |
//! |------|-------------------------|
//! | `0`  | Send                    |
//! | `1`  | SetRep                  |
//! | `2`  | SetInfo                 |
//! | `3`  | ModifyPermissions       |
//! | `4`  | CreateIdentifier        |
//! | `5`  | TokenAdminSupply        |
//! | `6`  | TokenAdminModifyBalance |
//! | `7`  | Receive                 |
//! | `8`  | ManageCertificate       |
//! | `9`  | MatchSwap               |
//! | `10` | CancelSwap              |

// DER encoding/decoding support
use der::{
	asn1::{IntRef, Null, OctetStringRef, Utf8StringRef},
	Choice, Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, SliceReader, Tag, Writer,
};

/// Reads raw TLV bytes (tag + length + content) from reader.
fn read_tlv_bytes<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<&'a [u8]> {
	let header = reader.peek_header()?;
	let tlv_len = (header.encoded_len()? + header.length)?;
	reader.read_slice(tlv_len)
}

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

	/// Returns `true` if this is the NULL marker.
	pub fn is_null(&self) -> bool {
		matches!(self, NullOr::Null)
	}
}

impl<T> From<Option<T>> for NullOr<T> {
	fn from(value: Option<T>) -> Self {
		match value {
			Some(v) => NullOr::Value(v),
			None => NullOr::Null,
		}
	}
}

impl<T> From<NullOr<T>> for Option<T> {
	fn from(value: NullOr<T>) -> Self {
		match value {
			NullOr::Value(v) => Some(v),
			NullOr::Null => None,
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
	/// Subnet ID (optional, V1 only - ignored for V2 blocks)
	pub subnet: Option<u64>,
	/// Block timestamp as raw bytes
	pub date: &'a [u8],
	/// Block purpose (V2 only, defaults to Generic for V1)
	pub purpose: BlockPurpose,
	/// Account public key with type prefix
	pub account: &'a [u8],
	/// Previous block hash (32 bytes)
	pub previous: &'a [u8],
}

// ============================================================================
// Enum Types
// ============================================================================

/// Adjust method for supply/balance/permissions operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdjustMethod {
	Add = 0,
	Subtract = 1,
	Set = 2,
}

impl From<AdjustMethod> for u8 {
	fn from(method: AdjustMethod) -> Self {
		method as u8
	}
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

impl<'a> Decode<'a> for AdjustMethod {
	fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
		let value: u8 = reader.decode()?;
		Self::try_from(value).map_err(|_| Tag::Integer.value_error())
	}
}

impl Encode for AdjustMethod {
	fn encoded_len(&self) -> der::Result<Length> {
		u8::from(*self).encoded_len()
	}

	fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
		u8::from(*self).encode(writer)
	}
}

/// Adjust method for relative operations (add/subtract only, no set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdjustMethodRelative {
	Add = 0,
	Subtract = 1,
}

impl From<AdjustMethodRelative> for u8 {
	fn from(method: AdjustMethodRelative) -> Self {
		method as u8
	}
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

impl From<AdjustMethodRelative> for AdjustMethod {
	fn from(method: AdjustMethodRelative) -> Self {
		match method {
			AdjustMethodRelative::Add => AdjustMethod::Add,
			AdjustMethodRelative::Subtract => AdjustMethod::Subtract,
		}
	}
}

impl TryFrom<AdjustMethod> for AdjustMethodRelative {
	type Error = AdjustMethod;

	fn try_from(method: AdjustMethod) -> Result<Self, Self::Error> {
		match method {
			AdjustMethod::Add => Ok(AdjustMethodRelative::Add),
			AdjustMethod::Subtract => Ok(AdjustMethodRelative::Subtract),
			AdjustMethod::Set => Err(AdjustMethod::Set),
		}
	}
}

impl<'a> Decode<'a> for AdjustMethodRelative {
	fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
		let value: u8 = reader.decode()?;
		Self::try_from(value).map_err(|_| Tag::Integer.value_error())
	}
}

impl Encode for AdjustMethodRelative {
	fn encoded_len(&self) -> der::Result<Length> {
		u8::from(*self).encoded_len()
	}

	fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
		u8::from(*self).encode(writer)
	}
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

/// Tag `0`: SEND operation - Transfer tokens to another account
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

/// Tag `1`: SET_REP operation - Set representative for delegation
#[derive(Debug, Clone, Sequence)]
pub struct SetRepOp<'a> {
	/// Representative to delegate to
	pub to: Bytes<'a>,
}

/// Tag `2`: SET_INFO operation - Set account information
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

/// Tag `3`: MODIFY_PERMISSIONS operation - Modify account permissions
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
/// The `signers` field contains raw DER-encoded bytes representing
/// SEQUENCE OF OCTET STRING. Use `iter_signers()` to iterate over
/// individual signer public keys without allocation.
#[derive(Debug, Clone)]
pub struct MultisigArgs<'a> {
	/// Raw DER bytes of the signers SEQUENCE (tag 0x30 + length + content).
	/// Contains SEQUENCE OF OCTET STRING where each OCTET STRING is a signer public key.
	pub signers: &'a [u8],
	/// Required number of signatures
	pub quorum: u64,
}

impl<'a> MultisigArgs<'a> {
	/// Returns an iterator over signer public keys.
	///
	/// Each item is a Result containing the raw bytes of one signer's
	/// public key (the OCTET STRING content, without tag/length).
	///
	/// # Example
	/// ```ignore
	/// for signer_result in multisig_args.iter_signers() {
	///     let signer_pubkey = signer_result?;
	///     // signer_pubkey is &[u8] containing the public key bytes
	/// }
	/// ```
	pub fn iter_signers(&self) -> SignersIter<'a> {
		SignersIter::new(self.signers)
	}

	/// Returns the number of signers.
	///
	/// Returns an error if the signers data is malformed.
	pub fn signer_count(&self) -> der::Result<usize> {
		let mut count = 0;
		for result in self.iter_signers() {
			result?;
			count += 1;
		}
		Ok(count)
	}
}

impl<'a> DecodeValue<'a> for MultisigArgs<'a> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
		// Read signers as raw TLV bytes (SEQUENCE OF OCTET STRING)
		let signers = read_tlv_bytes(reader)?;
		let quorum: u64 = reader.decode()?;
		Ok(MultisigArgs { signers, quorum })
	}
}

impl EncodeValue for MultisigArgs<'_> {
	fn value_len(&self) -> der::Result<Length> {
		Length::try_from(self.signers.len())? + self.quorum.encoded_len()?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		writer.write(self.signers)?;
		self.quorum.encode(writer)
	}
}

impl<'a> Sequence<'a> for MultisigArgs<'a> {}

/// Iterator that yields raw signer public key bytes (without DER tag/length).
///
/// Construction is infallible. A malformed signers SEQUENCE surfaces as a
/// single `Err` item on the first call to [`Iterator::next`] rather than being
/// silently reported as empty.
#[derive(Debug, Clone)]
pub struct SignersIter<'a> {
	state: SignersState<'a>,
}

/// Parse progress for [`SignersIter`].
#[derive(Debug, Clone)]
enum SignersState<'a> {
	/// Raw SEQUENCE bytes awaiting their first parse.
	Pending(&'a [u8]),
	/// Reader positioned at the next OCTET STRING within the SEQUENCE content.
	Reading(SliceReader<'a>),
	/// Exhausted or unrecoverable; yields nothing further.
	Done,
}

impl<'a> SignersIter<'a> {
	/// Creates a new iterator over the raw signers SEQUENCE bytes.
	fn new(signers_sequence: &'a [u8]) -> Self {
		SignersIter { state: SignersState::Pending(signers_sequence) }
	}

	/// Parses the SEQUENCE header and returns a reader over its content.
	fn content_reader(signers_sequence: &'a [u8]) -> der::Result<SliceReader<'a>> {
		let mut outer = SliceReader::new(signers_sequence)?;
		let header = Header::decode(&mut outer)?;
		if header.tag != Tag::Sequence {
			return Err(Tag::Sequence.value_error());
		}
		let content = outer.read_slice(header.length)?;
		SliceReader::new(content)
	}
}

impl<'a> Iterator for SignersIter<'a> {
	type Item = der::Result<&'a [u8]>;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			match &mut self.state {
				SignersState::Done => return None,
				SignersState::Pending(bytes) => {
					let bytes = *bytes;
					if bytes.is_empty() {
						self.state = SignersState::Done;
						return None;
					}
					match Self::content_reader(bytes) {
						Ok(reader) => self.state = SignersState::Reading(reader),
						Err(e) => {
							self.state = SignersState::Done;
							return Some(Err(e));
						}
					}
				}
				SignersState::Reading(reader) => {
					if reader.is_finished() {
						self.state = SignersState::Done;
						return None;
					}
					return match Bytes::decode(reader) {
						Ok(octet_string) => Some(Ok(octet_string.as_bytes())),
						Err(e) => {
							self.state = SignersState::Done;
							Some(Err(e))
						}
					};
				}
			}
		}
	}
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
	/// Multisig creation arguments (tag `7`)
	#[asn1(context_specific = "7", tag_mode = "EXPLICIT", constructed = "true")]
	Multisig(MultisigArgs<'a>),
	/// Swap creation arguments (tag `8`)
	#[asn1(context_specific = "8", tag_mode = "EXPLICIT", constructed = "true")]
	Swap(SwapArgs<'a>),
}

/// Tag `4`: CREATE_IDENTIFIER operation - Create token, multisig, or swap
#[derive(Debug, Clone, Sequence)]
pub struct CreateIdentifierOp<'a> {
	/// Identifier to create
	pub identifier: Bytes<'a>,
	/// Creation arguments (optional, depends on identifier type)
	#[asn1(optional = "true")]
	pub create_arguments: Option<CreateIdentifierArgs<'a>>,
}

/// Tag `5`: TOKEN_ADMIN_SUPPLY operation - Modify token supply
#[derive(Debug, Clone, Copy, Sequence)]
pub struct TokenAdminSupplyOp<'a> {
	/// Amount to modify
	pub amount: Int<'a>,
	/// Method (add/subtract only, set is not allowed)
	pub method: AdjustMethodRelative,
}

/// Tag `6`: TOKEN_ADMIN_MODIFY_BALANCE operation - Modify account token balance
#[derive(Debug, Clone, Sequence)]
pub struct TokenAdminModifyBalanceOp<'a> {
	/// Token to modify balance of
	pub token: Bytes<'a>,
	/// Amount to modify
	pub amount: Int<'a>,
	/// Method (add/subtract/set)
	pub method: AdjustMethod,
}

/// Tag `7`: RECEIVE operation - Receive tokens from another account
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

/// Tag `8`: MANAGE_CERTIFICATE operation - Add or subtract certificates.
///
/// Certificate data is stored as raw DER bytes (can be OCTET STRING or SEQUENCE).
#[derive(Debug, Clone)]
pub struct ManageCertificateOp<'a> {
	/// Method (add/subtract).
	pub method: AdjustMethodRelative,
	/// Certificate DER bytes (if adding) or certificate hash (if removing).
	/// Stored with tag+length for roundtrip encoding.
	pub certificate_or_hash: &'a [u8],
	/// Intermediate certificates DER bytes, NULL, or absent.
	pub intermediate_certificates: Option<NullOr<&'a [u8]>>,
}

impl<'a> DecodeValue<'a> for ManageCertificateOp<'a> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
		let method = reader.decode()?;

		// Read certificate as raw TLV bytes (any tag type)
		let certificate_or_hash = read_tlv_bytes(reader)?;

		// Handle optional intermediate_certificates field
		let intermediate_certificates = if reader.is_finished() {
			None
		} else {
			let tag = reader.peek_tag()?;
			if tag == Tag::Null {
				let _: Null = reader.decode()?;
				Some(NullOr::Null)
			} else {
				Some(NullOr::Value(read_tlv_bytes(reader)?))
			}
		};

		Ok(ManageCertificateOp { method, certificate_or_hash, intermediate_certificates })
	}
}

impl EncodeValue for ManageCertificateOp<'_> {
	fn value_len(&self) -> der::Result<Length> {
		self.method.encoded_len()?
			+ Length::try_from(self.certificate_or_hash.len())?
			+ self
				.intermediate_certificates
				.as_ref()
				.map(|v| match v {
					NullOr::Null => Null.encoded_len(),
					NullOr::Value(bytes) => Length::try_from(bytes.len()),
				})
				.transpose()?
				.unwrap_or(Length::ZERO)
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		self.method.encode(writer)?;
		writer.write(self.certificate_or_hash)?;
		if let Some(ref certs) = self.intermediate_certificates {
			match certs {
				NullOr::Null => Null.encode(writer)?,
				NullOr::Value(bytes) => writer.write(bytes)?,
			}
		}
		Ok(())
	}
}

impl<'a> Sequence<'a> for ManageCertificateOp<'a> {}

/// Tag `9`: MATCH_SWAP operation - Match two swap orders
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

/// Tag `10`: CANCEL_SWAP operation - Cancel a swap order
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
	/// Tag `0`: Send tokens
	#[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
	Send(SendOp<'a>),
	/// Tag `1`: Set representative
	#[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
	SetRep(SetRepOp<'a>),
	/// Tag `2`: Set account info
	#[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
	SetInfo(SetInfoOp<'a>),
	/// Tag `3`: Modify permissions
	#[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
	ModifyPermissions(ModifyPermissionsOp<'a>),
	/// Tag `4`: Create identifier (token, multisig, swap)
	#[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
	CreateIdentifier(CreateIdentifierOp<'a>),
	/// Tag `5`: Token admin supply
	#[asn1(context_specific = "5", tag_mode = "EXPLICIT", constructed = "true")]
	TokenAdminSupply(TokenAdminSupplyOp<'a>),
	/// Tag `6`: Token admin modify balance
	#[asn1(context_specific = "6", tag_mode = "EXPLICIT", constructed = "true")]
	TokenAdminModifyBalance(TokenAdminModifyBalanceOp<'a>),
	/// Tag `7`: Receive tokens
	#[asn1(context_specific = "7", tag_mode = "EXPLICIT", constructed = "true")]
	Receive(ReceiveOp<'a>),
	/// Tag `8`: Manage certificate
	#[asn1(context_specific = "8", tag_mode = "EXPLICIT", constructed = "true")]
	ManageCertificate(ManageCertificateOp<'a>),
	/// Tag `9`: Match swap
	#[asn1(context_specific = "9", tag_mode = "EXPLICIT", constructed = "true")]
	MatchSwap(MatchSwapOp<'a>),
	/// Tag `10`: Cancel swap
	#[asn1(context_specific = "10", tag_mode = "EXPLICIT", constructed = "true")]
	CancelSwap(CancelSwapOp<'a>),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use der::{Decode, Encode};

	// Helper to create test bytes (33-byte address with Ed25519 prefix)
	fn test_address() -> [u8; 33] {
		let mut addr = [0u8; 33];
		addr[0] = 0x01; // Ed25519 prefix
		addr[1] = 0xAB;
		addr[32] = 0xCD;
		addr
	}

	// Helper to create test token (33 bytes)
	fn test_token() -> [u8; 33] {
		let mut token = [0u8; 33];
		token[0] = 0x01;
		token[1] = 0xDE;
		token[32] = 0xAD;
		token
	}

	// ============================================================================
	// NullOr Tests
	// ============================================================================

	#[test]
	fn nullor_null_roundtrip() -> der::Result<()> {
		let original: NullOr<Bytes> = NullOr::Null;
		let encoded = original.to_der()?;
		let decoded = NullOr::<Bytes>::from_der(&encoded)?;
		assert_eq!(decoded, NullOr::Null);
		Ok(())
	}

	#[test]
	fn nullor_value_roundtrip() -> der::Result<()> {
		let data = [1u8, 2, 3, 4];
		let original: NullOr<Bytes> = NullOr::Value(Bytes::new(&data)?);
		let encoded = original.to_der()?;
		let decoded = NullOr::<Bytes>::from_der(&encoded)?;
		assert_eq!(decoded, NullOr::Value(Bytes::new(&data)?));
		Ok(())
	}

	#[test]
	fn nullor_value_method() -> der::Result<()> {
		let data = [1u8, 2, 3];
		let null: NullOr<Bytes> = NullOr::Null;
		let value: NullOr<Bytes> = NullOr::Value(Bytes::new(&data)?);

		assert!(null.value().is_none());
		assert_eq!(value.value(), Some(&Bytes::new(&data)?));
		Ok(())
	}

	#[test]
	fn nullor_option_conversions() {
		let from_some: NullOr<u8> = Some(7u8).into();
		let from_none: NullOr<u8> = None::<u8>.into();
		assert_eq!(from_some, NullOr::Value(7));
		assert!(from_none.is_null());
		assert!(!from_some.is_null());
		assert_eq!(Option::from(NullOr::Value(9u8)), Some(9));
		assert_eq!(Option::<u8>::from(NullOr::Null), None);
	}

	// ============================================================================
	// Enum Tests
	// ============================================================================

	#[test]
	fn adjust_method_roundtrip() -> der::Result<()> {
		for method in [AdjustMethod::Add, AdjustMethod::Subtract, AdjustMethod::Set] {
			let encoded = method.to_der()?;
			let decoded = AdjustMethod::from_der(&encoded)?;
			assert_eq!(decoded, method);
		}
		Ok(())
	}

	#[test]
	fn adjust_method_relative_roundtrip() -> der::Result<()> {
		for method in [AdjustMethodRelative::Add, AdjustMethodRelative::Subtract] {
			let encoded = method.to_der()?;
			let decoded = AdjustMethodRelative::from_der(&encoded)?;
			assert_eq!(decoded, method);
		}
		Ok(())
	}

	#[test]
	fn adjust_method_conversions() {
		for (byte, method) in [(0u8, AdjustMethod::Add), (1, AdjustMethod::Subtract), (2, AdjustMethod::Set)] {
			assert_eq!(AdjustMethod::try_from(byte), Ok(method));
			assert_eq!(u8::from(method), byte);
		}
		assert_eq!(AdjustMethod::try_from(3u8), Err(3));

		for (byte, method) in [(0u8, AdjustMethodRelative::Add), (1, AdjustMethodRelative::Subtract)] {
			assert_eq!(AdjustMethodRelative::try_from(byte), Ok(method));
			assert_eq!(u8::from(method), byte);
		}
		assert_eq!(AdjustMethodRelative::try_from(2u8), Err(2));
	}

	#[test]
	fn adjust_method_widening_narrowing() {
		assert_eq!(AdjustMethod::from(AdjustMethodRelative::Add), AdjustMethod::Add);
		assert_eq!(AdjustMethod::from(AdjustMethodRelative::Subtract), AdjustMethod::Subtract);
		assert_eq!(AdjustMethodRelative::try_from(AdjustMethod::Add), Ok(AdjustMethodRelative::Add));
		assert_eq!(AdjustMethodRelative::try_from(AdjustMethod::Subtract), Ok(AdjustMethodRelative::Subtract));
		assert_eq!(AdjustMethodRelative::try_from(AdjustMethod::Set), Err(AdjustMethod::Set));
	}

	// ============================================================================
	// Supporting Type Tests
	// ============================================================================

	#[test]
	fn permission_roundtrip() -> der::Result<()> {
		let original = Permission { base: 0x1234, external: 0x5678 };
		let encoded = original.to_der()?;
		let decoded = Permission::from_der(&encoded)?;
		assert_eq!(decoded.base, original.base);
		assert_eq!(decoded.external, original.external);
		Ok(())
	}

	#[test]
	fn token_rate_roundtrip() -> der::Result<()> {
		let token = test_token();
		let rate = [0x64]; // 100 (canonical form)

		let original = TokenRate { token: Bytes::new(&token)?, rate: Int::new(&rate)? };
		let encoded = original.to_der()?;
		let decoded = TokenRate::from_der(&encoded)?;

		assert_eq!(decoded.token.as_bytes(), &token);
		assert_eq!(decoded.rate.as_bytes(), &rate);
		Ok(())
	}

	#[test]
	fn fee_rate_with_null_token_roundtrip() -> der::Result<()> {
		let rate = [0x0A]; // 10

		let original = FeeRate { token: NullOr::Null, rate: Int::new(&rate)? };
		let encoded = original.to_der()?;
		let decoded = FeeRate::from_der(&encoded)?;

		assert!(decoded.token.is_null());
		assert_eq!(decoded.rate.as_bytes(), &rate);
		Ok(())
	}

	#[test]
	fn fee_rate_with_token_roundtrip() -> der::Result<()> {
		let token = test_token();
		let rate = [0x0A]; // 10

		let original = FeeRate { token: NullOr::Value(Bytes::new(&token)?), rate: Int::new(&rate)? };
		let encoded = original.to_der()?;
		let decoded = FeeRate::from_der(&encoded)?;

		assert_eq!(decoded.token, NullOr::Value(Bytes::new(&token)?));
		assert_eq!(decoded.rate.as_bytes(), &rate);
		Ok(())
	}

	#[test]
	fn token_value_roundtrip() -> der::Result<()> {
		let token = test_token();
		let value = [0x00, 0xFF]; // 255

		let original = TokenValue { token: Bytes::new(&token)?, value: Int::new(&value)? };
		let encoded = original.to_der()?;
		let decoded = TokenValue::from_der(&encoded)?;

		assert_eq!(decoded.token.as_bytes(), &token);
		assert_eq!(decoded.value.as_bytes(), &value);
		Ok(())
	}

	#[test]
	fn fee_value_roundtrip() -> der::Result<()> {
		let value = [0x64]; // 100

		let original = FeeValue { token: NullOr::Null, value: Int::new(&value)? };
		let encoded = original.to_der()?;
		let decoded = FeeValue::from_der(&encoded)?;

		assert!(decoded.token.is_null());
		assert_eq!(decoded.value.as_bytes(), &value);
		Ok(())
	}

	#[test]
	fn fee_value_with_recipient_roundtrip() -> der::Result<()> {
		let token = test_token();
		let value = [0x64]; // 100
		let recipient = test_address();

		let original = FeeValueWithRecipient {
			token: NullOr::Value(Bytes::new(&token)?),
			value: Int::new(&value)?,
			recipient: Bytes::new(&recipient)?,
		};
		let encoded = original.to_der()?;
		let decoded = FeeValueWithRecipient::from_der(&encoded)?;

		assert_eq!(decoded.token, NullOr::Value(Bytes::new(&token)?));
		assert_eq!(decoded.recipient.as_bytes(), &recipient);
		Ok(())
	}

	// ============================================================================
	// Operation Tests
	// ============================================================================

	#[test]
	fn send_op_roundtrip() -> der::Result<()> {
		let to = test_address();
		let amount = [0x10]; // 16 (canonical form - no leading zeros)
		let token = test_token();

		let original =
			SendOp { to: Bytes::new(&to)?, amount: Int::new(&amount)?, token: Bytes::new(&token)?, external: None };
		let encoded = original.to_der()?;
		let decoded = SendOp::from_der(&encoded)?;

		assert_eq!(decoded.to.as_bytes(), &to);
		assert_eq!(decoded.amount.as_bytes(), &amount);
		assert_eq!(decoded.token.as_bytes(), &token);
		assert!(decoded.external.is_none());
		Ok(())
	}

	#[test]
	fn send_op_with_external_roundtrip() -> der::Result<()> {
		let to = test_address();
		let amount = [0x10]; // 16
		let token = test_token();
		let external = "ref-123";

		let original = SendOp {
			to: Bytes::new(&to)?,
			amount: Int::new(&amount)?,
			token: Bytes::new(&token)?,
			external: Some(Str::new(external)?),
		};
		let encoded = original.to_der()?;
		let decoded = SendOp::from_der(&encoded)?;

		assert_eq!(decoded.external, Some(Str::new(external)?));
		Ok(())
	}

	#[test]
	fn set_rep_op_roundtrip() -> der::Result<()> {
		let to = test_address();

		let original = SetRepOp { to: Bytes::new(&to)? };
		let encoded = original.to_der()?;
		let decoded = SetRepOp::from_der(&encoded)?;

		assert_eq!(decoded.to.as_bytes(), &to);
		Ok(())
	}

	#[test]
	fn set_info_op_roundtrip() -> der::Result<()> {
		let original = SetInfoOp {
			name: Str::new("Test Account")?,
			description: Str::new("A test account")?,
			metadata: Str::new("{}")?,
			default_permission: None,
		};
		let encoded = original.to_der()?;
		let decoded = SetInfoOp::from_der(&encoded)?;

		assert_eq!(decoded.name.as_str(), "Test Account");
		assert_eq!(decoded.description.as_str(), "A test account");
		assert_eq!(decoded.metadata.as_str(), "{}");
		Ok(())
	}

	#[test]
	fn set_info_op_with_permission_roundtrip() -> der::Result<()> {
		let original = SetInfoOp {
			name: Str::new("Test")?,
			description: Str::new("Desc")?,
			metadata: Str::new("{}")?,
			default_permission: Some(Permission { base: 0xFF, external: 0xAA }),
		};
		let encoded = original.to_der()?;
		let decoded = SetInfoOp::from_der(&encoded)?;

		let perm = decoded.default_permission.ok_or_else(|| Tag::Integer.value_error())?;
		assert_eq!(perm.base, 0xFF);
		assert_eq!(perm.external, 0xAA);
		Ok(())
	}

	#[test]
	fn modify_permissions_op_roundtrip() -> der::Result<()> {
		let principal = test_address();

		let original = ModifyPermissionsOp {
			principal: Bytes::new(&principal)?,
			method: AdjustMethod::Add,
			permissions: NullOr::Value(Permission { base: 0x10, external: 0x20 }),
			target: None,
		};
		let encoded = original.to_der()?;
		let decoded = ModifyPermissionsOp::from_der(&encoded)?;

		assert_eq!(decoded.principal.as_bytes(), &principal);
		assert_eq!(decoded.method, AdjustMethod::Add);
		let perm = decoded.permissions.value().ok_or_else(|| Tag::Integer.value_error())?;
		assert_eq!(perm.base, 0x10);
		assert_eq!(perm.external, 0x20);
		Ok(())
	}

	#[test]
	fn modify_permissions_op_clear_roundtrip() -> der::Result<()> {
		let principal = test_address();

		let original = ModifyPermissionsOp {
			principal: Bytes::new(&principal)?,
			method: AdjustMethod::Set,
			permissions: NullOr::Null,
			target: None,
		};
		let encoded = original.to_der()?;
		let decoded = ModifyPermissionsOp::from_der(&encoded)?;

		assert!(decoded.permissions.is_null());
		Ok(())
	}

	#[test]
	fn token_admin_supply_op_roundtrip() -> der::Result<()> {
		let amount = [0x00, 0xFF, 0xFF]; // 65535

		let original = TokenAdminSupplyOp { amount: Int::new(&amount)?, method: AdjustMethodRelative::Add };
		let encoded = original.to_der()?;
		let decoded = TokenAdminSupplyOp::from_der(&encoded)?;

		assert_eq!(decoded.amount.as_bytes(), &amount);
		assert_eq!(decoded.method, AdjustMethodRelative::Add);
		Ok(())
	}

	#[test]
	fn token_admin_modify_balance_op_roundtrip() -> der::Result<()> {
		let token = test_token();
		let amount = [0x64]; // 100

		let original = TokenAdminModifyBalanceOp {
			token: Bytes::new(&token)?,
			amount: Int::new(&amount)?,
			method: AdjustMethod::Subtract,
		};
		let encoded = original.to_der()?;
		let decoded = TokenAdminModifyBalanceOp::from_der(&encoded)?;

		assert_eq!(decoded.token.as_bytes(), &token);
		assert_eq!(decoded.method, AdjustMethod::Subtract);
		Ok(())
	}

	#[test]
	fn receive_op_roundtrip() -> der::Result<()> {
		let from = test_address();
		let token = test_token();
		let amount = [0x10]; // 16

		let original = ReceiveOp {
			amount: Int::new(&amount)?,
			token: Bytes::new(&token)?,
			from: Bytes::new(&from)?,
			exact: true,
			forward: None,
		};
		let encoded = original.to_der()?;
		let decoded = ReceiveOp::from_der(&encoded)?;

		assert_eq!(decoded.from.as_bytes(), &from);
		assert!(decoded.exact);
		assert!(decoded.forward.is_none());
		Ok(())
	}

	#[test]
	fn receive_op_with_forward_roundtrip() -> der::Result<()> {
		let from = test_address();
		let token = test_token();
		let amount = [0x10];
		let mut forward = [0u8; 33];
		forward[0] = 0x02; // Different address

		let original = ReceiveOp {
			amount: Int::new(&amount)?,
			token: Bytes::new(&token)?,
			from: Bytes::new(&from)?,
			exact: false,
			forward: Some(Bytes::new(&forward)?),
		};
		let encoded = original.to_der()?;
		let decoded = ReceiveOp::from_der(&encoded)?;

		assert!(!decoded.exact);
		assert_eq!(decoded.forward, Some(Bytes::new(&forward)?));
		Ok(())
	}

	#[test]
	fn manage_certificate_op_add_roundtrip() -> der::Result<()> {
		// Raw DER: SEQUENCE with some content (mock X.509 certificate)
		let cert_der = [0x30, 0x03, 0x01, 0x01, 0xFF]; // SEQUENCE { BOOLEAN TRUE }
		let intermediate_der = [0x30, 0x03, 0x02, 0x01, 0x00]; // SEQUENCE { INTEGER 0 }

		let original = ManageCertificateOp {
			method: AdjustMethodRelative::Add,
			certificate_or_hash: &cert_der,
			intermediate_certificates: Some(NullOr::Value(&intermediate_der)),
		};
		let encoded = original.to_der()?;
		let decoded = ManageCertificateOp::from_der(&encoded)?;

		assert_eq!(decoded.method, AdjustMethodRelative::Add);
		assert_eq!(decoded.certificate_or_hash, &cert_der);
		assert_eq!(decoded.intermediate_certificates, Some(NullOr::Value(&intermediate_der[..])));
		Ok(())
	}

	#[test]
	fn manage_certificate_op_add_no_intermediate_roundtrip() -> der::Result<()> {
		let cert_der = [0x30, 0x03, 0x01, 0x01, 0xFF];

		let original = ManageCertificateOp {
			method: AdjustMethodRelative::Add,
			certificate_or_hash: &cert_der,
			intermediate_certificates: Some(NullOr::Null),
		};
		let encoded = original.to_der()?;
		let decoded = ManageCertificateOp::from_der(&encoded)?;

		assert!(matches!(decoded.intermediate_certificates, Some(NullOr::Null)));
		Ok(())
	}

	#[test]
	fn manage_certificate_op_subtract_roundtrip() -> der::Result<()> {
		// OCTET STRING containing 32-byte hash
		let mut hash_der = [0u8; 34];
		hash_der[0] = 0x04; // OCTET STRING tag
		hash_der[1] = 0x20; // length 32
		hash_der[2..].fill(0xAB); // hash bytes

		let original = ManageCertificateOp {
			method: AdjustMethodRelative::Subtract,
			certificate_or_hash: &hash_der,
			intermediate_certificates: None,
		};
		let encoded = original.to_der()?;
		let decoded = ManageCertificateOp::from_der(&encoded)?;

		assert_eq!(decoded.method, AdjustMethodRelative::Subtract);
		assert!(decoded.intermediate_certificates.is_none());
		Ok(())
	}

	#[test]
	fn match_swap_op_roundtrip() -> der::Result<()> {
		let swap = test_address();
		let other = test_token();
		let sell_token = test_token();
		let buy_token = test_address();

		let original = MatchSwapOp {
			swap: Bytes::new(&swap)?,
			other: Bytes::new(&other)?,
			sell: TokenValue { token: Bytes::new(&sell_token)?, value: Int::new(&[0x64])? },
			buy: TokenValue { token: Bytes::new(&buy_token)?, value: Int::new(&[0x32])? },
			fee: NullOr::Null,
		};
		let encoded = original.to_der()?;
		let decoded = MatchSwapOp::from_der(&encoded)?;

		assert_eq!(decoded.swap.as_bytes(), &swap);
		assert!(decoded.fee.is_null());
		Ok(())
	}

	#[test]
	fn cancel_swap_op_roundtrip() -> der::Result<()> {
		let swap = test_address();
		let sell_token = test_token();

		let original = CancelSwapOp {
			swap: Bytes::new(&swap)?,
			sell: TokenValue { token: Bytes::new(&sell_token)?, value: Int::new(&[0x10])? },
			fee: NullOr::Null,
		};
		let encoded = original.to_der()?;
		let decoded = CancelSwapOp::from_der(&encoded)?;

		assert_eq!(decoded.swap.as_bytes(), &swap);
		Ok(())
	}

	// ============================================================================
	// CreateIdentifier Tests
	// ============================================================================

	#[test]
	fn create_identifier_token_roundtrip() -> der::Result<()> {
		let identifier = test_token();

		let original = CreateIdentifierOp { identifier: Bytes::new(&identifier)?, create_arguments: None };
		let encoded = original.to_der()?;
		let decoded = CreateIdentifierOp::from_der(&encoded)?;

		assert_eq!(decoded.identifier.as_bytes(), &identifier);
		assert!(decoded.create_arguments.is_none());
		Ok(())
	}

	#[test]
	fn create_identifier_multisig_roundtrip() -> der::Result<()> {
		let identifier = test_token();
		// SEQUENCE OF OCTET STRING with 2 signers (each 3 bytes)
		// SEQUENCE { OCTET STRING (AA BB CC), OCTET STRING (DD EE FF) }
		let signers_raw = [
			0x30, 0x0A, // SEQUENCE, length 10
			0x04, 0x03, 0xAA, 0xBB, 0xCC, // OCTET STRING, length 3, content
			0x04, 0x03, 0xDD, 0xEE, 0xFF, // OCTET STRING, length 3, content
		];

		let original = CreateIdentifierOp {
			identifier: Bytes::new(&identifier)?,
			create_arguments: Some(CreateIdentifierArgs::Multisig(MultisigArgs { signers: &signers_raw, quorum: 2 })),
		};
		let encoded = original.to_der()?;
		let decoded = CreateIdentifierOp::from_der(&encoded)?;

		let args = match decoded.create_arguments {
			Some(CreateIdentifierArgs::Multisig(args)) => args,
			_ => return Err(Tag::Integer.value_error()),
		};
		assert_eq!(args.signers, &signers_raw);
		assert_eq!(args.quorum, 2);

		let signers = args.iter_signers().collect::<der::Result<Vec<&[u8]>>>()?;
		assert_eq!(signers, vec![&[0xAA, 0xBB, 0xCC][..], &[0xDD, 0xEE, 0xFF][..]]);
		assert_eq!(args.signer_count()?, 2);
		Ok(())
	}

	#[test]
	fn multisig_args_iter_signers() -> der::Result<()> {
		// Test with realistic 33-byte public keys (Ed25519 prefix + 32 bytes)
		let signer1 = test_address(); // 33 bytes
		let signer2 = test_token(); // 33 bytes

		// Build SEQUENCE OF OCTET STRING manually
		// Each signer: 04 21 <33 bytes> = 35 bytes
		// Total content: 70 bytes
		// SEQUENCE header: 30 46 (0x46 = 70)
		let mut signers_raw = vec![
			0x30, // SEQUENCE tag
			0x46, // length 70
			0x04, // OCTET STRING tag
			0x21, // length 33
		];
		signers_raw.extend_from_slice(&signer1);
		signers_raw.extend_from_slice(&[0x04, 0x21]); // OCTET STRING tag + length 33
		signers_raw.extend_from_slice(&signer2);

		let args = MultisigArgs { signers: &signers_raw, quorum: 2 };

		let collected = args.iter_signers().collect::<der::Result<Vec<&[u8]>>>()?;
		assert_eq!(collected, vec![&signer1[..], &signer2[..]]);
		assert_eq!(args.signer_count()?, 2);
		Ok(())
	}

	#[test]
	fn multisig_args_empty_signers() -> der::Result<()> {
		// Empty SEQUENCE
		let signers_raw = [0x30, 0x00]; // SEQUENCE, length 0

		let args = MultisigArgs { signers: &signers_raw, quorum: 0 };

		let collected = args.iter_signers().collect::<der::Result<Vec<&[u8]>>>()?;
		assert!(collected.is_empty());
		assert_eq!(args.signer_count()?, 0);
		Ok(())
	}

	#[test]
	fn multisig_args_malformed_surfaces_error() {
		// Leading byte is OCTET STRING, not SEQUENCE: must surface an error,
		// not silently report zero signers.
		let malformed = [0x04, 0x01, 0xAA];
		let args = MultisigArgs { signers: &malformed, quorum: 1 };

		let mut iter = args.iter_signers();
		assert!(matches!(iter.next(), Some(Err(_))));
		assert!(iter.next().is_none());
		assert!(args.signer_count().is_err());
	}

	#[test]
	fn create_identifier_swap_roundtrip() -> der::Result<()> {
		let identifier = test_token();
		let sell_token = test_token();
		let buy_token = test_address();

		let original = CreateIdentifierOp {
			identifier: Bytes::new(&identifier)?,
			create_arguments: Some(CreateIdentifierArgs::Swap(SwapArgs {
				sell_token_rate: TokenRate { token: Bytes::new(&sell_token)?, rate: Int::new(&[0x64])? },
				buy_token_rate: TokenRate { token: Bytes::new(&buy_token)?, rate: Int::new(&[0x32])? },
				fee_token_rate: NullOr::Null,
				quantity: Int::new(&[0x0A])?,
			})),
		};
		let encoded = original.to_der()?;
		let decoded = CreateIdentifierOp::from_der(&encoded)?;

		let args = match decoded.create_arguments {
			Some(CreateIdentifierArgs::Swap(args)) => args,
			_ => return Err(Tag::Integer.value_error()),
		};
		assert!(args.fee_token_rate.is_null());
		Ok(())
	}
}
