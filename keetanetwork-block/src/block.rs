//! Block model: shared data, unsigned blocks and sealed (verified) blocks.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use keetanetwork_account::account::AccountSigner;
use keetanetwork_account::KeyPairType;
use keetanetwork_crypto::hash::{hash_default, BlockHash, Hashable};
use num_bigint::BigInt;

use crate::account_util::verify_account;
use crate::error::BlockError;
use crate::operation::{Operation, OperationContext, OperationType};
use crate::signer::{AccountRef, Signer};
use crate::time::BlockTime;
use crate::transport;
use crate::validation::ValidationConfig;

/// Multisig signer tree depth limit enforced during decoding.
pub(crate) const MAX_PARSE_SIGNER_DEPTH: usize = 3;

/// Supported block versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockVersion {
	/// Version 1: single signer, generic purpose only
	V1,
	/// Version 2: purposes, multisig signers, multiple signatures
	V2,
}

/// The declared purpose of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockPurpose {
	/// A regular block
	Generic = 0,
	/// A fee block (SEND operations only)
	Fee = 1,
}

impl BlockPurpose {
	pub(crate) fn to_bigint(self) -> BigInt {
		BigInt::from(self as u8)
	}
}

impl TryFrom<&BigInt> for BlockPurpose {
	type Error = BlockError;

	fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
		if *value == BigInt::ZERO {
			Ok(BlockPurpose::Generic)
		} else if *value == BigInt::from(1u8) {
			Ok(BlockPurpose::Fee)
		} else {
			Err(BlockError::InvalidPurpose)
		}
	}
}

/// A 64-byte block signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
	/// The raw signature bytes.
	pub fn as_bytes(&self) -> &[u8; 64] {
		&self.0
	}
}

impl core::fmt::Debug for Signature {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "Signature(")?;
		for byte in &self.0 {
			write!(f, "{byte:02X}")?;
		}
		write!(f, ")")
	}
}

impl From<[u8; 64]> for Signature {
	fn from(bytes: [u8; 64]) -> Self {
		Self(bytes)
	}
}

impl AsRef<[u8]> for Signature {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<&[u8]> for Signature {
	type Error = BlockError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let array: [u8; 64] = bytes
			.try_into()
			.map_err(|_| BlockError::InvalidSignatureLength { length: bytes.len() })?;
		Ok(Self(array))
	}
}

/// The shared fields of a block, present in both unsigned and sealed forms.
#[derive(Debug, Clone)]
pub struct BlockData {
	pub(crate) version: BlockVersion,
	pub(crate) purpose: BlockPurpose,
	pub(crate) network: BigInt,
	pub(crate) subnet: Option<BigInt>,
	pub(crate) idempotent: Option<Vec<u8>>,
	pub(crate) date: BlockTime,
	pub(crate) account: AccountRef,
	pub(crate) signer: Signer,
	pub(crate) previous: BlockHash,
	pub(crate) operations: Vec<Operation>,
}

impl BlockData {
	/// The block version.
	pub fn version(&self) -> BlockVersion {
		self.version
	}

	/// The block purpose.
	pub fn purpose(&self) -> BlockPurpose {
		self.purpose
	}

	/// The network identifier.
	pub fn network(&self) -> &BigInt {
		&self.network
	}

	/// The subnet identifier, when present.
	pub fn subnet(&self) -> Option<&BigInt> {
		self.subnet.as_ref()
	}

	/// The idempotent key, when present.
	pub fn idempotent(&self) -> Option<&[u8]> {
		self.idempotent.as_deref()
	}

	/// The block timestamp.
	pub fn date(&self) -> BlockTime {
		self.date
	}

	/// The account the block operates on.
	pub fn account(&self) -> &AccountRef {
		&self.account
	}

	/// The signer field.
	pub fn signer(&self) -> &Signer {
		&self.signer
	}

	/// The previous block hash.
	pub fn previous(&self) -> &BlockHash {
		&self.previous
	}

	/// The block operations.
	pub fn operations(&self) -> &[Operation] {
		&self.operations
	}

	/// The opening hash of the block account.
	pub fn account_opening_hash(&self) -> BlockHash {
		self.account.to_opening_hash()
	}

	/// Whether this block is the opening block of its account.
	pub fn is_opening(&self) -> bool {
		self.previous == self.account_opening_hash()
	}

	/// Validate the block contents (everything except signatures and
	/// byte-equality, which depend on the sealed form).
	pub(crate) fn validate(&self, hash: &BlockHash) -> Result<(), BlockError> {
		if self.previous == *hash {
			return Err(BlockError::PreviousSelf);
		}

		if self.network < BigInt::ZERO {
			return Err(BlockError::NegativeNetwork);
		}

		if let Some(subnet) = &self.subnet {
			if *subnet < BigInt::ZERO {
				return Err(BlockError::NegativeSubnet);
			}
		}

		if self.account.to_keypair_type() == KeyPairType::MULTISIG {
			return Err(BlockError::MultisigAccountForbidden);
		}

		if self.version == BlockVersion::V1 {
			if self.purpose != BlockPurpose::Generic {
				return Err(BlockError::V1PurposeInvalid);
			}

			if matches!(self.signer, Signer::Multisig { .. }) {
				return Err(BlockError::V1SingleSignerOnly);
			}
		}

		let config = ValidationConfig::for_network(&self.network).ok();

		self.validate_signer_field(config.as_ref())?;
		self.validate_operations(config.as_ref())?;
		self.validate_idempotent(config.as_ref())?;

		Ok(())
	}

	/// Walk the multisig signer tree breadth-first, enforcing depth, width
	/// and per-level uniqueness limits.
	fn validate_signer_field(&self, config: Option<&ValidationConfig>) -> Result<(), BlockError> {
		if !matches!(self.signer, Signer::Multisig { .. }) {
			return Ok(());
		}

		let mut queue: Vec<(u64, &Signer)> = vec![(1, &self.signer)];
		let mut index = 0;

		while index < queue.len() {
			let (depth, current) = queue[index];
			index += 1;

			let config = config.ok_or(BlockError::UnknownNetwork)?;
			config.validate_signer_depth(depth)?;

			let Signer::Multisig { address, signers } = current else {
				continue;
			};

			// The reference implementation only accepts MULTISIG principals
			// in the signer tree; mirror that here since the enum cannot
			// make it un-representable.
			if address.to_keypair_type() != KeyPairType::MULTISIG {
				return Err(BlockError::MalformedSigner);
			}

			config.validate_signer_count(signers.len() as u64)?;

			let mut seen: BTreeSet<String> = BTreeSet::new();
			for inner in signers {
				if matches!(inner, Signer::Multisig { .. }) {
					queue.push((depth + 1, inner));
				}

				if !seen.insert(inner.principal().to_string()) {
					return Err(BlockError::MultisigSignerDuplicate);
				}
			}
		}

		Ok(())
	}

	fn validate_operations(&self, config: Option<&ValidationConfig>) -> Result<(), BlockError> {
		for (operation_index, operation) in self.operations.iter().enumerate() {
			if self.purpose == BlockPurpose::Fee && operation.operation_type() != OperationType::Send {
				return Err(BlockError::FeePurposeRequiresSend { operation_index });
			}

			let ctx = OperationContext {
				config,
				account: &self.account,
				operations: &self.operations,
				previous: &self.previous,
				date_ms: self.date.unix_millis(),
				operation_index,
			};
			operation.validate(&ctx)?;
		}

		Ok(())
	}

	fn validate_idempotent(&self, config: Option<&ValidationConfig>) -> Result<(), BlockError> {
		let Some(idempotent) = &self.idempotent else {
			return Ok(());
		};

		let config = config.ok_or(BlockError::UnknownNetwork)?;
		if idempotent.len() > config.max_idempotent_bytes {
			return Err(BlockError::IdempotentTooLong { length: idempotent.len(), max: config.max_idempotent_bytes });
		}

		Ok(())
	}
}

/// A fully constructed but not yet signed block.
#[derive(Debug, Clone)]
pub struct UnsignedBlock {
	data: BlockData,
	bytes: Vec<u8>,
	hash: BlockHash,
}

impl TryFrom<BlockData> for UnsignedBlock {
	type Error = BlockError;

	/// Construct from block data, validating everything except signatures.
	fn try_from(data: BlockData) -> Result<Self, Self::Error> {
		let bytes = transport::encode_block(&data, None)?;
		let hash = BlockHash::from(hash_default(&bytes));

		data.validate(&hash)?;

		Ok(Self { data, bytes, hash })
	}
}

impl UnsignedBlock {
	/// The block data.
	pub fn data(&self) -> &BlockData {
		&self.data
	}

	/// The unsigned DER bytes.
	pub fn to_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// The accounts which must sign this block, in signature order.
	pub fn required_signers(&self) -> Vec<AccountRef> {
		self.data.signer.required_signers()
	}

	/// Seal the block with externally produced signatures.
	pub fn seal(self, signatures: Vec<Signature>) -> Result<Block, BlockError> {
		BlockParts { data: self.data, signatures }.try_into()
	}

	/// Sign with the private keys held by the required signer accounts and
	/// seal the block.
	pub fn sign(self) -> Result<Block, BlockError> {
		let mut signatures = Vec::new();
		for signer in self.required_signers() {
			let raw = signer.sign(self.hash.as_bytes(), None)?;
			signatures.push(Signature::try_from(raw.as_slice())?);
		}

		self.seal(signatures)
	}
}

impl Hashable for UnsignedBlock {
	fn hash(&self) -> BlockHash {
		self.hash
	}
}

/// A sealed block: structurally valid with verified signatures.
///
/// A `Block` can only be obtained through paths that validate and verify,
/// so holding one implies validity.
#[derive(Debug, Clone)]
pub struct Block {
	data: BlockData,
	signatures: Vec<Signature>,
	/// The signed DER bytes as transmitted on the network.
	bytes: Vec<u8>,
	hash: BlockHash,
}

/// Validated block data paired with its signatures: the single
/// construction path for [`Block`].
pub(crate) struct BlockParts {
	pub(crate) data: BlockData,
	pub(crate) signatures: Vec<Signature>,
}

impl TryFrom<BlockParts> for Block {
	type Error = BlockError;

	/// Encode, validate and verify the signatures; only verified parts
	/// become a [`Block`].
	fn try_from(parts: BlockParts) -> Result<Self, Self::Error> {
		let BlockParts { data, signatures } = parts;

		let unsigned_bytes = transport::encode_block(&data, None)?;
		let hash = BlockHash::from(hash_default(&unsigned_bytes));

		data.validate(&hash)?;

		if signatures.is_empty() {
			return Err(BlockError::SignatureRequired);
		}

		if data.version == BlockVersion::V1 && signatures.len() != 1 {
			return Err(BlockError::V1SingleSignerOnly);
		}

		let signers = data.signer.required_signers();
		if signatures.len() != signers.len() {
			return Err(BlockError::SignatureCountMismatch { expected: signers.len(), actual: signatures.len() });
		}

		for (index, (signer, signature)) in signers.iter().zip(&signatures).enumerate() {
			if verify_account(signer, hash.as_bytes(), signature.as_ref()).is_err() {
				return Err(BlockError::InvalidSignature { index, hash });
			}
		}

		let bytes = transport::encode_block(&data, Some(&signatures))?;
		Ok(Self { data, signatures, bytes, hash })
	}
}

impl Block {
	/// The block data.
	pub fn data(&self) -> &BlockData {
		&self.data
	}

	/// The block signatures, in required-signer order.
	pub fn signatures(&self) -> &[Signature] {
		&self.signatures
	}

	/// The signed DER bytes.
	pub fn to_bytes(&self) -> &[u8] {
		&self.bytes
	}
}

impl Hashable for Block {
	fn hash(&self) -> BlockHash {
		self.hash
	}
}

impl TryFrom<&[u8]> for Block {
	type Error = BlockError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let (data, signatures) = transport::decode_block(bytes)?;
		let signatures = signatures.ok_or(BlockError::SignatureRequired)?;

		let block = Self::try_from(BlockParts { data, signatures })?;
		if block.bytes != bytes {
			return Err(BlockError::RecalculatedBytesMismatch);
		}

		Ok(block)
	}
}

impl TryFrom<&[u8]> for UnsignedBlock {
	type Error = BlockError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let (data, signatures) = transport::decode_block(bytes)?;
		if signatures.is_some() {
			return Err(BlockError::RecalculatedBytesMismatch);
		}

		let unsigned = Self::try_from(data)?;
		if unsigned.bytes != bytes {
			return Err(BlockError::RecalculatedBytesMismatch);
		}

		Ok(unsigned)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::operation::SetRep;
	use crate::testing::{generate_ed25519_ref, generate_identifier_ref, valid_block_builder};
	use num_bigint::BigInt;

	#[test]
	fn test_rejects_negative_network() {
		let result = valid_block_builder().with_network(BigInt::from(-1)).build();
		assert!(matches!(result, Err(BlockError::NegativeNetwork)));
	}

	#[test]
	fn test_rejects_negative_subnet() {
		let result = valid_block_builder().with_subnet(BigInt::from(-1)).build();
		assert!(matches!(result, Err(BlockError::NegativeSubnet)));
	}

	#[test]
	fn test_rejects_multisig_account() {
		let result = valid_block_builder()
			.with_account(generate_identifier_ref(1, KeyPairType::MULTISIG, 0))
			.as_opening()
			.build();
		assert!(matches!(result, Err(BlockError::MultisigAccountForbidden)));
	}

	#[test]
	fn test_v1_rejects_fee_purpose() {
		let result = valid_block_builder()
			.with_version(BlockVersion::V1)
			.with_purpose(BlockPurpose::Fee)
			.build();
		assert!(matches!(result, Err(BlockError::V1PurposeInvalid)));
	}

	#[test]
	fn test_rejects_multisig_signer_with_non_multisig_address() {
		let signer = Signer::Multisig {
			address: generate_ed25519_ref(1),
			signers: vec![Signer::Single(generate_ed25519_ref(2))],
		};
		let result = valid_block_builder().with_signer(signer).build();
		assert!(matches!(result, Err(BlockError::MalformedSigner)));
	}

	#[test]
	fn test_v1_rejects_multisig_signer() {
		let signer = Signer::Multisig {
			address: generate_identifier_ref(1, KeyPairType::MULTISIG, 0),
			signers: vec![Signer::Single(generate_ed25519_ref(2))],
		};
		let result = valid_block_builder()
			.with_version(BlockVersion::V1)
			.with_signer(signer)
			.build();
		assert!(matches!(result, Err(BlockError::V1SingleSignerOnly)));
	}

	#[test]
	fn test_fee_purpose_rejects_non_send_operations() {
		let result = valid_block_builder()
			.with_purpose(BlockPurpose::Fee)
			.with_operation(SetRep { to: generate_ed25519_ref(2) })
			.build();
		assert!(matches!(result, Err(BlockError::FeePurposeRequiresSend { operation_index: 1 })));
	}

	#[test]
	fn test_rejects_idempotent_too_long() {
		let result = valid_block_builder().with_idempotent(vec![0u8; 37]).build();
		assert!(matches!(result, Err(BlockError::IdempotentTooLong { length: 37, max: 36 })));
	}

	#[test]
	fn test_rejects_idempotent_on_unknown_network() {
		let result = valid_block_builder()
			.with_network(1234u32)
			.with_idempotent(vec![0u8; 4])
			.build();
		assert!(matches!(result, Err(BlockError::UnknownNetwork)));
	}

	#[test]
	fn test_seal_rejects_missing_signatures() -> Result<(), BlockError> {
		let unsigned = valid_block_builder().build()?;
		assert!(matches!(unsigned.seal(Vec::new()), Err(BlockError::SignatureRequired)));
		Ok(())
	}

	#[test]
	fn test_seal_rejects_signature_count_mismatch() -> Result<(), BlockError> {
		let unsigned = valid_block_builder().build()?;
		let signature = Signature::from([0u8; 64]);
		let result = unsigned.seal(vec![signature, signature]);
		assert!(matches!(result, Err(BlockError::SignatureCountMismatch { expected: 1, actual: 2 })));
		Ok(())
	}

	#[test]
	fn test_seal_rejects_invalid_signature() -> Result<(), BlockError> {
		let unsigned = valid_block_builder().build()?;
		let result = unsigned.seal(vec![Signature::from([0u8; 64])]);
		assert!(matches!(result, Err(BlockError::InvalidSignature { index: 0, .. })));
		Ok(())
	}

	#[test]
	fn test_sign_and_decode_roundtrip() -> Result<(), BlockError> {
		let block = valid_block_builder().build()?.sign()?;
		let decoded = Block::try_from(block.to_bytes())?;
		assert_eq!(decoded.hash(), block.hash());
		assert_eq!(decoded.to_bytes(), block.to_bytes());
		Ok(())
	}

	#[test]
	fn test_unsigned_decode_rejects_signed_bytes() -> Result<(), BlockError> {
		let block = valid_block_builder().build()?.sign()?;
		let result = UnsignedBlock::try_from(block.to_bytes());
		assert!(matches!(result, Err(BlockError::RecalculatedBytesMismatch)));
		Ok(())
	}

	#[test]
	fn test_is_opening() -> Result<(), BlockError> {
		let unsigned = valid_block_builder().build()?;
		assert!(unsigned.data().is_opening());
		Ok(())
	}
}
