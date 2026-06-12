//! Fluent builder for unsigned blocks.

use keetanetwork_crypto::hash::BlockHash;
use num_bigint::BigInt;

use crate::block::{BlockData, BlockPurpose, BlockVersion, UnsignedBlock};
use crate::error::{BlockError, BlockField};
use crate::operation::Operation;
use crate::signer::{AccountRef, Signer};
use crate::time::BlockTime;

/// Previous-block reference accepted by the builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Previous {
	/// An explicit previous block hash
	Hash(BlockHash),
	/// No previous block: the account opening hash is used
	Opening,
}

/// Builds an [`UnsignedBlock`] with sensible defaults: version V2, generic
/// purpose, current time, signer defaulting to the account.
#[derive(Debug, Clone, Default)]
pub struct BlockBuilder {
	version: Option<BlockVersion>,
	purpose: Option<BlockPurpose>,
	network: Option<BigInt>,
	subnet: Option<BigInt>,
	idempotent: Option<Vec<u8>>,
	date: Option<BlockTime>,
	account: Option<AccountRef>,
	signer: Option<Signer>,
	previous: Option<Previous>,
	operations: Vec<Operation>,
}

impl BlockBuilder {
	/// Set the block version (default: V2).
	pub fn with_version(mut self, version: BlockVersion) -> Self {
		self.version = Some(version);
		self
	}

	/// Set the block purpose (default: generic).
	pub fn with_purpose(mut self, purpose: BlockPurpose) -> Self {
		self.purpose = Some(purpose);
		self
	}

	/// Set the network identifier (required).
	pub fn with_network(mut self, network: impl Into<BigInt>) -> Self {
		self.network = Some(network.into());
		self
	}

	/// Set the subnet identifier.
	pub fn with_subnet(mut self, subnet: impl Into<BigInt>) -> Self {
		self.subnet = Some(subnet.into());
		self
	}

	/// Set the idempotent key.
	pub fn with_idempotent(mut self, idempotent: impl Into<Vec<u8>>) -> Self {
		self.idempotent = Some(idempotent.into());
		self
	}

	/// Set the block date (default: now).
	pub fn with_date(mut self, date: BlockTime) -> Self {
		self.date = Some(date);
		self
	}

	/// Set the block account (required).
	pub fn with_account(mut self, account: impl Into<AccountRef>) -> Self {
		self.account = Some(account.into());
		self
	}

	/// Set the signer field (default: the block account).
	pub fn with_signer(mut self, signer: impl Into<Signer>) -> Self {
		self.signer = Some(signer.into());
		self
	}

	/// Set the previous block hash (required unless [`Self::as_opening`]).
	pub fn with_previous(mut self, previous: BlockHash) -> Self {
		self.previous = Some(Previous::Hash(previous));
		self
	}

	/// Mark this as the account opening block (previous becomes the
	/// account opening hash).
	pub fn as_opening(mut self) -> Self {
		self.previous = Some(Previous::Opening);
		self
	}

	/// Append an operation.
	pub fn with_operation(mut self, operation: impl Into<Operation>) -> Self {
		self.operations.push(operation.into());
		self
	}

	/// Append multiple operations.
	pub fn with_operations(mut self, operations: impl IntoIterator<Item = Operation>) -> Self {
		self.operations.extend(operations);
		self
	}

	/// Build and validate the unsigned block.
	pub fn build(self) -> Result<UnsignedBlock, BlockError> {
		let account = self
			.account
			.ok_or(BlockError::MissingField { field: BlockField::Account })?;
		let network = self
			.network
			.ok_or(BlockError::MissingField { field: BlockField::Network })?;
		let previous = self
			.previous
			.ok_or(BlockError::MissingField { field: BlockField::Previous })?;

		let previous = match previous {
			Previous::Hash(hash) => hash,
			Previous::Opening => account.to_opening_hash(),
		};

		let signer = match self.signer {
			Some(signer) => signer,
			None => Signer::Single(account.clone()),
		};

		let date = match self.date {
			Some(date) => date,
			None => BlockTime::now(),
		};

		let data = BlockData {
			version: self.version.unwrap_or(BlockVersion::V2),
			purpose: self.purpose.unwrap_or(BlockPurpose::Generic),
			network,
			subnet: self.subnet,
			idempotent: self.idempotent,
			date,
			account,
			signer,
			previous,
			operations: self.operations,
		};

		data.try_into()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_account::KeyPairType;

	use crate::amount::Amount;
	use crate::operation::Send;
	use crate::test_util::{ed25519, identifier};

	fn send() -> Send {
		Send { to: ed25519(2), amount: Amount::from(1u64), token: identifier(1, KeyPairType::TOKEN, 0), external: None }
	}

	fn valid_builder() -> BlockBuilder {
		BlockBuilder::default()
			.with_network(0u8)
			.with_account(ed25519(1))
			.as_opening()
			.with_operation(send())
	}

	#[test]
	fn test_missing_account_rejected() {
		let result = BlockBuilder::default()
			.with_network(0u8)
			.as_opening()
			.build();
		assert!(matches!(result, Err(BlockError::MissingField { field: BlockField::Account })));
	}

	#[test]
	fn test_missing_network_rejected() {
		let result = BlockBuilder::default()
			.with_account(ed25519(1))
			.as_opening()
			.build();
		assert!(matches!(result, Err(BlockError::MissingField { field: BlockField::Network })));
	}

	#[test]
	fn test_missing_previous_rejected() {
		let result = BlockBuilder::default()
			.with_network(0u8)
			.with_account(ed25519(1))
			.build();
		assert!(matches!(result, Err(BlockError::MissingField { field: BlockField::Previous })));
	}

	#[test]
	fn test_defaults() {
		let unsigned = valid_builder().build().unwrap();
		let data = unsigned.data();
		assert_eq!(data.version(), BlockVersion::V2);
		assert_eq!(data.purpose(), BlockPurpose::Generic);
		assert_eq!(*data.previous(), data.account_opening_hash());
		assert!(matches!(data.signer(), Signer::Single(signer) if signer.to_string() == data.account().to_string()));
	}

	#[test]
	fn test_explicit_previous() {
		let previous = BlockHash::from([0x11u8; 32]);
		let unsigned = valid_builder().with_previous(previous).build().unwrap();
		assert_eq!(*unsigned.data().previous(), previous);
	}
}
