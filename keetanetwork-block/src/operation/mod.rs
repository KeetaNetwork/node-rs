//! Block operations: the nine supported operation types, their domain
//! models and validation rules.
//!
//! Each operation lives in its own module and implements [`BlockOperation`],
//! which ties a variant to its [`OperationType`] discriminant and its
//! context-aware validation. The [`Operation`] enum unifies them; its
//! per-variant `From`, [`Operation::operation_type`] and validation dispatch
//! are generated from a single variant list.

mod create_identifier;
mod manage_certificate;
mod modify_permissions;
mod receive;
mod send;
mod set_info;
mod set_rep;
mod token_admin_modify_balance;
mod token_admin_supply;

pub use create_identifier::{CreateIdentifier, IdentifierCreateArguments, MultisigCreateArguments};
pub use manage_certificate::{CertificateDer, CertificateOrHash, IntermediateCertificates, ManageCertificate};
pub use modify_permissions::{ModifyPermissions, ModifyPermissionsPrincipal};
pub use receive::Receive;
pub use send::Send;
pub use set_info::SetInfo;
pub use set_rep::SetRep;
pub use token_admin_modify_balance::TokenAdminModifyBalance;
pub use token_admin_supply::TokenAdminSupply;

use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_crypto::hash::BlockHash;
use num_bigint::BigInt;

use crate::error::BlockError;
use crate::validation::ValidationConfig;

/// How a value adjustment is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AdjustMethod {
	/// Add to the existing value
	Add = 0,
	/// Subtract from the existing value
	Subtract = 1,
	/// Replace the existing value
	Set = 2,
}

impl AdjustMethod {
	pub(crate) fn to_bigint(self) -> BigInt {
		BigInt::from(u8::from(self))
	}
}

impl From<AdjustMethod> for u8 {
	fn from(method: AdjustMethod) -> Self {
		method as u8
	}
}

impl TryFrom<u8> for AdjustMethod {
	type Error = BlockError;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(AdjustMethod::Add),
			1 => Ok(AdjustMethod::Subtract),
			2 => Ok(AdjustMethod::Set),
			_ => Err(BlockError::InvalidAdjustMethod),
		}
	}
}

impl TryFrom<&BigInt> for AdjustMethod {
	type Error = BlockError;

	fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
		u8::try_from(value)
			.map_err(|_| BlockError::InvalidAdjustMethod)
			.and_then(AdjustMethod::try_from)
	}
}

/// Operation type discriminants matching the transport context tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OperationType {
	/// Send tokens to an account
	Send = 0,
	/// Set the representative
	SetRep = 1,
	/// Set account information
	SetInfo = 2,
	/// Modify account permissions
	ModifyPermissions = 3,
	/// Create an identifier account
	CreateIdentifier = 4,
	/// Adjust token supply
	TokenAdminSupply = 5,
	/// Adjust a token balance
	TokenAdminModifyBalance = 6,
	/// Receive tokens
	Receive = 7,
	/// Manage X.509 certificates
	ManageCertificate = 8,
}

impl From<OperationType> for u8 {
	fn from(operation_type: OperationType) -> Self {
		operation_type as u8
	}
}

impl TryFrom<u8> for OperationType {
	type Error = BlockError;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(OperationType::Send),
			1 => Ok(OperationType::SetRep),
			2 => Ok(OperationType::SetInfo),
			3 => Ok(OperationType::ModifyPermissions),
			4 => Ok(OperationType::CreateIdentifier),
			5 => Ok(OperationType::TokenAdminSupply),
			6 => Ok(OperationType::TokenAdminModifyBalance),
			7 => Ok(OperationType::Receive),
			8 => Ok(OperationType::ManageCertificate),
			_ => Err(BlockError::InvalidOperationType),
		}
	}
}

/// Behavior common to every block operation variant.
///
/// Each operation declares its [`OperationType`] discriminant and validates
/// itself against the surrounding block via an [`OperationContext`]. The
/// `Into<Operation>` bound is the conversion into the unifying enum.
pub(crate) trait BlockOperation: Into<Operation> {
	/// The operation type discriminant for this variant.
	const TYPE: OperationType;

	/// Validate this operation within its block context.
	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError>;
}

/// Borrowed downcast from the unifying [`Operation`] enum to one variant.
pub(crate) trait FromOperationRef<'a>: Sized {
	/// Borrow `operation` as this variant, or `None` for any other variant.
	fn from_operation_ref(operation: &'a Operation) -> Option<Self>;
}

/// A block operation.
#[derive(Debug, Clone)]
pub enum Operation {
	/// Send tokens
	Send(Send),
	/// Set representative
	SetRep(SetRep),
	/// Set account info
	SetInfo(SetInfo),
	/// Modify permissions
	ModifyPermissions(ModifyPermissions),
	/// Create an identifier
	CreateIdentifier(CreateIdentifier),
	/// Adjust token supply
	TokenAdminSupply(TokenAdminSupply),
	/// Adjust a token balance
	TokenAdminModifyBalance(TokenAdminModifyBalance),
	/// Receive tokens
	Receive(Receive),
	/// Manage certificates
	ManageCertificate(ManageCertificate),
}

/// Generate the `From`, discriminant and validation dispatch for [`Operation`]
/// from a single variant list. Each variant name matches its inner struct.
macro_rules! dispatch_operations {
	($($variant:ident),+ $(,)?) => {
		$(
			impl From<$variant> for Operation {
				fn from(operation: $variant) -> Self {
					Operation::$variant(operation)
				}
			}

			impl<'a> FromOperationRef<'a> for &'a $variant {
				fn from_operation_ref(operation: &'a Operation) -> Option<Self> {
					match operation {
						Operation::$variant(inner) => Some(inner),
						_ => None,
					}
				}
			}
		)+

		impl Operation {
			/// The operation type discriminant.
			pub fn operation_type(&self) -> OperationType {
				match self {
					$( Operation::$variant(_) => <$variant as BlockOperation>::TYPE, )+
				}
			}

			/// Validate this operation within its block context.
			pub(crate) fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
				match self {
					$( Operation::$variant(operation) => operation.validate(ctx), )+
				}
			}
		}
	};
}

dispatch_operations!(
	Send,
	SetRep,
	SetInfo,
	ModifyPermissions,
	CreateIdentifier,
	TokenAdminSupply,
	TokenAdminModifyBalance,
	Receive,
	ManageCertificate,
);

/// Context shared by all operation validators.
pub(crate) struct OperationContext<'a> {
	/// Resolved validation config; `None` when the network is unknown
	/// (errors surface only where the reference implementation would
	/// consult the configuration).
	pub config: Option<&'a ValidationConfig>,
	/// The block account
	pub account: &'a GenericAccount,
	/// All operations of the block
	pub operations: &'a [Operation],
	/// The previous block hash
	pub previous: &'a BlockHash,
	/// The block date in Unix milliseconds
	pub date_ms: i64,
	/// Index of the operation being validated
	pub operation_index: usize,
}

impl<'a> OperationContext<'a> {
	/// Iterate over the block operations that are the concrete variant `T`.
	fn iter_type<T: 'a>(&self) -> impl Iterator<Item = &'a T>
	where
		&'a T: FromOperationRef<'a>,
	{
		self.operations
			.iter()
			.filter_map(<&'a T>::from_operation_ref)
	}

	fn config(&self) -> Result<&ValidationConfig, BlockError> {
		self.config.ok_or(BlockError::UnknownNetwork)
	}

	fn validate_numeric(&self, value: &BigInt) -> Result<(), BlockError> {
		if *value >= BigInt::ZERO {
			return Ok(());
		}

		self.config()?.validate_numeric_value(value, self.date_ms)
	}

	fn account_is_token(&self) -> bool {
		self.account.to_keypair_type() == KeyPairType::TOKEN
	}

	/// Require `token` to be a token identifier and validate `amount` against
	/// the numeric rules. Shared entry guard for the token-bearing operations.
	fn guard_token_amount(&self, token: &GenericAccount, amount: &BigInt) -> Result<(), BlockError> {
		require_token(token)?;
		self.validate_numeric(amount)
	}

	/// Reject the operation when the block account is itself a token.
	fn reject_token_account(&self) -> Result<(), BlockError> {
		if self.account_is_token() {
			return Err(BlockError::TokenOperationForbidden);
		}

		Ok(())
	}
}

/// Require the account to be a token identifier.
fn require_token(account: &GenericAccount) -> Result<(), BlockError> {
	if account.to_keypair_type() != KeyPairType::TOKEN {
		return Err(BlockError::TokenFieldNotToken);
	}

	Ok(())
}

/// Whether the account type can delegate voting weight via SET_REP.
fn can_delegate(key_type: KeyPairType) -> bool {
	if !key_type.is_identifier() {
		return true;
	}

	key_type == KeyPairType::STORAGE
}

#[cfg(test)]
pub(crate) mod harness {
	use alloc::string::{String, ToString};
	use alloc::vec::Vec;

	use keetanetwork_account::KeyPairType;
	use keetanetwork_crypto::hash::BlockHash;

	use crate::amount::Amount;
	use crate::error::BlockError;
	use crate::permissions::{BaseFlag, Permissions};
	use crate::signer::AccountRef;
	use crate::testing::{generate_ed25519_ref, generate_identifier_ref};
	use crate::validation::ValidationConfig;

	use super::{AdjustMethod, CertificateOrHash, Receive, Send, SetInfo};
	use super::{ManageCertificate, ModifyPermissions, ModifyPermissionsPrincipal, Operation, OperationContext};

	/// A date before the negative-amount cutoff.
	pub(crate) const PRE_CUTOFF_MS: i64 = 1_700_000_000_000;

	pub(crate) struct Harness {
		pub(crate) config: ValidationConfig,
		pub(crate) account: AccountRef,
		pub(crate) previous: BlockHash,
		pub(crate) operations: Vec<Operation>,
		pub(crate) date_ms: i64,
	}

	impl Harness {
		pub(crate) fn new(account: AccountRef) -> Self {
			let previous = account.to_opening_hash();
			Self {
				config: ValidationConfig::default(),
				account,
				previous,
				operations: Vec::new(),
				date_ms: PRE_CUTOFF_MS,
			}
		}

		pub(crate) fn validate(&self, operation: &Operation) -> Result<(), BlockError> {
			let ctx = OperationContext {
				config: Some(&self.config),
				account: &self.account,
				operations: &self.operations,
				previous: &self.previous,
				date_ms: self.date_ms,
				operation_index: 0,
			};
			operation.validate(&ctx)
		}
	}

	pub(crate) fn send(token: AccountRef, to: AccountRef) -> Send {
		Send { to, amount: Amount::from(1u64), token, external: None }
	}

	pub(crate) fn token(index: u32) -> AccountRef {
		generate_identifier_ref(1, KeyPairType::TOKEN, index)
	}

	pub(crate) fn receive(token: AccountRef, from: AccountRef) -> Receive {
		Receive { amount: Amount::from(1u64), token, from, exact: false, forward: None }
	}

	pub(crate) fn set_info() -> SetInfo {
		SetInfo {
			name: "MY_ACCOUNT".to_string(),
			description: "A description".to_string(),
			metadata: String::new(),
			default_permission: None,
		}
	}

	pub(crate) fn permissions(flags: &[BaseFlag], externals: &[u8]) -> Permissions {
		Permissions::from_flags(flags, externals).expect("test permission construction must succeed")
	}

	pub(crate) fn modify_permissions(permissions: Option<Permissions>) -> ModifyPermissions {
		ModifyPermissions {
			principal: ModifyPermissionsPrincipal::Account(generate_ed25519_ref(2)),
			method: AdjustMethod::Set,
			permissions,
			target: None,
		}
	}

	pub(crate) fn manage_certificate_subtract(hash_byte: u8) -> ManageCertificate {
		ManageCertificate {
			method: AdjustMethod::Subtract,
			certificate_or_hash: CertificateOrHash::Hash([hash_byte; 32]),
			intermediate_certificates: None,
		}
	}

	/// Run a table of validation cases. Each row pairs a label, a
	/// `(harness, operation)` setup and the expected [`Result`] pattern.
	macro_rules! assert_validation {
		($( $label:literal: $setup:expr => $expected:pat ),* $(,)?) => {{
			$( {
				let _case = $label;
				let (harness, operation) = $setup;
				assert!(matches!(harness.validate(&operation), $expected));
			} )*
		}};
	}

	pub(crate) use assert_validation;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::operation::harness::{send, token};
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_operation_type_roundtrip() -> Result<(), BlockError> {
		for tag in 0u8..=8 {
			let operation_type = OperationType::try_from(tag)?;
			assert_eq!(u8::from(operation_type), tag);
		}
		assert!(matches!(OperationType::try_from(9u8), Err(BlockError::InvalidOperationType)));
		Ok(())
	}

	#[test]
	fn test_adjust_method_roundtrip() -> Result<(), BlockError> {
		for tag in 0u8..=2 {
			let method = AdjustMethod::try_from(tag)?;
			assert_eq!(u8::from(method), tag);
		}
		assert!(matches!(AdjustMethod::try_from(3u8), Err(BlockError::InvalidAdjustMethod)));
		assert!(matches!(AdjustMethod::try_from(&BigInt::from(-1)), Err(BlockError::InvalidAdjustMethod)));
		Ok(())
	}

	#[test]
	fn test_operation_type_dispatch() {
		let operation: Operation = send(token(0), generate_ed25519_ref(2)).into();
		assert_eq!(operation.operation_type(), OperationType::Send);
	}
}
