//! CREATE_IDENTIFIER operation: create a derived identifier account.

use alloc::vec::Vec;

use keetanetwork_account::KeyPairType;
use num_bigint::BigInt;

use crate::account_util::{accounts_equal, unique_account_count};
use crate::error::BlockError;
use crate::signer::AccountRef;

use super::{BlockOperation, OperationContext, OperationType};

/// Arguments for creating a multisig identifier.
#[derive(Debug, Clone)]
pub struct MultisigCreateArguments {
	/// The member signer accounts
	pub signers: Vec<AccountRef>,
	/// The number of signers required
	pub quorum: BigInt,
}

/// Arguments for CREATE_IDENTIFIER, keyed by identifier type.
#[derive(Debug, Clone)]
pub enum IdentifierCreateArguments {
	/// Multisig identifier arguments
	Multisig(MultisigCreateArguments),
}

impl From<MultisigCreateArguments> for IdentifierCreateArguments {
	fn from(arguments: MultisigCreateArguments) -> Self {
		IdentifierCreateArguments::Multisig(arguments)
	}
}

/// CREATE_IDENTIFIER: create a derived identifier account.
#[derive(Debug, Clone)]
pub struct CreateIdentifier {
	/// The identifier account being created
	pub identifier: AccountRef,
	/// Creation arguments (required for multisig identifiers)
	pub create_arguments: Option<IdentifierCreateArguments>,
}

impl BlockOperation for CreateIdentifier {
	const TYPE: OperationType = OperationType::CreateIdentifier;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		if ctx.account.to_keypair_type().is_identifier() {
			return Err(BlockError::TokenOperationForbidden);
		}

		let created_type = self.identifier.to_keypair_type();
		if !created_type.is_identifier() {
			return Err(BlockError::IdentifierInvalid);
		}

		// The reference treats a previous equal to the account opening
		// hash as an opening block when deriving identifiers.
		let block_hash = if *ctx.previous == ctx.account.to_opening_hash() {
			None
		} else {
			Some(ctx.previous)
		};

		let derived = ctx
			.account
			.generate_identifier(created_type, block_hash, ctx.operation_index as u32)?;

		if !accounts_equal(&derived, &self.identifier) {
			return Err(BlockError::IdentifierInvalid);
		}

		let requires_arguments = created_type == KeyPairType::MULTISIG;
		if self.create_arguments.is_some() != requires_arguments {
			return Err(BlockError::InvalidCreateIdentifierArguments);
		}

		if let Some(IdentifierCreateArguments::Multisig(arguments)) = &self.create_arguments {
			validate_multisig_arguments(arguments, created_type, ctx)?;
		}

		Ok(())
	}
}

/// Validate the arguments of a multisig CREATE_IDENTIFIER: the created type
/// must be multisig, the signer count must be permitted, every signer must be
/// a keyed account or nested multisig, signers must be unique, and the quorum
/// must fall within `1..=unique`.
fn validate_multisig_arguments(
	arguments: &MultisigCreateArguments,
	created_type: KeyPairType,
	ctx: &OperationContext<'_>,
) -> Result<(), BlockError> {
	if created_type != KeyPairType::MULTISIG {
		return Err(BlockError::InvalidCreateIdentifierArguments);
	}

	let signer_count = arguments.signers.len();

	ctx.config()?.validate_signer_count(signer_count as u64)?;

	for signer in &arguments.signers {
		let signer_type = signer.to_keypair_type();
		if !signer_type.supports_crypto() && signer_type != KeyPairType::MULTISIG {
			return Err(BlockError::InvalidCreateIdentifierArguments);
		}
	}

	let unique = unique_account_count(&arguments.signers);
	if unique != signer_count {
		return Err(BlockError::MultisigSignerDuplicate);
	}

	if arguments.quorum < BigInt::from(1u8) || arguments.quorum > BigInt::from(unique) {
		return Err(BlockError::MultisigQuorumInvalid);
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use alloc::vec;

	use super::*;
	use crate::operation::harness::{assert_validation, token, Harness};
	use crate::testing::{generate_ed25519_ref, generate_identifier_ref};

	#[test]
	fn test_create_arguments_from_multisig() {
		let arguments =
			IdentifierCreateArguments::from(MultisigCreateArguments { signers: Vec::new(), quorum: BigInt::from(1) });
		assert!(matches!(arguments, IdentifierCreateArguments::Multisig(_)));
	}

	#[test]
	fn test_create_identifier_validation() {
		assert_validation! {
			"rejects_keyed_identifier":
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier { identifier: generate_ed25519_ref(2), create_arguments: None }.into(),
				) => Err(BlockError::IdentifierInvalid),
			"rejects_wrong_derivation":
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier {
						identifier: generate_identifier_ref(1, KeyPairType::TOKEN, 5),
						create_arguments: None,
					}
					.into(),
				) => Err(BlockError::IdentifierInvalid),
			"rejects_arguments_for_token": {
				let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments {
					signers: vec![generate_ed25519_ref(2)],
					quorum: BigInt::from(1u8),
				});
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier { identifier: token(0), create_arguments: Some(arguments) }.into(),
				)
			} => Err(BlockError::InvalidCreateIdentifierArguments),
			"requires_arguments_for_multisig":
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier {
						identifier: generate_identifier_ref(1, KeyPairType::MULTISIG, 0),
						create_arguments: None,
					}
					.into(),
				) => Err(BlockError::InvalidCreateIdentifierArguments),
			"rejects_zero_quorum": {
				let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments {
					signers: vec![generate_ed25519_ref(2), generate_ed25519_ref(3)],
					quorum: BigInt::ZERO,
				});
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier {
						identifier: generate_identifier_ref(1, KeyPairType::MULTISIG, 0),
						create_arguments: Some(arguments),
					}
					.into(),
				)
			} => Err(BlockError::MultisigQuorumInvalid),
			"rejects_non_keyed_signer": {
				let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments {
					signers: vec![generate_ed25519_ref(2), token(0)],
					quorum: BigInt::from(1u8),
				});
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier {
						identifier: generate_identifier_ref(1, KeyPairType::MULTISIG, 0),
						create_arguments: Some(arguments),
					}
					.into(),
				)
			} => Err(BlockError::InvalidCreateIdentifierArguments),
			"rejects_duplicate_signers": {
				let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments {
					signers: vec![generate_ed25519_ref(2), generate_ed25519_ref(2)],
					quorum: BigInt::from(1u8),
				});
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier {
						identifier: generate_identifier_ref(1, KeyPairType::MULTISIG, 0),
						create_arguments: Some(arguments),
					}
					.into(),
				)
			} => Err(BlockError::MultisigSignerDuplicate),
			"accepts_matching_derivation":
				(
					Harness::new(generate_ed25519_ref(1)),
					CreateIdentifier { identifier: token(0), create_arguments: None }.into(),
				) => Ok(()),
		}
	}
}
