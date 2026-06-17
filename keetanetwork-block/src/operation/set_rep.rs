//! SET_REP operation: delegate voting weight to a representative.

use crate::error::BlockError;
use crate::signer::AccountRef;

use super::{can_delegate, BlockOperation, OperationContext, OperationType};

/// SET_REP: delegate voting weight to a representative.
#[derive(Debug, Clone)]
pub struct SetRep {
	/// The representative account
	pub to: AccountRef,
}

impl BlockOperation for SetRep {
	const TYPE: OperationType = OperationType::SetRep;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		if !can_delegate(ctx.account.to_keypair_type()) {
			return Err(BlockError::IdentifierDelegationForbidden);
		}

		if self.to.to_keypair_type().is_identifier() {
			return Err(BlockError::IdentifierDelegationForbidden);
		}

		let set_rep_count = ctx
			.operations
			.iter()
			.filter(|operation| operation.operation_type() == OperationType::SetRep)
			.count();
		if set_rep_count > 1 {
			return Err(BlockError::MultipleSetRep);
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use alloc::vec;

	use keetanetwork_account::KeyPairType;

	use super::*;
	use crate::operation::harness::{assert_validation, token, Harness};
	use crate::operation::Operation;
	use crate::testing::{generate_ed25519_ref, generate_identifier_ref};

	#[test]
	fn test_set_rep_validation() {
		assert_validation! {
			"rejects_token_account":
				(Harness::new(token(0)), SetRep { to: generate_ed25519_ref(2) }.into())
				=> Err(BlockError::IdentifierDelegationForbidden),
			"accepts_storage_account":
				(
					Harness::new(generate_identifier_ref(1, KeyPairType::STORAGE, 0)),
					SetRep { to: generate_ed25519_ref(2) }.into(),
				) => Ok(()),
			"rejects_identifier_representative":
				(Harness::new(generate_ed25519_ref(1)), SetRep { to: token(0) }.into())
				=> Err(BlockError::IdentifierDelegationForbidden),
			"rejects_multiple_per_block": {
				let mut harness = Harness::new(generate_ed25519_ref(1));
				let operation: Operation = SetRep { to: generate_ed25519_ref(2) }.into();
				harness.operations = vec![operation.clone(), SetRep { to: generate_ed25519_ref(3) }.into()];
				(harness, operation)
			} => Err(BlockError::MultipleSetRep),
		}
	}
}
