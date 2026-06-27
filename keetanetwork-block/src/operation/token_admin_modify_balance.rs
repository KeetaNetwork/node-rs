//! TOKEN_ADMIN_MODIFY_BALANCE operation: adjust an account's token balance.

use crate::amount::Amount;
use crate::error::BlockError;
use crate::signer::AccountRef;

use super::{AdjustMethod, BlockOperation, OperationContext, OperationType};

/// TOKEN_ADMIN_MODIFY_BALANCE: adjust an account's token balance.
#[derive(Debug, Clone)]
pub struct TokenAdminModifyBalance {
	/// The token whose balance is adjusted
	pub token: AccountRef,
	/// Amount to adjust by
	pub amount: Amount,
	/// How the balance is adjusted
	pub method: AdjustMethod,
}

impl BlockOperation for TokenAdminModifyBalance {
	const TYPE: OperationType = OperationType::TokenAdminModifyBalance;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		ctx.guard_token_amount(&self.token, self.amount.as_bigint())?;
		ctx.reject_token_account()?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::operation::harness::{assert_validation, token, Harness};
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_modify_balance_validation() {
		assert_validation! {
			"rejects_non_token_field":
				(
					Harness::new(generate_ed25519_ref(1)),
					TokenAdminModifyBalance {
						token: generate_ed25519_ref(2),
						amount: Amount::from(1u64),
						method: AdjustMethod::Add,
					}
					.into(),
				) => Err(BlockError::TokenFieldNotToken),
			"rejects_token_account":
				(
					Harness::new(token(0)),
					TokenAdminModifyBalance {
						token: token(0),
						amount: Amount::from(1u64),
						method: AdjustMethod::Add,
					}
					.into(),
				) => Err(BlockError::TokenOperationForbidden),
		}
	}
}
