//! TOKEN_ADMIN_SUPPLY operation: adjust the supply of a token.

use crate::amount::Amount;
use crate::error::BlockError;

use super::{AdjustMethod, BlockOperation, OperationContext, OperationType};

/// TOKEN_ADMIN_SUPPLY: adjust the supply of a token.
#[derive(Debug, Clone)]
pub struct TokenAdminSupply {
	/// Amount to adjust by
	pub amount: Amount,
	/// Add or Subtract (SET is forbidden)
	pub method: AdjustMethod,
}

impl BlockOperation for TokenAdminSupply {
	const TYPE: OperationType = OperationType::TokenAdminSupply;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		if self.method == AdjustMethod::Set {
			return Err(BlockError::AdjustMethodSetForbidden);
		}

		ctx.validate_numeric(self.amount.as_bigint())?;

		if !ctx.account_is_token() {
			return Err(BlockError::TokenAccountRequired);
		}

		ctx.config()?.validate_supply(self.amount.as_bigint())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::operation::harness::{assert_validation, token, Harness};
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_token_admin_supply_validation() {
		assert_validation! {
			"rejects_set_method":
				(
					Harness::new(token(0)),
					TokenAdminSupply { amount: Amount::from(1u64), method: AdjustMethod::Set }.into(),
				) => Err(BlockError::AdjustMethodSetForbidden),
			"requires_token_account":
				(
					Harness::new(generate_ed25519_ref(1)),
					TokenAdminSupply { amount: Amount::from(1u64), method: AdjustMethod::Add }.into(),
				) => Err(BlockError::TokenAccountRequired),
			"rejects_excess_supply": {
				let harness = Harness::new(token(0));
				let over = harness.config.max_supply.clone() + 1;
				(
					harness,
					TokenAdminSupply { amount: Amount::from(over), method: AdjustMethod::Add }.into(),
				)
			} => Err(BlockError::SupplyInvalid),
		}
	}
}
