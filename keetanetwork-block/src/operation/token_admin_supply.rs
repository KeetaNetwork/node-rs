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

	#[test]
	fn test_negative_supply_amount_allowed_pre_cutoff() {
		// Matches the TypeScript reference: negative amounts remain valid for
		// blocks dated before the numeric cutoff epoch.
		use crate::operation::harness::PRE_CUTOFF_MS;
		let mut harness = Harness::new(token(0));
		harness.date_ms = PRE_CUTOFF_MS;
		let operation = TokenAdminSupply {
			amount: Amount::from(-1i64),
			method: AdjustMethod::Add,
		};
		assert!(harness.validate(&operation.into()).is_ok());
	}

	#[test]
	fn test_negative_supply_amount_rejected_post_cutoff() {
		let mut harness = Harness::new(token(0));
		harness.date_ms = harness.config.numeric_cutoff_epoch_ms;
		let operation = TokenAdminSupply {
			amount: Amount::from(-1i64),
			method: AdjustMethod::Add,
		};
		assert!(matches!(
			harness.validate(&operation.into()),
			Err(BlockError::AmountBelowZero)
		));
	}
}
