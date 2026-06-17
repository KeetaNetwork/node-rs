//! SEND operation: transfer tokens to another account.

use alloc::string::String;

use keetanetwork_account::KeyPairType;

use crate::account_util::accounts_equal;
use crate::amount::Amount;
use crate::error::BlockError;
use crate::signer::AccountRef;
use crate::validation::TextRuleViolation;

use super::{require_token, BlockOperation, OperationContext, OperationType};

/// SEND: transfer tokens to another account.
#[derive(Debug, Clone)]
pub struct Send {
	/// Destination account
	pub to: AccountRef,
	/// Amount to send
	pub amount: Amount,
	/// Token being sent
	pub token: AccountRef,
	/// Optional external reference data
	pub external: Option<String>,
}

impl BlockOperation for Send {
	const TYPE: OperationType = OperationType::Send;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		require_token(&self.token)?;
		ctx.validate_numeric(self.amount.as_bigint())?;

		if ctx.account_is_token() && !accounts_equal(&self.token, ctx.account) {
			return Err(BlockError::TokenOperationForbidden);
		}

		if self.to.to_keypair_type() == KeyPairType::TOKEN && !accounts_equal(&self.to, &self.token) {
			return Err(BlockError::TokenReceiveDiffers);
		}

		let config = ctx.config()?;
		match &self.external {
			Some(external) if !external.is_empty() => match config.external.check(external) {
				Err(TextRuleViolation::TooLong { length, max }) => {
					return Err(BlockError::ExternalTooLong { length, max });
				}
				Err(TextRuleViolation::InvalidCharacter) => return Err(BlockError::ExternalInvalid),
				Ok(()) => {}
			},
			_ => {
				if !config.external.can_be_empty {
					return Err(BlockError::ExternalMissing);
				}
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;

	use super::*;
	use crate::operation::harness::{assert_validation, send, token, Harness};
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_send_validation() {
		assert_validation! {
			"rejects_non_token_token_field":
				(Harness::new(generate_ed25519_ref(1)), send(generate_ed25519_ref(2), generate_ed25519_ref(3)).into())
				=> Err(BlockError::TokenFieldNotToken),
			"rejects_token_account_sending_other_token":
				(Harness::new(token(0)), send(token(1), generate_ed25519_ref(2)).into())
				=> Err(BlockError::TokenOperationForbidden),
			"rejects_token_destination_mismatch":
				(Harness::new(generate_ed25519_ref(1)), send(token(0), token(1)).into())
				=> Err(BlockError::TokenReceiveDiffers),
			"rejects_external_too_long": {
				let mut operation = send(token(0), generate_ed25519_ref(2));
				operation.external = Some("A".repeat(1025));
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::ExternalTooLong { .. }),
			"rejects_external_invalid_character": {
				let mut operation = send(token(0), generate_ed25519_ref(2));
				operation.external = Some("bad☃".to_string());
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::ExternalInvalid),
			"rejects_negative_amount_after_cutoff": {
				let mut harness = Harness::new(generate_ed25519_ref(1));
				harness.date_ms = harness.config.numeric_cutoff_epoch_ms;
				let mut operation = send(token(0), generate_ed25519_ref(2));
				operation.amount = Amount::from(-1i64);
				(harness, operation.into())
			} => Err(BlockError::AmountBelowZero),
			"accepts_valid_operation":
				(Harness::new(generate_ed25519_ref(1)), send(token(0), generate_ed25519_ref(2)).into())
				=> Ok(()),
		}
	}
}
