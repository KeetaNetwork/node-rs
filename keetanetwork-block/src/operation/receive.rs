//! RECEIVE operation: receive tokens from a send.

use keetanetwork_account::KeyPairType;

use crate::account_util::accounts_equal;
use crate::amount::Amount;
use crate::error::BlockError;
use crate::signer::AccountRef;

use super::{require_token, BlockOperation, OperationContext, OperationType};

/// RECEIVE: receive tokens from a send.
#[derive(Debug, Clone)]
pub struct Receive {
	/// Amount to receive
	pub amount: Amount,
	/// Token being received
	pub token: AccountRef,
	/// Account the tokens come from
	pub from: AccountRef,
	/// Whether the amount must match exactly
	pub exact: bool,
	/// Optional account to forward the funds to
	pub forward: Option<AccountRef>,
}

impl BlockOperation for Receive {
	const TYPE: OperationType = OperationType::Receive;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		require_token(&self.token)?;
		ctx.validate_numeric(self.amount.as_bigint())?;

		if ctx.account_is_token() {
			return Err(BlockError::TokenOperationForbidden);
		}

		if let Some(forward) = &self.forward {
			if accounts_equal(forward, ctx.account) {
				return Err(BlockError::ForwardToSelf);
			}

			if !self.exact {
				return Err(BlockError::ForwardRequiresExact);
			}

			if forward.to_keypair_type() == KeyPairType::TOKEN && !accounts_equal(forward, &self.token) {
				return Err(BlockError::TokenReceiveDiffers);
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::operation::harness::{assert_validation, receive, token, Harness};
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_receive_validation() {
		assert_validation! {
			"rejects_forward_to_self": {
				let account = generate_ed25519_ref(1);
				let mut operation = receive(token(0), generate_ed25519_ref(2));
				operation.exact = true;
				operation.forward = Some(account.clone());
				(Harness::new(account), operation.into())
			} => Err(BlockError::ForwardToSelf),
			"rejects_forward_without_exact": {
				let mut operation = receive(token(0), generate_ed25519_ref(2));
				operation.forward = Some(generate_ed25519_ref(3));
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::ForwardRequiresExact),
			"rejects_token_account":
				(Harness::new(token(0)), receive(token(0), generate_ed25519_ref(2)).into())
				=> Err(BlockError::TokenOperationForbidden),
			"rejects_token_forward_mismatch": {
				let mut operation = receive(token(0), generate_ed25519_ref(2));
				operation.exact = true;
				operation.forward = Some(token(1));
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::TokenReceiveDiffers),
		}
	}
}
