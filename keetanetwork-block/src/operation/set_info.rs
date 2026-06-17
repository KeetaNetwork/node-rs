//! SET_INFO operation: set account name, description and metadata.

use alloc::string::String;

use num_bigint::BigInt;

use crate::error::{BlockError, InfoField};
use crate::permissions::{GroupKind, Permissions};

use super::{BlockOperation, OperationContext, OperationType};

/// SET_INFO: set account name, description and metadata.
#[derive(Debug, Clone)]
pub struct SetInfo {
	/// Account name
	pub name: String,
	/// Account description
	pub description: String,
	/// Account metadata
	pub metadata: String,
	/// Default permissions (required for identifier accounts)
	pub default_permission: Option<Permissions>,
}

impl BlockOperation for SetInfo {
	const TYPE: OperationType = OperationType::SetInfo;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		let config = ctx.config()?;

		let fields = [
			(InfoField::Name, &self.name, &config.name),
			(InfoField::Description, &self.description, &config.description),
			(InfoField::Metadata, &self.metadata, &config.metadata),
		];
		for (field, value, rule) in fields {
			if !rule.is_valid(value) {
				return Err(BlockError::InfoFieldInvalid { field });
			}
		}

		if ctx.account.to_keypair_type().is_identifier() {
			let Some(default_permission) = &self.default_permission else {
				return Err(BlockError::DefaultPermissionRequired);
			};

			if *default_permission.external().as_bigint() != BigInt::ZERO {
				return Err(BlockError::PermissionsExternalDefaultForbidden);
			}

			if !default_permission.base().is_valid_for_default() {
				return Err(BlockError::PermissionsInvalidDefault);
			}

			if !default_permission
				.base()
				.check_account_matches_group(GroupKind::Entity, Some(ctx.account))
			{
				return Err(BlockError::PermissionsInvalidEntity);
			}
		} else if self.default_permission.is_some() {
			return Err(BlockError::IdentifierAccountRequired);
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;

	use super::*;
	use crate::operation::harness::{assert_validation, permissions, set_info, token, Harness};
	use crate::permissions::BaseFlag;
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_set_info_validation() {
		assert_validation! {
			"rejects_invalid_name": {
				let mut operation = set_info();
				operation.name = "lower case".to_string();
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::InfoFieldInvalid { field: InfoField::Name }),
			"rejects_default_permission_on_keyed_account": {
				let mut operation = set_info();
				operation.default_permission = Some(permissions(&[BaseFlag::Access], &[]));
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::IdentifierAccountRequired),
			"requires_default_permission_on_identifier":
				(Harness::new(token(0)), set_info().into())
				=> Err(BlockError::DefaultPermissionRequired),
			"rejects_external_default_permission": {
				let mut operation = set_info();
				operation.default_permission = Some(permissions(&[BaseFlag::Access], &[3]));
				(Harness::new(token(0)), operation.into())
			} => Err(BlockError::PermissionsExternalDefaultForbidden),
			"rejects_non_default_flags": {
				let mut operation = set_info();
				operation.default_permission =
					Some(permissions(&[BaseFlag::UpdateInfo], &[]));
				(Harness::new(token(0)), operation.into())
			} => Err(BlockError::PermissionsInvalidDefault),
		}
	}
}
