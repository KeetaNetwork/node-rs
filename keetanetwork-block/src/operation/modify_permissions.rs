//! MODIFY_PERMISSIONS operation: adjust permissions for a principal.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

use crate::error::BlockError;
use crate::permissions::{BaseFlag, GroupKind, Permissions};
use crate::signer::AccountRef;

use super::{AdjustMethod, BlockOperation, Operation, OperationContext, OperationType};

/// The principal of a MODIFY_PERMISSIONS operation.
#[derive(Debug, Clone)]
pub enum ModifyPermissionsPrincipal {
	/// A direct account principal
	Account(AccountRef),
	/// A certificate-based principal
	Certificate {
		/// Hash of the certificate
		hash: [u8; 32],
		/// Account the certificate was issued to
		account: AccountRef,
	},
}

impl ModifyPermissionsPrincipal {
	fn dedup_key(&self) -> String {
		match self {
			ModifyPermissionsPrincipal::Account(account) => account.to_string(),
			ModifyPermissionsPrincipal::Certificate { hash, account } => {
				format!("cert:{}:{}", hex::encode_upper(hash), account)
			}
		}
	}
}

impl From<AccountRef> for ModifyPermissionsPrincipal {
	fn from(account: AccountRef) -> Self {
		ModifyPermissionsPrincipal::Account(account)
	}
}

/// MODIFY_PERMISSIONS: adjust permissions for a principal.
#[derive(Debug, Clone)]
pub struct ModifyPermissions {
	/// Who receives the permission change
	pub principal: ModifyPermissionsPrincipal,
	/// How the permissions are applied
	pub method: AdjustMethod,
	/// The permissions to apply (`None` clears, requiring SET)
	pub permissions: Option<Permissions>,
	/// Optional target account the permissions are scoped to
	pub target: Option<AccountRef>,
}

impl ModifyPermissions {
	/// Validate a non-empty permission payload against the issuing account,
	/// principal, and target.
	fn validate_payload(&self, ctx: &OperationContext<'_>, permissions: &Permissions) -> Result<(), BlockError> {
		permissions.validate(ctx.config()?.max_external_offset)?;

		if !ctx.account.to_keypair_type().is_identifier() && permissions.has(&[BaseFlag::Owner], &[]) {
			return Err(BlockError::IdentifierAccountRequired);
		}

		let base = permissions.base();

		match &self.principal {
			ModifyPermissionsPrincipal::Account(principal) => {
				if !base.check_account_matches_group(GroupKind::Principal, Some(principal)) {
					return Err(BlockError::PermissionsInvalidPrincipal);
				}
			}
			ModifyPermissionsPrincipal::Certificate { .. } => {
				if !base.is_valid_for_default() {
					return Err(BlockError::PermissionsInvalidDefault);
				}
			}
		}

		if let Some(target) = &self.target {
			if !base.check_account_matches_group(GroupKind::Target, Some(target)) {
				return Err(BlockError::PermissionsInvalidTarget);
			}
		}

		if !base.check_account_matches_group(GroupKind::Entity, Some(ctx.account)) {
			return Err(BlockError::PermissionsInvalidEntity);
		}

		if self.target.is_some() && permissions.has(&[BaseFlag::Admin], &[]) {
			return Err(BlockError::AdminWithTarget);
		}
		if self.method != AdjustMethod::Set && !permissions.can_use_delegation() {
			return Err(BlockError::DelegationForbidden);
		}

		Ok(())
	}

	/// Reject a SET that follows an earlier modification for the same
	/// principal/target pair within the same block.
	fn reject_duplicate_set(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		let mut found: BTreeMap<String, BTreeMap<String, AdjustMethod>> = BTreeMap::new();
		for operation in ctx.operations {
			let Operation::ModifyPermissions(other) = operation else {
				continue;
			};

			let principal_key = other.principal.dedup_key();
			let target_key = match &other.target {
				Some(target) => target.to_string(),
				None => ctx.account.to_string(),
			};

			let targets = found.entry(principal_key).or_default();
			let previous = targets.insert(target_key, other.method);

			if previous.is_some() && other.method == AdjustMethod::Set {
				return Err(BlockError::DuplicatePermissionModification);
			}
		}

		Ok(())
	}
}

impl BlockOperation for ModifyPermissions {
	const TYPE: OperationType = OperationType::ModifyPermissions;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		match &self.permissions {
			None if self.method != AdjustMethod::Set => return Err(BlockError::PermissionsRequireSet),
			None => {}
			Some(permissions) => self.validate_payload(ctx, permissions)?,
		}

		self.reject_duplicate_set(ctx)
	}
}

#[cfg(test)]
mod tests {
	use alloc::vec;

	use super::*;
	use crate::operation::harness::{assert_validation, modify_permissions, permissions, token, Harness};
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_principal_from_account() {
		let principal = ModifyPermissionsPrincipal::from(generate_ed25519_ref(1));
		assert!(matches!(principal, ModifyPermissionsPrincipal::Account(_)));
	}

	#[test]
	fn test_modify_permissions_validation() {
		assert_validation! {
			"clear_requires_set": {
				let mut operation = modify_permissions(None);
				operation.method = AdjustMethod::Add;
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::PermissionsRequireSet),
			"rejects_target_for_targetless_flags": {
				let mut operation =
					modify_permissions(Some(permissions(&[BaseFlag::Admin], &[])));
				operation.target = Some(token(0));
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::PermissionsInvalidTarget),
			"rejects_delegated_adjust": {
				let mut operation = modify_permissions(Some(permissions(
					&[BaseFlag::PermissionDelegateAdd],
					&[],
				)));
				operation.method = AdjustMethod::Add;
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::DelegationForbidden),
			"rejects_duplicate_set": {
				let mut harness = Harness::new(generate_ed25519_ref(1));
				let operation: Operation =
					modify_permissions(Some(permissions(&[BaseFlag::Access], &[]))).into();
				harness.operations = vec![operation.clone(), operation.clone()];
				(harness, operation)
			} => Err(BlockError::DuplicatePermissionModification),
			"accepts_valid_set": {
				let operation = modify_permissions(Some(permissions(
					&[BaseFlag::Access, BaseFlag::UpdateInfo],
					&[],
				)));
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Ok(()),
		}
	}
}
