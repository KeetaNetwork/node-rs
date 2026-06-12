//! Account permissions: base flags, external offsets and group rules.

use keetanetwork_account::GenericAccount;
use num_bigint::BigInt;
use num_traits::Zero;

use crate::error::BlockError;

/// Well-known base permission flags and their bit offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BaseFlag {
	/// Account has access
	Access = 0,
	/// Account is an owner
	Owner = 1,
	/// Account is an administrator
	Admin = 2,
	/// Account can update info
	UpdateInfo = 3,
	/// Account can send on behalf of the entity
	SendOnBehalf = 4,
	/// Account can create tokens
	TokenAdminCreate = 5,
	/// Account can modify token supply
	TokenAdminSupply = 6,
	/// Account can modify token balances
	TokenAdminModifyBalance = 7,
	/// Account can create storage accounts
	StorageCreate = 8,
	/// Storage account can hold the principal token
	StorageCanHold = 9,
	/// Account can deposit into the storage account
	StorageDeposit = 10,
	/// Account can delegate permission additions
	PermissionDelegateAdd = 11,
	/// Account can delegate permission removals
	PermissionDelegateRemove = 12,
	/// Account can manage certificates
	ManageCertificate = 13,
	/// Account is a multisig signer
	MultisigSigner = 14,
}

/// All base flags in offset order.
const ALL_BASE_FLAGS: [BaseFlag; 15] = [
	BaseFlag::Access,
	BaseFlag::Owner,
	BaseFlag::Admin,
	BaseFlag::UpdateInfo,
	BaseFlag::SendOnBehalf,
	BaseFlag::TokenAdminCreate,
	BaseFlag::TokenAdminSupply,
	BaseFlag::TokenAdminModifyBalance,
	BaseFlag::StorageCreate,
	BaseFlag::StorageCanHold,
	BaseFlag::StorageDeposit,
	BaseFlag::PermissionDelegateAdd,
	BaseFlag::PermissionDelegateRemove,
	BaseFlag::ManageCertificate,
	BaseFlag::MultisigSigner,
];

/// Account groups a permission flag may be associated with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionGroup {
	/// Never matches any account
	Never,
	/// Matches any account
	Any,
	/// Matches keyed (non-identifier) accounts and multisig addresses
	NonIdentifier,
	/// Matches network identifiers
	Network,
	/// Matches token identifiers
	Token,
	/// Matches storage identifiers
	Storage,
	/// Matches keyed accounts or multisig addresses
	NonIdentifierOrMultisig,
	/// Matches multisig addresses
	Multisig,
}

/// Which group constraint of a flag rule is being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
	/// The account the block operates on
	Entity,
	/// The account receiving the permissions
	Principal,
	/// The optional target account
	Target,
}

struct FlagRule {
	can_be_default: bool,
	entity: PermissionGroup,
	principal: PermissionGroup,
	target: PermissionGroup,
}

impl FlagRule {
	fn group(&self, kind: GroupKind) -> PermissionGroup {
		match kind {
			GroupKind::Entity => self.entity,
			GroupKind::Principal => self.principal,
			GroupKind::Target => self.target,
		}
	}
}

const fn rule_for(flag: BaseFlag) -> FlagRule {
	match flag {
		BaseFlag::Access => FlagRule {
			can_be_default: true,
			entity: PermissionGroup::Any,
			principal: PermissionGroup::Any,
			target: PermissionGroup::Any,
		},
		BaseFlag::Owner | BaseFlag::Admin | BaseFlag::UpdateInfo => FlagRule {
			can_be_default: false,
			entity: PermissionGroup::Any,
			principal: PermissionGroup::NonIdentifier,
			target: PermissionGroup::Never,
		},
		BaseFlag::SendOnBehalf => FlagRule {
			can_be_default: false,
			entity: PermissionGroup::Any,
			principal: PermissionGroup::NonIdentifier,
			target: PermissionGroup::Token,
		},
		BaseFlag::StorageCreate | BaseFlag::TokenAdminCreate => FlagRule {
			can_be_default: true,
			entity: PermissionGroup::Network,
			principal: PermissionGroup::NonIdentifier,
			target: PermissionGroup::Never,
		},
		BaseFlag::StorageCanHold => FlagRule {
			can_be_default: true,
			entity: PermissionGroup::Storage,
			principal: PermissionGroup::Token,
			target: PermissionGroup::Never,
		},
		BaseFlag::StorageDeposit => FlagRule {
			can_be_default: true,
			entity: PermissionGroup::Storage,
			principal: PermissionGroup::Any,
			target: PermissionGroup::Token,
		},
		BaseFlag::TokenAdminSupply => FlagRule {
			can_be_default: false,
			entity: PermissionGroup::Token,
			principal: PermissionGroup::NonIdentifier,
			target: PermissionGroup::Never,
		},
		BaseFlag::TokenAdminModifyBalance => FlagRule {
			can_be_default: false,
			entity: PermissionGroup::Token,
			principal: PermissionGroup::NonIdentifier,
			target: PermissionGroup::Any,
		},
		BaseFlag::PermissionDelegateAdd | BaseFlag::PermissionDelegateRemove => FlagRule {
			can_be_default: false,
			entity: PermissionGroup::Any,
			principal: PermissionGroup::NonIdentifier,
			target: PermissionGroup::Any,
		},
		BaseFlag::ManageCertificate => FlagRule {
			can_be_default: true,
			entity: PermissionGroup::Any,
			principal: PermissionGroup::Any,
			target: PermissionGroup::Never,
		},
		BaseFlag::MultisigSigner => FlagRule {
			can_be_default: false,
			entity: PermissionGroup::Multisig,
			principal: PermissionGroup::NonIdentifierOrMultisig,
			target: PermissionGroup::Never,
		},
	}
}

fn bit_set(bits: &BigInt, offset: u8) -> bool {
	!((bits & (BigInt::from(1) << offset)).is_zero())
}

fn account_matches_group(group: PermissionGroup, account: &GenericAccount) -> bool {
	match group {
		PermissionGroup::Any => true,
		PermissionGroup::Never => false,
		PermissionGroup::NonIdentifier | PermissionGroup::NonIdentifierOrMultisig => {
			!account.to_keypair_type().is_identifier() || matches!(account, GenericAccount::Multisig(_))
		}
		PermissionGroup::Network => matches!(account, GenericAccount::Network(_)),
		PermissionGroup::Token => matches!(account, GenericAccount::Token(_)),
		PermissionGroup::Storage => matches!(account, GenericAccount::Storage(_)),
		PermissionGroup::Multisig => matches!(account, GenericAccount::Multisig(_)),
	}
}

/// The normalized set of base permission flags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BaseSet {
	bits: BigInt,
	flags: Vec<BaseFlag>,
}

impl BaseSet {
	/// Construct from flags.
	pub fn from_flags(flags: &[BaseFlag]) -> Result<Self, BlockError> {
		let mut bits = BigInt::ZERO;
		for flag in flags {
			bits |= BigInt::from(1) << (*flag as u8);
		}
		Self::try_from(bits)
	}

	/// The raw bitfield, including any unknown high bits.
	pub fn as_bigint(&self) -> &BigInt {
		&self.bits
	}

	/// The normalized flags present in this set.
	pub fn flags(&self) -> &[BaseFlag] {
		&self.flags
	}

	/// Whether all the given flags are present.
	pub fn has_flags(&self, flags: &[BaseFlag]) -> bool {
		flags.iter().all(|flag| self.flags.contains(flag))
	}

	/// Whether this set may be used as default permissions.
	pub fn is_valid_for_default(&self) -> bool {
		self.flags.iter().all(|flag| rule_for(*flag).can_be_default)
	}

	/// Resolve the single permission group for the given rule kind.
	fn flag_group(&self, kind: GroupKind) -> Result<PermissionGroup, BlockError> {
		compute_flag_group(kind, &self.flags)
	}

	/// Whether the account (or its absence) satisfies the group constraint
	/// of this flag set for the given rule kind.
	pub fn check_account_matches_group(&self, kind: GroupKind, account: Option<&GenericAccount>) -> bool {
		let Ok(group) = self.flag_group(kind) else {
			return false;
		};

		let Some(account) = account else {
			if kind == GroupKind::Target {
				return true;
			}

			return group == PermissionGroup::Never;
		};

		account_matches_group(group, account)
	}
}

fn compute_flag_group(kind: GroupKind, flags: &[BaseFlag]) -> Result<PermissionGroup, BlockError> {
	let mut final_group = PermissionGroup::Any;

	for flag in flags {
		let found = rule_for(*flag).group(kind);

		if found == PermissionGroup::Any || found == final_group {
			continue;
		}

		if found == PermissionGroup::Never {
			return Ok(found);
		}

		if final_group == PermissionGroup::Any {
			final_group = found;
			continue;
		}

		return Err(BlockError::PermissionsCannotMix);
	}

	Ok(final_group)
}

impl TryFrom<BigInt> for BaseSet {
	type Error = BlockError;

	fn try_from(bits: BigInt) -> Result<Self, Self::Error> {
		let raw_flags: Vec<BaseFlag> = ALL_BASE_FLAGS
			.iter()
			.copied()
			.filter(|flag| bit_set(&bits, *flag as u8))
			.collect();

		compute_flag_group(GroupKind::Entity, &raw_flags)?;
		compute_flag_group(GroupKind::Principal, &raw_flags)?;
		compute_flag_group(GroupKind::Target, &raw_flags)?;

		// OWNER and ADMIN override all other flags; any non-empty set
		// implies ACCESS.
		let mut flags = raw_flags;
		if flags.contains(&BaseFlag::Owner) {
			flags = vec![BaseFlag::Owner];
		}
		if flags.contains(&BaseFlag::Admin) {
			flags = vec![BaseFlag::Admin];
		}
		if !flags.is_empty() && !flags.contains(&BaseFlag::Access) {
			flags.push(BaseFlag::Access);
		}

		// Rewrite the known offsets while preserving unknown high bits.
		let mut normalized = bits;
		for flag in ALL_BASE_FLAGS {
			let mask = BigInt::from(1) << (flag as u8);
			if flags.contains(&flag) {
				normalized |= mask;
			} else if bit_set(&normalized, flag as u8) {
				normalized ^= mask;
			}
		}

		Ok(Self { bits: normalized, flags })
	}
}

/// External (application-defined) permission offsets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalSet {
	bits: BigInt,
}

impl ExternalSet {
	/// The raw bitfield.
	pub fn as_bigint(&self) -> &BigInt {
		&self.bits
	}

	/// Whether the given offset is set.
	pub fn has_offset(&self, offset: u8) -> bool {
		bit_set(&self.bits, offset)
	}

	/// The bitfield size as defined by the reference implementation
	/// (the length of the binary string representation).
	fn size(&self) -> u64 {
		self.bits.to_str_radix(2).len() as u64
	}

	/// Validate the bitfield against the maximum external offset.
	pub fn validate(&self, max_external_offset: u64) -> Result<(), BlockError> {
		let size = self.size();
		if size >= max_external_offset {
			return Err(BlockError::PermissionsExternalOffsetTooLarge { size, max: max_external_offset });
		}

		Ok(())
	}
}

impl From<BigInt> for ExternalSet {
	fn from(bits: BigInt) -> Self {
		Self { bits }
	}
}

/// A base and external permission set pair.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Permissions {
	base: BaseSet,
	external: ExternalSet,
}

impl Permissions {
	/// Construct from raw base and external bitfields.
	pub fn from_bigints(base: BigInt, external: BigInt) -> Result<Self, BlockError> {
		Ok(Self { base: BaseSet::try_from(base)?, external: ExternalSet::from(external) })
	}

	/// Construct from base flags and external offsets.
	pub fn from_flags(flags: &[BaseFlag], external_offsets: &[u8]) -> Result<Self, BlockError> {
		let mut external = BigInt::ZERO;
		for offset in external_offsets {
			external |= BigInt::from(1) << *offset;
		}

		Ok(Self { base: BaseSet::from_flags(flags)?, external: ExternalSet::from(external) })
	}

	/// The base flag set.
	pub fn base(&self) -> &BaseSet {
		&self.base
	}

	/// The external offset set.
	pub fn external(&self) -> &ExternalSet {
		&self.external
	}

	/// Validate against network constraints.
	pub fn validate(&self, max_external_offset: u64) -> Result<(), BlockError> {
		self.external.validate(max_external_offset)
	}

	/// Whether this set grants all the given flags and external offsets.
	///
	/// `OWNER` implies everything; `ADMIN` implies everything except
	/// `OWNER`; `ACCESS` is required for any grant.
	pub fn has(&self, flags: &[BaseFlag], offsets: &[u8]) -> bool {
		if flags.is_empty() && offsets.is_empty() {
			return true;
		}

		if !self.base.has_flags(&[BaseFlag::Access]) {
			return false;
		}

		if self.base.has_flags(&[BaseFlag::Owner]) {
			return true;
		}

		if !flags.contains(&BaseFlag::Owner) && self.base.has_flags(&[BaseFlag::Admin]) {
			return true;
		}

		flags.iter().all(|flag| self.base.has_flags(&[*flag]))
			&& offsets
				.iter()
				.all(|offset| self.external.has_offset(*offset))
	}

	/// Whether delegation-based adjust methods are allowed for this set.
	pub fn can_use_delegation(&self) -> bool {
		let forbidden = [BaseFlag::Admin, BaseFlag::PermissionDelegateAdd, BaseFlag::PermissionDelegateRemove];
		!forbidden.iter().any(|flag| self.has(&[*flag], &[]))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_owner_overrides_other_flags() {
		let bits = BigInt::from((1 << 1) | (1 << 3));
		let set = BaseSet::try_from(bits).unwrap();
		assert_eq!(set.flags(), &[BaseFlag::Owner, BaseFlag::Access]);
		assert_eq!(*set.as_bigint(), BigInt::from((1 << 1) | 1));
	}

	#[test]
	fn test_access_implied_by_nonempty_set() {
		let set = BaseSet::try_from(BigInt::from(1 << 3)).unwrap();
		assert!(set.has_flags(&[BaseFlag::Access, BaseFlag::UpdateInfo]));
	}

	#[test]
	fn test_unknown_high_bits_preserved() {
		let bits = BigInt::from(1u64 << 40);
		let set = BaseSet::try_from(bits.clone()).unwrap();
		assert!(set.flags().is_empty());
		assert_eq!(*set.as_bigint(), bits);
	}

	#[test]
	fn test_mixed_groups_rejected() {
		// TOKEN_ADMIN_SUPPLY (entity TOKEN) + STORAGE_DEPOSIT (entity STORAGE)
		let bits = BigInt::from((1 << 6) | (1 << 10));
		let result = BaseSet::try_from(bits);
		assert!(matches!(result, Err(BlockError::PermissionsCannotMix)));
	}

	#[test]
	fn test_has_owner_grants_all() {
		let permissions = Permissions::from_flags(&[BaseFlag::Owner], &[]).unwrap();
		assert!(permissions.has(&[BaseFlag::UpdateInfo], &[5]));
	}

	#[test]
	fn test_has_admin_grants_all_but_owner() {
		let permissions = Permissions::from_flags(&[BaseFlag::Admin], &[]).unwrap();
		assert!(permissions.has(&[BaseFlag::UpdateInfo], &[]));
		assert!(!permissions.has(&[BaseFlag::Owner], &[]));
	}

	#[test]
	fn test_has_requires_access() {
		let permissions = Permissions::default();
		assert!(permissions.has(&[], &[]));
		assert!(!permissions.has(&[BaseFlag::Access], &[]));
	}

	#[test]
	fn test_external_offset_validation() {
		let permissions = Permissions::from_flags(&[], &[31]).unwrap();
		assert!(matches!(
			permissions.validate(32),
			Err(BlockError::PermissionsExternalOffsetTooLarge { size: 32, max: 32 })
		));

		let small = Permissions::from_flags(&[], &[30]).unwrap();
		assert!(small.validate(32).is_ok());
	}

	#[test]
	fn test_can_use_delegation() {
		let plain = Permissions::from_flags(&[BaseFlag::UpdateInfo], &[]).unwrap();
		assert!(plain.can_use_delegation());

		let admin = Permissions::from_flags(&[BaseFlag::Admin], &[]).unwrap();
		assert!(!admin.can_use_delegation());

		let delegate = Permissions::from_flags(&[BaseFlag::PermissionDelegateAdd], &[]).unwrap();
		assert!(!delegate.can_use_delegation());
	}

	#[test]
	fn test_is_valid_for_default() {
		let valid = BaseSet::from_flags(&[BaseFlag::Access]).unwrap();
		assert!(valid.is_valid_for_default());

		let invalid = BaseSet::from_flags(&[BaseFlag::UpdateInfo]).unwrap();
		assert!(!invalid.is_valid_for_default());
	}
}
