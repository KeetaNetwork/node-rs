//! Block operations: the nine supported operation types, their domain
//! models and validation rules.

pub(crate) mod codec;

use std::collections::{HashMap, HashSet};

use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_crypto::hash::{hash_default, BlockHash};
use num_bigint::BigInt;

use crate::account_util::accounts_equal;
use crate::amount::Amount;
use crate::error::{BlockError, InfoField};
use crate::permissions::{BaseFlag, GroupKind, Permissions};
use crate::signer::AccountRef;
use crate::validation::{TextRuleViolation, ValidationConfig};

/// How a value adjustment is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AdjustMethod {
	/// Add to the existing value
	Add = 0,
	/// Subtract from the existing value
	Subtract = 1,
	/// Replace the existing value
	Set = 2,
}

impl AdjustMethod {
	pub(crate) fn to_bigint(self) -> BigInt {
		BigInt::from(self as u8)
	}
}

impl TryFrom<&BigInt> for AdjustMethod {
	type Error = BlockError;

	fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
		if *value == BigInt::from(0u8) {
			Ok(AdjustMethod::Add)
		} else if *value == BigInt::from(1u8) {
			Ok(AdjustMethod::Subtract)
		} else if *value == BigInt::from(2u8) {
			Ok(AdjustMethod::Set)
		} else {
			Err(BlockError::InvalidAdjustMethod)
		}
	}
}

/// Operation type discriminants matching the wire context tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OperationType {
	/// Send tokens to an account
	Send = 0,
	/// Set the representative
	SetRep = 1,
	/// Set account information
	SetInfo = 2,
	/// Modify account permissions
	ModifyPermissions = 3,
	/// Create an identifier account
	CreateIdentifier = 4,
	/// Adjust token supply
	TokenAdminSupply = 5,
	/// Adjust a token balance
	TokenAdminModifyBalance = 6,
	/// Receive tokens
	Receive = 7,
	/// Manage X.509 certificates
	ManageCertificate = 8,
}

/// DER bytes of an X.509 certificate.
///
/// Stored as raw bytes for wire fidelity; with the `x509` feature the
/// certificate can be parsed into a typed [`keetanetwork_x509`] certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDer(Vec<u8>);

impl CertificateDer {
	/// The raw DER bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// The certificate hash (SHA3-256 of the DER bytes), as used for
	/// duplicate detection and `MANAGE_CERTIFICATE` removals.
	pub fn hash(&self) -> [u8; 32] {
		hash_default(&self.0)
	}

	/// Parse into a typed certificate.
	#[cfg(feature = "x509")]
	pub fn to_certificate(&self) -> Result<keetanetwork_x509::certificates::Certificate, BlockError> {
		Ok(keetanetwork_x509::certificates::Certificate::try_from(self.0.as_slice())?)
	}
}

impl From<Vec<u8>> for CertificateDer {
	fn from(bytes: Vec<u8>) -> Self {
		Self(bytes)
	}
}

#[cfg(feature = "x509")]
impl TryFrom<&keetanetwork_x509::certificates::Certificate> for CertificateDer {
	type Error = BlockError;

	fn try_from(certificate: &keetanetwork_x509::certificates::Certificate) -> Result<Self, Self::Error> {
		Ok(Self(certificate.to_der()?))
	}
}

/// A certificate referenced either by value or by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateOrHash {
	/// The full certificate (used when adding)
	Certificate(CertificateDer),
	/// The certificate hash (used when removing)
	Hash([u8; 32]),
}

impl CertificateOrHash {
	/// The certificate hash for duplicate detection.
	pub fn hash(&self) -> [u8; 32] {
		match self {
			CertificateOrHash::Certificate(certificate) => certificate.hash(),
			CertificateOrHash::Hash(hash) => *hash,
		}
	}
}

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

/// SET_REP: delegate voting weight to a representative.
#[derive(Debug, Clone)]
pub struct SetRep {
	/// The representative account
	pub to: AccountRef,
}

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

/// CREATE_IDENTIFIER: create a derived identifier account.
#[derive(Debug, Clone)]
pub struct CreateIdentifier {
	/// The identifier account being created
	pub identifier: AccountRef,
	/// Creation arguments (required for multisig identifiers)
	pub create_arguments: Option<IdentifierCreateArguments>,
}

/// TOKEN_ADMIN_SUPPLY: adjust the supply of a token.
#[derive(Debug, Clone)]
pub struct TokenAdminSupply {
	/// Amount to adjust by
	pub amount: Amount,
	/// Add or Subtract (SET is forbidden)
	pub method: AdjustMethod,
}

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

/// Intermediate certificates accompanying a MANAGE_CERTIFICATE add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntermediateCertificates {
	/// No intermediates (encoded as NULL)
	None,
	/// A possibly empty certificate bundle (encoded as a SEQUENCE)
	Bundle(Vec<CertificateDer>),
}

/// MANAGE_CERTIFICATE: add or remove an X.509 certificate.
#[derive(Debug, Clone)]
pub struct ManageCertificate {
	/// Add or Subtract (SET is forbidden)
	pub method: AdjustMethod,
	/// The certificate (add) or its hash (remove)
	pub certificate_or_hash: CertificateOrHash,
	/// Intermediate certificates; present exactly when adding
	pub intermediate_certificates: Option<IntermediateCertificates>,
}

/// A block operation.
#[derive(Debug, Clone)]
pub enum Operation {
	/// Send tokens
	Send(Send),
	/// Set representative
	SetRep(SetRep),
	/// Set account info
	SetInfo(SetInfo),
	/// Modify permissions
	ModifyPermissions(ModifyPermissions),
	/// Create an identifier
	CreateIdentifier(CreateIdentifier),
	/// Adjust token supply
	TokenAdminSupply(TokenAdminSupply),
	/// Adjust a token balance
	TokenAdminModifyBalance(TokenAdminModifyBalance),
	/// Receive tokens
	Receive(Receive),
	/// Manage certificates
	ManageCertificate(ManageCertificate),
}

impl Operation {
	/// The operation type discriminant.
	pub fn operation_type(&self) -> OperationType {
		match self {
			Operation::Send(_) => OperationType::Send,
			Operation::SetRep(_) => OperationType::SetRep,
			Operation::SetInfo(_) => OperationType::SetInfo,
			Operation::ModifyPermissions(_) => OperationType::ModifyPermissions,
			Operation::CreateIdentifier(_) => OperationType::CreateIdentifier,
			Operation::TokenAdminSupply(_) => OperationType::TokenAdminSupply,
			Operation::TokenAdminModifyBalance(_) => OperationType::TokenAdminModifyBalance,
			Operation::Receive(_) => OperationType::Receive,
			Operation::ManageCertificate(_) => OperationType::ManageCertificate,
		}
	}
}

macro_rules! impl_operation_from {
	($($struct_name:ident),+ $(,)?) => {
		$(
			impl From<$struct_name> for Operation {
				fn from(operation: $struct_name) -> Self {
					Operation::$struct_name(operation)
				}
			}
		)+
	};
}

impl_operation_from!(
	Send,
	SetRep,
	SetInfo,
	ModifyPermissions,
	CreateIdentifier,
	TokenAdminSupply,
	TokenAdminModifyBalance,
	Receive,
	ManageCertificate,
);

/// Context shared by all operation validators.
pub(crate) struct OperationContext<'a> {
	/// Resolved validation config; `None` when the network is unknown
	/// (errors surface only where the reference implementation would
	/// consult the configuration).
	pub config: Option<&'a ValidationConfig>,
	/// The block account
	pub account: &'a GenericAccount,
	/// All operations of the block
	pub operations: &'a [Operation],
	/// The previous block hash
	pub previous: &'a BlockHash,
	/// The block date in Unix milliseconds
	pub date_ms: i64,
	/// Index of the operation being validated
	pub operation_index: usize,
}

impl OperationContext<'_> {
	fn config(&self) -> Result<&ValidationConfig, BlockError> {
		self.config.ok_or(BlockError::UnknownNetwork)
	}

	fn validate_numeric(&self, value: &BigInt) -> Result<(), BlockError> {
		if *value >= BigInt::ZERO {
			return Ok(());
		}

		self.config()?.validate_numeric_value(value, self.date_ms)
	}

	fn account_is_token(&self) -> bool {
		self.account.to_keypair_type() == KeyPairType::TOKEN
	}
}

fn require_token(account: &GenericAccount) -> Result<(), BlockError> {
	if account.to_keypair_type() != KeyPairType::TOKEN {
		return Err(BlockError::TokenFieldNotToken);
	}

	Ok(())
}

/// Whether the account type can delegate voting weight via SET_REP.
fn can_delegate(key_type: KeyPairType) -> bool {
	if !key_type.is_identifier() {
		return true;
	}

	key_type == KeyPairType::STORAGE
}

impl Send {
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

impl Receive {
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

impl SetRep {
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

impl SetInfo {
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

impl ModifyPermissions {
	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		match &self.permissions {
			None => {
				if self.method != AdjustMethod::Set {
					return Err(BlockError::PermissionsRequireSet);
				}
			}
			Some(permissions) => {
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
			}
		}

		// Disallow a SET after permissions were already updated for the
		// same principal/target pair.
		let mut found: HashMap<String, HashMap<String, AdjustMethod>> = HashMap::new();
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

impl CreateIdentifier {
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
			if created_type != KeyPairType::MULTISIG {
				return Err(BlockError::InvalidCreateIdentifierArguments);
			}

			ctx.config()?
				.validate_signer_count(arguments.signers.len() as u64)?;

			let unique: HashSet<String> = arguments
				.signers
				.iter()
				.map(|signer| signer.to_string())
				.collect();
			if unique.len() != arguments.signers.len() {
				return Err(BlockError::MultisigSignerDuplicate);
			}

			if arguments.quorum < BigInt::from(1u8) || arguments.quorum > BigInt::from(unique.len()) {
				return Err(BlockError::MultisigQuorumInvalid);
			}
		}

		Ok(())
	}
}

impl TokenAdminSupply {
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

impl TokenAdminModifyBalance {
	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		require_token(&self.token)?;
		ctx.validate_numeric(self.amount.as_bigint())?;

		if ctx.account_is_token() {
			return Err(BlockError::TokenOperationForbidden);
		}

		Ok(())
	}
}

impl ManageCertificate {
	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		if self.method == AdjustMethod::Set {
			return Err(BlockError::AdjustMethodSetForbidden);
		}

		if self.intermediate_certificates.is_none() == (self.method == AdjustMethod::Add) {
			return Err(BlockError::IntermediateCertificatesOnlyAdd);
		}

		if self.method == AdjustMethod::Add {
			let CertificateOrHash::Certificate(certificate) = &self.certificate_or_hash else {
				return Err(BlockError::InvalidCertificateValue);
			};

			#[cfg(feature = "x509")]
			{
				let parsed = certificate.to_certificate()?;
				let subject_key = &parsed
					.tbs_certificate
					.subject_public_key_info
					.subject_public_key;
				let account_bytes = ctx.account.to_public_key_with_type();
				if subject_key.raw_bytes() != &account_bytes[1..] {
					return Err(BlockError::CertificateSubjectMismatch);
				}
			}
			#[cfg(not(feature = "x509"))]
			{
				let _ = certificate;
			}
		}

		let mut seen: HashSet<[u8; 32]> = HashSet::new();
		for operation in ctx.operations {
			let Operation::ManageCertificate(other) = operation else {
				continue;
			};

			if !seen.insert(other.certificate_or_hash.hash()) {
				return Err(BlockError::DuplicateCertificateOperation);
			}
		}

		Ok(())
	}
}

impl Operation {
	/// Validate this operation within its block context.
	pub(crate) fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		match self {
			Operation::Send(op) => op.validate(ctx),
			Operation::SetRep(op) => op.validate(ctx),
			Operation::SetInfo(op) => op.validate(ctx),
			Operation::ModifyPermissions(op) => op.validate(ctx),
			Operation::CreateIdentifier(op) => op.validate(ctx),
			Operation::TokenAdminSupply(op) => op.validate(ctx),
			Operation::TokenAdminModifyBalance(op) => op.validate(ctx),
			Operation::Receive(op) => op.validate(ctx),
			Operation::ManageCertificate(op) => op.validate(ctx),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::error::InfoField;
	use crate::test_util::{ed25519, identifier};

	/// A date before the negative-amount cutoff.
	const PRE_CUTOFF_MS: i64 = 1_700_000_000_000;

	struct Harness {
		config: ValidationConfig,
		account: AccountRef,
		previous: BlockHash,
		operations: Vec<Operation>,
		date_ms: i64,
	}

	impl Harness {
		fn new(account: AccountRef) -> Self {
			let previous = account.to_opening_hash();
			Self {
				config: ValidationConfig::default(),
				account,
				previous,
				operations: Vec::new(),
				date_ms: PRE_CUTOFF_MS,
			}
		}

		fn validate(&self, operation: &Operation) -> Result<(), BlockError> {
			let ctx = OperationContext {
				config: Some(&self.config),
				account: &self.account,
				operations: &self.operations,
				previous: &self.previous,
				date_ms: self.date_ms,
				operation_index: 0,
			};
			operation.validate(&ctx)
		}
	}

	fn send(token: AccountRef, to: AccountRef) -> Send {
		Send { to, amount: Amount::from(1u64), token, external: None }
	}

	fn token(index: u32) -> AccountRef {
		identifier(1, KeyPairType::TOKEN, index)
	}

	// --- SEND ---

	#[test]
	fn test_send_rejects_non_token_token_field() {
		let harness = Harness::new(ed25519(1));
		let operation = send(ed25519(2), ed25519(3)).into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::TokenFieldNotToken)));
	}

	#[test]
	fn test_send_rejects_token_account_sending_other_token() {
		let harness = Harness::new(token(0));
		let operation = send(token(1), ed25519(2)).into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::TokenOperationForbidden)));
	}

	#[test]
	fn test_send_rejects_token_destination_mismatch() {
		let harness = Harness::new(ed25519(1));
		let operation = send(token(0), token(1)).into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::TokenReceiveDiffers)));
	}

	#[test]
	fn test_send_rejects_external_too_long() {
		let harness = Harness::new(ed25519(1));
		let mut operation = send(token(0), ed25519(2));
		operation.external = Some("A".repeat(1025));
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::ExternalTooLong { .. })));
	}

	#[test]
	fn test_send_rejects_external_invalid_character() {
		let harness = Harness::new(ed25519(1));
		let mut operation = send(token(0), ed25519(2));
		operation.external = Some("bad☃".to_string());
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::ExternalInvalid)));
	}

	#[test]
	fn test_send_rejects_negative_amount_after_cutoff() {
		let mut harness = Harness::new(ed25519(1));
		harness.date_ms = harness.config.numeric_cutoff_epoch_ms;
		let mut operation = send(token(0), ed25519(2));
		operation.amount = Amount::from(-1i64);
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::AmountBelowZero)));
	}

	#[test]
	fn test_send_accepts_valid_operation() {
		let harness = Harness::new(ed25519(1));
		let operation = send(token(0), ed25519(2)).into();
		assert!(harness.validate(&operation).is_ok());
	}

	// --- RECEIVE ---

	fn receive(token: AccountRef, from: AccountRef) -> Receive {
		Receive { amount: Amount::from(1u64), token, from, exact: false, forward: None }
	}

	#[test]
	fn test_receive_rejects_forward_to_self() {
		let account = ed25519(1);
		let harness = Harness::new(account.clone());
		let mut operation = receive(token(0), ed25519(2));
		operation.exact = true;
		operation.forward = Some(account);
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::ForwardToSelf)));
	}

	#[test]
	fn test_receive_rejects_forward_without_exact() {
		let harness = Harness::new(ed25519(1));
		let mut operation = receive(token(0), ed25519(2));
		operation.forward = Some(ed25519(3));
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::ForwardRequiresExact)));
	}

	#[test]
	fn test_receive_rejects_token_account() {
		let harness = Harness::new(token(0));
		let operation = receive(token(0), ed25519(2)).into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::TokenOperationForbidden)));
	}

	#[test]
	fn test_receive_rejects_token_forward_mismatch() {
		let harness = Harness::new(ed25519(1));
		let mut operation = receive(token(0), ed25519(2));
		operation.exact = true;
		operation.forward = Some(token(1));
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::TokenReceiveDiffers)));
	}

	// --- SET_REP ---

	#[test]
	fn test_set_rep_rejects_token_account() {
		let harness = Harness::new(token(0));
		let operation = SetRep { to: ed25519(2) }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::IdentifierDelegationForbidden)));
	}

	#[test]
	fn test_set_rep_accepts_storage_account() {
		let harness = Harness::new(identifier(1, KeyPairType::STORAGE, 0));
		let operation = SetRep { to: ed25519(2) }.into();
		assert!(harness.validate(&operation).is_ok());
	}

	#[test]
	fn test_set_rep_rejects_identifier_representative() {
		let harness = Harness::new(ed25519(1));
		let operation = SetRep { to: token(0) }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::IdentifierDelegationForbidden)));
	}

	#[test]
	fn test_set_rep_rejects_multiple_per_block() {
		let mut harness = Harness::new(ed25519(1));
		let operation: Operation = SetRep { to: ed25519(2) }.into();
		harness.operations = vec![operation.clone(), SetRep { to: ed25519(3) }.into()];
		assert!(matches!(harness.validate(&operation), Err(BlockError::MultipleSetRep)));
	}

	// --- SET_INFO ---

	fn set_info() -> SetInfo {
		SetInfo {
			name: "MY_ACCOUNT".to_string(),
			description: "A description".to_string(),
			metadata: String::new(),
			default_permission: None,
		}
	}

	#[test]
	fn test_set_info_rejects_invalid_name() {
		let harness = Harness::new(ed25519(1));
		let mut operation = set_info();
		operation.name = "lower case".to_string();
		assert!(matches!(
			harness.validate(&operation.into()),
			Err(BlockError::InfoFieldInvalid { field: InfoField::Name })
		));
	}

	#[test]
	fn test_set_info_rejects_default_permission_on_keyed_account() {
		let harness = Harness::new(ed25519(1));
		let mut operation = set_info();
		operation.default_permission = Some(Permissions::from_flags(&[BaseFlag::Access], &[]).unwrap());
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::IdentifierAccountRequired)));
	}

	#[test]
	fn test_set_info_requires_default_permission_on_identifier() {
		let harness = Harness::new(token(0));
		let operation = set_info().into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::DefaultPermissionRequired)));
	}

	#[test]
	fn test_set_info_rejects_external_default_permission() {
		let harness = Harness::new(token(0));
		let mut operation = set_info();
		operation.default_permission = Some(Permissions::from_flags(&[BaseFlag::Access], &[3]).unwrap());
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::PermissionsExternalDefaultForbidden)));
	}

	#[test]
	fn test_set_info_rejects_non_default_flags() {
		let harness = Harness::new(token(0));
		let mut operation = set_info();
		operation.default_permission = Some(Permissions::from_flags(&[BaseFlag::UpdateInfo], &[]).unwrap());
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::PermissionsInvalidDefault)));
	}

	// --- MODIFY_PERMISSIONS ---

	fn modify_permissions(permissions: Option<Permissions>) -> ModifyPermissions {
		ModifyPermissions {
			principal: ModifyPermissionsPrincipal::Account(ed25519(2)),
			method: AdjustMethod::Set,
			permissions,
			target: None,
		}
	}

	#[test]
	fn test_modify_permissions_clear_requires_set() {
		let harness = Harness::new(ed25519(1));
		let mut operation = modify_permissions(None);
		operation.method = AdjustMethod::Add;
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::PermissionsRequireSet)));
	}

	#[test]
	fn test_modify_permissions_rejects_target_for_targetless_flags() {
		let harness = Harness::new(ed25519(1));
		let mut operation = modify_permissions(Some(Permissions::from_flags(&[BaseFlag::Admin], &[]).unwrap()));
		operation.target = Some(token(0));
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::PermissionsInvalidTarget)));
	}

	#[test]
	fn test_modify_permissions_rejects_delegated_adjust() {
		let harness = Harness::new(ed25519(1));
		let mut operation =
			modify_permissions(Some(Permissions::from_flags(&[BaseFlag::PermissionDelegateAdd], &[]).unwrap()));
		operation.method = AdjustMethod::Add;
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::DelegationForbidden)));
	}

	#[test]
	fn test_modify_permissions_rejects_duplicate_set() {
		let mut harness = Harness::new(ed25519(1));
		let operation: Operation =
			modify_permissions(Some(Permissions::from_flags(&[BaseFlag::Access], &[]).unwrap())).into();
		harness.operations = vec![operation.clone(), operation.clone()];
		assert!(matches!(harness.validate(&operation), Err(BlockError::DuplicatePermissionModification)));
	}

	#[test]
	fn test_modify_permissions_accepts_valid_set() {
		let harness = Harness::new(ed25519(1));
		let operation =
			modify_permissions(Some(Permissions::from_flags(&[BaseFlag::Access, BaseFlag::UpdateInfo], &[]).unwrap()));
		assert!(harness.validate(&operation.into()).is_ok());
	}

	// --- CREATE_IDENTIFIER ---

	#[test]
	fn test_create_identifier_rejects_keyed_identifier() {
		let harness = Harness::new(ed25519(1));
		let operation = CreateIdentifier { identifier: ed25519(2), create_arguments: None }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::IdentifierInvalid)));
	}

	#[test]
	fn test_create_identifier_rejects_wrong_derivation() {
		let harness = Harness::new(ed25519(1));
		let operation =
			CreateIdentifier { identifier: identifier(1, KeyPairType::TOKEN, 5), create_arguments: None }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::IdentifierInvalid)));
	}

	#[test]
	fn test_create_identifier_rejects_arguments_for_token() {
		let harness = Harness::new(ed25519(1));
		let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments {
			signers: vec![ed25519(2)],
			quorum: BigInt::from(1u8),
		});
		let operation = CreateIdentifier { identifier: token(0), create_arguments: Some(arguments) }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::InvalidCreateIdentifierArguments)));
	}

	#[test]
	fn test_create_identifier_requires_arguments_for_multisig() {
		let harness = Harness::new(ed25519(1));
		let operation =
			CreateIdentifier { identifier: identifier(1, KeyPairType::MULTISIG, 0), create_arguments: None }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::InvalidCreateIdentifierArguments)));
	}

	#[test]
	fn test_create_identifier_rejects_zero_quorum() {
		let harness = Harness::new(ed25519(1));
		let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments {
			signers: vec![ed25519(2), ed25519(3)],
			quorum: BigInt::ZERO,
		});
		let operation =
			CreateIdentifier { identifier: identifier(1, KeyPairType::MULTISIG, 0), create_arguments: Some(arguments) }
				.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::MultisigQuorumInvalid)));
	}

	#[test]
	fn test_create_identifier_rejects_duplicate_signers() {
		let harness = Harness::new(ed25519(1));
		let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments {
			signers: vec![ed25519(2), ed25519(2)],
			quorum: BigInt::from(1u8),
		});
		let operation =
			CreateIdentifier { identifier: identifier(1, KeyPairType::MULTISIG, 0), create_arguments: Some(arguments) }
				.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::MultisigSignerDuplicate)));
	}

	#[test]
	fn test_create_identifier_accepts_matching_derivation() {
		let harness = Harness::new(ed25519(1));
		let operation = CreateIdentifier { identifier: token(0), create_arguments: None }.into();
		assert!(harness.validate(&operation).is_ok());
	}

	// --- TOKEN_ADMIN_SUPPLY ---

	#[test]
	fn test_token_admin_supply_rejects_set_method() {
		let harness = Harness::new(token(0));
		let operation = TokenAdminSupply { amount: Amount::from(1u64), method: AdjustMethod::Set }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::AdjustMethodSetForbidden)));
	}

	#[test]
	fn test_token_admin_supply_requires_token_account() {
		let harness = Harness::new(ed25519(1));
		let operation = TokenAdminSupply { amount: Amount::from(1u64), method: AdjustMethod::Add }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::TokenAccountRequired)));
	}

	#[test]
	fn test_token_admin_supply_rejects_excess_supply() {
		let harness = Harness::new(token(0));
		let over = harness.config.max_supply.clone() + 1;
		let operation = TokenAdminSupply { amount: Amount::from(over), method: AdjustMethod::Add }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::SupplyInvalid)));
	}

	// --- TOKEN_ADMIN_MODIFY_BALANCE ---

	#[test]
	fn test_modify_balance_rejects_non_token_field() {
		let harness = Harness::new(ed25519(1));
		let operation =
			TokenAdminModifyBalance { token: ed25519(2), amount: Amount::from(1u64), method: AdjustMethod::Add }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::TokenFieldNotToken)));
	}

	#[test]
	fn test_modify_balance_rejects_token_account() {
		let harness = Harness::new(token(0));
		let operation =
			TokenAdminModifyBalance { token: token(0), amount: Amount::from(1u64), method: AdjustMethod::Add }.into();
		assert!(matches!(harness.validate(&operation), Err(BlockError::TokenOperationForbidden)));
	}

	// --- MANAGE_CERTIFICATE ---

	fn manage_certificate_subtract(hash_byte: u8) -> ManageCertificate {
		ManageCertificate {
			method: AdjustMethod::Subtract,
			certificate_or_hash: CertificateOrHash::Hash([hash_byte; 32]),
			intermediate_certificates: None,
		}
	}

	#[test]
	fn test_manage_certificate_rejects_set_method() {
		let harness = Harness::new(ed25519(1));
		let mut operation = manage_certificate_subtract(7);
		operation.method = AdjustMethod::Set;
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::AdjustMethodSetForbidden)));
	}

	#[test]
	fn test_manage_certificate_rejects_intermediates_on_subtract() {
		let harness = Harness::new(ed25519(1));
		let mut operation = manage_certificate_subtract(7);
		operation.intermediate_certificates = Some(IntermediateCertificates::None);
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::IntermediateCertificatesOnlyAdd)));
	}

	#[test]
	fn test_manage_certificate_rejects_hash_on_add() {
		let harness = Harness::new(ed25519(1));
		let mut operation = manage_certificate_subtract(7);
		operation.method = AdjustMethod::Add;
		operation.intermediate_certificates = Some(IntermediateCertificates::None);
		assert!(matches!(harness.validate(&operation.into()), Err(BlockError::InvalidCertificateValue)));
	}

	#[test]
	fn test_manage_certificate_rejects_duplicate_certificate() {
		let mut harness = Harness::new(ed25519(1));
		let operation: Operation = manage_certificate_subtract(7).into();
		harness.operations = vec![operation.clone(), operation.clone()];
		assert!(matches!(harness.validate(&operation), Err(BlockError::DuplicateCertificateOperation)));
	}
}
