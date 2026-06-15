//! Error types for block construction, serialization and validation.

use alloc::string::ToString;

use keetanetwork_account::AccountError;
use keetanetwork_asn1::Asn1Error;
use keetanetwork_crypto::error::CryptoError;
use keetanetwork_crypto::hash::BlockHash;
use keetanetwork_error::KeetaNetError;
use keetanetwork_utils::impl_source_error_from;
use snafu::Snafu;

/// Block field names used in structured errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockField {
	/// Block version
	Version,
	/// Network identifier
	Network,
	/// Block account
	Account,
	/// Previous block hash
	Previous,
	/// Block signer
	Signer,
	/// Block date
	Date,
}

/// Account info fields validated by `SET_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoField {
	/// Account name
	Name,
	/// Account description
	Description,
	/// Account metadata
	Metadata,
}

impl core::fmt::Display for BlockField {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let name = match self {
			BlockField::Version => "version",
			BlockField::Network => "network",
			BlockField::Account => "account",
			BlockField::Previous => "previous",
			BlockField::Signer => "signer",
			BlockField::Date => "date",
		};
		write!(f, "{name}")
	}
}

impl core::fmt::Display for InfoField {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let name = match self {
			InfoField::Name => "name",
			InfoField::Description => "description",
			InfoField::Metadata => "metadata",
		};
		write!(f, "{name}")
	}
}

/// Errors produced by the block crate.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum BlockError {
	/// ASN.1 serialization or deserialization failed
	#[snafu(display("ASN.1 codec error: {source}"))]
	Codec {
		/// Underlying codec error
		source: Asn1Error,
	},
	/// Account operation failed
	#[snafu(display("account error: {source}"))]
	Account {
		/// Underlying account error
		source: AccountError,
	},
	/// Cryptographic operation failed
	#[snafu(display("crypto error: {source}"))]
	Crypto {
		/// Underlying crypto error
		source: CryptoError,
	},
	/// X.509 certificate handling failed
	#[cfg(feature = "x509")]
	#[snafu(display("certificate error: {source}"))]
	Certificate {
		/// Underlying certificate error
		source: keetanetwork_x509::error::CertificateError,
	},

	/// Unsupported block version
	#[snafu(display("unsupported block version"))]
	InvalidVersion,
	/// Block references itself as previous
	#[snafu(display("block references itself as previous"))]
	PreviousSelf,
	/// Network identifier must not be negative
	#[snafu(display("network ID must be a positive number"))]
	NegativeNetwork,
	/// Subnet identifier must not be negative
	#[snafu(display("subnet ID must be a positive number"))]
	NegativeSubnet,
	/// Network identifier is not a known network
	#[snafu(display("unknown network ID"))]
	UnknownNetwork,
	/// Blocks cannot be created for multisig accounts
	#[snafu(display("cannot create a block for a multisig account"))]
	MultisigAccountForbidden,
	/// A required builder field is missing
	#[snafu(display("missing required block field: {field}"))]
	MissingField {
		/// The missing field
		field: BlockField,
	},
	/// Account field redundantly repeats the signer (or vice versa)
	#[snafu(display("account and signer must not both be present when equal"))]
	RedundantAccountField,

	/// Block requires signatures but has none
	#[snafu(display("block has not been signed"))]
	SignatureRequired,
	/// Signature count does not match required signer count
	#[snafu(display("signer count {expected} does not match signature count {actual}"))]
	SignatureCountMismatch {
		/// Required signer count
		expected: usize,
		/// Provided signature count
		actual: usize,
	},
	/// A signature failed verification
	#[snafu(display("unable to validate signature at index {index} for block {hash}"))]
	InvalidSignature {
		/// Index of the failing signature
		index: usize,
		/// Hash of the block being verified
		hash: BlockHash,
	},
	/// Signature has the wrong length
	#[snafu(display("signature must be exactly 64 bytes, got {length}"))]
	InvalidSignatureLength {
		/// Provided length
		length: usize,
	},
	/// A signature sequence must contain more than one signature
	#[snafu(display("signature sequence must contain more than one signature"))]
	InvalidSignatureSequence,
	/// Decoded bytes do not match the re-encoded canonical form
	#[snafu(display("block bytes do not match recalculated bytes"))]
	RecalculatedBytesMismatch,
	/// V1 blocks support exactly one signer and signature
	#[snafu(display("V1 blocks support only a single signer and signature"))]
	V1SingleSignerOnly,
	/// V1 blocks only support the generic purpose
	#[snafu(display("V1 block purpose must be generic"))]
	V1PurposeInvalid,

	/// Idempotent key exceeds the maximum length
	#[snafu(display("idempotent key length {length} exceeds maximum {max}"))]
	IdempotentTooLong {
		/// Provided length
		length: usize,
		/// Maximum permitted length
		max: usize,
	},
	/// FEE purpose blocks may only contain SEND operations
	#[snafu(display("FEE purpose block contains non-SEND operation at index {operation_index}"))]
	FeePurposeRequiresSend {
		/// Index of the offending operation
		operation_index: usize,
	},
	/// Unknown block purpose value
	#[snafu(display("invalid block purpose"))]
	InvalidPurpose,
	/// Unknown operation type tag
	#[snafu(display("invalid operation type"))]
	InvalidOperationType,
	/// Unknown adjust method value
	#[snafu(display("invalid adjust method"))]
	InvalidAdjustMethod,
	/// SET adjust method is forbidden for this operation
	#[snafu(display("cannot use the SET adjust method for this operation"))]
	AdjustMethodSetForbidden,

	/// Multisig signer tree exceeds the maximum depth
	#[snafu(display("multisig signer depth {depth} exceeds maximum {max}"))]
	MultisigSignerDepthExceeded {
		/// Observed depth
		depth: u64,
		/// Maximum permitted depth
		max: u64,
	},
	/// Multisig signer count out of range
	#[snafu(display("multisig signer count {count} out of range [1, {max}]"))]
	MultisigSignerCountInvalid {
		/// Observed count
		count: u64,
		/// Maximum permitted count
		max: u64,
	},
	/// Duplicate signer within a multisig level
	#[snafu(display("duplicate multisig signer"))]
	MultisigSignerDuplicate,
	/// Multisig quorum out of range
	#[snafu(display("multisig quorum out of range"))]
	MultisigQuorumInvalid,
	/// Malformed multisig signer structure
	#[snafu(display("malformed multisig signer structure"))]
	MalformedSigner,

	/// Amounts must not be negative
	#[snafu(display("amount cannot be negative"))]
	AmountBelowZero,
	/// Token supply exceeds maximum
	#[snafu(display("supply exceeds maximum value"))]
	SupplyInvalid,
	/// SEND/RECEIVE token field must reference a token account
	#[snafu(display("token field must reference a token account"))]
	TokenFieldNotToken,
	/// Token accounts cannot use this operation
	#[snafu(display("token accounts cannot use this operation"))]
	TokenOperationForbidden,
	/// Only token accounts can use this operation
	#[snafu(display("only token accounts can use this operation"))]
	TokenAccountRequired,
	/// Sending a token to a different token account
	#[snafu(display("cannot send a token to a token account different from itself"))]
	TokenReceiveDiffers,
	/// External data exceeds the maximum length
	#[snafu(display("external length {length} exceeds maximum {max}"))]
	ExternalTooLong {
		/// Provided length
		length: usize,
		/// Maximum permitted length
		max: usize,
	},
	/// External data contains invalid characters
	#[snafu(display("external has invalid characters"))]
	ExternalInvalid,
	/// External data is required
	#[snafu(display("external is required when using SEND"))]
	ExternalMissing,
	/// RECEIVE cannot forward to self
	#[snafu(display("cannot use forward field to send to self"))]
	ForwardToSelf,
	/// RECEIVE forward requires exact
	#[snafu(display("cannot use forward field without exact being set to true"))]
	ForwardRequiresExact,
	/// Account type cannot delegate or target is an identifier
	#[snafu(display("identifier accounts cannot be used for delegation"))]
	IdentifierDelegationForbidden,
	/// SET_REP may only appear once per block
	#[snafu(display("SET_REP may only be used once per block"))]
	MultipleSetRep,
	/// Account info field fails format validation
	#[snafu(display("{field} does not fit the required format"))]
	InfoFieldInvalid {
		/// The failing field
		field: InfoField,
	},
	/// Identifier accounts require default permissions in SET_INFO
	#[snafu(display("identifier accounts need default permissions in SET_INFO"))]
	DefaultPermissionRequired,
	/// Only identifier accounts may use this construct
	#[snafu(display("only identifier accounts may use this construct"))]
	IdentifierAccountRequired,
	/// Requested identifier does not match the derived identifier
	#[snafu(display("requested identifier is not valid"))]
	IdentifierInvalid,
	/// Invalid create-identifier arguments
	#[snafu(display("invalid create identifier arguments"))]
	InvalidCreateIdentifierArguments,
	/// Invalid principal for MODIFY_PERMISSIONS
	#[snafu(display("invalid principal for MODIFY_PERMISSIONS"))]
	InvalidPrincipal,
	/// Method must be SET when permissions are absent
	#[snafu(display("method must be SET when permissions are absent"))]
	PermissionsRequireSet,
	/// Cannot set admin or higher with a target specified
	#[snafu(display("cannot set admin or higher with a target specified"))]
	AdminWithTarget,
	/// Delegation not allowed for these permission flags
	#[snafu(display("cannot use delegation for these permission flags"))]
	DelegationForbidden,
	/// Duplicate permission modification for the same principal/target
	#[snafu(display("cannot have a SET after another change with the same target in MODIFY_PERMISSIONS"))]
	DuplicatePermissionModification,

	/// Base permission flags from different groups cannot be mixed
	#[snafu(display("cannot mix base permission flags with different groups"))]
	PermissionsCannotMix,
	/// External permission offsets exceed the maximum
	#[snafu(display("external permission size {size} exceeds maximum offset {max}"))]
	PermissionsExternalOffsetTooLarge {
		/// Observed bitfield size
		size: u64,
		/// Maximum permitted offset
		max: u64,
	},
	/// Permissions are not valid as defaults
	#[snafu(display("permissions are not valid as default permissions"))]
	PermissionsInvalidDefault,
	/// Entity account does not match the permission flag group
	#[snafu(display("incorrect entity for permission flags"))]
	PermissionsInvalidEntity,
	/// Principal account does not match the permission flag group
	#[snafu(display("incorrect principal for permission flags"))]
	PermissionsInvalidPrincipal,
	/// Target account does not match the permission flag group
	#[snafu(display("incorrect target for permission flags"))]
	PermissionsInvalidTarget,
	/// External permissions cannot be used for default permissions
	#[snafu(display("cannot set default permissions with external permissions"))]
	PermissionsExternalDefaultForbidden,

	/// Certificate value invalid for the requested method
	#[snafu(display("invalid certificate value for MANAGE_CERTIFICATE"))]
	InvalidCertificateValue,
	/// Certificate subject does not match the block account
	#[snafu(display("certificate subject does not match the block account"))]
	CertificateSubjectMismatch,
	/// Intermediate certificates only valid on ADD
	#[snafu(display("intermediate certificates can only be provided when adding"))]
	IntermediateCertificatesOnlyAdd,
	/// The same certificate cannot be operated on twice in one block
	#[snafu(display("cannot operate on the same certificate twice"))]
	DuplicateCertificateOperation,
}

impl_source_error_from!(BlockError, {
	Asn1Error => Codec,
	AccountError => Account,
	CryptoError => Crypto,
});

#[cfg(feature = "x509")]
impl_source_error_from!(BlockError, {
	keetanetwork_x509::error::CertificateError => Certificate,
});

impl BlockError {
	/// The TypeScript-compatible error code for this error, when one exists.
	pub fn code(&self) -> Option<&'static str> {
		let code = match self {
			BlockError::InvalidVersion => "BLOCK_INVALID_VERSION",
			BlockError::PreviousSelf => "BLOCK_PREVIOUS_SELF",
			BlockError::MultisigAccountForbidden => "BLOCK_NO_MULTISIG_OP",
			BlockError::SignatureRequired => "BLOCK_SIGNATURE_REQUIRED",
			BlockError::SignatureCountMismatch { .. } | BlockError::V1SingleSignerOnly => "BLOCK_INVALID_SIGNER",
			BlockError::InvalidSignature { .. } | BlockError::RecalculatedBytesMismatch => "BLOCK_INVALID_SIGNATURE",
			BlockError::IdempotentTooLong { .. } => "BLOCK_INVALID_IDEMPOTENT_LENGTH",
			BlockError::FeePurposeRequiresSend { .. } | BlockError::V1PurposeInvalid => {
				"BLOCK_INVALID_PURPOSE_VALIDATION"
			}
			BlockError::InvalidOperationType => "BLOCK_INVALID_TYPE",
			BlockError::MultisigSignerDepthExceeded { .. } => "BLOCK_INVALID_MULTISIG_SIGNER_DEPTH",
			BlockError::MultisigSignerCountInvalid { .. } => "BLOCK_INVALID_MULTISIG_SIGNER_COUNT",
			BlockError::MultisigSignerDuplicate => "BLOCK_INVALID_MULTISIG_SIGNER_DUPLICATE",
			BlockError::MultisigQuorumInvalid => "BLOCK_INVALID_MULTISIG_QUORUM",
			BlockError::AmountBelowZero => "BLOCK_AMOUNT_BELOW_ZERO",
			BlockError::SupplyInvalid => "BLOCK_SUPPLY_INVALID",
			BlockError::TokenFieldNotToken => "BLOCK_CANNOT_SEND_NON_TOKEN",
			BlockError::TokenOperationForbidden => "BLOCK_NO_TOKEN_OP",
			BlockError::TokenAccountRequired => "BLOCK_ONLY_TOKEN_OP",
			BlockError::TokenReceiveDiffers => "BLOCK_TOKEN_RECEIVE_DIFFERS",
			BlockError::ExternalTooLong { .. } => "BLOCK_EXTERNAL_TOO_LONG",
			BlockError::ExternalInvalid => "BLOCK_EXTERNAL_INVALID",
			BlockError::ExternalMissing => "BLOCK_EXTERNAL_MISSING",
			BlockError::ForwardToSelf => "BLOCK_CANNOT_FORWARD_TO_SELF",
			BlockError::ForwardRequiresExact => "BLOCK_EXACT_TRUE_WHEN_FORWARDING",
			BlockError::IdentifierDelegationForbidden => "BLOCK_NO_IDENTIFIER_OP",
			BlockError::MultipleSetRep => "BLOCK_NO_MULTIPLE_SET_REP",
			BlockError::InfoFieldInvalid { .. } | BlockError::PermissionsExternalDefaultForbidden => {
				"BLOCK_GENERAL_FIELD_INVALID"
			}
			BlockError::DefaultPermissionRequired => "BLOCK_IDENTIFIER_NEED_DEFAULT_PERMISSIONS",
			BlockError::IdentifierAccountRequired => "BLOCK_ONLY_IDENTIFIER_OP",
			BlockError::IdentifierInvalid => "BLOCK_IDENTIFIER_INVALID",
			BlockError::InvalidCreateIdentifierArguments => "BLOCK_INVALID_CREATE_IDENTIFIER_ARGS",
			BlockError::InvalidPrincipal => "BLOCK_INVALID_PRINCIPAL",
			BlockError::AdminWithTarget => "BLOCK_NO_ADMIN_ON_TARGET",
			BlockError::DelegationForbidden => "BLOCK_NO_DELEGATE_ADMIN",
			BlockError::DuplicatePermissionModification => "BLOCK_NO_MODIFY_PERMISSION_DUPE",
			BlockError::PermissionsCannotMix => "PERMISSIONS_CANNOT_MIX_FLAGS_AND_TYPES",
			BlockError::PermissionsExternalOffsetTooLarge { .. } => "PERMISSIONS_EXTERNAL_OFFSET_TOO_LARGE",
			BlockError::PermissionsInvalidDefault => "BLOCK_PERMISSIONS_INVALID_DEFAULT",
			BlockError::PermissionsInvalidEntity => "BLOCK_PERMISSIONS_INVALID_ENTITY",
			BlockError::PermissionsInvalidPrincipal => "BLOCK_PERMISSIONS_INVALID_PRINCIPAL",
			BlockError::PermissionsInvalidTarget => "BLOCK_PERMISSIONS_INVALID_TARGET",
			BlockError::InvalidCertificateValue => "BLOCK_INVALID_CERTIFICATE_VALUE",
			BlockError::CertificateSubjectMismatch => "BLOCK_CERTIFICATE_SUBJECT_MISMATCH",
			BlockError::IntermediateCertificatesOnlyAdd => "BLOCK_INTERMEDIATE_CERTIFICATES_ONLY_ADD",
			BlockError::DuplicateCertificateOperation => "BLOCK_NO_DUPLICATE_CERTIFICATE_OPERATION",
			_ => return None,
		};

		Some(code)
	}
}

impl From<BlockError> for KeetaNetError {
	fn from(error: BlockError) -> Self {
		if let Some(code) = error.code() {
			KeetaNetError::Code { code: code.to_string(), message: error.to_string() }
		} else {
			KeetaNetError::Unknown { msg: error.to_string() }
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_code_mapping() {
		assert_eq!(BlockError::InvalidVersion.code(), Some("BLOCK_INVALID_VERSION"));
		assert_eq!(BlockError::PreviousSelf.code(), Some("BLOCK_PREVIOUS_SELF"));
		assert_eq!(BlockError::NegativeNetwork.code(), None);
	}

	#[test]
	fn test_keetanet_error_bridge() {
		let bridged = KeetaNetError::from(BlockError::PreviousSelf);
		assert!(matches!(bridged, KeetaNetError::Code { code, .. } if code == "BLOCK_PREVIOUS_SELF"));

		let unknown = KeetaNetError::from(BlockError::NegativeNetwork);
		assert!(matches!(unknown, KeetaNetError::Unknown { .. }));
	}

	#[test]
	fn test_source_conversions() {
		let codec_error = Asn1Error::RasnError { reason: "boom".to_string() };
		assert!(matches!(BlockError::from(codec_error), BlockError::Codec { .. }));
		assert!(matches!(BlockError::from(AccountError::InvalidKeyType), BlockError::Account { .. }));
		assert!(matches!(BlockError::from(CryptoError::InvalidInput), BlockError::Crypto { .. }));
	}
}
