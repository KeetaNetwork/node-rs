//! Error types for vote construction, decoding, and validation.
//!
//! Every fallible operation in the crate surfaces a [`VoteError`]. Each
//! variant additionally exposes a stable, programmatic identifier through
//! [`VoteError::code`] suitable for cross-implementation error matching
//! and structured logging.

use keetanetwork_account::AccountError;
use keetanetwork_block::BlockError;
use keetanetwork_crypto::error::CryptoError;
use keetanetwork_error::KeetaNetError;
use keetanetwork_utils::impl_source_error_from;
use snafu::Snafu;

/// Errors produced by the vote crate.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum VoteError {
	/// DER serialization or deserialization failed
	#[snafu(display("DER error: {source}"))]
	Der {
		/// Underlying DER error
		source: der::Error,
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
	/// Block decoding or validation failed
	#[snafu(display("block error: {source}"))]
	Block {
		/// Underlying block error
		source: BlockError,
	},
	/// zlib (de)compression failed for a vote staple wrapper
	#[snafu(display("staple compression error: {source}"))]
	Compression {
		/// Underlying I/O error from `flate2`
		source: std::io::Error,
	},

	// ----- Vote-level -----
	/// Subject DN serial does not match the certificate serial
	#[snafu(display("vote subject serial does not match certificate serial"))]
	SerialMismatch,
	/// Vote certificate version is not supported
	#[snafu(display("vote certificate version must be 3"))]
	InvalidVersion,
	/// Vote could not be constructed from the supplied bytes
	#[snafu(display("vote bytes are not a recognized construction"))]
	InvalidConstruction,
	/// Vote signature did not verify against the issuer public key
	#[snafu(display("vote signature did not verify"))]
	SignatureInvalid,
	/// Vote validity period has elapsed at the configured moment
	#[snafu(display("vote has expired"))]
	Expired,
	/// `validityFrom > validityTo`
	#[snafu(display("vote validity range is invalid"))]
	InvalidValidity,
	/// The check moment lands before `validityFrom` minus the slop
	#[snafu(display("vote was issued in the future"))]
	MomentBeforeValidityFrom,

	// ----- Staple-level -----
	/// Staple bytes do not contain a valid two-element SEQUENCE
	#[snafu(display("malformed vote staple wrapper"))]
	MalformedStaple,
	/// Staple does not contain at least one block
	#[snafu(display("vote staple must contain at least one block"))]
	StapleBlocksAtLeastOne,
	/// Staple does not contain at least one vote
	#[snafu(display("vote staple must contain at least one vote"))]
	StapleVotesAtLeastOne,
	/// Inner staple element shape was wrong
	#[snafu(display("malformed vote staple element: {what}"))]
	MalformedStapleElement {
		/// Which element was malformed (`"blocks"` or `"votes"`)
		what: &'static str,
	},
	/// All votes in a staple must cover the same number of blocks
	#[snafu(display("votes within a staple disagree on block count"))]
	StapleBlockCountMismatch,
	/// A vote references a block hash that is not in the staple
	#[snafu(display("vote references a block hash not in the staple"))]
	StapleMissingBlock,
	/// Votes within a staple disagree on block ordering
	#[snafu(display("votes within a staple disagree on block ordering"))]
	StapleBlockOrderMismatch,
	/// Two votes in a staple share the same issuer
	#[snafu(display("vote staple has duplicate issuer"))]
	StapleDuplicateIssuer,
	/// Mixed permanent and temporary votes in a single staple
	#[snafu(display("vote staple mixes permanent and temporary votes"))]
	StaplePermanenceMismatch,
	/// Vote staple was attempted to be constructed with no inputs
	#[snafu(display("invalid vote staple construction"))]
	StapleInvalidConstruction,

	// ----- Builder-level -----
	/// Builder was misconfigured before sealing
	#[snafu(display("invalid vote builder construction"))]
	BuilderInvalidConstruction,
	/// Builder received a value that is not a block hash
	#[snafu(display("invalid block reference for vote builder"))]
	BuilderInvalidBlockType,
	/// Serial supplied to builder is not a positive integer
	#[snafu(display("invalid serial supplied to vote builder"))]
	BuilderInvalidSerial,
	/// `validity_from` / `validity_to` combination is invalid
	#[snafu(display("invalid validity range supplied to vote builder"))]
	BuilderInvalidValidToFrom,
	/// Fee value supplied to builder is invalid
	#[snafu(display("invalid fee supplied to vote builder"))]
	BuilderInvalidFee,

	// ----- Wire / DER details -----
	/// Outer wrapper does not parse as a 3-element SEQUENCE
	#[snafu(display("malformed vote wrapper"))]
	MalformedWrapper,
	/// TBS certificate did not parse as expected
	#[snafu(display("malformed vote certificate body"))]
	MalformedVoteContent,
	/// TBS certificate has unexpected trailing data
	#[snafu(display("vote certificate has extra trailing data"))]
	MalformedVoteContentExtraData,
	/// Version field had the wrong tag or contents
	#[snafu(display("malformed vote version field"))]
	MalformedVoteVersion,
	/// Serial field was missing or wrong-typed
	#[snafu(display("malformed vote serial field"))]
	MalformedVoteSerial,
	/// Signature algorithm SEQUENCE was malformed
	#[snafu(display("malformed vote signature algorithm field"))]
	MalformedVoteSignatureInformation,
	/// Issuer DN was malformed
	#[snafu(display("malformed vote issuer information"))]
	MalformedVoteIssuerInformation,
	/// Subject DN was malformed
	#[snafu(display("malformed vote subject information"))]
	MalformedVoteSubjectInformation,
	/// Validity SEQUENCE was malformed
	#[snafu(display("malformed vote validity information"))]
	MalformedVoteValidityInformation,
	/// Extensions context tag or layout was malformed
	#[snafu(display("malformed vote extensions field"))]
	MalformedVoteExtensions,
	/// Per-extension data field was malformed
	#[snafu(display("malformed vote extension contents"))]
	MalformedVoteExtensionsData,
	/// Per-extension element shape was malformed
	#[snafu(display("malformed vote extension element"))]
	MalformedVoteExtensionsValue,
	/// Per-extension OID was missing or wrong-typed
	#[snafu(display("malformed vote extension OID"))]
	MalformedVoteExtensionsValueOid,
	/// Per-extension `critical` flag was wrong-typed
	#[snafu(display("malformed vote extension critical flag"))]
	MalformedVoteExtensionsValueCritical,
	/// An unknown critical extension was encountered
	#[snafu(display("unknown critical vote extension"))]
	MalformedVoteExtensionsValueCriticalType,
	/// Wrapper signature algorithm and TBS algorithm disagree
	#[snafu(display("vote signature algorithm does not match wrapper"))]
	MalformedVoteSignatureSchemeDoesNotMatchWrapper,
	/// Wrapper signature algorithm does not match the issuer key type
	#[snafu(display("vote signature algorithm does not match issuer"))]
	MalformedVoteSignatureSchemeDoesNotMatchIssuer,
	/// Signature algorithm OID is not one we know how to verify
	#[snafu(display("unsupported vote signature scheme"))]
	MalformedVoteSignatureUnsupportedScheme,
	/// SubjectPublicKeyInfo had the wrong shape
	#[snafu(display("malformed subject public key info"))]
	MalformedVoteSubjectPublicKeyInformation,
	/// Signature BIT STRING was missing or malformed
	#[snafu(display("malformed vote signature value"))]
	MalformedVoteSignatureValue,
	/// No `hashData` extension was present in the vote certificate
	#[snafu(display("vote contains no block-hash extension"))]
	MalformedVoteNoBlocksFound,

	// ----- DN parsing helpers -----
	/// DN was not a SEQUENCE while looking for an RDN
	#[snafu(display("malformed DN: not a sequence"))]
	MalformedFindRdnInvalidType,
	/// DN was empty
	#[snafu(display("malformed DN: empty"))]
	MalformedFindRdnMustHaveOne,
	/// DN element was not well-formed (missing `name` or `value`)
	#[snafu(display("malformed DN: element not well-formed"))]
	MalformedFindRdnPartWellFormed,
	/// DN element was not a SET
	#[snafu(display("malformed DN: element not a set"))]
	MalformedFindRdnMustBeSet,
	/// DN element name was not an OID
	#[snafu(display("malformed DN: element name not an OID"))]
	MalformedFindRdnTypeMustBeOid,

	// ----- hashData extension contents -----
	/// `hashData` extension input was not parseable as ASN.1
	#[snafu(display("malformed hashData extension input"))]
	MalformedHashesFromVoteInvalidInput,
	/// `hashData` extension was not a context-specific tag
	#[snafu(display("hashData extension is not a context-specific tag"))]
	MalformedHashesFromVoteInvalidType,
	/// `hashData` extension context tag value was wrong
	#[snafu(display("hashData extension has wrong context tag"))]
	MalformedHashesFromVoteInvalidContextSpecific,
	/// `hashData` extension did not contain a 2-element SEQUENCE
	#[snafu(display("hashData extension data is not a sequence"))]
	MalformedHashesFromVoteDataHashDataMustBeSequence,
	/// `hashData` extension SEQUENCE had wrong number of items
	#[snafu(display("hashData extension expected exactly two items"))]
	MalformedHashesFromVoteDataNotTwoItems,
	/// `hashData` extension hash-algorithm OID was missing
	#[snafu(display("hashData extension is missing the hash algorithm OID"))]
	MalformedHashesFromVoteDataNeedsOid,
	/// `hashData` extension declared an unsupported hash algorithm
	#[snafu(display("hashData extension uses an unsupported hash algorithm"))]
	MalformedHashesFromVoteDataUnsupportedHashFunc,
	/// `hashData` extension blocks element was not a SEQUENCE
	#[snafu(display("hashData extension blocks element must be a sequence"))]
	MalformedHashesFromVoteDataSecondMustBeSequence,
	/// `hashData` extension contained a block hash that was not an OCTET STRING
	#[snafu(display("hashData extension contains a non-octet-string block hash"))]
	MalformedHashesFromVoteDataUnsupportedHashType,

	// ----- Fees extension -----
	/// Fee amount was negative
	#[snafu(display("fee amount cannot be negative"))]
	MalformedFeesAmount,
	/// Fees extension was not parseable as ASN.1
	#[snafu(display("fees extension is not valid ASN.1"))]
	MalformedFeesFromVoteInvalidInput,
	/// Permanent vote may not carry fees
	#[snafu(display("permanent votes cannot carry fees"))]
	MalformedFeesInPermanentVote,
	/// Fees extension `quote` flag did not match the vote variant
	#[snafu(display("fees extension quote flag does not match vote variant"))]
	MalformedFeesQuoteInvalid,
	/// Multi-fee extension was an empty array
	#[snafu(display("multiple-fee extension array is empty"))]
	MalformedFeesMultipleFeeEmpty,
	/// `payTo` field was not a valid account or storage address
	#[snafu(display("fee payTo is not an account or storage address"))]
	MalformedFeesPayToInvalid,
	/// `token` field was not a token account
	#[snafu(display("fee token field is not a token account"))]
	MalformedFeesTokenNotToken,

	// ----- Quote / non-quote distinction -----
	/// Tried to construct a `Vote` from quote bytes
	#[snafu(display("attempted to construct a Vote from a VoteQuote"))]
	FeeIsQuote,
	/// Tried to construct a `VoteQuote` from non-quote bytes
	#[snafu(display("attempted to construct a VoteQuote from a Vote"))]
	FeeNotQuote,
	/// Quote vote was missing fees
	#[snafu(display("quote vote must carry fees"))]
	FeeQuoteMissingFees,

	// ----- Round-trip strictness -----
	/// Vote bytes did not round-trip through canonical DER encoding
	#[snafu(display("vote bytes are not canonical DER"))]
	MalformedNonCanonicalEncoding,
	/// Tried to construct a [`crate::VoteQuote`] from non-quote bytes
	#[snafu(display("VoteQuote requires fees with quote=true"))]
	QuoteFeeRequired,
}

impl_source_error_from!(VoteError, {
	der::Error => Der,
	AccountError => Account,
	CryptoError => Crypto,
	BlockError => Block,
	std::io::Error => Compression,
});

impl VoteError {
	/// A stable, programmatic identifier for this error.
	///
	/// Returns [`None`] for the wrapped variants ([`VoteError::Der`],
	/// [`VoteError::Account`], [`VoteError::Crypto`],
	/// [`VoteError::Block`], [`VoteError::Compression`]) whose underlying
	/// source error already carries its own code.
	pub fn code(&self) -> Option<&'static str> {
		let code = match self {
			VoteError::SerialMismatch => "VOTE_SERIAL_MISMATCH",
			VoteError::InvalidVersion => "VOTE_INVALID_VERSION",
			VoteError::InvalidConstruction => "VOTE_INVALID_CONSTRUCTION",
			VoteError::SignatureInvalid => "VOTE_SIGNATURE_INVALID",
			VoteError::Expired => "VOTE_EXPIRED",
			VoteError::InvalidValidity => "VOTE_INVALID_VALIDITY",
			VoteError::MomentBeforeValidityFrom => "VOTE_MOMENT_BEFORE_VALIDITY_FROM",

			VoteError::StapleInvalidConstruction => "VOTE_STAPLE_INVALID_CONSTRUCTION",
			VoteError::StapleBlockCountMismatch => "VOTE_STAPLE_ALL_VOTES_MUST_HAVE_SAME_BLOCKS_COUNT",
			VoteError::StapleMissingBlock => "VOTE_STAPLE_ALL_VOTES_MUST_HAVE_SAME_BLOCKS_MISSING",
			VoteError::StapleBlockOrderMismatch => "VOTE_STAPLE_ALL_VOTES_MUST_HAVE_SAME_BLOCKS_ORDER",
			VoteError::StapleDuplicateIssuer => "VOTE_STAPLE_DUPLICATE_VOTE_ISSUER",
			VoteError::StaplePermanenceMismatch => "VOTE_STAPLE_PERMANENCE_MISMATCH",

			VoteError::BuilderInvalidConstruction => "VOTE_BUILDER_INVALID_CONSTRUCTION",
			VoteError::BuilderInvalidBlockType => "VOTE_BUILDER_INVALID_BLOCK_TYPE",
			VoteError::BuilderInvalidSerial => "VOTE_BUILDER_INVALID_SERIAL",
			VoteError::BuilderInvalidValidToFrom => "VOTE_BUILDER_INVALID_VALID_TO_FROM",
			VoteError::BuilderInvalidFee => "VOTE_BUILDER_INVALID_FEE",

			VoteError::MalformedWrapper => "VOTE_MALFORMED_WRAPPER",
			VoteError::MalformedVoteContent => "VOTE_MALFORMED_VOTE_CONTENT",
			VoteError::MalformedVoteContentExtraData => "VOTE_MALFORMED_VOTE_CONTENT_EXTRA_DATA",
			VoteError::MalformedVoteVersion => "VOTE_MALFORMED_VOTE_VERSION",
			VoteError::MalformedVoteSerial => "VOTE_MALFORMED_VOTE_SERIAL",
			VoteError::MalformedVoteSignatureInformation => "VOTE_MALFORMED_VOTE_SIGNATURE_INFORMATION",
			VoteError::MalformedVoteIssuerInformation => "VOTE_MALFORMED_VOTE_ISSUER_INFORMATION",
			VoteError::MalformedVoteSubjectInformation => "VOTE_MALFORMED_VOTE_SUBJECT_INFORMATION",
			VoteError::MalformedVoteValidityInformation => "VOTE_MALFORMED_VOTE_VALIDITY_INFORMATION",
			VoteError::MalformedVoteExtensions => "VOTE_MALFORMED_VOTE_EXTENSIONS",
			VoteError::MalformedVoteExtensionsData => "VOTE_MALFORMED_VOTE_EXTENSIONS_DATA",
			VoteError::MalformedVoteExtensionsValue => "VOTE_MALFORMED_VOTE_EXTENSIONS_VALUE",
			VoteError::MalformedVoteExtensionsValueOid => "VOTE_MALFORMED_VOTE_EXTENSIONS_VALUE_OID",
			VoteError::MalformedVoteExtensionsValueCritical => "VOTE_MALFORMED_VOTE_EXTENSIONS_VALUE_CRITICAL",
			VoteError::MalformedVoteExtensionsValueCriticalType => "VOTE_MALFORMED_VOTE_EXTENSIONS_VALUE_CRITICAL_TYPE",
			VoteError::MalformedVoteSignatureSchemeDoesNotMatchWrapper => {
				"VOTE_MALFORMED_VOTE_SIGNATURE_SCHEME_DOES_NOT_MATCH_WRAPPER"
			}
			VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer => {
				"VOTE_MALFORMED_VOTE_SIGNATURE_SCHEME_DOES_NOT_MATCH_ISSUER"
			}
			VoteError::MalformedVoteSignatureUnsupportedScheme => "VOTE_MALFORMED_VOTE_SIGNATURE_UNSUPPORTED_SCHEME",
			VoteError::MalformedVoteSubjectPublicKeyInformation => "VOTE_MALFORMED_VOTE_SUBJECT_PUBLIC_KEY_INFORMATION",
			VoteError::MalformedVoteSignatureValue => "VOTE_MALFORMED_VOTE_SIGNATURE_VALUE",
			VoteError::MalformedVoteNoBlocksFound => "VOTE_MALFORMED_VOTE_NO_BLOCKS_FOUND",

			VoteError::MalformedStaple => "VOTE_MALFORMED_STAPLE",
			VoteError::MalformedStapleElement { what: "blocks" } => "VOTE_MALFORMED_STAPLE_BLOCKS",
			VoteError::MalformedStapleElement { what: "votes" } => "VOTE_MALFORMED_STAPLE_VOTES",
			VoteError::StapleBlocksAtLeastOne => "VOTE_MALFORMED_STAPLE_BLOCKS_AT_LEAST_ONE",
			VoteError::StapleVotesAtLeastOne => "VOTE_MALFORMED_STAPLE_VOTES_AT_LEAST_ONE",

			VoteError::MalformedFindRdnInvalidType => "VOTE_MALFORMED_FIND_RDN_INVALID_TYPE",
			VoteError::MalformedFindRdnMustHaveOne => "VOTE_MALFORMED_FIND_RDN_MUST_HAVE_ONE",
			VoteError::MalformedFindRdnPartWellFormed => "VOTE_MALFORMED_FIND_RDN_PART_WELL_FORMED",
			VoteError::MalformedFindRdnMustBeSet => "VOTE_MALFORMED_FIND_RDN_MUST_BE_SET",
			VoteError::MalformedFindRdnTypeMustBeOid => "VOTE_MALFORMED_FIND_RDN_TYPE_MUST_BE_OID",

			VoteError::MalformedHashesFromVoteInvalidInput => "VOTE_MALFORMED_HASHES_FROM_VOTE_INVALID_INPUT",
			VoteError::MalformedHashesFromVoteInvalidType => "VOTE_MALFORMED_HASHES_FROM_VOTE_INVALID_TYPE",
			VoteError::MalformedHashesFromVoteInvalidContextSpecific => {
				"VOTE_MALFORMED_HASHES_FROM_VOTE_INVALID_CONTEXT_SPECIFIC"
			}
			VoteError::MalformedHashesFromVoteDataHashDataMustBeSequence => {
				"VOTE_MALFORMED_HASHES_FROM_VOTE_DATA_HASH_DATA_MUST_BE_SEQUENCE"
			}
			VoteError::MalformedHashesFromVoteDataNotTwoItems => "VOTE_MALFORMED_HASHES_FROM_VOTE_DATA_NOT_TWO_ITEMS",
			VoteError::MalformedHashesFromVoteDataNeedsOid => "VOTE_MALFORMED_HASHES_FROM_VOTE_DATA_NEEDS_OID",
			VoteError::MalformedHashesFromVoteDataUnsupportedHashFunc => {
				"VOTE_MALFORMED_HASHES_FROM_VOTE_DATA_UNSUPPORTED_HASH_FUNC"
			}
			VoteError::MalformedHashesFromVoteDataSecondMustBeSequence => {
				"VOTE_MALFORMED_HASHES_FROM_VOTE_DATA_SECOND_MUST_BE_SEQUENCE"
			}
			VoteError::MalformedHashesFromVoteDataUnsupportedHashType => {
				"VOTE_MALFORMED_HASHES_FROM_VOTE_DATA_UNSUPPORTED_HASH_TYPE"
			}

			VoteError::MalformedFeesAmount => "VOTE_MALFORMED_FEES_AMOUNT",
			VoteError::MalformedFeesFromVoteInvalidInput => "VOTE_MALFORMED_FEES_FROM_VOTE_INVALID_INPUT",
			VoteError::MalformedFeesInPermanentVote => "VOTE_MALFORMED_FEES_IN_PERMANENT_VOTE",
			VoteError::MalformedFeesQuoteInvalid => "VOTE_MALFORMED_FEES_QUOTE_INVALID",
			VoteError::MalformedFeesMultipleFeeEmpty => "VOTE_MALFORMED_FEES_MULTIPLE_FEE_EMPTY",
			VoteError::MalformedFeesPayToInvalid => "VOTE_MALFORMED_FEES_PAY_TO_INVALID",
			VoteError::MalformedFeesTokenNotToken => "VOTE_MALFORMED_FEES_TOKEN_NOT_TOKEN",

			VoteError::FeeIsQuote => "VOTE_FEE_IS_QUOTE",
			VoteError::FeeNotQuote => "VOTE_FEE_NOT_QUOTE",
			VoteError::FeeQuoteMissingFees => "VOTE_FEE_QUOTE_MISSING_FEES",

			_ => return None,
		};

		Some(code)
	}
}

impl From<VoteError> for KeetaNetError {
	fn from(error: VoteError) -> Self {
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
		assert_eq!(VoteError::SerialMismatch.code(), Some("VOTE_SERIAL_MISMATCH"));
		assert_eq!(VoteError::Expired.code(), Some("VOTE_EXPIRED"));
		assert_eq!(VoteError::FeeIsQuote.code(), Some("VOTE_FEE_IS_QUOTE"));
		assert_eq!(VoteError::Crypto { source: CryptoError::InvalidInput }.code(), None);
	}

	#[test]
	fn test_staple_element_codes_split() {
		assert_eq!(VoteError::MalformedStapleElement { what: "blocks" }.code(), Some("VOTE_MALFORMED_STAPLE_BLOCKS"));
		assert_eq!(VoteError::MalformedStapleElement { what: "votes" }.code(), Some("VOTE_MALFORMED_STAPLE_VOTES"));
	}

	#[test]
	fn test_keetanet_error_bridge() {
		let bridged = KeetaNetError::from(VoteError::SerialMismatch);
		assert!(matches!(bridged, KeetaNetError::Code { code, .. } if code == "VOTE_SERIAL_MISMATCH"));

		let unknown = KeetaNetError::from(VoteError::Crypto { source: CryptoError::InvalidInput });
		assert!(matches!(unknown, KeetaNetError::Unknown { .. }));
	}

	#[test]
	fn test_source_conversions() {
		assert!(matches!(VoteError::from(der::Error::incomplete(der::Length::ZERO)), VoteError::Der { .. }));
		assert!(matches!(VoteError::from(AccountError::InvalidKeyType), VoteError::Account { .. }));
		assert!(matches!(VoteError::from(CryptoError::InvalidInput), VoteError::Crypto { .. }));
	}
}
