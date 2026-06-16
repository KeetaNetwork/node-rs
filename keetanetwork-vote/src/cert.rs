//! Vote certificate (TBS) encoding and decoding.
//!
//! Votes are X.509-shaped certificates built on top of the
//! [`keetanetwork_asn1::vote`] codec. This module owns the domain-level
//! mapping between vote-crate types ([`AccountRef`], [`Validity`],
//! [`Fees`], [`BlockHash`]) and the codec's neutral transport types,
//! plus the extension list assembled during encode and parsed during decode.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use hex::FromHex;
use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_asn1::vote as transport;
use keetanetwork_block::{AccountRef, BlockHash};
use num_bigint::BigInt;
use num_traits::Num;

use crate::error::VoteError;
use crate::fee::Fees;
use crate::validity::Validity;

/// Signature algorithm carried in a vote's `signatureAlgo` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureAlgo {
	Ed25519,
	EcdsaWithSha3_256,
}

impl SignatureAlgo {
	pub(crate) fn from_issuer(account: &GenericAccount) -> Result<Self, VoteError> {
		match account.to_keypair_type() {
			KeyPairType::ED25519 => Ok(Self::Ed25519),
			KeyPairType::ECDSASECP256K1 | KeyPairType::ECDSASECP256R1 => Ok(Self::EcdsaWithSha3_256),
			_ => Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer),
		}
	}

	fn matches_issuer(self, account: &GenericAccount) -> bool {
		matches!(
			(self, account.to_keypair_type()),
			(Self::Ed25519, KeyPairType::ED25519)
				| (Self::EcdsaWithSha3_256, KeyPairType::ECDSASECP256K1 | KeyPairType::ECDSASECP256R1)
		)
	}

	fn to_transport(self) -> transport::VoteSignatureAlgo {
		match self {
			Self::Ed25519 => transport::VoteSignatureAlgo::Ed25519,
			Self::EcdsaWithSha3_256 => transport::VoteSignatureAlgo::EcdsaWithSha3_256,
		}
	}

	fn from_transport(value: transport::VoteSignatureAlgo) -> Self {
		match value {
			transport::VoteSignatureAlgo::Ed25519 => Self::Ed25519,
			transport::VoteSignatureAlgo::EcdsaWithSha3_256 => Self::EcdsaWithSha3_256,
		}
	}
}

/// Decoded contents of a vote certificate.
#[derive(Debug, Clone)]
pub(crate) struct DecodedVote {
	pub(crate) serial: BigInt,
	pub(crate) signature_algo: SignatureAlgo,
	pub(crate) issuer: AccountRef,
	pub(crate) validity: Validity,
	pub(crate) blocks: Vec<BlockHash>,
	pub(crate) fees: Option<Fees>,
	pub(crate) signature: Vec<u8>,
	/// Exact TBS bytes used by signature verification (the SEQUENCE TLV
	/// including outer tag and length).
	pub(crate) tbs_bytes: Vec<u8>,
}

/// Build the transport-shape TBS body for a vote.
pub(crate) fn build_tbs(
	serial: &BigInt,
	signature_algo: SignatureAlgo,
	issuer: &AccountRef,
	validity: Validity,
	blocks: &[BlockHash],
	fees: Option<&Fees>,
) -> Result<transport::TbsCertificate, VoteError> {
	if signature_algo != SignatureAlgo::from_issuer(issuer)? {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer);
	}
	build_tbs_inner(serial, signature_algo, issuer, validity, blocks, fees)
}

/// Encode a TBS certificate body for a vote (the bytes signed by the issuer).
pub(crate) fn encode_tbs(tbs: &transport::TbsCertificate) -> Result<Vec<u8>, VoteError> {
	transport::encode_tbs(tbs).map_err(VoteError::from)
}

/// Encode a complete signed vote (TBS + signature wrapper).
pub(crate) fn encode_vote(
	tbs: transport::TbsCertificate,
	signature_algo: SignatureAlgo,
	signature: Vec<u8>,
) -> Result<Vec<u8>, VoteError> {
	let value = transport::VoteCertificate { tbs, signature_algo: signature_algo.to_transport(), signature };
	transport::encode_vote(&value).map_err(VoteError::from)
}

/// Decode a vote wrapper into its constituent fields.
pub(crate) fn decode_wrapper(bytes: &[u8]) -> Result<DecodedVote, VoteError> {
	let decoded = transport::decode_vote(bytes).map_err(decode_error_to_vote)?;
	if decoded.tbs.signature_algo != decoded.signature_algo {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchWrapper);
	}

	let signature_algo = SignatureAlgo::from_transport(decoded.signature_algo);
	let serial = decoded.tbs.serial_number.clone();

	let issuer_string = take_dn_value(&decoded.tbs.issuer, &transport::oids::COMMON_NAME)
		.ok_or(VoteError::MalformedVoteIssuerInformation)?;
	let issuer: AccountRef = Arc::new(
		issuer_string
			.parse::<GenericAccount>()
			.map_err(|_| VoteError::MalformedVoteIssuerInformation)?,
	);

	if !signature_algo.matches_issuer(&issuer) {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer);
	}

	// Reference treats both "no serialNumber RDN" and "serialNumber RDN
	// is not a hex string" as MALFORMED_VOTE_SERIAL (typeof check on the
	// `findRDN` result).
	let subject_serial_hex =
		take_dn_value(&decoded.tbs.subject, &transport::oids::SERIAL_NUMBER).ok_or(VoteError::MalformedVoteSerial)?;
	let subject_serial = parse_lower_hex_bigint(&subject_serial_hex).map_err(|_| VoteError::MalformedVoteSerial)?;
	if subject_serial != serial {
		return Err(VoteError::SerialMismatch);
	}

	let subject_public_key = decode_subject_public_key(&decoded.tbs.subject_public_key)?;
	if !accounts_match(&subject_public_key, &issuer) {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer);
	}

	let validity = Validity::try_new(decoded.tbs.validity.not_before.into(), decoded.tbs.validity.not_after.into())?;
	let (blocks, fees) = collect_extensions(&decoded.tbs.extensions)?;

	Ok(DecodedVote {
		serial,
		signature_algo,
		issuer,
		validity,
		blocks,
		fees,
		signature: decoded.signature,
		tbs_bytes: decoded.tbs_bytes,
	})
}

// ---------------------------------------------------------------------------
// Transport <-> domain helpers
// ---------------------------------------------------------------------------

fn build_tbs_inner(
	serial: &BigInt,
	signature_algo: SignatureAlgo,
	issuer: &AccountRef,
	validity: Validity,
	blocks: &[BlockHash],
	fees: Option<&Fees>,
) -> Result<transport::TbsCertificate, VoteError> {
	Ok(transport::TbsCertificate {
		serial_number: serial.clone(),
		signature_algo: signature_algo.to_transport(),
		issuer: dn_with_attribute(transport::oids::COMMON_NAME, issuer.to_string()),
		validity: transport::Validity { not_before: validity.from.into(), not_after: validity.to.into() },
		subject: dn_with_attribute(transport::oids::SERIAL_NUMBER, bigint_to_lower_hex(serial)),
		subject_public_key: subject_public_key_for_issuer(issuer)?,
		extensions: build_extension_list(blocks, fees)?,
	})
}

fn dn_with_attribute(oid: transport::VoteOid, value: String) -> transport::DistinguishedName {
	transport::DistinguishedName { rdns: vec![vec![transport::AttributeTypeAndValue { oid, value }]] }
}

fn take_dn_value(dn: &transport::DistinguishedName, oid: &transport::VoteOid) -> Option<String> {
	let mut found: Option<String> = None;
	for rdn in &dn.rdns {
		for attribute in rdn {
			if &attribute.oid == oid {
				found = Some(attribute.value.clone());
			}
		}
	}
	found
}

fn subject_public_key_for_issuer(issuer: &AccountRef) -> Result<transport::VoteSubjectPublicKey, VoteError> {
	let bytes = issuer.to_public_key_with_type();
	let raw = bytes
		.get(1..)
		.ok_or(VoteError::MalformedVoteSubjectPublicKeyInformation)?
		.to_vec();
	match issuer.to_keypair_type() {
		KeyPairType::ED25519 => Ok(transport::VoteSubjectPublicKey::Ed25519 { key: raw }),
		KeyPairType::ECDSASECP256K1 => {
			Ok(transport::VoteSubjectPublicKey::Ecdsa { curve: transport::EcdsaCurve::Secp256k1, key: raw })
		}
		KeyPairType::ECDSASECP256R1 => {
			Ok(transport::VoteSubjectPublicKey::Ecdsa { curve: transport::EcdsaCurve::Secp256r1, key: raw })
		}
		_ => Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer),
	}
}

fn decode_subject_public_key(value: &transport::VoteSubjectPublicKey) -> Result<AccountRef, VoteError> {
	let (key_type, raw) = match value {
		transport::VoteSubjectPublicKey::Ed25519 { key } => (KeyPairType::ED25519, key),
		transport::VoteSubjectPublicKey::Ecdsa { curve, key } => match curve {
			transport::EcdsaCurve::Secp256k1 => (KeyPairType::ECDSASECP256K1, key),
			transport::EcdsaCurve::Secp256r1 => (KeyPairType::ECDSASECP256R1, key),
		},
	};

	let mut bytes = Vec::with_capacity(1 + raw.len());
	bytes.push(key_type as u8);
	bytes.extend_from_slice(raw);

	let account = GenericAccount::from_hex(hex::encode(bytes))
		.map_err(|_| VoteError::MalformedVoteSubjectPublicKeyInformation)?;

	Ok(Arc::new(account))
}

fn build_extension_list(blocks: &[BlockHash], fees: Option<&Fees>) -> Result<Vec<transport::Extension>, VoteError> {
	let mut extensions = Vec::new();
	let hash_data = transport::HashData {
		algorithm: transport::oids::SHA3_256,
		hashes: blocks.iter().map(|hash| hash.as_bytes().to_vec()).collect(),
	};

	let hash_data_value = transport::encode_hash_data(&hash_data).map_err(VoteError::from)?;
	extensions.push(transport::Extension { oid: transport::oids::HASH_DATA, critical: true, value: hash_data_value });

	if let Some(fees) = fees {
		let fees_transport = fees.to_transport()?;
		let fees_value = transport::encode_fees(&fees_transport).map_err(VoteError::from)?;
		extensions.push(transport::Extension { oid: transport::oids::FEES, critical: true, value: fees_value });
	}

	Ok(extensions)
}

fn collect_extensions(extensions: &[transport::Extension]) -> Result<(Vec<BlockHash>, Option<Fees>), VoteError> {
	let mut blocks: Option<Vec<BlockHash>> = None;
	let mut fees: Option<Fees> = None;

	for extension in extensions {
		if extension.oid == transport::oids::HASH_DATA {
			let hash_data = transport::decode_hash_data(&extension.value).map_err(hash_data_error)?;
			if hash_data.algorithm != transport::oids::SHA3_256 {
				return Err(VoteError::MalformedHashesFromVoteDataUnsupportedHashFunc);
			}

			let mut converted = Vec::with_capacity(hash_data.hashes.len());
			for raw in hash_data.hashes {
				let hash = BlockHash::try_from(raw.as_slice())
					.map_err(|_| VoteError::MalformedHashesFromVoteDataUnsupportedHashType)?;
				converted.push(hash);
			}

			blocks = Some(converted);
		} else if extension.oid == transport::oids::FEES {
			fees = Some(Fees::from_transport(transport::decode_fees(&extension.value).map_err(fees_error)?)?);
		} else if extension.critical {
			return Err(VoteError::MalformedVoteExtensionsValueCriticalType);
		}
	}

	let blocks = blocks.ok_or(VoteError::MalformedVoteNoBlocksFound)?;
	Ok((blocks, fees))
}

fn decode_error_to_vote(error: keetanetwork_asn1::Asn1Error) -> VoteError {
	use keetanetwork_asn1::vote::VoteDecodeSlot;
	use keetanetwork_asn1::Asn1Error;
	match error {
		Asn1Error::InvalidVoteVersion => VoteError::InvalidVersion,
		Asn1Error::VoteDecode { slot } => match slot {
			VoteDecodeSlot::Wrapper => VoteError::MalformedWrapper,
			VoteDecodeSlot::WrapperExtraData => VoteError::MalformedWrapper,
			VoteDecodeSlot::TbsContent => VoteError::MalformedVoteWrapper,
			VoteDecodeSlot::Version => VoteError::MalformedVoteContent,
			VoteDecodeSlot::VersionValue => VoteError::MalformedVoteVersion,
			VoteDecodeSlot::Serial => VoteError::MalformedVoteSerial,
			VoteDecodeSlot::SignatureAlgorithm => VoteError::MalformedVoteSignatureInformation,
			VoteDecodeSlot::Issuer => VoteError::MalformedVoteIssuerInformation,
			VoteDecodeSlot::Validity => VoteError::MalformedVoteValidityInformation,
			VoteDecodeSlot::Subject => VoteError::MalformedVoteSubjectInformation,
			VoteDecodeSlot::SubjectPublicKey => VoteError::MalformedVoteSubjectPublicKeyInformation,
			VoteDecodeSlot::Extensions => VoteError::MalformedVoteExtensions,
			VoteDecodeSlot::TbsExtraData => VoteError::MalformedVoteContentExtraData,
			VoteDecodeSlot::WrapperSignatureAlgorithm => VoteError::MalformedVoteSignatureInformation,
			VoteDecodeSlot::SignatureValue => VoteError::MalformedVoteSignatureValue,
		},
		other => other.into(),
	}
}

fn hash_data_error(_error: keetanetwork_asn1::Asn1Error) -> VoteError {
	VoteError::MalformedHashesFromVoteInvalidInput
}

fn fees_error(_error: keetanetwork_asn1::Asn1Error) -> VoteError {
	VoteError::MalformedFeesFromVoteInvalidInput
}

fn accounts_match(left: &AccountRef, right: &AccountRef) -> bool {
	left.to_public_key_with_type() == right.to_public_key_with_type()
}

fn bigint_to_lower_hex(value: &BigInt) -> String {
	value.to_str_radix(16)
}

fn parse_lower_hex_bigint(value: &str) -> Result<BigInt, num_bigint::ParseBigIntError> {
	BigInt::from_str_radix(value, 16)
}
