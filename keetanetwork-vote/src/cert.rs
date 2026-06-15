//! Vote certificate (TBS) encoding and decoding.
//!
//! Votes are X.509-shaped certificates encoded in DER. The wrapper carries
//! a `tbsCertificate` body, the signature algorithm identifier, and the
//! signature value as a `BIT STRING`:
//!
//! ```text
//! VoteWrapper ::= SEQUENCE {
//!     tbs            TbsCertificate,
//!     signatureAlgo  AlgorithmIdentifier,
//!     signatureValue BIT STRING
//! }
//!
//! TbsCertificate ::= SEQUENCE {
//!     [0] EXPLICIT INTEGER  version (X.509 v3, encoded as 2),
//!     INTEGER               serial,
//!     AlgorithmIdentifier   tbsSignatureAlgo,
//!     SEQUENCE OF Set       issuer,
//!     SEQUENCE              validity { GeneralizedTime, GeneralizedTime },
//!     SEQUENCE OF Set       subject,
//!     SEQUENCE              subjectPublicKeyInfo { AlgorithmIdentifier, BIT STRING },
//!     [3] EXPLICIT SEQUENCE extensions
//! }
//! ```
//!
//! ## Recognized Extensions
//!
//! Two extensions populate the `extensions` field:
//!
//! - **`hashData`** - the SHA3-256 digests of every block this vote
//!   covers, in declaration order. Always present and always critical.
//! - **`fees`** - the fee schedule the issuer attaches to the vote, with
//!   a `quote` flag distinguishing binding votes from non-binding quotes.
//!   Optional. Critical when present.

use std::sync::Arc;

use der::asn1::{BitStringRef, ObjectIdentifier, Utf8StringRef};
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};
use hex::FromHex;
use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_block::{AccountRef, Amount, BlockHash, BlockTime};
use num_bigint::BigInt;
use num_traits::Num;

use crate::error::VoteError;
use crate::extension::{decode_extension, decode_hash_data, encode_fees_extension, encode_hash_data_extension};
use crate::fee::Fees;
use crate::oids::{
	COMMON_NAME, ECDSA_WITH_SHA3_256, EC_PUBLIC_KEY, ED25519, FEES, HASH_DATA, SECP256K1, SECP256R1, SERIAL_NUMBER,
};
use crate::validity::Validity;
use crate::wire::{
	encode_amount, read_bigint, read_bit_string, read_explicit_context, read_sequence, read_utf8, unexpected_tag,
	wrap_explicit_context, wrap_sequence,
};

const VERSION_TAG: TagNumber = TagNumber::N0;
const EXTENSIONS_TAG: TagNumber = TagNumber::N3;
const VOTE_VERSION_VALUE: u8 = 2;

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

	fn oid(self) -> ObjectIdentifier {
		match self {
			Self::Ed25519 => ED25519,
			Self::EcdsaWithSha3_256 => ECDSA_WITH_SHA3_256,
		}
	}

	fn from_oid(oid: ObjectIdentifier) -> Result<Self, VoteError> {
		if oid == ED25519 {
			Ok(Self::Ed25519)
		} else if oid == ECDSA_WITH_SHA3_256 {
			Ok(Self::EcdsaWithSha3_256)
		} else {
			Err(VoteError::MalformedVoteSignatureUnsupportedScheme)
		}
	}

	fn matches_issuer(self, account: &GenericAccount) -> bool {
		matches!(
			(self, account.to_keypair_type()),
			(Self::Ed25519, KeyPairType::ED25519)
				| (Self::EcdsaWithSha3_256, KeyPairType::ECDSASECP256K1 | KeyPairType::ECDSASECP256R1)
		)
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

/// Encode a TBS certificate body for a vote.
pub(crate) fn encode_tbs(
	serial: &BigInt,
	signature_algo: SignatureAlgo,
	issuer: &AccountRef,
	validity: Validity,
	blocks: &[BlockHash],
	fees: Option<&Fees>,
) -> Result<Vec<u8>, VoteError> {
	if signature_algo != SignatureAlgo::from_issuer(issuer)? {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer);
	}

	let mut out = Vec::new();

	let mut version = Vec::new();
	let version_amount: Amount = BigInt::from(VOTE_VERSION_VALUE).into();
	encode_amount(&mut version, &version_amount)?;
	out.extend_from_slice(&wrap_explicit_context(VERSION_TAG, &version)?);

	let serial_amount: Amount = serial.clone().into();
	encode_amount(&mut out, &serial_amount)?;

	out.extend_from_slice(&encode_signature_algo_sequence(signature_algo)?);
	out.extend_from_slice(&encode_dn(COMMON_NAME, &issuer.to_string())?);
	out.extend_from_slice(&encode_validity(validity)?);

	let serial_hex = bigint_to_lower_hex(serial);
	out.extend_from_slice(&encode_dn(SERIAL_NUMBER, &serial_hex)?);
	out.extend_from_slice(&encode_subject_public_key_info(issuer)?);
	out.extend_from_slice(&encode_extensions(blocks, fees)?);

	wrap_sequence(&out)
}

/// Encode the wrapper SEQUENCE around an already-built TBS and its signature.
pub(crate) fn encode_wrapper(
	tbs_bytes: &[u8],
	signature_algo: SignatureAlgo,
	signature: &[u8],
) -> Result<Vec<u8>, VoteError> {
	let mut out = Vec::new();
	out.extend_from_slice(tbs_bytes);
	out.extend_from_slice(&encode_signature_algo_sequence(signature_algo)?);
	out.extend_from_slice(&encode_signature_bit_string(signature)?);

	wrap_sequence(&out)
}

/// Decode a vote wrapper into its constituent fields.
pub(crate) fn decode_wrapper(bytes: &[u8]) -> Result<DecodedVote, VoteError> {
	let mut outer = SliceReader::new(bytes).map_err(|_| VoteError::MalformedWrapper)?;
	let wrapper_inner = read_sequence(&mut outer).map_err(|_| VoteError::MalformedWrapper)?;
	if !outer.is_finished() {
		return Err(VoteError::MalformedWrapper);
	}

	let mut wrapper_reader = SliceReader::new(wrapper_inner).map_err(|_| VoteError::MalformedWrapper)?;

	let tbs_bytes = capture_tlv(&mut wrapper_reader, Tag::Sequence).map_err(|_| VoteError::MalformedVoteContent)?;
	let mut tbs_outer = SliceReader::new(&tbs_bytes).map_err(|_| VoteError::MalformedVoteContent)?;
	let tbs_content = read_sequence(&mut tbs_outer).map_err(|_| VoteError::MalformedVoteContent)?;
	if !tbs_outer.is_finished() {
		return Err(VoteError::MalformedVoteContent);
	}

	let mut tbs_reader = SliceReader::new(tbs_content).map_err(|_| VoteError::MalformedVoteContent)?;

	let version_bytes =
		read_explicit_context(&mut tbs_reader, VERSION_TAG).map_err(|_| VoteError::MalformedVoteContent)?;
	let mut version_reader = SliceReader::new(version_bytes).map_err(|_| VoteError::MalformedVoteVersion)?;
	let version = read_bigint(&mut version_reader).map_err(|_| VoteError::MalformedVoteVersion)?;
	if !version_reader.is_finished() {
		return Err(VoteError::MalformedVoteVersion);
	}
	if version != BigInt::from(VOTE_VERSION_VALUE) {
		return Err(VoteError::InvalidVersion);
	}

	let serial = read_bigint(&mut tbs_reader).map_err(|_| VoteError::MalformedVoteSerial)?;

	let tbs_signature_algo =
		decode_signature_algo_sequence(&mut tbs_reader).map_err(|_| VoteError::MalformedVoteSignatureInformation)?;

	let issuer_string =
		decode_dn_value(&mut tbs_reader, COMMON_NAME).map_err(|_| VoteError::MalformedVoteIssuerInformation)?;
	let issuer: AccountRef = Arc::new(
		issuer_string
			.parse::<GenericAccount>()
			.map_err(|_| VoteError::MalformedVoteIssuerInformation)?,
	);

	let validity = decode_validity(&mut tbs_reader)?;

	let subject_serial_hex =
		decode_dn_value(&mut tbs_reader, SERIAL_NUMBER).map_err(|_| VoteError::MalformedVoteSubjectInformation)?;
	let subject_serial = parse_lower_hex_bigint(&subject_serial_hex).map_err(|_| VoteError::MalformedVoteSerial)?;
	if subject_serial != serial {
		return Err(VoteError::SerialMismatch);
	}

	let subject_public_key = decode_subject_public_key_info(&mut tbs_reader)
		.map_err(|_| VoteError::MalformedVoteSubjectPublicKeyInformation)?;

	let (blocks, fees) = decode_extensions(&mut tbs_reader)?;

	if !tbs_reader.is_finished() {
		return Err(VoteError::MalformedVoteContentExtraData);
	}

	let wrapper_signature_algo = decode_signature_algo_sequence(&mut wrapper_reader)
		.map_err(|_| VoteError::MalformedVoteSignatureInformation)?;
	if wrapper_signature_algo != tbs_signature_algo {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchWrapper);
	}

	if !wrapper_signature_algo.matches_issuer(&issuer) {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer);
	}
	if !accounts_match(&subject_public_key, &issuer) {
		return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer);
	}

	let signature = decode_signature_bit_string(&mut wrapper_reader)?;

	if !wrapper_reader.is_finished() {
		return Err(VoteError::MalformedWrapper);
	}

	Ok(DecodedVote {
		serial,
		signature_algo: wrapper_signature_algo,
		issuer,
		validity,
		blocks,
		fees,
		signature,
		tbs_bytes,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encode_signature_algo_sequence(algo: SignatureAlgo) -> Result<Vec<u8>, VoteError> {
	let mut content = Vec::new();
	algo.oid().encode_to_vec(&mut content)?;
	wrap_sequence(&content)
}

fn decode_signature_algo_sequence(reader: &mut SliceReader<'_>) -> Result<SignatureAlgo, VoteError> {
	let inner = read_sequence(reader)?;
	let mut inner_reader = SliceReader::new(inner)?;
	let oid = ObjectIdentifier::decode(&mut inner_reader)?;
	if !inner_reader.is_finished() {
		return Err(VoteError::MalformedVoteSignatureInformation);
	}
	SignatureAlgo::from_oid(oid)
}

fn encode_dn(attribute_oid: ObjectIdentifier, value: &str) -> Result<Vec<u8>, VoteError> {
	let mut attr = Vec::new();
	attribute_oid.encode_to_vec(&mut attr)?;
	Utf8StringRef::new(value)?.encode_to_vec(&mut attr)?;
	let attr_seq = wrap_sequence(&attr)?;
	let set_bytes = wrap_set(&attr_seq)?;
	wrap_sequence(&set_bytes)
}

fn wrap_set(content: &[u8]) -> Result<Vec<u8>, VoteError> {
	Ok(der::asn1::AnyRef::new(Tag::Set, content)?.to_der()?)
}

fn read_set<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], VoteError> {
	let any = der::asn1::AnyRef::decode(reader)?;
	if any.tag() != Tag::Set {
		return Err(unexpected_tag(any.tag()));
	}
	Ok(any.value())
}

fn decode_dn_value(reader: &mut SliceReader<'_>, expected_oid: ObjectIdentifier) -> Result<String, VoteError> {
	let dn_inner = read_sequence(reader)?;
	let mut dn_reader = SliceReader::new(dn_inner)?;
	let mut attribute_value: Option<String> = None;
	while !dn_reader.is_finished() {
		let set_inner = read_set(&mut dn_reader)?;
		let mut set_reader = SliceReader::new(set_inner)?;
		while !set_reader.is_finished() {
			let attr_inner = read_sequence(&mut set_reader)?;
			let mut attr_reader = SliceReader::new(attr_inner)?;
			let oid = ObjectIdentifier::decode(&mut attr_reader)?;
			let value = read_utf8(&mut attr_reader)?;
			if !attr_reader.is_finished() {
				return Err(VoteError::MalformedFindRdnPartWellFormed);
			}

			if oid == expected_oid {
				attribute_value = Some(value);
			}
		}
	}

	attribute_value.ok_or(VoteError::MalformedFindRdnMustHaveOne)
}

fn encode_validity(validity: Validity) -> Result<Vec<u8>, VoteError> {
	let mut content = Vec::new();
	validity.from.encode_to_vec(&mut content)?;
	validity.to.encode_to_vec(&mut content)?;
	wrap_sequence(&content)
}

fn decode_validity(reader: &mut SliceReader<'_>) -> Result<Validity, VoteError> {
	let inner = read_sequence(reader).map_err(|_| VoteError::MalformedVoteValidityInformation)?;
	let mut inner_reader = SliceReader::new(inner).map_err(|_| VoteError::MalformedVoteValidityInformation)?;
	let from = BlockTime::decode(&mut inner_reader).map_err(|_| VoteError::MalformedVoteValidityInformation)?;
	let to = BlockTime::decode(&mut inner_reader).map_err(|_| VoteError::MalformedVoteValidityInformation)?;
	if !inner_reader.is_finished() {
		return Err(VoteError::MalformedVoteValidityInformation);
	}

	Validity::try_new(from, to)
}

fn encode_subject_public_key_info(account: &AccountRef) -> Result<Vec<u8>, VoteError> {
	let bytes = account.to_public_key_with_type();
	let raw = bytes
		.get(1..)
		.ok_or(VoteError::MalformedVoteSubjectPublicKeyInformation)?;

	let algo_seq = match account.to_keypair_type() {
		KeyPairType::ED25519 => {
			let mut content = Vec::new();
			ED25519.encode_to_vec(&mut content)?;
			wrap_sequence(&content)?
		}
		KeyPairType::ECDSASECP256K1 => {
			let mut content = Vec::new();
			EC_PUBLIC_KEY.encode_to_vec(&mut content)?;
			SECP256K1.encode_to_vec(&mut content)?;
			wrap_sequence(&content)?
		}
		KeyPairType::ECDSASECP256R1 => {
			let mut content = Vec::new();
			EC_PUBLIC_KEY.encode_to_vec(&mut content)?;
			SECP256R1.encode_to_vec(&mut content)?;
			wrap_sequence(&content)?
		}
		_ => return Err(VoteError::MalformedVoteSignatureSchemeDoesNotMatchIssuer),
	};

	let bit_string = BitStringRef::from_bytes(raw)?.to_der()?;

	let mut content = Vec::new();
	content.extend_from_slice(&algo_seq);
	content.extend_from_slice(&bit_string);
	wrap_sequence(&content)
}

fn decode_subject_public_key_info(reader: &mut SliceReader<'_>) -> Result<AccountRef, VoteError> {
	let inner = read_sequence(reader)?;
	let mut inner_reader = SliceReader::new(inner)?;
	let algo_inner = read_sequence(&mut inner_reader)?;

	let mut algo_reader = SliceReader::new(algo_inner)?;
	let first_oid = ObjectIdentifier::decode(&mut algo_reader)?;
	let key_type = if first_oid == ED25519 {
		if !algo_reader.is_finished() {
			return Err(VoteError::MalformedVoteSubjectPublicKeyInformation);
		}

		KeyPairType::ED25519
	} else if first_oid == EC_PUBLIC_KEY {
		let curve_oid = ObjectIdentifier::decode(&mut algo_reader)?;
		if !algo_reader.is_finished() {
			return Err(VoteError::MalformedVoteSubjectPublicKeyInformation);
		}
		if curve_oid == SECP256K1 {
			KeyPairType::ECDSASECP256K1
		} else if curve_oid == SECP256R1 {
			KeyPairType::ECDSASECP256R1
		} else {
			return Err(VoteError::MalformedVoteSubjectPublicKeyInformation);
		}
	} else {
		return Err(VoteError::MalformedVoteSubjectPublicKeyInformation);
	};

	let raw = read_bit_string(&mut inner_reader)?;
	if !inner_reader.is_finished() {
		return Err(VoteError::MalformedVoteSubjectPublicKeyInformation);
	}

	let mut bytes = Vec::with_capacity(1 + raw.len());
	bytes.push(key_type as u8);
	bytes.extend_from_slice(raw);

	let account = GenericAccount::from_hex(hex::encode(bytes))
		.map_err(|_| VoteError::MalformedVoteSubjectPublicKeyInformation)?;

	Ok(Arc::new(account))
}

fn encode_signature_bit_string(signature: &[u8]) -> Result<Vec<u8>, VoteError> {
	Ok(BitStringRef::from_bytes(signature)?.to_der()?)
}

fn decode_signature_bit_string(reader: &mut SliceReader<'_>) -> Result<Vec<u8>, VoteError> {
	let value = BitStringRef::decode(reader).map_err(|_| VoteError::MalformedVoteSignatureValue)?;
	let bytes = value
		.as_bytes()
		.ok_or(VoteError::MalformedVoteSignatureValue)?;

	Ok(bytes.to_vec())
}

fn encode_extensions(blocks: &[BlockHash], fees: Option<&Fees>) -> Result<Vec<u8>, VoteError> {
	let mut content = Vec::new();

	content.extend_from_slice(&encode_hash_data_extension(blocks)?);

	if let Some(fees) = fees {
		content.extend_from_slice(&encode_fees_extension(fees)?);
	}

	let sequence = wrap_sequence(&content)?;
	wrap_explicit_context(EXTENSIONS_TAG, &sequence)
}

fn decode_extensions(reader: &mut SliceReader<'_>) -> Result<(Vec<BlockHash>, Option<Fees>), VoteError> {
	let extensions_inner =
		read_explicit_context(reader, EXTENSIONS_TAG).map_err(|_| VoteError::MalformedVoteExtensions)?;

	let mut extensions_reader = SliceReader::new(extensions_inner).map_err(|_| VoteError::MalformedVoteExtensions)?;
	if !extensions_reader.is_finished() {
		return Err(VoteError::MalformedVoteExtensions);
	}
	
	let sequence_inner = read_sequence(&mut extensions_reader).map_err(|_| VoteError::MalformedVoteExtensions)?;
	let mut sequence_reader = SliceReader::new(sequence_inner)?;
	let mut blocks: Option<Vec<BlockHash>> = None;
	let mut fees: Option<Fees> = None;
	while !sequence_reader.is_finished() {
		let tlv = capture_tlv(&mut sequence_reader, Tag::Sequence)?;
		let extension = decode_extension(&tlv)?;
		if extension.oid == HASH_DATA {
			blocks = Some(decode_hash_data(extension.value)?);
		} else if extension.oid == FEES {
			fees = Some(Fees::decode_extension_body(extension.value)?);
		} else if extension.critical {
			return Err(VoteError::MalformedVoteExtensionsValueCriticalType);
		}
	}

	let blocks = blocks.ok_or(VoteError::MalformedVoteNoBlocksFound)?;
	Ok((blocks, fees))
}

fn capture_tlv(reader: &mut SliceReader<'_>, expected_tag: Tag) -> Result<Vec<u8>, VoteError> {
	let any = der::asn1::AnyRef::decode(reader)?;
	if any.tag() != expected_tag {
		return Err(unexpected_tag(any.tag()));
	}

	Ok(any.to_der()?)
}

fn accounts_match(left: &AccountRef, right: &AccountRef) -> bool {
	left.to_public_key_with_type() == right.to_public_key_with_type()
}

fn bigint_to_lower_hex(value: &BigInt) -> String {
	// Lower-case, no `0x` prefix, no leading zeros: the canonical hex
	// shape that the subject DN serial string is compared against.
	value.to_str_radix(16)
}

fn parse_lower_hex_bigint(value: &str) -> Result<BigInt, num_bigint::ParseBigIntError> {
	BigInt::from_str_radix(value, 16)
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::testing::{ed25519_issuer, find_version_tag, secp256k1_issuer, validity_seconds};

	/// Encode a TBS preamble + serial number + signature algo + issuer DN +
	/// validity + subject DN. Centralizes the boilerplate that two manual
	/// TBS-construction tests share.
	fn encode_tbs_preamble(
		serial: &BigInt,
		subject_serial_hex: &str,
		issuer: &AccountRef,
		validity: Validity,
	) -> Result<Vec<u8>, VoteError> {
		let mut out = Vec::new();

		let mut version = Vec::new();
		let version_amount: Amount = BigInt::from(VOTE_VERSION_VALUE).into();
		encode_amount(&mut version, &version_amount)?;

		out.extend_from_slice(&wrap_explicit_context(VERSION_TAG, &version)?);

		let serial_amount: Amount = serial.clone().into();
		encode_amount(&mut out, &serial_amount)?;

		out.extend_from_slice(&encode_signature_algo_sequence(SignatureAlgo::Ed25519)?);
		out.extend_from_slice(&encode_dn(COMMON_NAME, &issuer.to_string())?);
		out.extend_from_slice(&encode_validity(validity)?);
		out.extend_from_slice(&encode_dn(SERIAL_NUMBER, subject_serial_hex)?);
		out.extend_from_slice(&encode_subject_public_key_info(issuer)?);

		Ok(out)
	}

	#[test]
	fn test_signature_algo_round_trip_via_oid() -> Result<(), VoteError> {
		assert_eq!(SignatureAlgo::Ed25519.oid(), ED25519);
		assert_eq!(SignatureAlgo::EcdsaWithSha3_256.oid(), ECDSA_WITH_SHA3_256);
		assert_eq!(SignatureAlgo::from_oid(ED25519)?, SignatureAlgo::Ed25519);
		assert_eq!(SignatureAlgo::from_oid(ECDSA_WITH_SHA3_256)?, SignatureAlgo::EcdsaWithSha3_256);
		assert!(matches!(SignatureAlgo::from_oid(SECP256K1), Err(VoteError::MalformedVoteSignatureUnsupportedScheme)));
		Ok(())
	}

	#[test]
	fn test_dn_round_trip() -> Result<(), VoteError> {
		let bytes = encode_dn(COMMON_NAME, "hello-world")?;
		let mut reader = SliceReader::new(&bytes)?;
		assert_eq!(decode_dn_value(&mut reader, COMMON_NAME)?, "hello-world");
		Ok(())
	}

	#[test]
	fn test_validity_round_trip() -> Result<(), VoteError> {
		let validity = validity_seconds(1_000, 2_000);
		let bytes = encode_validity(validity)?;
		let mut reader = SliceReader::new(&bytes)?;
		let parsed = decode_validity(&mut reader)?;
		assert_eq!(parsed, validity);
		Ok(())
	}

	#[test]
	fn test_subject_public_key_round_trip_ed25519() -> Result<(), VoteError> {
		let account = ed25519_issuer(b"alice");
		let bytes = encode_subject_public_key_info(&account)?;
		let mut reader = SliceReader::new(&bytes)?;
		let parsed = decode_subject_public_key_info(&mut reader)?;
		assert_eq!(parsed.to_public_key_with_type(), account.to_public_key_with_type());
		Ok(())
	}

	#[test]
	fn test_subject_public_key_round_trip_secp256k1() -> Result<(), VoteError> {
		let account = secp256k1_issuer(b"alice");
		let bytes = encode_subject_public_key_info(&account)?;
		let mut reader = SliceReader::new(&bytes)?;
		let parsed = decode_subject_public_key_info(&mut reader)?;
		assert_eq!(parsed.to_public_key_with_type(), account.to_public_key_with_type());
		Ok(())
	}

	#[test]
	fn test_serial_hex_round_trip() -> Result<(), Box<dyn std::error::Error>> {
		let serial = BigInt::from(0xDEADBEEFu32);
		let hex = bigint_to_lower_hex(&serial);
		assert_eq!(hex, "deadbeef");
		assert_eq!(parse_lower_hex_bigint(&hex)?, serial);
		Ok(())
	}

	#[test]
	fn test_tbs_round_trip_ed25519_no_fees() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let validity = validity_seconds(0, 60);
		let blocks = vec![BlockHash::from([1u8; 32]), BlockHash::from([2u8; 32])];

		let tbs_bytes = encode_tbs(&BigInt::from(7u64), SignatureAlgo::Ed25519, &issuer, validity, &blocks, None)?;

		let wrapper = encode_wrapper(&tbs_bytes, SignatureAlgo::Ed25519, &[0u8; 64])?;
		let decoded = decode_wrapper(&wrapper)?;

		assert_eq!(decoded.serial, BigInt::from(7u64));
		assert_eq!(decoded.signature_algo, SignatureAlgo::Ed25519);
		assert_eq!(decoded.blocks, blocks);
		assert!(decoded.fees.is_none());
		assert_eq!(decoded.tbs_bytes, tbs_bytes);
		assert!(accounts_match(&decoded.issuer, &issuer));
		Ok(())
	}

	#[test]
	fn test_tbs_round_trip_ecdsa_with_fees() -> Result<(), VoteError> {
		use crate::fee::{Fee, Fees};
		use keetanetwork_block::Amount;

		let issuer = secp256k1_issuer(b"alice");
		let validity = validity_seconds(0, 60);
		let blocks = vec![BlockHash::from([3u8; 32])];
		let fees = Fees::Single { quote: false, fee: Fee { amount: Amount::from(1u64), pay_to: None, token: None } };

		let tbs_bytes = encode_tbs(
			&BigInt::from(42u64),
			SignatureAlgo::EcdsaWithSha3_256,
			&issuer,
			validity,
			&blocks,
			Some(&fees),
		)?;

		// 72 byte DER ECDSA placeholder; signature parsing is content-agnostic
		// in this round-trip test.
		let wrapper = encode_wrapper(&tbs_bytes, SignatureAlgo::EcdsaWithSha3_256, &[0u8; 70])?;
		let decoded = decode_wrapper(&wrapper)?;

		assert_eq!(decoded.signature_algo, SignatureAlgo::EcdsaWithSha3_256);
		assert!(decoded.fees.is_some());
		assert_eq!(decoded.blocks, blocks);
		Ok(())
	}

	#[test]
	fn test_decode_rejects_bad_version() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let blocks = vec![BlockHash::from([1u8; 32])];
		let validity = validity_seconds(0, 60);
		let tbs_bytes = encode_tbs(&BigInt::from(1u64), SignatureAlgo::Ed25519, &issuer, validity, &blocks, None)?;
		let wrapper = encode_wrapper(&tbs_bytes, SignatureAlgo::Ed25519, &[0u8; 64])?;

		let mut tampered = wrapper;
		let position = find_version_tag(&tampered)?;
		tampered[position + 4] = 0xff;

		let result = decode_wrapper(&tampered);
		assert!(matches!(result, Err(VoteError::InvalidVersion) | Err(VoteError::Der { .. })));
		Ok(())
	}

	#[test]
	fn test_decode_rejects_serial_mismatch() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let validity = validity_seconds(0, 60);
		let blocks = vec![BlockHash::from([1u8; 32])];

		// TBS where subject serial ("08") differs from certificate serial (7).
		let mut tbs = encode_tbs_preamble(&BigInt::from(7u64), "08", &issuer, validity)?;
		tbs.extend_from_slice(&encode_extensions(&blocks, None)?);
		let wrapped = wrap_sequence(&tbs)?;
		let wrapper = encode_wrapper(&wrapped, SignatureAlgo::Ed25519, &[0u8; 64])?;

		assert!(matches!(decode_wrapper(&wrapper), Err(VoteError::SerialMismatch)));
		Ok(())
	}

	#[test]
	fn test_decode_rejects_unknown_critical_extension() -> Result<(), VoteError> {
		use crate::extension::encode_extension_critical;

		let issuer = ed25519_issuer(b"alice");
		let validity = validity_seconds(0, 60);
		let blocks = vec![BlockHash::from([1u8; 32])];

		let mut ext_content = Vec::new();
		ext_content.extend_from_slice(&encode_hash_data_extension(&blocks)?);
		ext_content
			.extend_from_slice(&encode_extension_critical(ObjectIdentifier::new_unwrap("1.2.3.4.5"), b"opaque")?);
		let extensions_seq = wrap_sequence(&ext_content)?;
		let extensions_field = wrap_explicit_context(EXTENSIONS_TAG, &extensions_seq)?;

		let mut tbs = encode_tbs_preamble(&BigInt::from(1u64), "01", &issuer, validity)?;
		tbs.extend_from_slice(&extensions_field);
		let wrapped = wrap_sequence(&tbs)?;
		let wrapper = encode_wrapper(&wrapped, SignatureAlgo::Ed25519, &[0u8; 64])?;

		assert!(matches!(decode_wrapper(&wrapper), Err(VoteError::MalformedVoteExtensionsValueCriticalType)));
		Ok(())
	}
}
