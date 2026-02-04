//! KeetaBlock DER parsing and encoding
//!
//! This module provides `Decode` and `Encode` implementations for `KeetaBlock`,
//! enabling full block serialization and deserialization.
//!
//! ## Block Formats
//!
//! - **V1**: Plain SEQUENCE with version field = 0
//! - **V2**: Wrapped in context tag `1`

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use der::{asn1::OctetStringRef, Decode, Encode, Header, Length, Reader, Tag, TagNumber, Writer};

use crate::types::{
	BlockHeader, BlockPurpose, BlockVersion, KeetaBlock, MultiSigSigner, MultiSigSignerInfo, Operation, SignerField,
};

// ============================================================================
// KeetaBlock Decode Implementation
// ============================================================================

#[cfg(any(feature = "alloc", feature = "std"))]
impl<'a> Decode<'a> for KeetaBlock<'a> {
	fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
		// Peek at the first tag to determine block version
		let tag = reader.peek_tag()?;

		if tag == Tag::Sequence {
			// V1 block: plain SEQUENCE
			decode_v1_block(reader)
		} else if tag.is_context_specific() && tag.number() == TagNumber::new(1) {
			// V2 block: context tag [1]
			decode_v2_block(reader)
		} else {
			Err(Tag::Sequence.value_error())
		}
	}
}

/// Decode a V1 block
///
/// V1 Structure:
/// ```text
/// SEQUENCE {
///     version         INTEGER (= 0),
///     network         INTEGER,
///     [subnet]        NULL or INTEGER,
///     date            GeneralizedTime,
///     account         OCTET STRING,
///     [signer]        NULL or OCTET STRING,
///     previous        OCTET STRING,
///     operations      SEQUENCE OF Operation,
///     signature       OCTET STRING
/// }
/// ```
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_v1_block<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<KeetaBlock<'a>> {
	reader.sequence(|seq| {
		// version (must be 0 for V1)
		let version: u8 = seq.decode()?;
		if version != 0 {
			return Err(Tag::Integer.value_error());
		}

		// network
		let network: u64 = seq.decode()?;

		// subnet
		let subnet = decode_null_or_integer(seq)?;

		// date
		let date = read_generalized_time_bytes(seq)?;

		// account
		let account: OctetStringRef = seq.decode()?;

		// signer
		let signer = decode_v1_signer(seq)?;

		// previous
		let previous: OctetStringRef = seq.decode()?;

		// operations
		let operations = decode_operations(seq)?;

		// signature
		let signature: OctetStringRef = seq.decode()?;

		Ok(KeetaBlock {
			version: BlockVersion::V1,
			header: BlockHeader {
				network,
				subnet,
				date,
				purpose: BlockPurpose::Generic,
				account: account.as_bytes(),
				signer,
				previous: previous.as_bytes(),
			},
			operations,
			signatures: vec![signature.as_bytes()],
		})
	})
}

/// Decode a V2 block
///
/// V2 Structure:
/// ```text
/// [1] EXPLICIT {
///     SEQUENCE {
///         network         INTEGER,
///         date            GeneralizedTime,
///         purpose         INTEGER,
///         account         OCTET STRING,
///         signer          NULL | OCTET STRING | SEQUENCE,
///         previous        OCTET STRING,
///         operations      SEQUENCE OF Operation,
///         signature       OCTET STRING
///     }
/// }
/// ```
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_v2_block<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<KeetaBlock<'a>> {
	// Read and verify context tag [1]
	let header = Header::decode(reader)?;
	if !header.tag.is_context_specific() || header.tag.number() != TagNumber::new(1) {
		return Err(Tag::ContextSpecific { number: TagNumber::new(1), constructed: true }.value_error());
	}

	// Read the inner SEQUENCE
	reader.sequence(|seq| {
		// network
		let network: u64 = seq.decode()?;

		// date
		let date = read_generalized_time_bytes(seq)?;

		// purpose
		let purpose_val: u8 = seq.decode()?;
		let purpose = BlockPurpose::try_from(purpose_val).map_err(|_| Tag::Integer.value_error())?;

		// account
		let account: OctetStringRef = seq.decode()?;

		// signer
		let signer = decode_v2_signer(seq)?;

		// previous
		let previous: OctetStringRef = seq.decode()?;

		// operations
		let operations = decode_operations(seq)?;

		// signatures
		let signatures = decode_signatures(seq)?;

		Ok(KeetaBlock {
			version: BlockVersion::V2,
			header: BlockHeader {
				network,
				subnet: None,
				date,
				purpose,
				account: account.as_bytes(),
				signer,
				previous: previous.as_bytes(),
			},
			operations,
			signatures,
		})
	})
}

// ============================================================================
// Helper Functions for Decoding
// ============================================================================

/// Decodes `NULL` or `INTEGER`, returning `Option<u64>`.
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_null_or_integer<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<Option<u64>> {
	let tag = reader.peek_tag()?;
	if tag == Tag::Null {
		let _: der::asn1::Null = reader.decode()?;
		Ok(None)
	} else {
		let value: u64 = reader.decode()?;
		Ok(Some(value))
	}
}

/// Reads `GeneralizedTime` as raw content bytes.
#[cfg(any(feature = "alloc", feature = "std"))]
fn read_generalized_time_bytes<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<&'a [u8]> {
	let header = Header::decode(reader)?;
	if header.tag != Tag::GeneralizedTime {
		return Err(Tag::GeneralizedTime.value_error());
	}
	reader.read_slice(header.length)
}

/// Decodes V1 signer field.
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_v1_signer<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<SignerField<'a>> {
	let tag = reader.peek_tag()?;
	if tag == Tag::Null {
		let _: der::asn1::Null = reader.decode()?;
		Ok(SignerField::AccountIsSigner)
	} else {
		let signer: OctetStringRef = reader.decode()?;
		Ok(SignerField::Single(signer.as_bytes()))
	}
}

/// Decodes V2 signer field.
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_v2_signer<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<SignerField<'a>> {
	let tag = reader.peek_tag()?;

	if tag == Tag::Null {
		let _: der::asn1::Null = reader.decode()?;
		Ok(SignerField::AccountIsSigner)
	} else if tag == Tag::OctetString {
		let signer: OctetStringRef = reader.decode()?;
		Ok(SignerField::Single(signer.as_bytes()))
	} else if tag == Tag::Sequence {
		// Multisig signer - read sequence content directly
		let header = Header::decode(reader)?;
		let content = reader.read_slice(header.length)?;
		let multisig = decode_multisig_content(content)?;
		Ok(SignerField::Multisig(multisig))
	} else {
		Err(tag.value_error())
	}
}

/// Decodes multisig signer info from `SEQUENCE` content.
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_multisig_content<'a>(content: &'a [u8]) -> der::Result<MultiSigSignerInfo<'a>> {
	use der::SliceReader;
	let mut reader = SliceReader::new(content)?;

	// multisig public key
	let multisig_pub_key: OctetStringRef = reader.decode()?;

	// Read inner SEQUENCE header for signers
	let inner_header = Header::decode(&mut reader)?;
	if inner_header.tag != Tag::Sequence {
		return Err(Tag::Sequence.value_error());
	}
	let signers_content = reader.read_slice(inner_header.length)?;

	// Read signers from the inner content
	let signers = decode_multisig_signers(signers_content)?;

	Ok(MultiSigSignerInfo { multisig_pub_key: multisig_pub_key.as_bytes(), signers })
}

/// Decodes a list of multisig signers from raw bytes.
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_multisig_signers<'a>(content: &'a [u8]) -> der::Result<Vec<MultiSigSigner<'a>>> {
	use der::SliceReader;
	let mut reader = SliceReader::new(content)?;
	let mut signers = Vec::new();

	while !reader.is_finished() {
		let tag = reader.peek_tag()?;
		if tag == Tag::OctetString {
			let key: OctetStringRef = reader.decode()?;
			signers.push(MultiSigSigner::Key(key.as_bytes()));
		} else if tag == Tag::Sequence {
			// For nested multisig, read the content and recurse
			let header = Header::decode(&mut reader)?;
			let nested_content = reader.read_slice(header.length)?;
			let nested = decode_multisig_content(nested_content)?;
			signers.push(MultiSigSigner::Nested(Box::new(nested)));
		} else {
			return Err(tag.value_error());
		}
	}

	Ok(signers)
}

/// Decodes signatures from a single or multiple `OCTET STRING`.
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_signatures<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<Vec<&'a [u8]>> {
	let tag = reader.peek_tag()?;

	if tag == Tag::OctetString {
		// Single signature
		let sig: OctetStringRef = reader.decode()?;
		Ok(vec![sig.as_bytes()])
	} else if tag == Tag::Sequence {
		// Multiple signatures wrapped in SEQUENCE
		let header = Header::decode(reader)?;
		let content = reader.read_slice(header.length)?;

		// Parse signatures from the sequence content
		use der::SliceReader;
		let mut sig_reader = SliceReader::new(content)?;
		let mut signatures = Vec::new();

		while !sig_reader.is_finished() {
			let sig: OctetStringRef = sig_reader.decode()?;
			signatures.push(sig.as_bytes());
		}

		Ok(signatures)
	} else {
		Err(Tag::OctetString.value_error())
	}
}

/// Decodes operations sequence.
#[cfg(any(feature = "alloc", feature = "std"))]
fn decode_operations<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<Vec<Operation<'a>>> {
	let mut operations = Vec::new();
	reader.sequence(|seq| {
		while !seq.is_finished() {
			operations.push(Operation::decode(seq)?);
		}
		Ok(())
	})?;
	Ok(operations)
}

// ============================================================================
// KeetaBlock Encode Implementation
// ============================================================================

#[cfg(any(feature = "alloc", feature = "std"))]
impl Encode for KeetaBlock<'_> {
	fn encoded_len(&self) -> der::Result<Length> {
		match self.version {
			BlockVersion::V1 => self.v1_encoded_len(),
			BlockVersion::V2 => self.v2_encoded_len(),
		}
	}

	fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
		match self.version {
			BlockVersion::V1 => self.encode_v1(writer),
			BlockVersion::V2 => self.encode_v2(writer),
		}
	}
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl KeetaBlock<'_> {
	/// Calculate encoded length for V1 block
	fn v1_encoded_len(&self) -> der::Result<Length> {
		let content_len = self.v1_content_len()?;
		Header::new(Tag::Sequence, content_len)?.encoded_len() + content_len
	}

	/// Calculate V1 content length
	fn v1_content_len(&self) -> der::Result<Length> {
		// version (0 for V1)
		let version_len = 0u8.encoded_len()?;

		// network
		let network_len = self.header.network.encoded_len()?;

		// subnet (NULL or INTEGER)
		let subnet_len = match self.header.subnet {
			Some(s) => s.encoded_len()?,
			None => der::asn1::Null.encoded_len()?,
		};

		// date
		let date_len = encode_generalized_time_len(self.header.date)?;

		// account
		let account_len = OctetStringRef::new(self.header.account)?.encoded_len()?;

		// signer
		let signer_len = encode_signer_len(&self.header.signer)?;

		// previous
		let previous_len = OctetStringRef::new(self.header.previous)?.encoded_len()?;

		// operations
		let ops_len = self.operations_encoded_len()?;

		// signature
		let sig_len = if !self.signatures.is_empty() {
			OctetStringRef::new(self.signatures[0])?.encoded_len()?
		} else {
			Length::ZERO
		};

		version_len + network_len + subnet_len + date_len + account_len + signer_len + previous_len + ops_len + sig_len
	}

	/// Encode V1 block
	fn encode_v1(&self, writer: &mut impl Writer) -> der::Result<()> {
		let content_len = self.v1_content_len()?;
		Header::new(Tag::Sequence, content_len)?.encode(writer)?;

		// version (0 for V1)
		0u8.encode(writer)?;

		// network
		self.header.network.encode(writer)?;

		// subnet
		match self.header.subnet {
			Some(s) => s.encode(writer)?,
			None => der::asn1::Null.encode(writer)?,
		};

		// date
		encode_generalized_time(self.header.date, writer)?;

		// account
		OctetStringRef::new(self.header.account)?.encode(writer)?;

		// signer
		encode_signer(&self.header.signer, writer)?;

		// previous
		OctetStringRef::new(self.header.previous)?.encode(writer)?;

		// operations
		self.encode_operations(writer)?;

		// signature
		if !self.signatures.is_empty() {
			OctetStringRef::new(self.signatures[0])?.encode(writer)?;
		}

		Ok(())
	}

	/// Calculate encoded length for V2 block
	fn v2_encoded_len(&self) -> der::Result<Length> {
		let inner_content_len = self.v2_content_len()?;
		let inner_seq_len = (Header::new(Tag::Sequence, inner_content_len)?.encoded_len() + inner_content_len)?;

		// Context tag [1] wrapping
		let ctx_header =
			Header::new(Tag::ContextSpecific { number: TagNumber::new(1), constructed: true }, inner_seq_len)?;
		ctx_header.encoded_len() + inner_seq_len
	}

	/// Calculate V2 content length
	fn v2_content_len(&self) -> der::Result<Length> {
		// network
		let network_len = self.header.network.encoded_len()?;

		// date
		let date_len = encode_generalized_time_len(self.header.date)?;

		// purpose
		let purpose_len = (self.header.purpose as u8).encoded_len()?;

		// account
		let account_len = OctetStringRef::new(self.header.account)?.encoded_len()?;

		// signer
		let signer_len = encode_signer_len(&self.header.signer)?;

		// previous
		let previous_len = OctetStringRef::new(self.header.previous)?.encoded_len()?;

		// operations
		let ops_len = self.operations_encoded_len()?;

		// signatures
		let sig_len = self.signatures_encoded_len()?;

		network_len + date_len + purpose_len + account_len + signer_len + previous_len + ops_len + sig_len
	}

	/// Encode V2 block
	fn encode_v2(&self, writer: &mut impl Writer) -> der::Result<()> {
		let inner_content_len = self.v2_content_len()?;
		let inner_seq_len = (Header::new(Tag::Sequence, inner_content_len)?.encoded_len() + inner_content_len)?;

		// Write context tag [1]
		Header::new(Tag::ContextSpecific { number: TagNumber::new(1), constructed: true }, inner_seq_len)?
			.encode(writer)?;

		// Write inner SEQUENCE
		Header::new(Tag::Sequence, inner_content_len)?.encode(writer)?;

		// network
		self.header.network.encode(writer)?;

		// date
		encode_generalized_time(self.header.date, writer)?;

		// purpose
		(self.header.purpose as u8).encode(writer)?;

		// account
		OctetStringRef::new(self.header.account)?.encode(writer)?;

		// signer
		encode_signer(&self.header.signer, writer)?;

		// previous
		OctetStringRef::new(self.header.previous)?.encode(writer)?;

		// operations
		self.encode_operations(writer)?;

		// signature(s)
		self.encode_signatures(writer)?;

		Ok(())
	}

	/// Calculate encoded length of signatures
	fn signatures_encoded_len(&self) -> der::Result<Length> {
		if self.signatures.is_empty() {
			return Ok(Length::ZERO);
		}

		if self.signatures.len() == 1 {
			// Single signature: just OCTET STRING
			OctetStringRef::new(self.signatures[0])?.encoded_len()
		} else {
			// Multiple signatures: SEQUENCE of OCTET STRINGs
			let mut content_len = Length::ZERO;
			for sig in &self.signatures {
				content_len = (content_len + OctetStringRef::new(sig)?.encoded_len()?)?;
			}
			Header::new(Tag::Sequence, content_len)?.encoded_len() + content_len
		}
	}

	/// Encode signatures
	fn encode_signatures(&self, writer: &mut impl Writer) -> der::Result<()> {
		if self.signatures.is_empty() {
			return Ok(());
		}

		if self.signatures.len() == 1 {
			// Single signature: just OCTET STRING
			OctetStringRef::new(self.signatures[0])?.encode(writer)
		} else {
			// Multiple signatures: SEQUENCE of OCTET STRINGs
			let mut content_len = Length::ZERO;
			for sig in &self.signatures {
				content_len = (content_len + OctetStringRef::new(sig)?.encoded_len()?)?;
			}
			Header::new(Tag::Sequence, content_len)?.encode(writer)?;
			for sig in &self.signatures {
				OctetStringRef::new(sig)?.encode(writer)?;
			}
			Ok(())
		}
	}

	/// Calculate encoded length of operations sequence
	fn operations_encoded_len(&self) -> der::Result<Length> {
		let mut content_len = Length::ZERO;
		for op in &self.operations {
			content_len = (content_len + op.encoded_len()?)?;
		}
		Header::new(Tag::Sequence, content_len)?.encoded_len() + content_len
	}

	/// Encode operations sequence
	fn encode_operations(&self, writer: &mut impl Writer) -> der::Result<()> {
		let mut content_len = Length::ZERO;
		for op in &self.operations {
			content_len = (content_len + op.encoded_len()?)?;
		}
		Header::new(Tag::Sequence, content_len)?.encode(writer)?;
		for op in &self.operations {
			op.encode(writer)?;
		}
		Ok(())
	}
}

// ============================================================================
// Helper Functions for Encoding
// ============================================================================

/// Calculates signer field encoded length.
#[cfg(any(feature = "alloc", feature = "std"))]
fn encode_signer_len(signer: &SignerField) -> der::Result<Length> {
	match signer {
		SignerField::AccountIsSigner => der::asn1::Null.encoded_len(),
		SignerField::Single(key) => OctetStringRef::new(key)?.encoded_len(),
		SignerField::Multisig(info) => encode_multisig_len(info),
	}
}

/// Encodes signer field.
#[cfg(any(feature = "alloc", feature = "std"))]
fn encode_signer(signer: &SignerField, writer: &mut impl Writer) -> der::Result<()> {
	match signer {
		SignerField::AccountIsSigner => der::asn1::Null.encode(writer),
		SignerField::Single(key) => OctetStringRef::new(key)?.encode(writer),
		SignerField::Multisig(info) => encode_multisig(info, writer),
	}
}

/// Calculates multisig signer encoded length.
#[cfg(any(feature = "alloc", feature = "std"))]
fn encode_multisig_len(info: &MultiSigSignerInfo) -> der::Result<Length> {
	let pubkey_len = OctetStringRef::new(info.multisig_pub_key)?.encoded_len()?;

	let mut signers_content_len = Length::ZERO;
	for signer in &info.signers {
		let signer_len = match signer {
			MultiSigSigner::Key(key) => OctetStringRef::new(key)?.encoded_len()?,
			MultiSigSigner::Nested(nested) => encode_multisig_len(nested)?,
		};
		signers_content_len = (signers_content_len + signer_len)?;
	}
	let signers_seq_len = (Header::new(Tag::Sequence, signers_content_len)?.encoded_len() + signers_content_len)?;

	let content_len = (pubkey_len + signers_seq_len)?;
	Header::new(Tag::Sequence, content_len)?.encoded_len() + content_len
}

/// Encodes multisig signer.
#[cfg(any(feature = "alloc", feature = "std"))]
fn encode_multisig(info: &MultiSigSignerInfo, writer: &mut impl Writer) -> der::Result<()> {
	let pubkey_len = OctetStringRef::new(info.multisig_pub_key)?.encoded_len()?;

	let mut signers_content_len = Length::ZERO;
	for signer in &info.signers {
		let signer_len = match signer {
			MultiSigSigner::Key(key) => OctetStringRef::new(key)?.encoded_len()?,
			MultiSigSigner::Nested(nested) => encode_multisig_len(nested)?,
		};
		signers_content_len = (signers_content_len + signer_len)?;
	}
	let signers_seq_len = (Header::new(Tag::Sequence, signers_content_len)?.encoded_len() + signers_content_len)?;

	let content_len = (pubkey_len + signers_seq_len)?;

	// Write outer sequence
	Header::new(Tag::Sequence, content_len)?.encode(writer)?;

	// Write pubkey
	OctetStringRef::new(info.multisig_pub_key)?.encode(writer)?;

	// Write signers sequence
	Header::new(Tag::Sequence, signers_content_len)?.encode(writer)?;
	for signer in &info.signers {
		match signer {
			MultiSigSigner::Key(key) => OctetStringRef::new(key)?.encode(writer)?,
			MultiSigSigner::Nested(nested) => encode_multisig(nested, writer)?,
		}
	}

	Ok(())
}

/// Calculates `GeneralizedTime` encoded length.
#[cfg(any(feature = "alloc", feature = "std"))]
fn encode_generalized_time_len(date_bytes: &[u8]) -> der::Result<Length> {
	let content_len = Length::try_from(date_bytes.len())?;
	Header::new(Tag::GeneralizedTime, content_len)?.encoded_len() + content_len
}

/// Encodes `GeneralizedTime` from raw bytes.
#[cfg(any(feature = "alloc", feature = "std"))]
fn encode_generalized_time(date_bytes: &[u8], writer: &mut impl Writer) -> der::Result<()> {
	let content_len = Length::try_from(date_bytes.len())?;
	Header::new(Tag::GeneralizedTime, content_len)?.encode(writer)?;
	writer.write(date_bytes)
}

// ============================================================================
// BlockPurpose Encode
// ============================================================================

#[cfg(any(feature = "alloc", feature = "std"))]
impl From<BlockPurpose> for u8 {
	fn from(purpose: BlockPurpose) -> u8 {
		match purpose {
			BlockPurpose::Generic => 0,
			BlockPurpose::Fee => 1,
		}
	}
}
