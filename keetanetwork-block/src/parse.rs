//! DER utility functions for zero-copy parsing.

use der::{Decode, Header, Reader, SliceReader, Tag, TagNumber};

/// Extracts the operations SEQUENCE content from raw block bytes.
///
/// This function skips block header fields and returns a slice containing
/// the raw DER content of the operations SEQUENCE.
pub fn extract_operations_slice(data: &[u8]) -> Option<&[u8]> {
	if data.is_empty() {
		return None;
	}

	let mut reader = SliceReader::new(data).ok()?;
	let tag = reader.peek_tag().ok()?;

	if tag == Tag::Sequence {
		// V1 block: plain SEQUENCE
		extract_operations_v1(&mut reader)
	} else if tag.is_context_specific() && tag.number() == TagNumber::new(1) {
		// V2 block: context tag [1]
		extract_operations_v2(&mut reader)
	} else {
		None
	}
}

/// Extract operations from V1 block.
fn extract_operations_v1<'a>(reader: &mut SliceReader<'a>) -> Option<&'a [u8]> {
	let header = Header::decode(reader).ok()?;
	if header.tag != Tag::Sequence {
		return None;
	}
	let content = reader.read_slice(header.length).ok()?;
	let mut inner = SliceReader::new(content).ok()?;

	// Skip V1 header fields: version, network, subnet, date, account, signer, previous
	for _ in 0..7 {
		skip_any(&mut inner).ok()?;
	}

	read_sequence_content(&mut inner)
}

/// Extract operations from V2 block.
fn extract_operations_v2<'a>(reader: &mut SliceReader<'a>) -> Option<&'a [u8]> {
	let ctx_header = Header::decode(reader).ok()?;
	if !ctx_header.tag.is_context_specific() || ctx_header.tag.number() != TagNumber::new(1) {
		return None;
	}
	let inner_content = reader.read_slice(ctx_header.length).ok()?;
	let mut inner = SliceReader::new(inner_content).ok()?;

	let seq_header = Header::decode(&mut inner).ok()?;
	if seq_header.tag != Tag::Sequence {
		return None;
	}
	let seq_content = inner.read_slice(seq_header.length).ok()?;
	let mut seq_reader = SliceReader::new(seq_content).ok()?;

	// Skip V2 header fields: network, date, purpose, account, signer, previous
	for _ in 0..6 {
		skip_any(&mut seq_reader).ok()?;
	}

	read_sequence_content(&mut seq_reader)
}

/// Skip any DER element (tag + length + content).
pub(crate) fn skip_any<'a>(reader: &mut SliceReader<'a>) -> der::Result<()> {
	let header = Header::decode(reader)?;
	reader.read_slice(header.length)?;
	Ok(())
}

/// Read a SEQUENCE and return its content bytes.
fn read_sequence_content<'a>(reader: &mut SliceReader<'a>) -> Option<&'a [u8]> {
	let header = Header::decode(reader).ok()?;
	if header.tag != Tag::Sequence {
		return None;
	}
	reader.read_slice(header.length).ok()
}
