//! SDK Compatibility Tests
//!
//! These tests parse block DER bytes and verify roundtrip encoding.
//! Test data includes:
//! - Mainnet blocks from the Keeta Network explorer
//! - Manually constructed test vectors for edge cases and operation variants

mod samples;

use der::{Decode, Encode, Reader, SliceReader};
use keetanetwork_block::{extract_operations_slice, KeetaBlock, Operation};

#[test]
fn test_block_roundtrip_all_samples() {
	for (sample_name, original_bytes) in samples::ALL_SAMPLES {
		let block = match KeetaBlock::from_der(original_bytes) {
			Ok(b) => b,
			Err(e) => panic!("Failed to parse {} block: {:?}", sample_name, e),
		};

		assert!(!block.operations.is_empty(), "{} block should have operations", sample_name);
		assert!(!block.signatures.is_empty(), "{} block should have signatures", sample_name);

		let encoded = block
			.to_der()
			.unwrap_or_else(|_| panic!("Failed to encode {} block", sample_name));

		assert_eq!(encoded, *original_bytes, "Roundtrip encoding mismatch for {} block", sample_name);
	}
}

// ============================================================================
// Invalid/Malformed DER Input Tests
// ============================================================================

/// Test that empty input returns an error (not panic)
#[test]
fn test_malformed_empty_input() {
	let result = KeetaBlock::from_der(&[]);
	assert!(result.is_err(), "Empty input should fail to parse");
}

/// Test that truncated data returns an error
#[test]
fn test_malformed_truncated_data() {
	// Take a valid sample and truncate it
	let valid = samples::SET_REP;
	let truncated = &valid[..valid.len() / 2];
	let result = KeetaBlock::from_der(truncated);
	assert!(result.is_err(), "Truncated data should fail to parse");
}

/// Test that invalid outer tag returns an error
#[test]
fn test_malformed_invalid_tag() {
	// Use OCTET STRING tag (0x04) instead of SEQUENCE (0x30) or [1] (0xa1)
	let invalid = [0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
	let result = KeetaBlock::from_der(&invalid);
	assert!(result.is_err(), "Invalid outer tag should fail to parse");
}

/// Test that length exceeding data returns an error
#[test]
fn test_malformed_length_overflow() {
	// SEQUENCE with length 0xFF but only 5 bytes of data
	let invalid = [0x30, 0x81, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05];
	let result = KeetaBlock::from_der(&invalid);
	assert!(result.is_err(), "Length overflow should fail to parse");
}

/// Test that extra trailing bytes are handled
#[test]
fn test_malformed_trailing_data() {
	// Take a valid sample and append extra bytes
	let valid = samples::SET_REP;
	let mut with_trailing = valid.to_vec();
	with_trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
	let result = KeetaBlock::from_der(&with_trailing);
	// The der crate typically rejects trailing data
	assert!(result.is_err(), "Trailing data should fail to parse");
}

/// Test that invalid nested structure returns an error
#[test]
fn test_malformed_invalid_nested_structure() {
	// V1 block header start, but with invalid content inside
	// SEQUENCE { INTEGER 0, ... garbage }
	let invalid = [
		0x30, 0x10, // SEQUENCE of 16 bytes
		0x02, 0x01, 0x00, // INTEGER 0 (version)
		0x02, 0x02, 0x53, 0x82, // INTEGER 21378 (parent)
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // garbage
	];
	let result = KeetaBlock::from_der(&invalid);
	assert!(result.is_err(), "Invalid nested structure should fail to parse");
}

/// Test that zero-length required fields return an error
#[test]
fn test_malformed_zero_length_field() {
	// SEQUENCE with empty OCTET STRING where account key is expected
	let invalid = [
		0x30, 0x08, // SEQUENCE of 8 bytes
		0x02, 0x01, 0x00, // INTEGER 0 (version)
		0x02, 0x01, 0x01, // INTEGER 1 (parent)
		0x04, 0x00, // Empty OCTET STRING (invalid account)
	];
	let result = KeetaBlock::from_der(&invalid);
	assert!(result.is_err(), "Zero-length required field should fail to parse");
}

// ============================================================================
// extract_operations_slice Tests
// ============================================================================

/// Test that extract_operations_slice works with all sample blocks
#[test]
fn test_extract_operations_slice_all_samples() {
	for (sample_name, original_bytes) in samples::ALL_SAMPLES {
		// First parse using full KeetaBlock to get expected operations
		let block = KeetaBlock::from_der(original_bytes)
			.unwrap_or_else(|e| panic!("Failed to parse {} block: {:?}", sample_name, e));

		let ops_slice = extract_operations_slice(original_bytes)
			.unwrap_or_else(|| panic!("extract_operations_slice failed for {}", sample_name));

		// Parse operations from the slice and verify count matches
		let mut reader = SliceReader::new(ops_slice).expect("SliceReader failed");
		let mut op_count = 0;
		while !reader.is_finished() {
			let _op = Operation::decode(&mut reader)
				.unwrap_or_else(|e| panic!("Failed to decode operation {} in {}: {:?}", op_count, sample_name, e));
			op_count += 1;
		}

		assert_eq!(
			op_count,
			block.operations.len(),
			"Operation count mismatch for {}: extracted {} vs block {}",
			sample_name,
			op_count,
			block.operations.len()
		);
	}
}

/// Test that extract_operations_slice returns None for invalid input
#[test]
fn test_extract_operations_slice_invalid() {
	// Empty input
	assert!(extract_operations_slice(&[]).is_none());

	// Invalid tag
	assert!(extract_operations_slice(&[0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]).is_none());

	// Truncated data
	let valid = samples::SET_REP;
	assert!(extract_operations_slice(&valid[..10]).is_none());
}
