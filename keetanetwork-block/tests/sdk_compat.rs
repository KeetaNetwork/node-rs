//! SDK Compatibility Tests
//!
//! These tests verify operation parsing from block DER bytes.
//! Test data includes:
//! - Mainnet blocks from the Keeta Network explorer
//! - Manually constructed test vectors for edge cases and operation variants

mod samples;

use der::{Decode, Reader, SliceReader};
use keetanetwork_block::{extract_operations_slice, Operation};

/// Test that extract_operations_slice works with all sample blocks
#[test]
fn test_extract_operations_slice_all_samples() {
	for (sample_name, original_bytes) in samples::ALL_SAMPLES {
		let ops_slice = extract_operations_slice(original_bytes)
			.unwrap_or_else(|| panic!("extract_operations_slice failed for {}", sample_name));

		// Parse operations from the slice and verify at least one exists
		let mut reader = SliceReader::new(ops_slice).expect("SliceReader failed");
		let mut op_count = 0;
		while !reader.is_finished() {
			let _op = Operation::decode(&mut reader)
				.unwrap_or_else(|e| panic!("Failed to decode operation {} in {}: {:?}", op_count, sample_name, e));
			op_count += 1;
		}

		assert!(op_count > 0, "{} block should have operations", sample_name);
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
