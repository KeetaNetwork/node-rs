//! Integration tests for seed derivation from passphrase functionality.

use crypto::prelude::ExposeSecret;
use crypto::utils::seed_from_passphrase;

struct PassphraseTestCase {
	passphrase: &'static str,
	expected_seed: &'static str,
}

struct PassphraseFailureCase {
	passphrase: &'static str,
	expected_error_contains: &'static str,
}

// Test passphrase used in multiple tests
const TEST_PASSPHRASE: &str = "this is the example length for a sufficient passphrase to be set secured";

// Test cases that should pass
const PASSPHRASE_SUCCESS_CASES: &[PassphraseTestCase] = &[
	PassphraseTestCase {
		passphrase: TEST_PASSPHRASE,
		expected_seed: "f4844098340a279dc09f7f6286081a9c92a518797634905e0e146bbaf708f9f3",
	},
	PassphraseTestCase {
		passphrase: "one one one one one one one one one one one one one one one one one one one one",
		expected_seed: "281918a051553c41c79e2aab60a4566c0abeb5ade5a62a0ee08d0253e9171349",
	},
	PassphraseTestCase {
		passphrase: "😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀", // Unicode emoji test
		expected_seed: "b5201e5635362c7e1f749eda356de2965f5017a26e4a0247852821c10c0d983b",
	},
];

// Test cases that should fail
const PASSPHRASE_FAILURE_CASES: &[PassphraseFailureCase] = &[
	PassphraseFailureCase {
		passphrase: "this is the example length for a too short passphrase",
		expected_error_contains: "must be at least 60 bytes",
	},
	PassphraseFailureCase { passphrase: "", expected_error_contains: "must be at least 60 bytes" },
	PassphraseFailureCase {
		passphrase: "😀", // Single emoji - too short
		expected_error_contains: "must be at least 60 bytes",
	},
];

#[test]
fn test_passphrase_to_seed_success_cases() {
	for test_case in PASSPHRASE_SUCCESS_CASES {
		let result_seed = seed_from_passphrase(test_case.passphrase).unwrap();
		let result_hex = hex::encode(*result_seed.expose_secret()).to_lowercase();
		assert_eq!(
			result_hex, test_case.expected_seed,
			"Seed derivation failed for passphrase: '{}'",
			test_case.passphrase
		);
	}
}

#[test]
fn test_passphrase_to_seed_failure_cases() {
	for test_case in PASSPHRASE_FAILURE_CASES {
		let result = seed_from_passphrase(test_case.passphrase);
		assert!(result.is_err(), "Expected passphrase '{}' to fail but it succeeded", test_case.passphrase);

		let error_msg = format!("{}", result.unwrap_err());
		assert!(
			error_msg.contains(test_case.expected_error_contains),
			"Error message '{}' does not contain expected text '{}' for passphrase '{}'",
			error_msg,
			test_case.expected_error_contains,
			test_case.passphrase
		);
	}
}

#[test]
fn test_passphrase_deterministic_behavior() {
	// Multiple calls with same passphrase should produce identical results
	let seed1 = seed_from_passphrase(TEST_PASSPHRASE).unwrap();
	let seed2 = seed_from_passphrase(TEST_PASSPHRASE).unwrap();
	assert_eq!(*seed1.expose_secret(), *seed2.expose_secret(), "Passphrase derivation should be deterministic");
}

#[test]
fn test_passphrase_different_inputs_different_outputs() {
	let passphrase_variations = [
		(TEST_PASSPHRASE, "Original passphrase"),
		("this is the example length for a sufficient passphrase to be set secured1", "One char added"),
		// cspell:disable-next-line
		("this is the example length for a sufficient passphrase to be set securedx", "Last char changed"),
		("this is the example length for a sufficient passphrase to be set secured!", "Different punctuation"),
	];

	// Generate seeds for all variations
	let mut seeds = Vec::new();
	for (passphrase, description) in &passphrase_variations {
		let seed = seed_from_passphrase(passphrase).unwrap();
		seeds.push((*seed.expose_secret(), description));
	}

	// Verify all seeds are different
	for i in 0..seeds.len() {
		for j in (i + 1)..seeds.len() {
			assert_ne!(seeds[i].0, seeds[j].0, "Seeds should be different: {} vs {}", seeds[i].1, seeds[j].1);
		}
	}
}

#[test]
fn test_passphrase_normalization() {
	let normalization_test_cases = [
		(
			"This Is The Example Length For A Sufficient Passphrase To Be Set Secured",
			// cspell:disable-next-line
			"thisistheexamplelengthforasufficientpassphrasetobesetsecured",
			"Mixed case with spaces",
		),
		(
			"this  is  the  example  length  for  a  sufficient  passphrase  to  be  set  secured",
			// cspell:disable-next-line
			"thisistheexamplelengthforasufficientpassphrasetobesetsecured",
			"Multiple spaces",
		),
		(
			" this is the example length for a sufficient passphrase to be set secured ",
			// cspell:disable-next-line
			"thisistheexamplelengthforasufficientpassphrasetobesetsecured",
			"Leading and trailing spaces",
		),
		(
			"THIS IS THE EXAMPLE LENGTH FOR A SUFFICIENT PASSPHRASE TO BE SET SECURED",
			// cspell:disable-next-line
			"thisistheexamplelengthforasufficientpassphrasetobesetsecured",
			"All uppercase",
		),
	];

	// All these should produce the same seed due to normalization
	let mut seeds = Vec::new();
	for (passphrase, normalized_expected, description) in &normalization_test_cases {
		let seed = seed_from_passphrase(passphrase).unwrap();
		seeds.push((*seed.expose_secret(), description));

		// Also verify the normalized version produces the same result
		let normalized_seed = seed_from_passphrase(normalized_expected).unwrap();
		assert_eq!(
			*seed.expose_secret(),
			*normalized_seed.expose_secret(),
			"Passphrase '{passphrase}' should normalize to '{normalized_expected}' and produce the same seed"
		);
	}

	// Verify all normalized passphrases produce the same seed
	for i in 1..seeds.len() {
		assert_eq!(seeds[0].0, seeds[i].0, "Normalization failed: '{}' vs '{}'", seeds[0].1, seeds[i].1);
	}
}
