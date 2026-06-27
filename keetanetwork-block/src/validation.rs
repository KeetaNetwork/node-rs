//! Network-parameterized validation configuration.

use num_bigint::BigInt;
use num_traits::Pow;

use crate::error::BlockError;

/// Known network identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
	/// Test default network (ID 0)
	TestDefault,
	/// Main network
	Main,
	/// Staging network
	Staging,
	/// Test network
	Test,
	/// Development network
	Dev,
}

impl Network {
	/// The numeric network identifier.
	pub fn id(&self) -> u64 {
		match self {
			Network::TestDefault => 0,
			Network::Main => 0x5382,
			Network::Staging => 0x538201,
			Network::Test => 0x5445_5354,
			Network::Dev => 0x44_4556,
		}
	}
}

impl TryFrom<&BigInt> for Network {
	type Error = BlockError;

	fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
		let candidates = [Network::TestDefault, Network::Main, Network::Staging, Network::Test, Network::Dev];
		candidates
			.into_iter()
			.find(|network| BigInt::from(network.id()) == *value)
			.ok_or(BlockError::UnknownNetwork)
	}
}

/// A violation of a [`TextRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextRuleViolation {
	/// The value exceeds the maximum length.
	TooLong {
		/// The value length in UTF-16 code units
		length: usize,
		/// The maximum permitted length
		max: usize,
	},
	/// The value contains a character outside the permitted set.
	InvalidCharacter,
}

/// A length- and charset-constrained text rule.
#[derive(Debug, Clone, Copy)]
pub struct TextRule {
	/// Maximum length in UTF-16 code units (all permitted characters are
	/// single-unit, so character count is equivalent).
	pub max_length: usize,
	/// Whether an empty value bypasses validation.
	pub can_be_empty: bool,
	is_valid_char: fn(char) -> bool,
}

impl TextRule {
	/// Check the value against this rule, reporting which constraint
	/// failed.
	pub fn check(&self, value: &str) -> Result<(), TextRuleViolation> {
		if self.can_be_empty && value.is_empty() {
			return Ok(());
		}

		let length = value.encode_utf16().count();
		if length > self.max_length {
			return Err(TextRuleViolation::TooLong { length, max: self.max_length });
		}

		if !value.chars().all(self.is_valid_char) {
			return Err(TextRuleViolation::InvalidCharacter);
		}

		Ok(())
	}

	/// Whether the value satisfies this rule.
	pub fn is_valid(&self, value: &str) -> bool {
		self.check(value).is_ok()
	}
}

fn name_char(c: char) -> bool {
	c.is_ascii_uppercase() || c == '_'
}

fn description_char(c: char) -> bool {
	c.is_ascii_alphanumeric()
		|| matches!(
			c,
			'_' | '!'
				| '"' | '#' | '$'
				| '%' | '&' | '\''
				| '(' | ')' | '*'
				| '+' | ',' | '-'
				| '.' | '/' | ':'
				| ';' | '?' | '@'
				| '\\' | '^' | '‘'
				| '~' | ' '
		)
}

fn metadata_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '/' | '=')
}

fn external_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=' | ' ')
}

/// Validation configuration for a network.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
	/// Account name rule
	pub name: TextRule,
	/// Account description rule
	pub description: TextRule,
	/// Account metadata rule
	pub metadata: TextRule,
	/// SEND external data rule
	pub external: TextRule,
	/// Maximum token supply
	pub max_supply: BigInt,
	/// Maximum multisig signer count per level
	pub max_signer_count: u64,
	/// Maximum multisig signer depth
	pub max_signer_depth: u64,
	/// Maximum external permission offset
	pub max_external_offset: u64,
	/// Unix epoch milliseconds after which negative amounts are rejected
	pub numeric_cutoff_epoch_ms: i64,
	/// Maximum idempotent key length in bytes
	pub max_idempotent_bytes: usize,
}

impl Default for ValidationConfig {
	fn default() -> Self {
		Self {
			name: TextRule { max_length: 50, can_be_empty: false, is_valid_char: name_char },
			description: TextRule { max_length: 250, can_be_empty: false, is_valid_char: description_char },
			metadata: TextRule { max_length: 5464, can_be_empty: true, is_valid_char: metadata_char },
			external: TextRule { max_length: 1024, can_be_empty: true, is_valid_char: external_char },
			max_supply: BigInt::from(10u8).pow(200u32) - 1,
			max_signer_count: 16,
			max_signer_depth: 3,
			max_external_offset: 32,
			// 2025-11-21T00:00:00.000Z
			numeric_cutoff_epoch_ms: 1_763_683_200_000,
			max_idempotent_bytes: 36,
		}
	}
}

impl ValidationConfig {
	/// The validation configuration for the given network ID.
	///
	/// All known networks currently share the base configuration; unknown
	/// networks are rejected, matching the reference implementation.
	pub fn for_network(network: &BigInt) -> Result<Self, BlockError> {
		Network::try_from(network)?;
		Ok(Self::default())
	}

	/// Validate a multisig signer count for one level.
	pub fn validate_signer_count(&self, count: u64) -> Result<(), BlockError> {
		if count > self.max_signer_count || count < 1 {
			return Err(BlockError::MultisigSignerCountInvalid { count, max: self.max_signer_count });
		}

		Ok(())
	}

	/// Validate a multisig signer depth.
	pub fn validate_signer_depth(&self, depth: u64) -> Result<(), BlockError> {
		if depth > self.max_signer_depth {
			return Err(BlockError::MultisigSignerDepthExceeded { depth, max: self.max_signer_depth });
		}

		Ok(())
	}

	/// Validate a supply amount.
	pub fn validate_supply(&self, amount: &BigInt) -> Result<(), BlockError> {
		if *amount > self.max_supply {
			return Err(BlockError::SupplyInvalid);
		}

		Ok(())
	}

	/// Validate a numeric value against the negative-amount cutoff.
	pub fn validate_numeric_value(&self, value: &BigInt, block_date_ms: i64) -> Result<(), BlockError> {
		if *value >= BigInt::ZERO {
			return Ok(());
		}

		if block_date_ms < self.numeric_cutoff_epoch_ms {
			return Ok(());
		}

		Err(BlockError::AmountBelowZero)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_known_networks() {
		for id in [0u64, 0x5382, 0x538201, 0x5445_5354, 0x44_4556] {
			assert!(ValidationConfig::for_network(&BigInt::from(id)).is_ok());
		}
	}

	#[test]
	fn test_unknown_network_rejected() {
		let result = ValidationConfig::for_network(&BigInt::from(1234u64));
		assert!(matches!(result, Err(BlockError::UnknownNetwork)));
	}

	#[test]
	fn test_name_rule() {
		let config = ValidationConfig::default();
		assert!(config.name.is_valid("MY_TOKEN"));
		assert!(!config.name.is_valid("my_token"));
		assert!(config.name.is_valid(""));
		assert!(!config.name.is_valid(&"A".repeat(51)));
	}

	#[test]
	fn test_metadata_rule() {
		let config = ValidationConfig::default();
		assert!(config.metadata.is_valid("aGVsbG8="));
		assert!(config.metadata.is_valid(""));
		assert!(!config.metadata.is_valid("white space"));
	}

	#[test]
	fn test_external_rule() {
		let config = ValidationConfig::default();
		assert!(config.external.is_valid("payment ref 123"));
		assert!(!config.external.is_valid("bad\u{1F600}"));
	}

	#[test]
	fn test_description_rule() {
		let config = ValidationConfig::default();
		assert!(config.description.is_valid("A token; for testing!"));
		assert!(config.description.is_valid("quote ‘ allowed"));
		assert!(!config.description.is_valid("angle <brackets>"));
	}

	#[test]
	fn test_supply_validation() {
		let config = ValidationConfig::default();
		assert!(config.validate_supply(&config.max_supply.clone()).is_ok());
		let over = &config.max_supply + 1;
		assert!(matches!(config.validate_supply(&over), Err(BlockError::SupplyInvalid)));
	}

	#[test]
	fn test_numeric_cutoff() {
		let config = ValidationConfig::default();
		let negative = BigInt::from(-1);
		assert!(config
			.validate_numeric_value(&negative, config.numeric_cutoff_epoch_ms - 1)
			.is_ok());
		assert!(matches!(
			config.validate_numeric_value(&negative, config.numeric_cutoff_epoch_ms),
			Err(BlockError::AmountBelowZero)
		));
		assert!(config
			.validate_numeric_value(&BigInt::ZERO, config.numeric_cutoff_epoch_ms)
			.is_ok());
	}

	#[test]
	fn test_signer_limits() {
		let config = ValidationConfig::default();
		assert!(config.validate_signer_count(16).is_ok());
		assert!(config.validate_signer_count(17).is_err());
		assert!(config.validate_signer_count(0).is_err());
		assert!(config.validate_signer_depth(3).is_ok());
		assert!(config.validate_signer_depth(4).is_err());
	}
}
