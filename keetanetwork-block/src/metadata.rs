//! Metadata parsing.
//!
//! Decodes base64 JSON metadata and extracts asset_id/authority/symbol.
//! This module is no_std compatible and does not allocate.

use base64ct::{Base64, Encoding};
use serde::Deserialize;

const MAX_FIELD_LEN: usize = 64;

/// Raw metadata structure for JSON deserialization.
#[derive(Deserialize)]
struct RawMetadata<'a> {
	#[serde(default)]
	asset_id: Option<&'a str>,
	#[serde(default)]
	authority: Option<&'a str>,
	#[serde(default)]
	symbol: Option<&'a str>,
}

/// Decoded metadata with fixed-size buffers.
pub struct DecodedMetadata {
	pub asset_id: [u8; MAX_FIELD_LEN],
	pub asset_id_len: usize,
	pub authority: [u8; MAX_FIELD_LEN],
	pub authority_len: usize,
	pub symbol: [u8; MAX_FIELD_LEN],
	pub symbol_len: usize,
}

impl DecodedMetadata {
	/// Get the asset_id as a string slice, if present.
	pub fn asset_id_str(&self) -> Option<&str> {
		field_str(&self.asset_id, self.asset_id_len)
	}

	/// Get the authority as a string slice, if present.
	pub fn authority_str(&self) -> Option<&str> {
		field_str(&self.authority, self.authority_len)
	}

	/// Get the symbol as a string slice, if present.
	pub fn symbol_str(&self) -> Option<&str> {
		field_str(&self.symbol, self.symbol_len)
	}
}

impl Default for DecodedMetadata {
	fn default() -> Self {
		Self {
			asset_id: [0u8; MAX_FIELD_LEN],
			asset_id_len: 0,
			authority: [0u8; MAX_FIELD_LEN],
			authority_len: 0,
			symbol: [0u8; MAX_FIELD_LEN],
			symbol_len: 0,
		}
	}
}

/// Returns the populated prefix of `buf` as UTF-8, or `None` when empty/invalid.
fn field_str(buf: &[u8], len: usize) -> Option<&str> {
	if len > 0 {
		core::str::from_utf8(&buf[..len]).ok()
	} else {
		None
	}
}

/// Result of metadata decoding.
///
/// The `Decoded` variant intentionally inlines fixed-size buffers so the type
/// works without `alloc`; boxing would defeat that, so the size disparity is
/// accepted.
#[allow(clippy::large_enum_variant)]
pub enum MetadataDisplay {
	/// Successfully decoded metadata with at least one known field.
	Decoded(DecodedMetadata),
	/// Valid JSON but no known fields (asset_id, authority, symbol).
	Unknown,
	/// Invalid base64 encoding or malformed JSON.
	Invalid,
	/// Empty input string.
	Empty,
}

/// Decode base64 metadata and extract known fields.
///
/// # Arguments
/// * `base64_input` - Base64-encoded JSON string
/// * `decode_buf` - Buffer for base64 decoding, must be >= input.len() * 3/4
///
/// # Returns
/// A `MetadataDisplay` variant indicating the result.
pub fn decode_metadata(base64_input: &str, decode_buf: &mut [u8]) -> MetadataDisplay {
	if base64_input.is_empty() {
		return MetadataDisplay::Empty;
	}

	let decoded = match Base64::decode(base64_input.as_bytes(), decode_buf) {
		Ok(bytes) => bytes,
		Err(_) => return MetadataDisplay::Invalid,
	};

	let raw: RawMetadata = match serde_json_core::from_slice(decoded) {
		Ok((meta, _)) => meta,
		Err(_) => return MetadataDisplay::Invalid,
	};

	let mut result = DecodedMetadata::default();

	let copy_field = |value: &str, buf: &mut [u8; MAX_FIELD_LEN]| -> usize {
		let len = value.len().min(MAX_FIELD_LEN);
		buf[..len].copy_from_slice(&value.as_bytes()[..len]);
		len
	};

	if let Some(v) = raw.asset_id {
		result.asset_id_len = copy_field(v, &mut result.asset_id);
	}
	if let Some(v) = raw.authority {
		result.authority_len = copy_field(v, &mut result.authority);
	}
	if let Some(v) = raw.symbol {
		result.symbol_len = copy_field(v, &mut result.symbol);
	}

	if result.asset_id_len > 0 || result.authority_len > 0 || result.symbol_len > 0 {
		MetadataDisplay::Decoded(result)
	} else {
		MetadataDisplay::Unknown
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Maps a result to a stable discriminant label for assertions.
	fn kind(display: &MetadataDisplay) -> &'static str {
		match display {
			MetadataDisplay::Decoded(_) => "decoded",
			MetadataDisplay::Unknown => "unknown",
			MetadataDisplay::Invalid => "invalid",
			MetadataDisplay::Empty => "empty",
		}
	}

	/// Extracts the decoded metadata, panicking on any other variant.
	fn expect_decoded(input: &str, buf: &mut [u8]) -> DecodedMetadata {
		match decode_metadata(input, buf) {
			MetadataDisplay::Decoded(meta) => meta,
			other => panic!("expected Decoded, got {}", kind(&other)),
		}
	}

	#[test]
	fn test_decode_metadata_full() {
		let mut buf = [0u8; 512];

		let json =
			r#"{"asset_id":"asset://1f0ccae9-5666/1","authority":"keeta_abc123def456","signature":"c2lnbmF0dXJl"}"#;
		let b64 = base64_encode_for_test(json.as_bytes());

		let meta = expect_decoded(&b64, &mut buf);
		assert_eq!(meta.asset_id_str(), Some("asset://1f0ccae9-5666/1"));
		assert_eq!(meta.authority_str(), Some("keeta_abc123def456"));
	}

	#[test]
	fn test_decode_metadata_with_symbol() {
		let mut buf = [0u8; 512];

		let json = r#"{"asset_id":"asset://123","symbol":"KEETA"}"#;
		let b64 = base64_encode_for_test(json.as_bytes());

		let meta = expect_decoded(&b64, &mut buf);
		assert_eq!(meta.asset_id_str(), Some("asset://123"));
		assert_eq!(meta.symbol_str(), Some("KEETA"));
		assert_eq!(meta.authority_str(), None);
	}

	#[test]
	fn test_decode_metadata_non_decoded_cases() {
		let unknown_json = r#"{"foo":"bar","baz":123}"#;
		let unknown_b64 = base64_encode_for_test(unknown_json.as_bytes());
		let invalid_json_b64 = base64_encode_for_test(b"not json at all");

		let cases: &[(&str, &str)] = &[
			("", "empty"),
			(&unknown_b64, "unknown"),
			("not-valid-base64!!!", "invalid"),
			(&invalid_json_b64, "invalid"),
		];

		for (input, expected) in cases {
			let mut buf = [0u8; 512];
			let result = decode_metadata(input, &mut buf);
			assert_eq!(kind(&result), *expected, "case input {input:?}");
		}
	}

	fn base64_encode_for_test(input: &[u8]) -> String {
		const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		let mut result = String::new();

		for chunk in input.chunks(3) {
			let b0 = chunk[0] as u32;
			let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
			let b2 = chunk.get(2).copied().unwrap_or(0) as u32;

			let n = (b0 << 16) | (b1 << 8) | b2;

			result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
			result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);

			if chunk.len() > 1 {
				result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
			} else {
				result.push('=');
			}

			if chunk.len() > 2 {
				result.push(CHARS[(n & 0x3F) as usize] as char);
			} else {
				result.push('=');
			}
		}

		result
	}
}
