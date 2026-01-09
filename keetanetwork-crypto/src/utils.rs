use core::str::FromStr;

use bip39_dict::DefaultDictionary;
use pbkdf2;
use rand_core::TryRngCore;
use secrecy::SecretBox;
use zeroize::Zeroize;

use crate::algorithms::ed25519::Ed25519Derivation;
use crate::algorithms::secp256k1::Secp256k1Derivation;
use crate::algorithms::{Algorithm, AnyPrivateKey, AnyPublicKey};
use crate::algorithms::{KeyDerivation, PrivateKey};
use crate::constants::*;
use crate::error::CryptoError;
use crate::IntoSecret;

/// Macro to implement secure zeroization for wrapper structs.
///
/// This macro generates a `Zeroize` implementation that:
/// - Uses memory fences to prevent CPU and compiler reordering
/// - Uses `write_volatile` for compiler-resistant memory clearing
/// - Provides cryptographically robust memory clearing
/// - Supports multiple fields in a single invocation
/// - Auto-implements `ZeroizeOnDrop`
///
/// # Single Field Usage
/// ```rust,ignore
/// impl_secure_zeroize!(Secp256k1PrivateKey, K256SecretKey, inner);
/// ```
///
/// # Multiple Fields Usage
/// ```rust,ignore
/// impl_secure_zeroize!(MyPrivateKey, {
///     key_data: SecretKeyType,
///     nonce: NonceType,
///     salt: SaltType
/// });
/// ```
#[macro_export]
macro_rules! impl_secure_zeroize {
	// Helper macro for the actual zeroization logic
	(@zeroize_field $field_ptr:expr, $field_type:ty) => {
		unsafe {
			let ptr = $field_ptr as *mut $field_type as *mut u8;
			let size = core::mem::size_of::<$field_type>();
			for i in 0..size {
				// Use write_volatile in a loop for cryptographically
				// secure memory clearing. write_volatile prevents the
				// compiler from optimizing away these writes, ensuring
				// that sensitive data is actually overwritten in memory.
				core::ptr::write_volatile(ptr.add(i), 0u8);
			}
		}
	};

	// Single field variant
	($wrapper_type:ty, $inner_type:ty, $field_name:ident) => {
		impl zeroize::Zeroize for $wrapper_type {
			fn zeroize(&mut self) {
				// Pre-clear fence: Ensure all prior operations using this key
				// complete. This prevents speculative execution and ensures
				// cache coherency.
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

				// Zeroize the field
				$crate::impl_secure_zeroize!(@zeroize_field &mut self.$field_name, $inner_type);

				// Post-clear fence: Ensure the write is completed before any
				// subsequent operations. This prevents both compiler and CPU
				// reordering that could leave sensitive data exposed.
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
			}
		}
	};

	// Multiple fields variant
	($wrapper_type:ty, { $($field_name:ident: $field_type:ty),+ $(,)? }) => {
		impl zeroize::Zeroize for $wrapper_type {
			fn zeroize(&mut self) {
				// Pre-clear fence
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

				// Zeroize each field safely
				$(
					$crate::impl_secure_zeroize!(@zeroize_field &mut self.$field_name, $field_type);
				)+

				// Post-clear fence
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
			}
		}
	};
}

// Helper functions for error creation
// Note: These are necessary for test coverage
#[inline]
fn create_rng_error() -> CryptoError {
	CryptoError::InternalError { message: "Failed to generate random number".to_string() }
}

#[inline]
fn create_string_conversion_error() -> CryptoError {
	CryptoError::InternalError { message: "Failed to convert word to string".to_string() }
}

/// Derive a seed from a passphrase using PBKDF2 with SHA-256.
///
/// This function applies PBKDF2 key derivation to convert a passphrase
/// into a 32-byte seed suitable for key derivation.
pub fn seed_from_passphrase(passphrase: impl AsRef<str>) -> Result<SecretBox<[u8; 32]>, CryptoError> {
	// Normalize passphrase (lowercase, remove spaces)
	let clean_passphrase = passphrase.as_ref().to_lowercase().replace(" ", "");
	let passphrase_buffer = clean_passphrase.as_bytes();
	if passphrase_buffer.len() < MIN_PASSPHRASE_LENGTH {
		return Err(CryptoError::InvalidLength {
			message: format!(
				"Invalid passphrase, must be at least {} bytes after internal processing, got {}",
				MIN_PASSPHRASE_LENGTH,
				passphrase_buffer.len()
			),
		});
	}

	let mut key = [0u8; 32];

	// Use PBKDF2 with SHA-256, 64000 iterations,
	// using passphrase as both input and salt
	pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase_buffer, passphrase_buffer, PBKDF2_ITERATIONS, &mut key);
	Ok(key.into_secret())
}

/// Generates a random 24-word passphrase using a specified dictionary.
/// The default is the English dictionary.
/// Returns an error if the OS RNG fails.
pub fn generate_random_passphrase(
	dictionary: Option<DefaultDictionary>,
) -> Result<SecretBox<Vec<String>>, CryptoError> {
	let words = dictionary.unwrap_or(bip39_dict::ENGLISH).words;
	let word_count = words.len() as u32;

	// Pre-allocate to avoid reallocations that could leave fragments
	let mut passphrase = Vec::with_capacity(24);
	let mut random_indices = [0u32; 24];

	rand_core::OsRng
		.try_fill_bytes(unsafe {
			core::slice::from_raw_parts_mut(
				random_indices.as_mut_ptr() as *mut u8,
				core::mem::size_of_val(&random_indices),
			)
		})
		.map_err(|_| create_rng_error())?;

	core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

	// Convert random bytes to word indices
	for &raw_index in &random_indices {
		let word_index = raw_index % word_count;
		let word = words[word_index as usize];

		// Convert to owned string
		let word_string = String::from_str(word).map_err(|_| create_string_conversion_error())?;
		passphrase.push(word_string);
	}

	// Clear the random indices array
	random_indices.zeroize();

	core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

	Ok(passphrase.into_secret())
}

/// Generates a random 32-byte seed using the OS RNG.
/// Returns an error if the OS RNG fails.
#[inline]
pub fn generate_random_seed() -> Result<SecretBox<[u8; 32]>, CryptoError> {
	let random_bytes = generate_random_bytes::<32>()?;
	Ok(random_bytes.into_secret())
}

/// Generate random bytes of the specified length using the OS RNG.
/// Returns an error if the OS RNG fails.
#[inline]
pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
	let mut bytes = [0u8; N];

	rand_core::OsRng
		.try_fill_bytes(&mut bytes)
		.map_err(|_| create_rng_error())?;

	Ok(bytes)
}

/// Create a key pair for the specified algorithm
pub fn create_keypair_from_seed(
	seed: SecretBox<Vec<u8>>,
	algorithm: Algorithm,
) -> Result<(AnyPrivateKey, AnyPublicKey), CryptoError> {
	match algorithm {
		Algorithm::Secp256k1 => {
			let private_key = Secp256k1Derivation::derive_from_seed(seed)?;
			let public_key = private_key.as_public_key();

			Ok((AnyPrivateKey::Secp256k1(private_key), AnyPublicKey::Secp256k1(public_key)))
		}
		Algorithm::Ed25519 => {
			let private_key = Ed25519Derivation::derive_from_seed(seed)?;
			let public_key = private_key.as_public_key();

			Ok((AnyPrivateKey::Ed25519(private_key), AnyPublicKey::Ed25519(public_key)))
		}
		Algorithm::Secp256r1 => {
			Err(CryptoError::UnsupportedAlgorithm { algorithm: "secp256r1 not implemented".to_string() })
		}
	}
}

/// Parse DER-encoded ECDSA signature to extract r,s components.
///
/// DER format: SEQUENCE { r INTEGER, s INTEGER }
///
/// This function is only available when the "der" feature is enabled.
///
/// # Example
///
/// ```rust
/// # #[cfg(any(feature = "der", feature = "rasn"))]
/// # {
/// use keetanetwork_crypto::utils::parse_der_ecdsa_signature;
///
/// // Example DER-encoded ECDSA signature (minimal valid structure)
/// let der_sig = &[
///     0x30, 0x44,             // SEQUENCE, 68 bytes
///     0x02, 0x20,             // INTEGER, 32 bytes (r)
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
///     0x02, 0x20,             // INTEGER, 32 bytes (s)
///     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
///     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
///     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
///     0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
/// ];
///
/// let (r, s) = parse_der_ecdsa_signature(der_sig).unwrap();
/// assert_eq!(r.len(), 32);
/// assert_eq!(s.len(), 32);
/// # }
/// ```
#[cfg(any(feature = "der", feature = "rasn"))]
pub fn parse_der_ecdsa_signature(der_bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
	if der_bytes.len() < 8 || der_bytes[0] != 0x30 {
		return Err(CryptoError::InvalidInput);
	}

	let seq_len = der_bytes[1] as usize;
	if seq_len + 2 > der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}

	let mut pos = 2;

	// Parse r INTEGER
	if pos >= der_bytes.len() || der_bytes[pos] != 0x02 {
		return Err(CryptoError::InvalidInput);
	}

	pos += 1;
	if pos >= der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}

	let r_len = der_bytes[pos] as usize;

	pos += 1;
	if pos + r_len > der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}

	let r_bytes = &der_bytes[pos..pos + r_len];

	pos += r_len;
	// Parse s INTEGER
	if pos >= der_bytes.len() || der_bytes[pos] != 0x02 {
		return Err(CryptoError::InvalidInput);
	}

	pos += 1;
	if pos >= der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}

	let s_len = der_bytes[pos] as usize;

	pos += 1;
	if pos + s_len > der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}

	// Convert to exactly 32-byte arrays like TypeScript does
	let mut r_array = [0u8; 32];
	let mut s_array = [0u8; 32];

	// Handle r value: truncate from left if > 32 bytes, pad on left if < 32 bytes
	if r_bytes.len() > 32 {
		// TypeScript: sigSECValue.slice(-32) - take last 32 bytes
		r_array.copy_from_slice(&r_bytes[r_bytes.len() - 32..]);
	} else {
		// Pad on the left with zeros
		let start = 32 - r_bytes.len();
		r_array[start..].copy_from_slice(r_bytes);
	}

	// Handle s value: truncate from left if > 32 bytes, pad on left if < 32 bytes
	let s_bytes = &der_bytes[pos..pos + s_len];
	if s_bytes.len() > 32 {
		// TypeScript: sigSECValue.slice(-32) - take last 32 bytes
		s_array.copy_from_slice(&s_bytes[s_bytes.len() - 32..]);
	} else {
		// Pad on the left with zeros
		let start = 32 - s_bytes.len();
		s_array[start..].copy_from_slice(s_bytes);
	}

	Ok((r_array, s_array))
}

/// Encode ECDSA signature components (r, s) to DER format.
///
/// DER format: SEQUENCE { r INTEGER, s INTEGER }
///
/// This function takes the raw r and s components of an ECDSA signature
/// and encodes them into DER format as required by X.509 certificates.
///
/// # Arguments
///
/// * `r` - The r component of the ECDSA signature (32 bytes)
/// * `s` - The s component of the ECDSA signature (32 bytes)
///
/// # Returns
///
/// Returns a vec containing the DER-encoded signature.
///
/// # Example
///
/// ```rust
/// # #[cfg(any(feature = "der", feature = "rasn"))]
/// # {
/// use keetanetwork_crypto::utils::encode_ecdsa_signature_to_der;
///
/// let r = [0x01u8; 32];
/// let s = [0x02u8; 32];
///
/// let der_sig = encode_ecdsa_signature_to_der(&r, &s);
/// assert!(der_sig.len() > 64); // DER encoding adds overhead
/// assert_eq!(der_sig[0], 0x30); // SEQUENCE tag
/// # }
/// ```
#[cfg(any(feature = "der", feature = "rasn"))]
pub fn encode_ecdsa_signature_to_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
	// Helper function to encode a single integer, removing leading zeros
	// but adding a zero byte if the most significant bit is set (to ensure positive)
	fn encode_integer(value: &[u8]) -> Vec<u8> {
		// Remove leading zeros
		let start = value
			.iter()
			.position(|&b| b != 0)
			.unwrap_or(value.len().saturating_sub(1));
		let trimmed = &value[start..];

		// If the most significant bit is set, prepend a zero byte to ensure positive
		if trimmed.is_empty() {
			vec![0x02, 0x01, 0x00] // INTEGER, length 1, value 0
		} else if trimmed[0] & 0x80 != 0 {
			let mut result = vec![0x02, (trimmed.len() + 1) as u8, 0x00];
			result.extend_from_slice(trimmed);
			result
		} else {
			let mut result = vec![0x02, trimmed.len() as u8];
			result.extend_from_slice(trimmed);
			result
		}
	}

	let r_encoded = encode_integer(r);
	let s_encoded = encode_integer(s);

	let total_length = r_encoded.len() + s_encoded.len();

	// Build the SEQUENCE
	let mut result = vec![0x30, total_length as u8];
	result.extend_from_slice(&r_encoded);
	result.extend_from_slice(&s_encoded);

	result
}

// ============================================================================
// Low-S Signature Normalization (BIP-62)
// ============================================================================

/// Secp256k1 curve order n
const SECP256K1_N: [u8; 32] = [
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC,
	0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Secp256k1 n/2 (half the curve order) - threshold for low-S
const SECP256K1_HALF_N: [u8; 32] = [
	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E,
	0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Secp256r1 (P-256) curve order n
const SECP256R1_N: [u8; 32] = [
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA,
	0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Secp256r1 n/2 (half the curve order) - threshold for low-S
const SECP256R1_HALF_N: [u8; 32] = [
	0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDE, 0x73, 0x7D,
	0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// Normalize an ECDSA signature to low-S form (BIP-62).
///
/// ECDSA signatures have malleability: both `(r, s)` and `(r, n - s)` are valid
/// signatures for the same message. BIP-62 requires "low-S" where `s <= n/2`.
///
/// This function modifies the signature in-place if `s > n/2` by computing `s' = n - s`.
///
/// # Arguments
///
/// * `signature` - A 64-byte signature in raw format (r || s, 32 bytes each)
/// * `algorithm` - The signing algorithm (determines which curve order to use)
///
/// # Returns
///
/// Returns `true` if normalization was performed, `false` if the signature was already low-S.
///
/// # Note
///
/// Ed25519 signatures do not have this malleability issue and are returned unchanged.
///
/// # Example
///
/// ```rust
/// use keetanetwork_crypto::utils::normalize_low_s;
/// use keetanetwork_crypto::algorithms::Algorithm;
///
/// let mut signature = [0u8; 64];
/// // ... fill with actual signature bytes ...
/// signature[32] = 0x80; // High-S value (MSB set)
///
/// let was_normalized = normalize_low_s(&mut signature, Algorithm::Secp256k1);
/// assert!(was_normalized);
/// ```
pub fn normalize_low_s(signature: &mut [u8; 64], algorithm: Algorithm) -> bool {
	let (n, half_n) = match algorithm {
		Algorithm::Secp256k1 => (&SECP256K1_N, &SECP256K1_HALF_N),
		Algorithm::Secp256r1 => (&SECP256R1_N, &SECP256R1_HALF_N),
		Algorithm::Ed25519 => return false, // Ed25519 doesn't need low-S normalization
	};

	let s = &signature[32..64];

	// Check if s > n/2
	if compare_be_32(s, half_n) > 0 {
		// s = n - s
		let mut new_s = [0u8; 32];
		subtract_be_32(n, s, &mut new_s);
		signature[32..64].copy_from_slice(&new_s);
		true
	} else {
		false
	}
}

/// Check if an ECDSA signature has low-S form (BIP-62 compliant).
///
/// A signature is low-S if `s <= n/2` where `n` is the curve order.
///
/// # Arguments
///
/// * `signature` - A 64-byte signature in raw format (r || s, 32 bytes each)
/// * `algorithm` - The signing algorithm (determines which curve order to use)
///
/// # Returns
///
/// Returns `true` if the signature is in low-S form, `false` otherwise.
///
/// # Note
///
/// Ed25519 signatures always return `true` as they don't have this malleability issue.
///
/// # Example
///
/// ```rust
/// use keetanetwork_crypto::utils::is_low_s;
/// use keetanetwork_crypto::algorithms::Algorithm;
///
/// let signature = [0u8; 64]; // All zeros is definitely low-S
/// assert!(is_low_s(&signature, Algorithm::Secp256k1));
/// ```
pub fn is_low_s(signature: &[u8; 64], algorithm: Algorithm) -> bool {
	let half_n = match algorithm {
		Algorithm::Secp256k1 => &SECP256K1_HALF_N,
		Algorithm::Secp256r1 => &SECP256R1_HALF_N,
		Algorithm::Ed25519 => return true, // Ed25519 signatures are always valid
	};

	compare_be_32(&signature[32..64], half_n) <= 0
}

/// Compare two big-endian 32-byte integers.
///
/// Returns: 1 if a > b, -1 if a < b, 0 if equal
#[inline]
fn compare_be_32(a: &[u8], b: &[u8]) -> i32 {
	for i in 0..32 {
		if a[i] > b[i] {
			return 1;
		}
		if a[i] < b[i] {
			return -1;
		}
	}
	0
}

/// Subtract b from a (big-endian): result = a - b
///
/// Assumes a >= b (no underflow check needed for low-S normalization)
#[inline]
fn subtract_be_32(a: &[u8; 32], b: &[u8], result: &mut [u8; 32]) {
	let mut borrow = 0i16;
	for i in (0..32).rev() {
		let diff = (a[i] as i16) - (b[i] as i16) - borrow;
		if diff < 0 {
			result[i] = (diff + 256) as u8;
			borrow = 1;
		} else {
			result[i] = diff as u8;
			borrow = 0;
		}
	}
}

#[cfg(test)]
mod tests {
	use zeroize::Zeroize;

	use super::*;
	use crate::prelude::{Algorithm, ExposeSecret, IntoSecret};

	// ============================================================================
	// Low-S Normalization Tests
	// ============================================================================

	mod low_s_tests {
		use super::*;

		#[test]
		fn test_already_low_s_minimal() {
			// s = 1 (smallest possible, already low)
			let mut sig = [0u8; 64];
			sig[63] = 1;

			let original = sig;
			let normalized = normalize_low_s(&mut sig, Algorithm::Secp256k1);

			assert!(!normalized, "s=1 should not be normalized");
			assert_eq!(sig, original, "s=1 should remain unchanged");
		}

		#[test]
		fn test_already_low_s_half_n_secp256k1() {
			// s = n/2 exactly (boundary case, should NOT be normalized)
			let mut sig = [0u8; 64];
			sig[32..64].copy_from_slice(&SECP256K1_HALF_N);

			let original = sig;
			let normalized = normalize_low_s(&mut sig, Algorithm::Secp256k1);

			assert!(!normalized, "s=n/2 should not be normalized");
			assert_eq!(sig, original, "s=n/2 should remain unchanged");
		}

		#[test]
		fn test_high_s_just_above_half_secp256k1() {
			// s = n/2 + 1 (should be normalized)
			let mut sig = [0u8; 64];
			sig[32..64].copy_from_slice(&SECP256K1_HALF_N);
			// Add 1
			let mut carry = 1u16;
			for i in (32..64).rev() {
				let sum = sig[i] as u16 + carry;
				sig[i] = sum as u8;
				carry = sum >> 8;
				if carry == 0 {
					break;
				}
			}

			let original_s = sig[32..64].to_vec();
			let normalized = normalize_low_s(&mut sig, Algorithm::Secp256k1);

			assert!(normalized, "s > n/2 should be normalized");
			assert_ne!(&sig[32..64], original_s.as_slice(), "s should have changed");
			assert!(is_low_s(&sig, Algorithm::Secp256k1), "result should be low-S");
		}

		#[test]
		fn test_high_s_maximum_secp256k1() {
			// s = n - 1 (maximum valid, definitely high)
			let mut sig = [0u8; 64];
			sig[32..64].copy_from_slice(&SECP256K1_N);
			sig[63] -= 1; // n - 1

			let normalized = normalize_low_s(&mut sig, Algorithm::Secp256k1);

			assert!(normalized, "s = n-1 should be normalized");
			// After normalization: new_s = n - (n-1) = 1
			assert_eq!(sig[63], 1, "n - (n-1) should equal 1");
			for i in 32..63 {
				assert_eq!(sig[i], 0, "all other bytes should be 0");
			}
		}

		#[test]
		fn test_r_value_preserved() {
			// Ensure r value is never modified
			let mut sig = [0u8; 64];
			for i in 0..32 {
				sig[i] = (i + 1) as u8;
			}
			// Set high s that needs normalization
			sig[32..64].copy_from_slice(&SECP256K1_N);
			sig[63] -= 1; // n - 1

			let original_r: [u8; 32] = sig[0..32].try_into().unwrap();
			normalize_low_s(&mut sig, Algorithm::Secp256k1);

			assert_eq!(&sig[0..32], &original_r, "r value should never be modified");
		}

		#[test]
		fn test_high_s_with_msb_set() {
			// s = 0x80...00 (high bit set, definitely > n/2)
			let mut sig = [0u8; 64];
			sig[32] = 0x80;

			let normalized = normalize_low_s(&mut sig, Algorithm::Secp256k1);

			assert!(normalized, "s with MSB set should be normalized");
			assert!(is_low_s(&sig, Algorithm::Secp256k1), "result should be low-S");
		}

		#[test]
		fn test_secp256r1_normalization() {
			// Test secp256r1 with high-S value
			let mut sig = [0u8; 64];
			sig[32] = 0x80; // High bit set

			let normalized = normalize_low_s(&mut sig, Algorithm::Secp256r1);

			assert!(normalized, "secp256r1 high-S should be normalized");
			assert!(is_low_s(&sig, Algorithm::Secp256r1), "result should be low-S");
		}

		#[test]
		fn test_secp256r1_half_n_boundary() {
			// s = n/2 exactly for secp256r1
			let mut sig = [0u8; 64];
			sig[32..64].copy_from_slice(&SECP256R1_HALF_N);

			let normalized = normalize_low_s(&mut sig, Algorithm::Secp256r1);

			assert!(!normalized, "secp256r1 s=n/2 should not be normalized");
			assert!(is_low_s(&sig, Algorithm::Secp256r1), "s=n/2 is low-S");
		}

		#[test]
		fn test_ed25519_no_normalization() {
			// Ed25519 should never normalize
			let mut sig = [0u8; 64];
			sig[32] = 0xFF; // Would be high-S for ECDSA

			let original = sig;
			let normalized = normalize_low_s(&mut sig, Algorithm::Ed25519);

			assert!(!normalized, "Ed25519 should not normalize");
			assert_eq!(sig, original, "Ed25519 signature should be unchanged");
		}

		#[test]
		fn test_ed25519_always_low_s() {
			// Ed25519 is_low_s should always return true
			let mut sig = [0u8; 64];
			sig[32] = 0xFF;
			sig[33] = 0xFF;

			assert!(is_low_s(&sig, Algorithm::Ed25519), "Ed25519 is always low-S");
		}

		#[test]
		fn test_is_low_s_zero() {
			// s = 0 is definitely low-S
			let sig = [0u8; 64];
			assert!(is_low_s(&sig, Algorithm::Secp256k1));
			assert!(is_low_s(&sig, Algorithm::Secp256r1));
		}

		#[test]
		fn test_is_low_s_high_value() {
			// s with MSB set is not low-S
			let mut sig = [0u8; 64];
			sig[32] = 0x80;

			assert!(!is_low_s(&sig, Algorithm::Secp256k1));
			assert!(!is_low_s(&sig, Algorithm::Secp256r1));
		}
	}

	// ============================================================================
	// Big-Endian Arithmetic Tests
	// ============================================================================

	mod bigint_tests {
		use super::*;

		#[test]
		fn test_compare_equal() {
			let a = [0x42u8; 32];
			let b = [0x42u8; 32];
			assert_eq!(compare_be_32(&a, &b), 0);
		}

		#[test]
		fn test_compare_greater_first_byte() {
			let mut a = [0u8; 32];
			let mut b = [0u8; 32];
			a[0] = 0x02;
			b[0] = 0x01;
			assert_eq!(compare_be_32(&a, &b), 1);
		}

		#[test]
		fn test_compare_less_first_byte() {
			let mut a = [0u8; 32];
			let mut b = [0u8; 32];
			a[0] = 0x01;
			b[0] = 0x02;
			assert_eq!(compare_be_32(&a, &b), -1);
		}

		#[test]
		fn test_compare_greater_last_byte() {
			let mut a = [0u8; 32];
			let mut b = [0u8; 32];
			a[31] = 0x02;
			b[31] = 0x01;
			assert_eq!(compare_be_32(&a, &b), 1);
		}

		#[test]
		fn test_subtract_no_borrow() {
			let a: [u8; 32] = {
				let mut arr = [0u8; 32];
				arr[31] = 0x10;
				arr
			};
			let b: [u8; 32] = {
				let mut arr = [0u8; 32];
				arr[31] = 0x05;
				arr
			};
			let mut result = [0u8; 32];

			subtract_be_32(&a, &b, &mut result);

			assert_eq!(result[31], 0x0B); // 16 - 5 = 11
		}

		#[test]
		fn test_subtract_with_borrow() {
			let a: [u8; 32] = {
				let mut arr = [0u8; 32];
				arr[30] = 0x01;
				arr[31] = 0x00;
				arr
			};
			let b: [u8; 32] = {
				let mut arr = [0u8; 32];
				arr[31] = 0x01;
				arr
			};
			let mut result = [0u8; 32];

			subtract_be_32(&a, &b, &mut result);

			// 0x0100 - 0x01 = 0xFF
			assert_eq!(result[30], 0x00);
			assert_eq!(result[31], 0xFF);
		}
	}

	#[test]
	fn test_seed_from_passphrase() {
		let passphrase = "panic category office glow ski camera file slight room escape indicate fiction";

		let seed = seed_from_passphrase(passphrase);
		assert!(seed.is_ok());

		let seed = seed.unwrap();
		assert_eq!(seed.expose_secret().len(), 32);

		// Test with passphrase shorter than MIN_PASSPHRASE_LENGTH (60 characters)
		let short_passphrase = "short"; // Only 5 characters
		let result = seed_from_passphrase(short_passphrase);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidLength { .. }));

		// Test with passphrase that's just under the limit
		let almost_long_passphrase = "a".repeat(59); // 59 characters, 1 under limit
		let result = seed_from_passphrase(&almost_long_passphrase);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidLength { .. }));

		// Test with passphrase that meets the minimum length
		let min_length_passphrase = "a".repeat(60); // Exactly 60 characters
		let result = seed_from_passphrase(&min_length_passphrase);
		assert!(result.is_ok());

		// Test that spaces are removed and lowercase is applied
		let passphrase_with_spaces = "PANIC CATEGORY OFFICE GLOW SKI CAMERA FILE SLIGHT ROOM ESCAPE INDICATE FICTION";
		// cspell:disable-next-line
		let normalized_passphrase = "paniccategoryofficeglowskicamerafileslightroomescapeindicatefiction";

		// Both should produce the same result
		let seed1 = seed_from_passphrase(passphrase_with_spaces).unwrap();
		let seed2 = seed_from_passphrase(normalized_passphrase).unwrap();
		assert_eq!(seed1.expose_secret(), seed2.expose_secret());
	}

	#[test]
	fn test_generate_random_passphrase() {
		let passphrase = generate_random_passphrase(None).unwrap();
		let passphrase = passphrase.expose_secret();
		assert_eq!(passphrase.len(), 24);

		// All words should be from the bip39 dictionary
		for word in passphrase {
			assert!(bip39_dict::ENGLISH.words.contains(&word.as_str()));
		}
	}

	#[test]
	fn test_generate_random_seed() {
		let seed = generate_random_seed().unwrap();
		let seed = seed.expose_secret();

		assert_eq!(seed.len(), 32);
		// Should not be all zeros (extremely unlikely)
		assert_ne!(*seed, [0u8; 32]);
	}

	#[test]
	fn test_generate_random_bytes() {
		// Test 16-byte generation
		let bytes16 = generate_random_bytes::<16>().unwrap();
		assert_eq!(bytes16.len(), 16);
		assert_ne!(bytes16, [0u8; 16]); // Should not be all zeros

		// Test 32-byte generation
		let bytes32 = generate_random_bytes::<32>().unwrap();
		assert_eq!(bytes32.len(), 32);
		assert_ne!(bytes32, [0u8; 32]); // Should not be all zeros

		// Test that multiple calls produce different results
		let bytes1 = generate_random_bytes::<16>().unwrap();
		let bytes2 = generate_random_bytes::<16>().unwrap();
		assert_ne!(bytes1, bytes2); // Should be different
	}

	#[test]
	fn test_create_keypair_from_seed() {
		let seed = b"test seed for keypair creation!!!!!";

		// Test secp256k1 creation
		let (private_key, public_key) =
			create_keypair_from_seed(seed.to_vec().into_secret(), Algorithm::Secp256k1).unwrap();
		assert_eq!(Algorithm::from(&private_key), Algorithm::Secp256k1);
		assert_eq!(Algorithm::from(&public_key), Algorithm::Secp256k1);

		// Test Ed25519 creation
		let (private_key, public_key) =
			create_keypair_from_seed(seed.to_vec().into_secret(), Algorithm::Ed25519).unwrap();
		assert_eq!(Algorithm::from(&private_key), Algorithm::Ed25519);
		assert_eq!(Algorithm::from(&public_key), Algorithm::Ed25519);

		// Test unsupported algorithm
		let result = create_keypair_from_seed(seed.to_vec().into_secret(), Algorithm::Secp256r1);
		assert!(result.is_err());
	}

	#[test]
	fn test_error_creation_functions() {
		// Test that error creation functions work correctly and return InternalError variants
		assert!(matches!(create_rng_error(), CryptoError::InternalError { .. }));
		assert!(matches!(create_string_conversion_error(), CryptoError::InternalError { .. }));
	}

	#[test]
	#[cfg(any(feature = "der", feature = "rasn"))]
	fn test_parse_der_ecdsa_signature() {
		// Valid DER-encoded ECDSA signature
		let valid_der = [
			0x30, 0x44, // SEQUENCE, length 68
			0x02, 0x20, // INTEGER, length 32 (r)
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
			0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x02,
			0x20, // INTEGER, length 32 (s)
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
			0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
		];

		let result = parse_der_ecdsa_signature(&valid_der);
		assert!(result.is_ok());

		let (r, s) = result.unwrap();
		assert_eq!(r.len(), 32);
		assert_eq!(s.len(), 32);

		// Check that r and s values are correctly extracted
		assert_eq!(r[0], 0x01);
		assert_eq!(r[31], 0x20);
		assert_eq!(s[0], 0x21);
		assert_eq!(s[31], 0x40);
	}

	#[test]
	#[cfg(any(feature = "der", feature = "rasn"))]
	fn test_encode_ecdsa_signature_to_der() {
		// Test with simple values
		let r = [0x01u8; 32];
		let s = [0x02u8; 32];

		// Should start with SEQUENCE tag
		let der_encoded = encode_ecdsa_signature_to_der(&r, &s);
		assert_eq!(der_encoded[0], 0x30);

		// Parse it back to verify round-trip
		let (parsed_r, parsed_s) = parse_der_ecdsa_signature(&der_encoded).unwrap();
		assert_eq!(parsed_r, r);
		assert_eq!(parsed_s, s);

		// Test with values that have leading zeros
		let r_with_zeros = [
			0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
			28, 29,
		];
		let s_with_zeros = [
			0, 0, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
			57, 58, 59, 60, 61,
		];

		let der_encoded2 = encode_ecdsa_signature_to_der(&r_with_zeros, &s_with_zeros);
		let (parsed_r2, parsed_s2) = parse_der_ecdsa_signature(&der_encoded2).unwrap();
		assert_eq!(parsed_r2, r_with_zeros);
		assert_eq!(parsed_s2, s_with_zeros);

		// Test with values that need padding (MSB set)
		let r_msb_set = [0x80u8; 32];
		let s_msb_set = [0xFFu8; 32];

		let der_encoded3 = encode_ecdsa_signature_to_der(&r_msb_set, &s_msb_set);
		let (parsed_r3, parsed_s3) = parse_der_ecdsa_signature(&der_encoded3).unwrap();
		assert_eq!(parsed_r3, r_msb_set);
		assert_eq!(parsed_s3, s_msb_set);
	}

	#[test]
	#[cfg(any(feature = "der", feature = "rasn"))]
	fn test_parse_der_ecdsa_signature_error_cases() {
		let test_cases = [
			// Basic invalid cases
			(&[] as &[u8], "Empty input"),
			(&[0x31, 0x44], "Wrong tag (not SEQUENCE)"),
			(&[0x30], "Missing length"),
			(&[0x30, 0x44], "Length but no data"),
			(&[0x30, 0xFF, 0x02], "Invalid sequence length"),
			// Precise positioning tests for r INTEGER
			(&[0x30, 0x02], "pos=2: Buffer ends, no r INTEGER tag"),
			(&[0x30, 0x03, 0x01], "pos=2: Wrong r tag byte"),
			(&[0x30, 0x03, 0x02], "pos=3: No r length byte"),
			(&[0x30, 0x04, 0x02, 0x05], "pos=4: r length=5 but no data"),
			// Precise positioning tests for s INTEGER
			(&[0x30, 0x05, 0x02, 0x01, 0x42], "pos=5: No s INTEGER tag"),
			(&[0x30, 0x06, 0x02, 0x01, 0x42, 0x01], "pos=5: Wrong s tag byte"),
			(&[0x30, 0x06, 0x02, 0x01, 0x42, 0x02], "pos=6: No s length byte"),
			(&[0x30, 0x07, 0x02, 0x01, 0x42, 0x02, 0x05], "pos=7: s length=5 but no data"),
			// Additional edge cases
			(&[0x30, 0x04, 0x01, 0x20], "Wrong r tag (not INTEGER)"),
			(&[0x30, 0x04, 0x02, 0x20], "r length but no data"),
			(&[0x30, 0x04, 0x02, 0xFF, 0x01], "Invalid r length"),
			(&[0x30, 0x44, 0x02, 0x20, 0x01], "Truncated signature"),
		];

		for (input, description) in test_cases {
			assert!(parse_der_ecdsa_signature(input).is_err(), "Failed case: {description}");
		}

		// Complex invalid s INTEGER cases
		let complex_cases = [
			([0x30, 0x24, 0x02, 0x01, 0x42, 0x01, 0x01, 0x43].as_slice(), "Invalid s tag (not INTEGER)"),
			([0x30, 0x04, 0x02, 0x01, 0x42, 0x02].as_slice(), "Missing s length"),
			([0x30, 0x06, 0x02, 0x01, 0x42, 0x02, 0xFF].as_slice(), "Invalid s length"),
		];

		for (input, description) in complex_cases {
			assert!(parse_der_ecdsa_signature(input).is_err(), "Failed case: {description}");
		}
	}

	#[test]
	fn test_impl_secure_zeroize() {
		// Test single field variant
		struct TestSingleKey {
			inner: [u8; 32],
		}

		impl_secure_zeroize!(TestSingleKey, [u8; 32], inner);
		impl zeroize::ZeroizeOnDrop for TestSingleKey {}

		let mut single_key = TestSingleKey { inner: [0x42u8; 32] };
		assert!(single_key.inner.iter().all(|&b| b == 0x42));
		single_key.zeroize();
		assert!(single_key.inner.iter().all(|&b| b == 0x00));

		// Test multiple fields variant with different types
		struct TestMultiKey {
			key_data: [u8; 32],
			nonce: [u8; 16],
			salt: u64,
			counter: [u32; 4],
			flag: u8,
		}

		impl_secure_zeroize!(TestMultiKey, {
			key_data: [u8; 32],
			nonce: [u8; 16],
			salt: u64,
			counter: [u32; 4],
			flag: u8
		});
		impl zeroize::ZeroizeOnDrop for TestMultiKey {}

		let mut multi_key = TestMultiKey {
			key_data: [0x11u8; 32],
			nonce: [0x22u8; 16],
			salt: 0x1234567890ABCDEF,
			counter: [0x11111111, 0x22222222, 0x33333333, 0x44444444],
			flag: 0xFF,
		};

		// Verify initial state
		assert!(multi_key.key_data.iter().all(|&b| b == 0x11));
		assert!(multi_key.nonce.iter().all(|&b| b == 0x22));
		assert_eq!(multi_key.salt, 0x1234567890ABCDEF);
		assert_eq!(multi_key.counter[0], 0x11111111);
		assert_eq!(multi_key.flag, 0xFF);

		// Zero and verify all fields cleared
		multi_key.zeroize();
		assert!(multi_key.key_data.iter().all(|&b| b == 0x00));
		assert!(multi_key.nonce.iter().all(|&b| b == 0x00));
		assert_eq!(multi_key.salt, 0);
		assert!(multi_key.counter.iter().all(|&v| v == 0));
		assert_eq!(multi_key.flag, 0);

		// Test ZeroizeOnDrop works without panics
		{
			let _drop_test = TestSingleKey { inner: [0x77u8; 32] };
		}
	}
}
