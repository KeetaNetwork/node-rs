//! Constants for cryptographic operations.

use crate::HashAlgorithm;

/// Minimum length for passphrases.
/// The BIP39 english word list is 2048 words long, so we can encode 11 bits
/// per word.  The average word length is 5.4 characters, so we can encode
/// 121 bits in 60 bytes (an average of 11 words).
pub const MIN_PASSPHRASE_LENGTH: usize = 60;

/// Default hash algorithm for KeetaNet (SHA3-256)
pub const DEFAULT_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha3_256;

/// Hash function name to use with key derivation and public key checksums
pub const HASH_FUNCTION_NAME: &str = "sha3-256";

/// Length of the hash function in bytes
pub const HASH_FUNCTION_LENGTH: usize = 32;

/// Number of iterations for PBKDF2 key derivation
pub const PBKDF2_ITERATIONS: u32 = 64000;
