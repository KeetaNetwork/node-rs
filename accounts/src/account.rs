use core::str::FromStr;

use crypto::algorithms::{Algorithm, CryptoAlgorithm};
use crypto::operations::SignatureError;
use crypto::prelude::*;
use crypto::utils::{generate_random_passphrase, seed_from_passphrase};
use hex::{FromHex, ToHex};
use strum_macros::{Display, EnumIter, EnumString};
use zeroize::Zeroize;

use crate::constants::NO_PREVIOUS;
use crate::error::AccountError;
use crate::utils::*;
use crate::{HexSeedAndIndex, Index, PassphraseAndIndex, Seed, SeedAndIndex};

/// Identifier key types (non-cryptographic)
const IDENTIFIER_KEY_TYPES: &[KeyPairType] =
	&[KeyPairType::NETWORK, KeyPairType::TOKEN, KeyPairType::STORAGE, KeyPairType::MULTISIG];

/// Supported cryptographic key pair types for the Keeta Network.
///
/// This enum defines all key types supported by the account system, including
/// both cryptographic keys for signing operations and identifier keys for
/// network addressing and resource identification.
///
/// # Cryptographic Key Types
///
/// These key types support full cryptographic operations including signing,
/// verification, and key derivation:
///
/// - [`ECDSASECP256K1`](KeyPairType::ECDSASECP256K1) - Bitcoin-style elliptic curve signatures
/// - [`ED25519`](KeyPairType::ED25519) - EdDSA signatures using Curve25519
/// - [`ECDSASECP256R1`](KeyPairType::ECDSASECP256R1) - NIST P-256 elliptic curve signatures
///
/// # Identifier Key Types
///
/// These key types are used for network addressing and resource identification
/// but do not support cryptographic operations:
///
/// - [`NETWORK`](KeyPairType::NETWORK) - Network identification
/// - [`TOKEN`](KeyPairType::TOKEN) - Token and asset identification
/// - [`STORAGE`](KeyPairType::STORAGE) - Storage resource identification
/// - [`MULTISIG`](KeyPairType::MULTISIG) - Multi-signature wallet identification
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Display, EnumString, EnumIter)]
pub enum KeyPairType {
	/// ECDSA over secp256k1 curve
	ECDSASECP256K1 = 0,
	/// Ed25519 digital signature algorithm
	ED25519 = 1,
	/// Network identifier keys
	NETWORK = 2,
	/// Token identifier keys  
	TOKEN = 3,
	/// Storage identifier keys
	STORAGE = 4,
	/// ECDSA over secp256r1 curve (NIST P-256)
	ECDSASECP256R1 = 6,
	/// Multisig identifier keys
	MULTISIG = 7,
}

impl KeyPairType {
	/// Check if this key type is an identifier type
	pub fn is_identifier(&self) -> bool {
		IDENTIFIER_KEY_TYPES.contains(self)
	}

	/// Check if this key type supports cryptographic operations
	pub fn supports_crypto(&self) -> bool {
		matches!(self, KeyPairType::ECDSASECP256K1 | KeyPairType::ED25519 | KeyPairType::ECDSASECP256R1)
	}
}

impl From<Algorithm> for KeyPairType {
	fn from(algorithm: Algorithm) -> Self {
		match algorithm {
			Algorithm::Secp256k1 => KeyPairType::ECDSASECP256K1,
			Algorithm::Ed25519 => KeyPairType::ED25519,
			Algorithm::Secp256r1 => KeyPairType::ECDSASECP256R1,
		}
	}
}

impl TryFrom<KeyPairType> for Algorithm {
	type Error = AccountError;

	fn try_from(key_type: KeyPairType) -> Result<Self, Self::Error> {
		match key_type {
			KeyPairType::ECDSASECP256K1 => Ok(Algorithm::Secp256k1),
			KeyPairType::ED25519 => Ok(Algorithm::Ed25519),
			KeyPairType::ECDSASECP256R1 => Ok(Algorithm::Secp256r1),
			// Identifier types do not map to crypto algorithms
			KeyPairType::NETWORK | KeyPairType::TOKEN | KeyPairType::STORAGE | KeyPairType::MULTISIG => {
				Err(AccountError::InvalidKeyType)
			}
		}
	}
}

/// Signing trait for accounts.
pub trait AccountSigner {
	/// Sign a message with the private key.
	///
	/// Returns the signature as a byte vector.
	fn sign<T: AsRef<[u8]>>(&self, _message: T, _options: Option<SigningOptions>) -> Result<Vec<u8>, AccountError> {
		Err(AccountError::NoIdentifierSign)
	}

	/// Get the signature size in bytes for this key type.
	fn signature_size(&self) -> usize {
		0
	}
}

/// Verifier trait for accounts.
pub trait AccountVerifier {
	/// Verify a signature against a message using the public key.
	fn verify<T: AsRef<[u8]>, S: AsRef<[u8]>>(
		&self,
		_message: T,
		_signature: S,
		_options: Option<SigningOptions>,
	) -> Result<(), AccountError> {
		Err(AccountError::NoIdentifierVerify)
	}
}

/// Trait for types that can provide raw public key bytes.
///
/// This trait provides a unified interface for both cryptographic public keys
/// and identifier keys to return their raw byte representation.
pub trait PublicKeyStorage: Into<Vec<u8>> + AsRef<[u8]> + AsymmetricEncryption + Send + Sync + Clone {}

/// Identifier key for non-cryptographic account types.
///
/// This type represents identifiers for network addresses, tokens, storage,
/// and multisig accounts. Unlike cryptographic keys, these are simple 32-byte
/// identifiers that cannot be used for signing operations.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentifierKey {
	/// The raw bytes of the identifier key.
	raw_bytes: Vec<u8>,
}

impl IdentifierKey {
	/// Create a new identifier key from raw bytes.
	pub fn new(bytes: Vec<u8>) -> Result<Self, AccountError> {
		bytes.try_into()
	}
}

impl From<&IdentifierKey> for Vec<u8> {
	fn from(key: &IdentifierKey) -> Self {
		key.raw_bytes.clone()
	}
}

impl From<IdentifierKey> for Vec<u8> {
	fn from(key: IdentifierKey) -> Self {
		(&key).into()
	}
}

impl TryFrom<Vec<u8>> for IdentifierKey {
	type Error = AccountError;

	fn try_from(raw_bytes: Vec<u8>) -> Result<Self, Self::Error> {
		if raw_bytes.len() != 32 {
			return Err(AccountError::InvalidConstruction);
		}

		Ok(Self { raw_bytes })
	}
}

impl AsRef<[u8]> for IdentifierKey {
	fn as_ref(&self) -> &[u8] {
		&self.raw_bytes
	}
}

impl core::fmt::Debug for IdentifierKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{}", hex::encode(&self.raw_bytes))
	}
}

impl AsymmetricEncryption for IdentifierKey {
	fn encrypt<T: AsRef<[u8]>>(&self, _key: T) -> Result<Vec<u8>, CryptoError> {
		Err(CryptoError::EncryptionNotSupported)
	}

	fn decrypt<C: AsRef<[u8]>>(&self, _: C) -> Result<Vec<u8>, CryptoError> {
		Err(CryptoError::EncryptionNotSupported)
	}
}

impl FromHex for IdentifierKey {
	type Error = AccountError;

	fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
		let bytes = hex::decode(hex).map_err(|_| AccountError::InvalidConstruction)?;
		Self::try_from(bytes)
	}
}

/// Trait defining the interface for cryptographic key pairs.
///
/// The `KeyPair` trait provides a unified interface for all supported
/// cryptographic algorithms and identifier types in the Keeta Network. It
/// combines signing, verification, encryption, and key derivation capabilities
/// with abstractions for different cryptographic primitives.
///
/// # Error Handling
///
/// All methods return `Result` types with [`AccountError`] for consistent
/// error handling across different key types and operations.
pub trait KeyPair: AccountSigner + AccountVerifier + Send + Sync + TryFrom<Keyable, Error = AccountError> {
	/// The public key storage type for this key pair.
	type PublicKey: PublicKeyStorage;

	/// The key pair type for this implementation.
	const KEY_PAIR_TYPE: KeyPairType;

	/// Returns the key pair type for this implementation.
	///
	/// This is a convenience method that returns the same value as the
	/// `KEY_PAIR_TYPE` constant. It's provided for consistency with instance
	/// methods.
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{KeyED25519, KeyPair, KeyPairType};
	///
	/// let key_type = KeyED25519::keypair_type();
	/// assert_eq!(key_type, KeyPairType::ED25519);
	/// ```
	fn keypair_type() -> KeyPairType {
		Self::KEY_PAIR_TYPE
	}

	/// Deterministically derives a private key from a seed and index.
	///
	/// This method uses HKDF (HMAC-based Key Derivation Function) to
	/// deterministically generate a private key from a seed and index.
	///
	/// # Parameters
	///
	/// - `seed`: A cryptographically secure random seed (32 bytes)
	/// - `index`: Derivation index for generating keys from the same seed
	///
	/// # Returns
	///
	/// A valid private key wrapped in [`AnyPrivateKey`] enum, or an error if
	/// key derivation fails after maximum retry attempts.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// # use crypto::generate_random_seed;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Generate a cryptographically secure seed
	/// # let seed = generate_random_seed()?;
	/// # let seed = generate_random_seed()?;
	/// // Derive the first private key (index 0)
	/// let private_key = KeyED25519::seed_to_private_key(&seed, 0)?;
	/// // Derive additional keys from the same seed
	/// let second_key = KeyED25519::seed_to_private_key(&seed, 1)?;
	/// let third_key = KeyED25519::seed_to_private_key(&seed, 2)?;
	/// # Ok(())
	/// # }
	/// ```
	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError>;

	/// Converts a private key into a formatted public key string.
	///
	/// This method generates the Keeta Network address string from a private
	/// key. The result is a base32-encoded string with a `keeta_` prefix,
	/// algorithm identifier, public key bytes, and checksum for error detection.
	///
	/// # Parameters
	///
	/// - `key`: The private key to derive the public key string from
	///
	/// # Returns
	///
	/// A formatted public key string suitable for use as a Keeta Network
	/// address, or an error if the key type doesn't match this key pair type.
	///
	/// # Format
	///
	/// The returned string follows the format: `keeta_{algorithm_prefix}{base32_encoded_data}`
	/// where the data contains: `[algorithm_byte][public_key_bytes][checksum_bytes]`
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	/// use crypto::prelude::AnyPrivateKey;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test keys
	/// # let (private_key, _, _) = doc_utils::create_ed25519_test_keys(None);
	/// # let any_private_key = AnyPrivateKey::Ed25519(private_key);
	/// // Generate the public key string
	/// let public_key_string = KeyED25519::derive_public_key_string(&any_private_key)?;
	/// assert!(public_key_string.starts_with("keeta_"));
	/// # Ok(())
	/// # }
	/// ```
	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError>;

	/// Encrypt data using the public key.
	///
	/// This method performs public key encryption using the appropriate scheme
	/// for the key type. The encrypted data can only be decrypted using the
	/// corresponding private key.
	///
	/// # Parameters
	///
	/// - `plaintext`: The data to encrypt (any type that can convert to bytes)
	///
	/// # Returns
	///
	/// The encrypted ciphertext as a byte vector, or an error if encryption
	/// fails or is not supported by this key type.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account with private key
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Encrypt a message
	/// let message = b"Secret message for the Keeta Network";
	/// let ciphertext = account.keypair.encrypt(message)?;
	/// # Ok(())
	/// # }
	/// ```
	fn encrypt<T: AsRef<[u8]>>(&self, plaintext: T) -> Result<Vec<u8>, AccountError> {
		let public_key = self.to_public_key();
		let ciphertext = public_key.encrypt(plaintext.as_ref())?;
		Ok(ciphertext)
	}

	/// Decrypt data using the private key.
	///
	/// This method performs private key decryption to recover the original
	/// plaintext from ciphertext that was encrypted using the corresponding
	/// public key. This operation requires access to the private key.
	///
	/// # Parameters
	///
	/// - `ciphertext`: The encrypted data to decrypt
	///
	/// # Returns
	///
	/// The decrypted plaintext as a byte vector, or an error if decryption
	/// fails, the private key is not available, or the key type does not
	/// support encryption.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account with private key
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Encrypt and then decrypt a message
	/// let original_message = b"Secret message for the Keeta Network";
	/// let ciphertext = account.keypair.encrypt(original_message)?;
	/// let plaintext = account.keypair.decrypt(&ciphertext)?;
	/// assert_eq!(original_message, plaintext.as_slice());
	/// # Ok(())
	/// # }
	/// ```
	fn decrypt<T: AsRef<[u8]>>(&self, ciphertext: T) -> Result<Vec<u8>, AccountError>;

	/// Check if this key pair supports encryption operations.
	///
	/// Returns `true` if both [`encrypt`](Self::encrypt) and [`decrypt`](Self::decrypt)
	/// operations are supported by this key type, `false` otherwise.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyNETWORK, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test accounts
	/// # let (_, _, ed25519_account) = doc_utils::create_ed25519_test_keys(None);
	/// # let network_account = doc_utils::create_network_test_account(Some(5));
	/// // Cryptographic keys support encryption
	/// assert!(ed25519_account.keypair.supports_encryption());
	/// // Identifier keys do not
	/// assert!(!network_account.keypair.supports_encryption());
	/// # Ok(())
	/// # }
	/// ```
	fn supports_encryption(&self) -> bool;

	/// Convert the key pair to a public key.
	///
	/// This method extracts the public key component from the key pair.
	/// The returned public key can be used for verification and encryption
	/// operations but not for signing or decryption.
	///
	/// # Returns
	///
	/// A clone of the public key component.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair, PublicKeyStorage};
	/// use crypto::operations::encryption::AsymmetricEncryption;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account
	/// # let (_, public_key_ref, account) = doc_utils::create_ed25519_test_keys(None);
	///
	/// // Extract the public key
	/// let public_key = account.keypair.to_public_key();
	/// // Verify it matches the expected public key
	/// assert_eq!(public_key, public_key_ref);
	///
	/// // Use the public key for encryption
	/// let message = b"Hello, World!";
	/// let ciphertext = public_key.encrypt(message)?;
	/// assert!(ciphertext.len() > 0);
	/// # Ok(())
	/// # }
	/// ```
	fn to_public_key(&self) -> Self::PublicKey;

	/// Convert the key pair to a keeta network address string.
	///
	/// This method generates a human-readable Keeta Network address string
	/// that uniquely identifies this key pair. The address includes the
	/// algorithm type and can be used for receiving transactions or messages.
	///
	/// # Returns
	///
	/// A formatted address string with `keeta_` prefix.
	///
	/// # Format
	///
	/// The address format varies by key type:
	/// - Ed25519: `keeta_ae...` or `keeta_ah...`
	/// - ECDSA secp256k1: `keeta_aa...` or `keeta_ab...`
	/// - ECDSA secp256r1: `keeta_ay...` or `keeta_az...`
	/// - Network: `keeta_ai...` through `keeta_al...`
	/// - Token: `keeta_am...` through `keeta_ap...`
	/// - Storage: `keeta_aq...` through `keeta_at...`
	/// - Multisig: `keeta_a4...` through `keeta_a7...`
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Get the network address
	/// let address = account.keypair.to_public_key_string();
	/// assert!(address.starts_with("keeta_ae") || address.starts_with("keeta_ah"));
	/// # Ok(())
	/// # }
	/// ```
	fn to_public_key_string(&self) -> String {
		let key_type_value = self.to_keypair_type() as u8;
		format_public_key_string(self.to_public_key(), key_type_value).expect("Failed to format public key")
	}

	/// Extract the private key if available.
	///
	/// This method consumes the account and returns the private key component
	/// if it exists. After calling this method, the account is no longer
	/// usable. This is useful for securely transferring private keys or
	/// converting between different key representations.
	///
	/// # Returns
	///
	/// `Some(private_key)` if a private key is available, `None` if this is
	/// a public-key-only account.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	/// use crypto::prelude::AnyPrivateKey;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account with private key
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Extract the private key (consumes the account)
	/// let private_key = account.keypair.take_private_key();
	/// match private_key {
	///     Some(AnyPrivateKey::Ed25519(_key)) => {
	///         // Private key was successfully extracted
	///         assert!(true);
	///     }
	///     _ => {
	///         panic!("Expected Ed25519 private key");
	///     }
	/// }
	/// # Ok(())
	/// # }
	/// ```
	fn take_private_key(self) -> Option<AnyPrivateKey>;

	/// Returns the key pair type for this instance.
	///
	/// This method returns the runtime key pair type identifier, which is
	/// useful for type checking and serialization. It returns the same value
	/// as the `KEY_PAIR_TYPE` constant but is available on instances.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair, KeyPairType};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Get the runtime key type
	/// let key_type = account.keypair.to_keypair_type();
	/// assert_eq!(key_type, KeyPairType::ED25519);
	///
	/// // Useful for pattern matching
	/// match key_type {
	///     KeyPairType::ED25519 => assert!(true), // Expected
	///     KeyPairType::ECDSASECP256K1 => panic!("Unexpected ECDSA key"),
	///     KeyPairType::NETWORK => panic!("Unexpected Network identifier"),
	///     _ => panic!("Other unexpected key type"),
	/// }
	/// # Ok(())
	/// # }
	/// ```
	fn to_keypair_type(&self) -> KeyPairType {
		Self::KEY_PAIR_TYPE
	}
}

/// Different types of key material that can be used to create key pairs.
#[derive(Zeroize)]
pub enum Keyable {
	/// Mnemonic passphrase with derivation index
	Passphrase(PassphraseAndIndex),
	/// Raw seed bytes with derivation index
	Seed(SeedAndIndex),
	/// Hex-encoded seed string with derivation index
	HexSeed(HexSeedAndIndex),
	/// Public key as a formatted string
	PublicKeyString(String),
	/// Private key as raw bytes
	PrivateKey(Vec<u8>),
	/// Public key as raw bytes
	PublicKey(Vec<u8>),
	/// Identifier string for identifier-based keys
	Identifier(String),
}

impl From<[u8; 32]> for Keyable {
	fn from(seed: [u8; 32]) -> Self {
		Keyable::Seed((seed.into_secret(), 0))
	}
}

impl From<String> for Keyable {
	fn from(hex_seed: String) -> Self {
		Keyable::HexSeed((hex_seed.into_secret(), 0))
	}
}

impl From<&str> for Keyable {
	fn from(hex_seed: &str) -> Self {
		Keyable::HexSeed((hex_seed.to_string().into_secret(), 0))
	}
}

impl From<Vec<String>> for Keyable {
	fn from(passphrase: Vec<String>) -> Self {
		Keyable::Passphrase((passphrase.into_secret(), 0))
	}
}

// Implementations for tuple variants with index
impl From<([u8; 32], Index)> for Keyable {
	fn from((seed, index): ([u8; 32], Index)) -> Self {
		Keyable::Seed((seed.into_secret(), index))
	}
}

impl From<(String, Index)> for Keyable {
	fn from((hex_seed, index): (String, Index)) -> Self {
		Keyable::HexSeed((hex_seed.into_secret(), index))
	}
}

impl From<(&str, Index)> for Keyable {
	fn from((hex_seed, index): (&str, Index)) -> Self {
		Keyable::HexSeed((hex_seed.to_string().into_secret(), index))
	}
}

impl From<(Vec<String>, Index)> for Keyable {
	fn from((passphrase, index): (Vec<String>, Index)) -> Self {
		Keyable::Passphrase((passphrase.into_secret(), index))
	}
}

/// ECDSA key pair using the secp256k1 elliptic curve.
///
/// This key type implements ECDSA (Elliptic Curve Digital Signature Algorithm)
/// over the secp256k1 curve, which is the same curve used by Bitcoin.
///
/// # Examples
///
/// ```rust
/// use accounts::{Account, KeyECDSASECP256K1, KeyPair};
/// use crypto::algorithms::secp256k1::Secp256k1Derivation;
/// use crypto::KeyDerivation;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create an account from a seed
/// let seed = b"abandon abandon abandon abandon abandon abandon";
/// let private_key = Secp256k1Derivation::derive_from_seed(seed)?;
///
/// let account = Account::<KeyECDSASECP256K1>::from(private_key);
/// // Verify it's a cryptographic key type
/// assert!(account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [SEC 2: Recommended Elliptic Curve Domain Parameters](http://www.secg.org/sec2-v2.pdf)
/// - [Bitcoin's use of secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
/// - [RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms](https://tools.ietf.org/html/rfc6090)
pub struct KeyECDSASECP256K1 {
	private_key: Option<Secp256k1PrivateKey>,
	pub public_key: Secp256k1PublicKey,
}

impl KeyPair for KeyECDSASECP256K1 {
	type PublicKey = Secp256k1PublicKey;
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::ECDSASECP256K1;

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Convert seed and index to bytes for HKDF
		let seed_buffer = combine_seed_and_index(seed, index);
		// Use the crypto crate's secp256k1 derivation
		let private_key = Secp256k1Derivation::derive_from_seed(seed_buffer)?;

		Ok(AnyPrivateKey::Secp256k1(private_key))
	}

	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError> {
		if let AnyPrivateKey::Secp256k1(secp_key) = key {
			let public_key = secp_key.as_public_key();
			let public_key_bytes = Vec::<u8>::from(&public_key);
			format_public_key_string(&public_key_bytes, Algorithm::Secp256k1 as u8)
		} else {
			Err(AccountError::InvalidConstruction)
		}
	}

	fn decrypt<T: AsRef<[u8]>>(&self, ciphertext: T) -> Result<Vec<u8>, AccountError> {
		let private_key = self
			.private_key
			.as_ref()
			.ok_or(AccountError::InvalidConstruction)?;

		let plaintext = private_key.decrypt(ciphertext.as_ref())?;
		Ok(plaintext)
	}

	fn supports_encryption(&self) -> bool {
		true // ECDSA secp256k1 supports ECIES encryption
	}

	fn to_public_key(&self) -> Self::PublicKey {
		self.public_key.clone()
	}

	fn take_private_key(self) -> Option<AnyPrivateKey> {
		self.private_key.map(AnyPrivateKey::Secp256k1)
	}
}

/// ECDSA key pair using the secp256r1 elliptic curve (NIST P-256).
///
/// This key type implements ECDSA (Elliptic Curve Digital Signature Algorithm)
/// over the secp256r1 curve, also known as NIST P-256 or prime256v1.
///
/// # Examples
///
/// ```rust
/// use accounts::{Account, KeyECDSASECP256R1, KeyPair};
/// use crypto::algorithms::secp256r1::Secp256r1Derivation;
/// use crypto::KeyDerivation;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create an account from a seed
/// let seed = b"abandon abandon abandon abandon abandon abandon";
/// let private_key = Secp256r1Derivation::derive_from_seed(seed)?;
///
/// let account = Account::<KeyECDSASECP256R1>::from(private_key);
/// // Verify it's a cryptographic key type
/// assert!(account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [NIST FIPS 186-4: Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
/// - [RFC 5480: Elliptic Curve Cryptography Subject Public Key Info](https://tools.ietf.org/html/rfc5480)
/// - [SEC 1: Elliptic Curve Cryptography](http://www.secg.org/sec1-v2.pdf)
pub struct KeyECDSASECP256R1 {
	private_key: Option<Secp256r1PrivateKey>,
	pub public_key: Secp256r1PublicKey,
}

impl KeyPair for KeyECDSASECP256R1 {
	type PublicKey = Secp256r1PublicKey;
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::ECDSASECP256R1;

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Convert seed and index to bytes for HKDF
		let seed_buffer = combine_seed_and_index(seed, index);
		// Use the crypto crate's secp256r1 derivation
		let private_key = Secp256r1Derivation::derive_from_seed(seed_buffer)?;
		Ok(AnyPrivateKey::Secp256r1(private_key))
	}

	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError> {
		if let AnyPrivateKey::Secp256r1(secp_key) = key {
			let public_key = secp_key.as_public_key();
			let public_key_bytes = Vec::<u8>::from(&public_key);
			format_public_key_string(&public_key_bytes, Algorithm::Secp256r1 as u8)
		} else {
			Err(AccountError::InvalidConstruction)
		}
	}

	fn decrypt<T: AsRef<[u8]>>(&self, ciphertext: T) -> Result<Vec<u8>, AccountError> {
		let private_key = self
			.private_key
			.as_ref()
			.ok_or(AccountError::InvalidConstruction)?;

		Ok(private_key.decrypt(ciphertext.as_ref())?)
	}

	fn supports_encryption(&self) -> bool {
		true // ECIES-secp256r1-AES256CBC is now implemented
	}

	fn to_public_key(&self) -> Self::PublicKey {
		self.public_key.clone()
	}

	fn take_private_key(self) -> Option<AnyPrivateKey> {
		self.private_key.map(AnyPrivateKey::Secp256r1)
	}
}

/// Ed25519 digital signature key pair implementation.
///
/// This key type implements the Ed25519 signature algorithm, which uses the
/// Edwards-curve Digital Signature Algorithm (EdDSA) with Curve25519. Ed25519
/// is designed for high performance and security, offering faster signature
/// generation and verification compared to traditional ECDSA implementations.
///
/// # Examples
///
/// ```rust
/// use accounts::{Account, KeyED25519, KeyPair};
/// use crypto::algorithms::ed25519::Ed25519Derivation;
/// use crypto::KeyDerivation;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create an account from a seed
/// let seed = b"abandon abandon abandon abandon abandon abandon";
/// let private_key = Ed25519Derivation::derive_from_seed(seed)?;
///
/// let account = Account::<KeyED25519>::from(private_key);
/// // Verify it's a cryptographic key type
/// assert!(account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
/// - [Curve25519: high-speed elliptic-curve cryptography](https://cr.yp.to/ecdh/curve25519-20060209.pdf)
/// - [Ed25519: high-speed high-security signatures](https://ed25519.cr.yp.to/)
/// - [RFC 8410: Algorithm Identifiers for Ed25519 in X.509](https://tools.ietf.org/html/rfc8410)
pub struct KeyED25519 {
	private_key: Option<Ed25519PrivateKey>,
	pub public_key: Ed25519PublicKey,
}

impl KeyPair for KeyED25519 {
	type PublicKey = Ed25519PublicKey;
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::ED25519;

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Convert seed and index to bytes for HKDF
		let seed_buffer = combine_seed_and_index(seed, index);
		// Use the crypto crate's Ed25519 derivation
		let private_key = Ed25519Derivation::derive_from_seed(seed_buffer)?;
		Ok(AnyPrivateKey::Ed25519(private_key))
	}

	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError> {
		if let AnyPrivateKey::Ed25519(ed_key) = key {
			let public_key = ed_key.verifying_key();
			let public_key_bytes = Vec::<u8>::from(&public_key);
			let formatted_key = format_public_key_string(&public_key_bytes, Algorithm::Ed25519 as u8)?;
			Ok(formatted_key)
		} else {
			Err(AccountError::InvalidConstruction)
		}
	}

	fn decrypt<T: AsRef<[u8]>>(&self, ciphertext: T) -> Result<Vec<u8>, AccountError> {
		let private_key = self
			.private_key
			.as_ref()
			.ok_or(AccountError::InvalidConstruction)?;

		Ok(private_key.decrypt(ciphertext.as_ref())?)
	}

	fn supports_encryption(&self) -> bool {
		true // ECIES-25519 via X25519 is now implemented
	}

	fn to_public_key(&self) -> Self::PublicKey {
		self.public_key.clone()
	}

	fn take_private_key(self) -> Option<AnyPrivateKey> {
		self.private_key.map(AnyPrivateKey::Ed25519)
	}
}

/// Network identifier key for node addressing and discovery.
///
/// This key type is used specifically for network-level operations including
/// node identification, peer discovery, and routing within the Keeta Network.
/// Unlike cryptographic key types, network identifiers do not support signing
/// operations but serve as unique network addresses.
///
/// # Examples
///
/// ```rust
/// use accounts::{Account, KeyNETWORK, KeyPair};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a network identifier from a network ID
/// let account = Account::<KeyNETWORK>::generate_network_address(12345)?;
/// assert!(account.is_identifier());
/// // Identifier keys do not support cryptographic operations
/// assert!(!account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct KeyNETWORK {
	pub public_key: IdentifierKey,
}

/// Token identifier key for asset and resource addressing.
///
/// This key type is used for identifying tokens, assets, and other fungible or
/// non-fungible resources within the Keeta Network ecosystem. Token identifiers
/// enable unique addressing of digital assets without requiring cryptographic
/// operations for basic identification and tracking.
///
/// # Examples
///
/// ```rust
/// use accounts::{Account, KeyTOKEN, KeyPair, Keyable, Accountable};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a token identifier directly from an identifier string
/// let keyable = Keyable::Identifier("test-token-id".to_string());
/// let account = Account::<KeyTOKEN>::try_from(Accountable::KeyAndType(keyable, accounts::KeyPairType::TOKEN))?;
/// assert!(account.is_identifier());
/// // Identifier keys do not support cryptographic operations
/// assert!(!account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct KeyTOKEN {
	pub public_key: IdentifierKey,
}

/// Storage identifier key for storage addresses.
///
/// This key type is used for derived storage accounts.
///
/// # Examples
///
/// ```rust
/// use accounts::{Account, KeySTORAGE, KeyPair, Keyable, Accountable};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a storage identifier directly from an identifier string
/// let keyable = Keyable::Identifier("test-storage-id".to_string());
/// let account = Account::<KeySTORAGE>::try_from(Accountable::KeyAndType(keyable, accounts::KeyPairType::STORAGE))?;
///
/// // Verify it's an identifier type (not cryptographic)
/// assert!(account.is_identifier());
/// assert!(!account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct KeySTORAGE {
	pub public_key: IdentifierKey,
}

/// Multi-signature wallet identifier key for coordinated signing operations.
///
/// This key type is used for  multi-signature wallets and coordinated signing
/// schemes within the Keeta Network.
///
/// # Examples
///
/// ```rust
/// use accounts::{Account, KeyMULTISIG, KeyPair, Keyable, Accountable};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a multisig identifier directly from an identifier string
/// let keyable = Keyable::Identifier("test-multisig-id".to_string());
/// let account = Account::<KeyMULTISIG>::try_from(Accountable::KeyAndType(keyable, accounts::KeyPairType::MULTISIG))?;
/// // Verify it's an identifier type (not cryptographic)
/// assert!(account.is_identifier());
/// assert!(!account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct KeyMULTISIG {
	pub public_key: IdentifierKey,
}

/// Enum to represent any account type for identifier generation results
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum GenericAccount {
	// Cryptographic accounts
	EcdsaSecp256k1(Account<KeyECDSASECP256K1>),
	EcdsaSecp256r1(Account<KeyECDSASECP256R1>),
	Ed25519(Account<KeyED25519>),
	// Identifier accounts
	Network(Account<KeyNETWORK>),
	Token(Account<KeyTOKEN>),
	Storage(Account<KeySTORAGE>),
	Multisig(Account<KeyMULTISIG>),
}

impl TryFrom<AnyPrivateKey> for GenericAccount {
	type Error = AccountError;

	fn try_from(private_key: AnyPrivateKey) -> Result<Self, Self::Error> {
		/// Macro to generate the repetitive private key conversion logic
		macro_rules! convert_private_key {
			($key:expr, $key_type:ty, $keypair_type:expr, $variant:ident) => {{
				let key_secret_box: SecretBox<Vec<u8>> = $key.into();
				let key_bytes = key_secret_box.expose_secret().clone();
				let account = Account::<$key_type>::try_from(Accountable::KeyAndType(
					Keyable::PrivateKey(key_bytes),
					$keypair_type,
				))?;

				Ok(GenericAccount::$variant(account))
			}};
		}

		match private_key {
			AnyPrivateKey::Ed25519(key) => convert_private_key!(key, KeyED25519, KeyPairType::ED25519, Ed25519),
			AnyPrivateKey::Secp256k1(key) => {
				convert_private_key!(key, KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1, EcdsaSecp256k1)
			}
			AnyPrivateKey::Secp256r1(key) => {
				convert_private_key!(key, KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1, EcdsaSecp256r1)
			}
		}
	}
}

impl TryFrom<AnyPublicKey> for GenericAccount {
	type Error = AccountError;

	fn try_from(public_key: AnyPublicKey) -> Result<Self, Self::Error> {
		/// Macro to generate the repetitive public key conversion logic
		macro_rules! convert_public_key {
			($key:expr, $key_type:ty, $keypair_type:expr, $variant:ident) => {{
				let key_bytes: Vec<u8> = $key.into();
				let account = Account::<$key_type>::try_from(Accountable::KeyAndType(
					Keyable::PublicKey(key_bytes),
					$keypair_type,
				))?;

				Ok(GenericAccount::$variant(account))
			}};
		}

		match public_key {
			AnyPublicKey::Ed25519(key) => convert_public_key!(key, KeyED25519, KeyPairType::ED25519, Ed25519),
			AnyPublicKey::Secp256k1(key) => {
				convert_public_key!(key, KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1, EcdsaSecp256k1)
			}
			AnyPublicKey::Secp256r1(key) => {
				convert_public_key!(key, KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1, EcdsaSecp256r1)
			}
		}
	}
}

impl FromStr for GenericAccount {
	type Err = AccountError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		// Handle keeta_ format - Try to determine the account type based on prefix
		if s.starts_with("keeta_aa") {
			let account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
				Keyable::PublicKeyString(s.to_string()),
				KeyPairType::ECDSASECP256K1,
			))?;
			Ok(GenericAccount::EcdsaSecp256k1(account))
		} else if s.starts_with("keeta_ae") || s.starts_with("keeta_ah") {
			let account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
				Keyable::PublicKeyString(s.to_string()),
				KeyPairType::ED25519,
			))?;
			Ok(GenericAccount::Ed25519(account))
		} else if s.starts_with("keeta_ay") {
			let account = Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(
				Keyable::PublicKeyString(s.to_string()),
				KeyPairType::ECDSASECP256R1,
			))?;
			Ok(GenericAccount::EcdsaSecp256r1(account))
		} else if s.starts_with("keeta_ai")
			|| s.starts_with("keeta_aj")
			|| s.starts_with("keeta_ak")
			|| s.starts_with("keeta_al")
		{
			let account = Account::<KeyNETWORK>::try_from(Accountable::KeyAndType(
				Keyable::PublicKeyString(s.to_string()),
				KeyPairType::NETWORK,
			))?;
			Ok(GenericAccount::Network(account))
		} else if s.starts_with("keeta_am")
			|| s.starts_with("keeta_an")
			|| s.starts_with("keeta_ao")
			|| s.starts_with("keeta_ap")
		{
			let account = Account::<KeyTOKEN>::try_from(Accountable::KeyAndType(
				Keyable::PublicKeyString(s.to_string()),
				KeyPairType::TOKEN,
			))?;
			Ok(GenericAccount::Token(account))
		} else if s.starts_with("keeta_aq")
			|| s.starts_with("keeta_ar")
			|| s.starts_with("keeta_as")
			|| s.starts_with("keeta_at")
		{
			let account = Account::<KeySTORAGE>::try_from(Accountable::KeyAndType(
				Keyable::PublicKeyString(s.to_string()),
				KeyPairType::STORAGE,
			))?;
			Ok(GenericAccount::Storage(account))
		} else if s.starts_with("keeta_a4")
			|| s.starts_with("keeta_a5")
			|| s.starts_with("keeta_a6")
			|| s.starts_with("keeta_a7")
		{
			let account = Account::<KeyMULTISIG>::try_from(Accountable::KeyAndType(
				Keyable::PublicKeyString(s.to_string()),
				KeyPairType::MULTISIG,
			))?;
			Ok(GenericAccount::Multisig(account))
		} else {
			Err(AccountError::InvalidConstruction)
		}
	}
}

impl FromHex for GenericAccount {
	type Error = AccountError;

	fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
		let data = hex::decode(hex).map_err(|_| AccountError::InvalidConstruction)?;
		if data.is_empty() {
			return Err(AccountError::InvalidConstruction);
		}

		// Extract key type and public key bytes
		let key_type_byte = data[0];
		let public_key_bytes = &data[1..];
		// Map type byte to KeyPairType
		let key_type = match key_type_byte {
			0 => KeyPairType::ECDSASECP256K1,
			1 => KeyPairType::ED25519,
			2 => KeyPairType::NETWORK,
			3 => KeyPairType::TOKEN,
			4 => KeyPairType::STORAGE,
			6 => KeyPairType::ECDSASECP256R1,
			7 => KeyPairType::MULTISIG,
			_ => return Err(AccountError::InvalidKeyType),
		};

		// Macro for crypto account creation
		macro_rules! create_crypto_account {
			($key_type_enum:ident, $key_struct:ty, $variant:ident) => {
				Account::<$key_struct>::try_from(Accountable::KeyAndType(
					Keyable::PublicKey(public_key_bytes.to_vec()),
					KeyPairType::$key_type_enum,
				))
				.map(GenericAccount::$variant)
			};
		}

		// Macro for identifier account creation
		macro_rules! create_identifier_account {
			($key_type_enum:ident, $key_struct:ty, $variant:ident) => {{
				let public_key_string = format_public_key_string(public_key_bytes, KeyPairType::$key_type_enum as u8)?;
				Account::<$key_struct>::try_from(Accountable::KeyAndType(
					Keyable::PublicKeyString(public_key_string),
					KeyPairType::$key_type_enum,
				))
				.map(GenericAccount::$variant)
			}};
		}

		// Create account based on type
		match key_type {
			KeyPairType::ECDSASECP256K1 => create_crypto_account!(ECDSASECP256K1, KeyECDSASECP256K1, EcdsaSecp256k1),
			KeyPairType::ED25519 => create_crypto_account!(ED25519, KeyED25519, Ed25519),
			KeyPairType::ECDSASECP256R1 => create_crypto_account!(ECDSASECP256R1, KeyECDSASECP256R1, EcdsaSecp256r1),
			KeyPairType::NETWORK => create_identifier_account!(NETWORK, KeyNETWORK, Network),
			KeyPairType::TOKEN => create_identifier_account!(TOKEN, KeyTOKEN, Token),
			KeyPairType::STORAGE => create_identifier_account!(STORAGE, KeySTORAGE, Storage),
			KeyPairType::MULTISIG => create_identifier_account!(MULTISIG, KeyMULTISIG, Multisig),
		}
	}
}

/// A generic type that can be either a key or an account.
pub enum Accountable<T>
where
	T: KeyPair,
{
	Key(T),
	Account(Account<T>),
	KeyAndType(Keyable, KeyPairType),
}

/// A generic account representing a cryptographic key pair or identifier.
///
/// The `Account` struct is the primary interface for working with cryptographic
/// keys and network identifiers in the Keeta Network. It provides a unified
/// abstraction over different key types while maintaining type safety through
/// the generic `KEYTYPE` parameter.
///
/// - **Cryptographic Types**: [`KeyECDSASECP256K1`], [`KeyED25519`], [`KeyECDSASECP256R1`]
/// - **Identifier Types**: [`KeyNETWORK`], [`KeyTOKEN`], [`KeySTORAGE`], [`KeyMULTISIG`]
///
/// # Examples
///
/// ## Creating Cryptographic Accounts
///
/// ```rust
/// use accounts::{Account, KeyED25519, KeyPair};
/// use crypto::algorithms::ed25519::Ed25519Derivation;
/// use crypto::prelude::KeyDerivation;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create an Ed25519 account from a seed
/// let seed = b"abandon abandon abandon abandon abandon abandon";
/// let private_key = Ed25519Derivation::derive_from_seed(seed)?;
/// let account = Account::from(private_key);
/// // Check capabilities
/// assert!(account.keypair.to_keypair_type().supports_crypto());
/// assert!(!account.is_identifier());
/// # Ok(())
/// # }
/// ```
///
/// ## Creating Identifier Accounts
///
/// ```rust
/// use accounts::{Account, KeyNETWORK, KeyPair};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a network identifier account from a network ID
/// let account = Account::<KeyNETWORK>::generate_network_address(5)?;
/// // Check capabilities
/// assert!(account.is_identifier());
/// // Identifier keys do not support cryptographic operations
/// assert!(!account.keypair.to_keypair_type().supports_crypto());
/// # Ok(())
/// # }
/// ```
///
/// # Account Operations
///
/// Accounts support various operations depending on their type:
///
/// ## Cryptographic Operations
/// ```rust
/// # use accounts::doc_utils;
/// use accounts::{KeyED25519};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create test account
/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
/// // Sign data (requires private key)
/// let data = b"Hello, World!";
/// let signature = account.sign(data, None)?;
///
/// // Verify signatures (public operation)
/// let result = account.verify(data, &signature, None);
/// assert!(result.is_ok());
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// Account is `Send + Sync` and can be safely used across threads.
#[derive(Debug)]
pub struct Account<KEYTYPE>
where
	KEYTYPE: KeyPair,
{
	pub keypair: KEYTYPE,
}

impl<KEYTYPE> Clone for Account<KEYTYPE>
where
	KEYTYPE: KeyPair,
{
	fn clone(&self) -> Self {
		// Reconstruct from public key string as private keys cannot be copied
		let public_key = self.keypair.to_public_key_string();
		let keyable = Keyable::PublicKeyString(public_key);

		let accountable = Accountable::KeyAndType(keyable, KEYTYPE::KEY_PAIR_TYPE);
		Account::<KEYTYPE>::try_from(accountable).expect("Already constructed accounts should be infallible.")
	}
}

// Trait for types that have a keypair type
pub trait HasKeypairType {
	const KEYPAIR_TYPE: KeyPairType;
}

// Blanket implementation for all KeyPair implementations
impl<T: KeyPair> HasKeypairType for T {
	const KEYPAIR_TYPE: KeyPairType = T::KEY_PAIR_TYPE;
}

// Blanket implementation for Account types
impl<KEYTYPE: KeyPair> HasKeypairType for Account<KEYTYPE> {
	const KEYPAIR_TYPE: KeyPairType = KEYTYPE::KEY_PAIR_TYPE;
}

impl<KEYTYPE> TryFrom<Accountable<KEYTYPE>> for Account<KEYTYPE>
where
	KEYTYPE: KeyPair,
{
	type Error = AccountError;

	fn try_from(input: Accountable<KEYTYPE>) -> Result<Self, Self::Error> {
		match input {
			Accountable::Account(account) => Ok(Account::<KEYTYPE> { keypair: account.keypair }),
			Accountable::Key(key) => Ok(Account::<KEYTYPE> { keypair: key }),
			Accountable::KeyAndType(key, key_type) => {
				if key_type == KEYTYPE::KEY_PAIR_TYPE {
					let keypair = KEYTYPE::try_from(key)?;
					Ok(Account::<KEYTYPE> { keypair })
				} else {
					Err(AccountError::InvalidKeyType)
				}
			}
		}
	}
}

impl<KEYTYPE> Account<KEYTYPE>
where
	KEYTYPE: KeyPair,
{
	pub fn to_keypair_type(&self) -> KeyPairType {
		self.keypair.to_keypair_type()
	}

	/// Computes a cryptographically secure seed from a passphrase using PBKDF2.
	///
	/// This method converts a human-readable passphrase into a cryptographically
	/// secure 32-byte seed suitable for key derivation. The passphrase can be
	/// provided as any iterable collection of strings, which will be joined
	/// with spaces before processing.
	///
	/// # Parameters
	///
	/// - `passphrase`: An iterable collection of strings representing the passphrase words
	///
	/// # Returns
	///
	/// A 32-byte cryptographically secure seed wrapped in [`SecretBox`] for secure
	/// memory handling, or an error if the passphrase is too short or processing fails.
	///
	/// # Error Handling
	///
	/// Returns an error if the passphrase is invalid or if key derivation fails.
	///
	/// # Security
	///
	/// - Uses PBKDF2 with SHA-256 and OWASP recommended iterations for key stretching
	/// - Requires minimum passphrase length for security
	/// - Normalizes input (lowercase, removes spaces) for consistency
	/// - Returns seed in secure memory container that zeros on drop
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeyED25519};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // From a word vector (minimum 12 words)
	/// let words = vec![
	///     "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
	///     "abandon", "abandon", "abandon", "abandon", "abandon", "abandon"
	/// ];
	/// let seed = Account::<KeyED25519>::compute_seed_from_passphrase(words)?;
	/// # Ok(())
	/// # }
	/// ```
	pub fn compute_seed_from_passphrase<I, S>(passphrase: I) -> Result<Seed, AccountError>
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let joined = passphrase
			.into_iter()
			.map(|s| s.as_ref().to_string())
			.collect::<Vec<String>>()
			.join(" ");

		Ok(seed_from_passphrase(&joined)?)
	}

	/// Generates a cryptographically secure random 24-word BIP39 passphrase.
	///
	/// This method creates a random mnemonic passphrase using the BIP39 English
	/// word list. The generated passphrase provides approximately 256 bits of
	/// entropy and can be used for secure key derivation.
	///
	/// # Returns
	///
	/// - Ok: A vector of 24 randomly selected words from BIP39
	/// - Err: An error if random number generation fails
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeyED25519};
	/// use crypto::ExposeSecret;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Generate a random passphrase
	/// let passphrase = Account::<KeyED25519>::generate_passphrase()?;
	/// let words = passphrase.expose_secret();
	/// assert_eq!(words.len(), 24);
	///
	/// // All words should be from the BIP39 English dictionary
	/// for word in words {
	///     assert!(word.chars().all(|c| c.is_ascii_lowercase()));
	/// }
	/// # Ok(())
	/// # }
	/// ```
	pub fn generate_passphrase() -> Result<SecretBox<Vec<String>>, AccountError> {
		Ok(generate_random_passphrase(None)?)
	}

	/// Generates a cryptographically secure random 32-byte seed.
	///
	/// This method creates a fresh random seed using the operating system's
	/// cryptographically secure random number generator. The seed can be used
	/// directly for key derivation or stored for later use.
	///
	/// # Returns
	///
	/// A 32-byte cryptographically secure random seed wrapped in [`SecretBox`]
	/// for secure memory handling, or an error if random generation fails.
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeyED25519};
	/// use crypto::ExposeSecret;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Generate a random seed
	/// let seed = Account::<KeyED25519>::generate_random_seed()?;
	/// assert_eq!(seed.expose_secret().len(), 32);
	///
	/// // Generate another seed - should be different
	/// let seed2 = Account::<KeyED25519>::generate_random_seed()?;
	/// assert_ne!(seed.expose_secret(), seed2.expose_secret());
	/// # Ok(())
	/// # }
	/// ```
	pub fn generate_random_seed() -> Result<Seed, AccountError> {
		Ok(crypto::generate_random_seed()?)
	}

	/// Generates a deterministic network address from a network ID.
	///
	/// This method creates a network identifier account from a numeric network
	/// ID using a deterministic process. The same network ID will always
	/// produce the same network address.
	///
	/// # Parameters
	///
	/// - `network_id`: A 64-bit unsigned integer representing the network ID
	///
	/// # Returns
	///
	/// A network account ([`Account<KeyNETWORK>`]) that represents the network
	/// address, or an error if account creation fails.
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeyNETWORK, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Generate network addresses for different networks
	/// let mainnet = Account::<KeyNETWORK>::generate_network_address(1)?;
	/// let testnet = Account::<KeyNETWORK>::generate_network_address(1337)?;
	/// let dev_net = Account::<KeyNETWORK>::generate_network_address(12345)?;
	/// assert!(mainnet.is_identifier());
	/// assert!(testnet.is_identifier());
	/// assert!(dev_net.is_identifier());
	///
	/// let mainnet2 = Account::<KeyNETWORK>::generate_network_address(1)?;
	/// // Same network ID produces same address
	/// assert_eq!(mainnet.to_string(), mainnet2.to_string());
	/// // Different network IDs produce different addresses
	/// assert_ne!(mainnet.to_string(), testnet.to_string());
	/// # Ok(())
	/// # }
	/// ```
	pub fn generate_network_address(network_id: u64) -> Result<Account<KeyNETWORK>, AccountError> {
		// Convert network ID to bytes
		let seed_bytes = network_id.to_be_bytes();
		let mut seed = [0u8; 32];
		// Place the u64 bytes at the end of the 32-byte array (big-endian)
		seed[24..32].copy_from_slice(&seed_bytes);

		// Create network account from seed
		let seed_and_index = (seed.into_secret(), 0);
		let keyable = Keyable::Seed(seed_and_index);

		let accountable = Accountable::KeyAndType(keyable, KeyPairType::NETWORK);
		Account::<KeyNETWORK>::try_from(accountable)
	}

	/// Encrypts data using the account's public key.
	///
	/// This method performs public key encryption using the appropriate
	/// encryption scheme for the account's key type. The encrypted data can
	/// only be decrypted using the corresponding private key. Not all key
	/// types support encryption.
	///
	/// # Parameters
	///
	/// - `plaintext`: The data to encrypt (any type that converts to bytes)
	///
	/// # Returns
	///
	/// The encrypted ciphertext as a byte vector, or an error if encryption
	/// fails or is not supported by this key type.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account with private key
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Encrypt a message
	/// let message = b"Secret message for the Keeta Network";
	/// let ciphertext = account.encrypt(message)?;
	/// assert_ne!(ciphertext.as_slice(), message);
	/// # Ok(())
	/// # }
	/// ```
	pub fn encrypt<T: AsRef<[u8]>>(&self, plaintext: T) -> Result<Vec<u8>, AccountError> {
		self.keypair.encrypt(plaintext)
	}

	/// Decrypts data using the account's private key.
	///
	/// This method performs private key decryption to recover the original
	/// plaintext from ciphertext that was encrypted using the corresponding
	/// public key. This operation requires access to the private key and
	/// matching encryption scheme.
	///
	/// # Parameters
	///
	/// - `ciphertext`: The encrypted data to decrypt
	///
	/// # Returns
	///
	/// The decrypted plaintext as a byte vector, or an error if decryption fails,
	/// the private key is not available, or the key type does not support encryption.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account with private key
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Encrypt and then decrypt a message
	/// let original_message = b"Secret message for the Keeta Network";
	/// let ciphertext = account.encrypt(original_message)?;
	/// let plaintext = account.decrypt(&ciphertext)?;
	/// assert_eq!(original_message, plaintext.as_slice());
	/// # Ok(())
	/// # }
	/// ```
	pub fn decrypt<T: AsRef<[u8]>>(&self, ciphertext: T) -> Result<Vec<u8>, AccountError> {
		self.keypair.decrypt(ciphertext)
	}

	/// Checks if this account supports encryption and decryption operations.
	///
	/// Returns `true` if both [`encrypt`](Self::encrypt) and [`decrypt`](Self::decrypt)
	/// operations are supported by this account's key type, `false` otherwise.
	///
	/// # Returns
	///
	/// - `true` for cryptographic key types (Ed25519, ECDSA secp256k1/r1)
	/// - `false` for identifier key types (Network, Token, Storage, Multisig)
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyNETWORK, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test accounts
	/// # let (_, _, ed25519_account) = doc_utils::create_ed25519_test_keys(None);
	/// # let network_account = doc_utils::create_network_test_account(Some(5));
	/// // Cryptographic keys support encryption
	/// assert!(ed25519_account.supports_encryption());
	/// // Identifier keys do not
	/// assert!(!network_account.supports_encryption());
	/// # Ok(())
	/// # }
	/// ```
	pub fn supports_encryption(&self) -> bool {
		self.keypair.supports_encryption()
	}

	/// Returns the signature size in bytes for this account's key type.
	///
	/// Different cryptographic algorithms produce signatures of different
	/// lengths. This method returns the expected signature size.
	///
	/// # Returns
	///
	/// The signature size in bytes, which varies by key type:
	/// - **Ed25519**: 64 bytes
	/// - **ECDSA secp256k1**: 64 bytes (32-byte r + 32-byte s)
	/// - **ECDSA secp256r1**: 64 bytes (32-byte r + 32-byte s)
	/// - **Identifier types**: 0 bytes (do not support signing)
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyECDSASECP256K1, KeyNETWORK, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test accounts
	/// # let (_, _, ed25519_account) = doc_utils::create_ed25519_test_keys(None);
	/// # let (_, _, secp256k1_account) = doc_utils::create_secp256k1_test_keys(None);
	/// # let network_account = doc_utils::create_network_test_account(Some(5));
	/// // Cryptographic keys have consistent signature sizes
	/// assert_eq!(ed25519_account.signature_size(), 64);
	/// assert_eq!(secp256k1_account.signature_size(), 64);
	/// // Identifier keys cannot sign
	/// assert_eq!(network_account.signature_size(), 0);
	/// # Ok(())
	/// # }
	/// ```
	pub fn signature_size(&self) -> usize {
		self.keypair.signature_size()
	}

	/// Generate an identifier from this account
	pub fn generate_identifier(
		&self,
		identifier_type: KeyPairType,
		// TODO Use Hashable once block crate is written
		block_hash: Option<&str>,
		operation_index: u32,
	) -> Result<GenericAccount, AccountError> {
		// Validate that we're generating an identifier type
		if !identifier_type.is_identifier() {
			return Err(AccountError::InvalidIdentifierConstruction);
		}

		// Get the account opening hash (for now, use a placeholder)
		let account_opening_hash = self.to_opening_hash();
		// Determine the block hash to use
		let hash_to_use = match block_hash {
			Some(NO_PREVIOUS) | None => account_opening_hash,
			Some(hash_str) => {
				// Validate hex string format - must not be empty
				if hash_str.is_empty()
					|| (!hash_str.starts_with("0x") && !hash_str.chars().all(|c| c.is_ascii_hexdigit()))
				{
					return Err(AccountError::InvalidConstruction);
				}

				// Parse hex string to bytes
				hex::decode(hash_str.strip_prefix("0x").unwrap_or(hash_str))?
			}
		};

		// Validate identifier generation rules
		if self.to_keypair_type().is_identifier() {
			// Only allow network -> token generation with specific conditions
			let is_network = self.to_keypair_type() == KeyPairType::NETWORK;
			let is_generating_token = identifier_type == KeyPairType::TOKEN;
			let is_first_operation = operation_index == 0;
			let is_opening = block_hash.is_none() || block_hash == Some(NO_PREVIOUS);
			if !(is_network && is_generating_token && is_first_operation && is_opening) {
				return Err(AccountError::InvalidIdentifierConstruction);
			}
		}

		// Create seed from public key + block hash (using hash abstraction)
		let mut seed_data = Vec::new();
		seed_data.push(self.to_keypair_type() as u8);
		seed_data.extend_from_slice(self.keypair.to_public_key().as_ref());
		seed_data.extend_from_slice(&hash_to_use);

		// Hash the combined data to create the seed
		let seed_hash: [u8; 32] = crypto::hash_array(&seed_data, None)?;

		// Helper macro to reduce repetition in account creation
		macro_rules! create_account {
			($key_type:ty, $variant:ident) => {{
				let seed = seed_hash.into_secret();
				let account = Account::<$key_type>::try_from(Accountable::KeyAndType(
					Keyable::Seed((seed, operation_index)),
					identifier_type,
				))?;

				Ok(GenericAccount::$variant(account))
			}};
		}

		match identifier_type {
			KeyPairType::NETWORK => create_account!(KeyNETWORK, Network),
			KeyPairType::TOKEN => create_account!(KeyTOKEN, Token),
			KeyPairType::STORAGE => create_account!(KeySTORAGE, Storage),
			KeyPairType::MULTISIG => create_account!(KeyMULTISIG, Multisig),
			_ => Err(AccountError::InvalidIdentifierConstruction),
		}
	}

	/// Get the account's opening hash
	/// // TODO Use BlockHash once available
	fn to_opening_hash(&self) -> Vec<u8> {
		crypto::hash_default(self.keypair.to_public_key()).to_vec()
	}

	/// Determines if this account is an identifier account.
	///
	/// # Returns
	///
	/// - `true` for identifier types
	/// - `false` for cryptographic types
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{Account, KeyED25519, KeyNETWORK, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test accounts
	/// # let (_, _, crypto_account) = doc_utils::create_ed25519_test_keys(None);
	/// let network_account = Account::<KeyNETWORK>::generate_network_address(12345)?;
	///
	/// // Cryptographic accounts are not identifiers
	/// assert!(!crypto_account.is_identifier());
	///
	/// // Network accounts are identifiers
	/// assert!(network_account.is_identifier());
	/// # Ok(())
	/// # }
	/// ```
	pub fn is_identifier(&self) -> bool {
		self.to_keypair_type().is_identifier()
	}

	/// Determines if this account is a network identifier.
	///
	/// # Returns
	///
	/// - `true` if this account is specifically a network identifier type
	/// - `false` if not
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeyNETWORK, KeyTOKEN};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let network_account = Account::<KeyNETWORK>::generate_network_address(12345)?;
	/// let token_account = Account::<KeyTOKEN>::try_from(accounts::Accountable::KeyAndType(
	///     accounts::Keyable::Identifier("test-token".to_string()),
	///     accounts::KeyPairType::TOKEN,
	/// ))?;
	///
	/// // Only network accounts return true
	/// assert!(network_account.is_network());
	/// assert!(!token_account.is_network());
	/// # Ok(())
	/// # }
	/// ```
	pub fn is_network(&self) -> bool {
		self.to_keypair_type() == KeyPairType::NETWORK
	}

	/// Determines if this account is a token identifier.
	///
	/// # Returns
	///
	/// - `true` if this account is specifically a token identifier type
	/// - `false` if not
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeyNETWORK, KeyTOKEN};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let network_account = Account::<KeyNETWORK>::generate_network_address(12345)?;
	/// let token_account = Account::<KeyTOKEN>::try_from(accounts::Accountable::KeyAndType(
	///     accounts::Keyable::Identifier("test-token".to_string()),
	///     accounts::KeyPairType::TOKEN,
	/// ))?;
	///
	/// // Only token accounts return true
	/// assert!(!network_account.is_token());
	/// assert!(token_account.is_token());
	/// # Ok(())
	/// # }
	/// ```
	pub fn is_token(&self) -> bool {
		self.to_keypair_type() == KeyPairType::TOKEN
	}

	/// Determines if this account is a storage identifier.
	///
	/// # Returns
	///
	/// - `true` if this account is specifically a storage identifier type
	/// - `false` if not
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeySTORAGE, KeyTOKEN};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let storage_account = Account::<KeySTORAGE>::try_from(accounts::Accountable::KeyAndType(
	///     accounts::Keyable::Identifier("test-storage".to_string()),
	///     accounts::KeyPairType::STORAGE,
	/// ))?;
	/// let token_account = Account::<KeyTOKEN>::try_from(accounts::Accountable::KeyAndType(
	///     accounts::Keyable::Identifier("test-token".to_string()),
	///     accounts::KeyPairType::TOKEN,
	/// ))?;
	///
	/// // Only storage accounts return true
	/// assert!(storage_account.is_storage());
	/// assert!(!token_account.is_storage());
	/// # Ok(())
	/// # }
	/// ```
	pub fn is_storage(&self) -> bool {
		self.to_keypair_type() == KeyPairType::STORAGE
	}

	/// Determines if this account is a multisig identifier.
	///
	/// # Returns
	///
	/// - `true` if this account is specifically a multisig identifier type
	/// - `false` if not
	///
	/// # Examples
	///
	/// ```rust
	/// use accounts::{Account, KeyMULTISIG, KeyTOKEN};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let multisig_account = Account::<KeyMULTISIG>::try_from(accounts::Accountable::KeyAndType(
	///     accounts::Keyable::Identifier("test-multisig".to_string()),
	///     accounts::KeyPairType::MULTISIG,
	/// ))?;
	/// let token_account = Account::<KeyTOKEN>::try_from(accounts::Accountable::KeyAndType(
	///     accounts::Keyable::Identifier("test-token".to_string()),
	///     accounts::KeyPairType::TOKEN,
	/// ))?;
	///
	/// // Only multisig accounts return true
	/// assert!(multisig_account.is_multisig());
	/// assert!(!token_account.is_multisig());
	/// # Ok(())
	/// # }
	/// ```
	pub fn is_multisig(&self) -> bool {
		matches!(self.to_keypair_type(), KeyPairType::MULTISIG)
	}

	/// Determines if this account has an associated private key.
	///
	/// This method checks whether the account was created with a private key
	/// component, which determines whether it can perform signing and
	/// decryption operations. Accounts created from public keys only or
	/// identifier accounts will not have private keys available.
	///
	/// # Returns
	///
	/// - `true` if a private key is available for cryptographic operations
	/// - `false` if only the public key is available or for identifier accounts
	///
	/// # Security Note
	///
	/// This method uses unsafe pointer casting to access the private key field
	/// without moving or borrowing the account. This is necessary due to the
	/// generic nature of the Account struct but is memory-safe as long as the
	/// account type matches (which it should always do).
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{Account, KeyED25519, KeyNETWORK, KeyPair, Keyable, Accountable};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Account created with private key
	/// # let (_, _, private_account) = doc_utils::create_ed25519_test_keys(None);
	/// assert!(private_account.has_private_key());
	///
	/// // Account created from public key string only
	/// let public_key_string = private_account.to_string();
	/// let public_only_account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
	///     Keyable::PublicKeyString(public_key_string),
	///     accounts::KeyPairType::ED25519,
	/// ))?;
	/// assert!(!public_only_account.has_private_key());
	///
	/// // Identifier accounts never have private keys
	/// let network_account = Account::<KeyNETWORK>::generate_network_address(12345)?;
	/// assert!(!network_account.has_private_key());
	/// # Ok(())
	/// # }
	/// ```
	pub fn has_private_key(&self) -> bool {
		macro_rules! check_private_key {
			($key_struct:ident) => {{
				let concrete_self = unsafe { &*(self as *const Self as *const Account<$key_struct>) };
				concrete_self.keypair.private_key.is_some()
			}};
		}

		match self.to_keypair_type() {
			KeyPairType::ECDSASECP256K1 => check_private_key!(KeyECDSASECP256K1),
			KeyPairType::ED25519 => check_private_key!(KeyED25519),
			KeyPairType::ECDSASECP256R1 => check_private_key!(KeyECDSASECP256R1),
			// Identifier types never have private keys
			KeyPairType::NETWORK | KeyPairType::TOKEN | KeyPairType::STORAGE | KeyPairType::MULTISIG => false,
		}
	}

	/// Compares this account's public key with another public key.
	///
	/// This method performs a string comparison of the formatted public key
	/// addresses, which provides a reliable way to determine if two accounts
	/// represent the same cryptographic identity, regardless of whether they
	/// have private keys.
	///
	/// # Parameters
	///
	/// - `other`: Another account, public key string, or any type that converts to string
	///
	/// # Returns
	///
	/// - `true` if the public key addresses match exactly
	/// - `false` otherwise.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair, Keyable, Accountable};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test accounts
	/// # let (_, _, account1) = doc_utils::create_ed25519_test_keys(None);
	/// # let (_, _, account2) = doc_utils::create_ed25519_test_keys(Some(b"art art art art art art"));
	/// // Compare with another account
	/// assert!(!account1.compare_public_key(account2.to_string()));
	/// // Compare with itself
	/// assert!(account1.compare_public_key(account1.to_string()));
	///
	/// // Compare with public key string
	/// let public_key_string = account1.to_string();
	/// assert!(account1.compare_public_key(&public_key_string));
	/// # Ok(())
	/// # }
	/// ```
	pub fn compare_public_key<T: AsRef<str>>(&self, other: T) -> bool {
		self.to_string() == other.as_ref()
	}

	/// Compares this account with another account for equality.
	///
	/// This method compares two accounts by their public key strings,
	/// providing a reliable way to determine if they represent the same
	/// cryptographic identity. This works across different account types
	/// and private key availability.
	///
	/// # Parameters
	///
	/// - `other`: Another account of any key type to compare against
	///
	/// # Returns
	///
	/// - `true` if both accounts have the same public key address
	/// - `false` otherwise
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyECDSASECP256K1, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test accounts
	/// # let (_, _, ed25519_account1) = doc_utils::create_ed25519_test_keys(None);
	/// # let (_, _, ed25519_account2) = doc_utils::create_ed25519_test_keys(Some(b"art art art art art art"));
	/// # let (_, _, secp256k1_account) = doc_utils::create_secp256k1_test_keys(None);
	/// // Same key type, different seeds
	/// assert!(!ed25519_account1.compare_account(&ed25519_account2));
	/// // Different key types
	/// assert!(!ed25519_account1.compare_account(&secp256k1_account));
	/// // Same account with itself
	/// assert!(ed25519_account1.compare_account(&ed25519_account1));
	/// # Ok(())
	/// # }
	/// ```
	pub fn compare_account<T>(&self, other: &Account<T>) -> bool
	where
		T: KeyPair,
	{
		self.to_string() == other.to_string()
	}

	/// Signs a message with the account's private key.
	///
	/// This method creates a cryptographic signature for the given message
	/// using the account's private key. The signature can later be verified by
	/// anyone with access to the corresponding public key.
	///
	/// # Parameters
	///
	/// - `message`: The data to sign (any type that converts to bytes)
	/// - `options`: Optional signing parameters
	///
	/// # Returns
	///
	/// - `Ok(_)` with the signature as a byte vector,
	/// - `Err(_)` if signing fails, the private key is not available, or the key type does not support signing.
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test account with private key
	/// # let (_, _, account) = doc_utils::create_ed25519_test_keys(None);
	/// // Sign a message
	/// let message = b"Hello, Keeta Network!";
	/// let signature = account.sign(message, None)?;
	/// assert_eq!(signature.len(), 64); // Ed25519 signature size
	///
	/// // Verify the signature works
	/// let result = account.verify(message, &signature, None);
	/// assert!(result.is_ok());
	/// # Ok(())
	/// # }
	/// ```
	pub fn sign<T: AsRef<[u8]>>(&self, message: T, options: Option<SigningOptions>) -> Result<Vec<u8>, AccountError> {
		self.keypair.sign(message, options)
	}

	/// Verifies a signature against a message using the account's public key.
	///
	/// This method checks whether a given signature was created by the private
	/// key corresponding to this account's public key. Verification is a
	/// public operation that does not require access to the private key.
	///
	/// # Parameters
	///
	/// - `message`: The original data that was signed
	/// - `signature`: The signature to verify (any type that converts to bytes)
	/// - `options`: Optional verification parameters
	///
	/// # Returns
	///
	/// - `Ok(())` if the signature is valid for this account and message
	/// - `Err(_)` if verification fails
	///
	/// # Examples
	///
	/// ```rust
	/// # use accounts::doc_utils;
	/// use accounts::{KeyED25519, KeyPair};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // Create test accounts
	/// # let (_, _, account1) = doc_utils::create_ed25519_test_keys(None);
	/// # let (_, _, account2) = doc_utils::create_ed25519_test_keys(Some(b"art art art art art art"));
	/// // Sign a message with one account
	/// let message = b"Hello, Keeta Network!";
	/// let signature = account1.sign(message, None)?;
	/// // Verify with the same account (should succeed)
	/// assert!(account1.verify(message, &signature, None).is_ok());
	/// // Verify with a different account (should fail)
	/// assert!(account2.verify(message, &signature, None).is_err());
	///
	/// // Verify with wrong message (should fail)
	/// let wrong_message = b"Different message";
	/// assert!(account1.verify(wrong_message, &signature, None).is_err());
	/// # Ok(())
	/// # }
	/// ```
	pub fn verify<T: AsRef<[u8]>, S: AsRef<[u8]>>(
		&self,
		message: T,
		signature: S,
		options: Option<SigningOptions>,
	) -> Result<(), AccountError> {
		self.keypair.verify(message, signature, options)
	}
}

impl<KEYTYPE> TryFrom<AnyPrivateKey> for Account<KEYTYPE>
where
	KEYTYPE: KeyPair + TryFrom<AnyPrivateKey>,
	<KEYTYPE as TryFrom<AnyPrivateKey>>::Error: Into<AccountError>,
{
	type Error = AccountError;

	fn try_from(value: AnyPrivateKey) -> Result<Self, Self::Error> {
		let keypair = KEYTYPE::try_from(value).map_err(|e| e.into())?;
		Ok(Self { keypair })
	}
}

// Blanket implementations for Account<K> where K implements the required traits
impl<K> AccountSigner for Account<K>
where
	K: AccountSigner + KeyPair,
{
	fn sign<T: AsRef<[u8]>>(&self, message: T, options: Option<SigningOptions>) -> Result<Vec<u8>, AccountError> {
		self.keypair.sign(message, options)
	}

	fn signature_size(&self) -> usize {
		self.keypair.signature_size()
	}
}

impl<K> AccountVerifier for Account<K>
where
	K: AccountVerifier + KeyPair,
{
	fn verify<T: AsRef<[u8]>, S: AsRef<[u8]>>(
		&self,
		message: T,
		signature: S,
		options: Option<SigningOptions>,
	) -> Result<(), AccountError> {
		self.keypair.verify(message, signature, options)
	}
}

impl<K, S> Signer<S> for Account<K>
where
	K: Signer<S> + KeyPair,
{
	fn try_sign(&self, message: &[u8]) -> Result<S, SignatureError> {
		self.keypair.try_sign(message)
	}
}

impl<K, S> Verifier<S> for Account<K>
where
	K: Verifier<S> + KeyPair,
{
	fn verify(&self, message: &[u8], signature: &S) -> Result<(), SignatureError> {
		<K as Verifier<S>>::verify(&self.keypair, message, signature)
	}
}

impl<K> CryptoAlgorithm for Account<K>
where
	K: CryptoAlgorithm + KeyPair,
{
	fn to_algorithm(&self) -> Algorithm {
		self.keypair.to_algorithm()
	}
}

impl<K, S> CryptoSigner<S> for Account<K>
where
	K: CryptoSigner<S> + KeyPair,
{
	fn has_private_key(&self) -> bool {
		self.keypair.has_private_key()
	}
}

impl<K, S> CryptoVerifier<S> for Account<K>
where
	K: CryptoVerifier<S> + KeyPair,
{
	fn public_key_bytes(&self) -> Vec<u8> {
		self.keypair.public_key_bytes()
	}
}

impl<K, S> CryptoSignerWithOptions<S> for Account<K>
where
	K: CryptoSignerWithOptions<S> + KeyPair,
{
	fn sign_with_options<T: AsRef<[u8]>>(&self, message: T, options: SigningOptions) -> Result<S, SignatureError> {
		self.keypair.sign_with_options(message, options)
	}
}

impl<K, S> CryptoVerifierWithOptions<S> for Account<K>
where
	K: CryptoVerifierWithOptions<S> + KeyPair,
{
	fn verify_with_options<T: AsRef<[u8]>>(
		&self,
		message: T,
		signature: &S,
		options: SigningOptions,
	) -> Result<(), SignatureError> {
		self.keypair
			.verify_with_options(message, signature, options)
	}
}

// Macro for type casting for public key access
macro_rules! cast_and_get_public_key_string {
	($self:expr, $key_type:ty) => {{
		let concrete_self = unsafe { &*($self as *const _ as *const Account<$key_type>) };
		concrete_self.keypair.to_public_key_string()
	}};
}

// Display blanket implementation for Account types
impl<KEYTYPE> core::fmt::Display for Account<KEYTYPE>
where
	KEYTYPE: KeyPair,
{
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let public_key_string = match self.to_keypair_type() {
			KeyPairType::ECDSASECP256K1 => cast_and_get_public_key_string!(self, KeyECDSASECP256K1),
			KeyPairType::ED25519 => cast_and_get_public_key_string!(self, KeyED25519),
			KeyPairType::ECDSASECP256R1 => cast_and_get_public_key_string!(self, KeyECDSASECP256R1),
			KeyPairType::NETWORK => cast_and_get_public_key_string!(self, KeyNETWORK),
			KeyPairType::TOKEN => cast_and_get_public_key_string!(self, KeyTOKEN),
			KeyPairType::STORAGE => cast_and_get_public_key_string!(self, KeySTORAGE),
			KeyPairType::MULTISIG => cast_and_get_public_key_string!(self, KeyMULTISIG),
		};

		write!(f, "{public_key_string}")
	}
}

// Macro to generate converter implementations for crypto key types
macro_rules! impl_crypto_key_try_from {
	(
		$key_type:ident,
		$private_key_type:ident,
		$public_key_type:ident,
		$algorithm:ident,
		$any_private_key_variant:ident,
		$public_key_len:expr,
		$private_key_len:expr
	) => {
		impl From<$private_key_type> for $key_type {
			fn from(key: $private_key_type) -> Self {
				let public_key = key.as_public_key();
				Self { private_key: Some(key), public_key }
			}
		}

		impl From<$private_key_type> for Account<$key_type> {
			fn from(key: $private_key_type) -> Self {
				let keypair = $key_type::from(key);
				Self { keypair }
			}
		}

		impl TryFrom<Keyable> for $key_type {
			type Error = AccountError;

			fn try_from(input: Keyable) -> Result<Self, AccountError> {
				// Helper closure to derive keys from seed
				let derive_from_seed = |seed: SecretBox<[u8; 32]>,
				                        index: u32|
				 -> Result<(Option<$private_key_type>, String), AccountError> {
					let any_private_key = $key_type::seed_to_private_key(&seed, index)?;
					let public_key_string = $key_type::derive_public_key_string(&any_private_key)?;

					if let AnyPrivateKey::$any_private_key_variant(key) = any_private_key {
						Ok((Some(key), public_key_string))
					} else {
						Err(AccountError::InvalidKeyType)
					}
				};

				match input {
					Keyable::Passphrase((passphrase, index)) => {
						let seed = seed_from_passphrase(&passphrase.expose_secret().join(" "))?;
						let (private_key, _) = derive_from_seed(seed, index)?;
						let public_key = private_key.as_ref().unwrap().as_public_key();
						Ok($key_type { private_key, public_key })
					}
					Keyable::Seed((seed, index)) => {
						let (private_key, _) = derive_from_seed(seed, index)?;
						let public_key = private_key.as_ref().unwrap().as_public_key();
						Ok($key_type { private_key, public_key })
					}
					Keyable::HexSeed((seed, index)) => {
						let decoded = hex::decode(seed.expose_secret())?;
						let bytes: [u8; 32] = decoded
							.try_into()
							.or(Err(AccountError::InvalidConstruction))?;

						let seed = bytes.into_secret();
						let (private_key, _) = derive_from_seed(seed, index)?;
						let public_key = private_key.as_ref().unwrap().as_public_key();
						Ok($key_type { private_key, public_key })
					}
					Keyable::PublicKeyString(public_key_string) => {
						// Validate the prefix first
						if !public_key_string.starts_with("keeta_") {
							return Err(AccountError::InvalidPrefix);
						}

						// Parse the public key string to extract key type and bytes
						let (public_key_bytes, algorithm) = parse_public_key(&public_key_string)?;
						let algorithm = algorithm.ok_or(AccountError::InvalidKeyType)?; // Must be a crypto algorithm
						if algorithm != Algorithm::$algorithm {
							return Err(AccountError::InvalidKeyType);
						}

						// Create the public key object from parsed bytes
						let public_key = $public_key_type::try_from(public_key_bytes.as_slice())
							.map_err(|_| AccountError::InvalidConstruction)?;

						Ok($key_type { private_key: None, public_key })
					}
					Keyable::PublicKey(public_key_bytes) => {
						// Validate key length
						if !$public_key_len.contains(&public_key_bytes.len()) {
							return Err(AccountError::InvalidConstruction);
						}

						// Create the public key object from raw bytes
						let public_key = $public_key_type::try_from(public_key_bytes.as_slice())
							.map_err(|_| AccountError::InvalidConstruction)?;

						Ok($key_type { private_key: None, public_key })
					}
					Keyable::PrivateKey(private_key_bytes) => {
						// Validate private key length
						if private_key_bytes.len() != $private_key_len {
							return Err(AccountError::InvalidConstruction);
						}

						// Create private key from raw bytes
						let private_key = $private_key_type::try_from(private_key_bytes.as_slice())?;
						let public_key = private_key.as_public_key();
						Ok($key_type { private_key: Some(private_key), public_key })
					}

					Keyable::Identifier(_) => Err(AccountError::InvalidIdentifierConstruction),
				}
			}
		}
	};
}

// Generate TryFrom<Keyable> implementations for crypto key types
impl_crypto_key_try_from!(
	KeyECDSASECP256K1,
	Secp256k1PrivateKey,
	Secp256k1PublicKey,
	Secp256k1,
	Secp256k1,
	&[33, 65],
	32
);
impl_crypto_key_try_from!(
	KeyECDSASECP256R1,
	Secp256r1PrivateKey,
	Secp256r1PublicKey,
	Secp256r1,
	Secp256r1,
	&[33, 65],
	32
);
impl_crypto_key_try_from!(KeyED25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519, Ed25519, &[32], 32);

// Macro to generate TryFrom<Keyable> implementations for identifier key types
macro_rules! impl_identifier_key_try_from {
	($key_type:ident, $key_type_value:literal, $($keeta_prefix:literal),+) => {
		impl TryFrom<Keyable> for $key_type {
			type Error = AccountError;

			fn try_from(input: Keyable) -> Result<Self, AccountError> {
				match input {
					Keyable::Identifier(id) => {
						// For identifier strings, hash them directly to get 32-byte identifiers
						let id_bytes = id.as_bytes();
						let hash_result: [u8; 32] = crypto::hash_array(id_bytes, None)?;
						let public_key = IdentifierKey::new(hash_result.to_vec())?;
						Ok($key_type { public_key })
					}
					Keyable::PublicKeyString(public_key_string) => {
						if $(public_key_string.starts_with($keeta_prefix))||+ {
							// Extract the raw bytes from the public key string
							let (decoded_bytes, _) = parse_public_key(&public_key_string)?;
							let public_key = IdentifierKey::new(decoded_bytes)?;
							Ok($key_type { public_key })
						} else {
							Err(AccountError::InvalidConstruction)
						}
					}
					Keyable::Seed((seed, index)) => {
						let (identifier, _) = create_identifier_key(&seed, index)?;
						let key_data = hex::decode(&identifier)?;
						let public_key = IdentifierKey::new(key_data)?;
						Ok($key_type { public_key })
					}
					_ => Err(AccountError::InvalidConstruction),
				}
			}
		}
	};
}

// Generate TryFrom<Keyable> implementations for identifier key types
impl_identifier_key_try_from!(KeyNETWORK, 2, "keeta_ai", "keeta_aj", "keeta_ak", "keeta_al");
impl_identifier_key_try_from!(KeyTOKEN, 3, "keeta_an", "keeta_am", "keeta_ao", "keeta_ap");
impl_identifier_key_try_from!(KeySTORAGE, 4, "keeta_aq", "keeta_ar", "keeta_as", "keeta_at");
impl_identifier_key_try_from!(KeyMULTISIG, 7, "keeta_a4", "keeta_a5", "keeta_a6", "keeta_a7");

/// Macro to implement KeyPair for identifier types that do not support
/// cryptographic operations.
macro_rules! impl_identifier_keypair {
	($key_type:ident, $pair_type:expr) => {
		impl KeyPair for $key_type {
			type PublicKey = IdentifierKey;
			const KEY_PAIR_TYPE: KeyPairType = $pair_type;

			fn seed_to_private_key(_seed: &Seed, _index: Index) -> Result<AnyPrivateKey, AccountError> {
				Err(AccountError::InvalidConstruction)
			}

			fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
				Err(AccountError::InvalidConstruction)
			}

			fn encrypt<T: AsRef<[u8]>>(&self, _plaintext: T) -> Result<Vec<u8>, AccountError> {
				Err(AccountError::EncryptionNotSupported)
			}

			fn decrypt<T: AsRef<[u8]>>(&self, _ciphertext: T) -> Result<Vec<u8>, AccountError> {
				Err(AccountError::EncryptionNotSupported)
			}

			fn supports_encryption(&self) -> bool {
				false
			}

			fn to_public_key(&self) -> Self::PublicKey {
				self.public_key.clone()
			}

			fn take_private_key(self) -> Option<AnyPrivateKey> {
				None // Identifier types do not have private keys
			}
		}

		impl From<IdentifierKey> for $key_type {
			fn from(public_key: IdentifierKey) -> Self {
				Self { public_key }
			}
		}

		impl From<IdentifierKey> for Account<$key_type> {
			fn from(public_key: IdentifierKey) -> Self {
				let keypair = $key_type::from(public_key);
				Self { keypair }
			}
		}
	};
}

// Generate identifier keypair implementations
impl_identifier_keypair!(KeyNETWORK, KeyPairType::NETWORK);
impl_identifier_keypair!(KeyTOKEN, KeyPairType::TOKEN);
impl_identifier_keypair!(KeySTORAGE, KeyPairType::STORAGE);
impl_identifier_keypair!(KeyMULTISIG, KeyPairType::MULTISIG);

// Macro to delegate method calls to all GenericAccount variants
macro_rules! delegate_to_variants {
	($self:ident, $method:ident $(, $param:expr)*) => {
		match $self {
			GenericAccount::EcdsaSecp256k1(account) => account.$method($($param),*),
			GenericAccount::EcdsaSecp256r1(account) => account.$method($($param),*),
			GenericAccount::Ed25519(account) => account.$method($($param),*),
			GenericAccount::Network(account) => account.$method($($param),*),
			GenericAccount::Token(account) => account.$method($($param),*),
			GenericAccount::Storage(account) => account.$method($($param),*),
			GenericAccount::Multisig(account) => account.$method($($param),*),
		}
	};
}

impl GenericAccount {
	/// Returns the key pair type for this instance.
	pub fn to_keypair_type(&self) -> KeyPairType {
		delegate_to_variants!(self, to_keypair_type)
	}
}

impl core::fmt::Display for GenericAccount {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		delegate_to_variants!(self, fmt, f)
	}
}

impl AccountSigner for GenericAccount {
	fn sign<T: AsRef<[u8]>>(&self, message: T, options: Option<SigningOptions>) -> Result<Vec<u8>, AccountError> {
		delegate_to_variants!(self, sign, message, options)
	}

	fn signature_size(&self) -> usize {
		delegate_to_variants!(self, signature_size)
	}
}

// Macro to apply the same expression to all GenericAccount variants
macro_rules! map_all_variants {
	($self:ident, $var:ident, $expr:expr) => {
		match $self {
			GenericAccount::EcdsaSecp256k1($var) => $expr,
			GenericAccount::EcdsaSecp256r1($var) => $expr,
			GenericAccount::Ed25519($var) => $expr,
			GenericAccount::Network($var) => $expr,
			GenericAccount::Token($var) => $expr,
			GenericAccount::Storage($var) => $expr,
			GenericAccount::Multisig($var) => $expr,
		}
	};
}

/// Macro to implement converters for AnyPrivateKey
macro_rules! impl_try_from_keypair {
	($($key_type:ty),+ $(,)?) => {
		$(
			impl TryFrom<$key_type> for AnyPrivateKey {
				type Error = AccountError;

				fn try_from(keypair: $key_type) -> Result<Self, Self::Error> {
					keypair
						.take_private_key()
						.ok_or(AccountError::InvalidConstruction)
				}
			}
		)+
	};
}

// Generate TryFrom implementations for all KeyPair types
impl_try_from_keypair!(KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyNETWORK, KeyTOKEN, KeySTORAGE, KeyMULTISIG);

/// Macro to generate Debug implementations for KeyPair types
macro_rules! impl_debug_for_keypair {
	($($type:ty),+ $(,)?) => {
		$(
			impl core::fmt::Debug for $type {
				fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
					let name = self.to_keypair_type().to_string();
					let public_key = self.to_public_key_string();

					f.debug_struct(&name).field("public_key", &public_key).finish()
				}
			}
		)+
	};
}

// Generate Debug implementations for all KeyPair types.
//
// Security: This macro generates Debug implementations for all keypair types
// ensuring consistent formatting and visibility of keypair details without
// exposing sensitive information. Do not implement Debug for private
// keypair types manually.
impl_debug_for_keypair!(
	KeyECDSASECP256K1,
	KeyECDSASECP256R1,
	KeyED25519,
	KeyNETWORK,
	KeyTOKEN,
	KeySTORAGE,
	KeyMULTISIG,
);

// FromHex implementations for specific Account types
// Unified macro to implement FromHex for all account types
macro_rules! impl_from_hex {
	($key_type:ty, $keypair_type:expr, $is_identifier:expr) => {
		impl FromHex for Account<$key_type> {
			type Error = AccountError;

			fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
				let data = hex::decode(hex).map_err(|_| AccountError::InvalidConstruction)?;
				if data.len() < 2 {
					return Err(AccountError::InvalidConstruction);
				}

				let key_type_byte = data[0];
				let data_bytes = &data[1..];
				if key_type_byte != $keypair_type as u8 {
					return Err(AccountError::InvalidConstruction);
				}

				let keyable = if $is_identifier {
					// For identifier types, convert bytes back to public key string
					let public_key_string = format_public_key_string(data_bytes, key_type_byte)?;
					Keyable::PublicKeyString(public_key_string)
				} else {
					// For crypto types, use raw bytes
					Keyable::PublicKey(data_bytes.to_vec())
				};

				Account::<$key_type>::try_from(Accountable::KeyAndType(keyable, $keypair_type))
			}
		}
	};
}

// Generate FromHex implementations for all account types
impl_from_hex!(KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1, false);
impl_from_hex!(KeyED25519, KeyPairType::ED25519, false);
impl_from_hex!(KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1, false);
impl_from_hex!(KeyNETWORK, KeyPairType::NETWORK, true);
impl_from_hex!(KeyTOKEN, KeyPairType::TOKEN, true);
impl_from_hex!(KeySTORAGE, KeyPairType::STORAGE, true);
impl_from_hex!(KeyMULTISIG, KeyPairType::MULTISIG, true);

// Unified macro to implement ToHex for all account types
macro_rules! impl_to_hex {
	($key_type:ty, $keypair_type:expr) => {
		impl ToHex for Account<$key_type> {
			fn encode_hex<T: FromIterator<char>>(&self) -> T {
				let key_type_byte = $keypair_type as u8;
				let data_bytes = parse_public_key(&self.to_string())
					.map(|(bytes, _)| bytes)
					.unwrap_or_default();

				let mut data = Vec::with_capacity(1 + data_bytes.len());
				data.push(key_type_byte);
				data.extend_from_slice(&data_bytes);

				hex::encode(data).to_uppercase().chars().collect()
			}

			fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
				self.encode_hex()
			}
		}
	};
}

impl ToHex for GenericAccount {
	fn encode_hex<T: FromIterator<char>>(&self) -> T {
		map_all_variants!(self, account, { account.encode_hex() })
	}

	fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
		self.encode_hex()
	}
}

// Generate ToHex implementations for all account types
impl_to_hex!(KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1);
impl_to_hex!(KeyED25519, KeyPairType::ED25519);
impl_to_hex!(KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1);
impl_to_hex!(KeyNETWORK, KeyPairType::NETWORK);
impl_to_hex!(KeyTOKEN, KeyPairType::TOKEN);
impl_to_hex!(KeySTORAGE, KeyPairType::STORAGE);
impl_to_hex!(KeyMULTISIG, KeyPairType::MULTISIG);

// FromStr implementations for Account types
macro_rules! impl_from_str {
	($key_type:ident, $variant:ident) => {
		impl FromStr for Account<$key_type> {
			type Err = AccountError;

			fn from_str(s: &str) -> Result<Self, Self::Err> {
				let generic: GenericAccount = s.parse()?;
				if let GenericAccount::$variant(account) = generic {
					Ok(account)
				} else {
					Err(AccountError::InvalidConstruction)
				}
			}
		}
	};
}

// Implement FromStr for each key type
impl_from_str!(KeyECDSASECP256K1, EcdsaSecp256k1);
impl_from_str!(KeyECDSASECP256R1, EcdsaSecp256r1);
impl_from_str!(KeyED25519, Ed25519);
impl_from_str!(KeyNETWORK, Network);
impl_from_str!(KeyTOKEN, Token);
impl_from_str!(KeySTORAGE, Storage);
impl_from_str!(KeyMULTISIG, Multisig);

// TryFrom implementations to convert GenericAccount variants back to specific Account types
macro_rules! impl_try_from {
	($key_type:ident, $variant:ident) => {
		impl TryFrom<GenericAccount> for Account<$key_type> {
			type Error = AccountError;

			fn try_from(generic: GenericAccount) -> Result<Self, Self::Error> {
				if let GenericAccount::$variant(account) = generic {
					Ok(account)
				} else {
					Err(AccountError::InvalidConstruction)
				}
			}
		}
	};
}

// Implement TryFrom for each key type
impl_try_from!(KeyECDSASECP256K1, EcdsaSecp256k1);
impl_try_from!(KeyECDSASECP256R1, EcdsaSecp256r1);
impl_try_from!(KeyED25519, Ed25519);
impl_try_from!(KeyNETWORK, Network);
impl_try_from!(KeyTOKEN, Token);
impl_try_from!(KeySTORAGE, Storage);
impl_try_from!(KeyMULTISIG, Multisig);

/// Macro to generate crypto trait implementations for cryptographic key types
macro_rules! impl_crypto_traits {
	($key_type:ty, $signature_type:ty, $private_key_type:ty, $public_key_type:ty, $algorithm:expr) => {
		impl AccountSigner for $key_type {
			fn sign<T: AsRef<[u8]>>(
				&self,
				message: T,
				options: Option<SigningOptions>,
			) -> Result<Vec<u8>, AccountError> {
				let signature = self.sign_with_options(message, options.unwrap_or_default())?;
				Ok(signature.to_bytes().to_vec())
			}

			fn signature_size(&self) -> usize {
				64
			}
		}

		impl AccountVerifier for $key_type {
			fn verify<T: AsRef<[u8]>, S: AsRef<[u8]>>(
				&self,
				message: T,
				signature: S,
				options: Option<SigningOptions>,
			) -> Result<(), AccountError> {
				// Parse the signature from bytes
				let sig =
					<$signature_type>::try_from(signature.as_ref()).map_err(|_| AccountError::InvalidConstruction)?;
				Ok(self.verify_with_options(message, &sig, options.unwrap_or_default())?)
			}
		}

		impl Signer<$signature_type> for $key_type {
			fn try_sign(&self, message: &[u8]) -> Result<$signature_type, SignatureError> {
				let private_key = self.private_key.as_ref().ok_or(SignatureError::new())?;
				private_key.sign_with_options(message, SigningOptions::default())
			}
		}

		impl Verifier<$signature_type> for $key_type {
			fn verify(&self, message: &[u8], signature: &$signature_type) -> Result<(), SignatureError> {
				let public_key = self.to_public_key();
				public_key.verify_with_options(message, signature, SigningOptions::default())
			}
		}

		impl CryptoAlgorithm for $key_type {
			fn to_algorithm(&self) -> Algorithm {
				$algorithm
			}
		}

		impl CryptoSigner<$signature_type> for $key_type {
			fn has_private_key(&self) -> bool {
				self.private_key.is_some()
			}
		}

		impl CryptoVerifier<$signature_type> for $key_type {
			fn public_key_bytes(&self) -> Vec<u8> {
				self.public_key.public_key_bytes()
			}
		}

		impl CryptoSignerWithOptions<$signature_type> for $key_type {
			fn sign_with_options<T: AsRef<[u8]>>(
				&self,
				message: T,
				options: SigningOptions,
			) -> Result<$signature_type, SignatureError> {
				let private_key = self.private_key.as_ref().ok_or(SignatureError::new())?;
				private_key.sign_with_options(message, options)
			}
		}

		impl CryptoVerifierWithOptions<$signature_type> for $key_type {
			fn verify_with_options<T: AsRef<[u8]>>(
				&self,
				message: T,
				signature: &$signature_type,
				options: SigningOptions,
			) -> Result<(), SignatureError> {
				let public_key = self.to_public_key();
				public_key.verify_with_options(message, signature, options)
			}
		}
	};
}

// Implement crypto traits for cryptographic key types
impl_crypto_traits!(
	KeyECDSASECP256K1,
	Secp256k1Signature,
	Secp256k1PrivateKey,
	Secp256k1PublicKey,
	Algorithm::Secp256k1
);
impl_crypto_traits!(
	KeyECDSASECP256R1,
	Secp256r1Signature,
	Secp256r1PrivateKey,
	Secp256r1PublicKey,
	Algorithm::Secp256r1
);
impl_crypto_traits!(KeyED25519, Ed25519Signature, Ed25519PrivateKey, Ed25519PublicKey, Algorithm::Ed25519);

// Macro to implement crypto traits for identifier key types that do
// not support crypto operations
macro_rules! impl_identifier_crypto_traits {
	($key_type:ty) => {
		impl AccountSigner for $key_type {}
		impl AccountVerifier for $key_type {}
	};
}

// Implement crypto traits for identifier key types
impl_identifier_crypto_traits!(KeyNETWORK);
impl_identifier_crypto_traits!(KeySTORAGE);
impl_identifier_crypto_traits!(KeyTOKEN);
impl_identifier_crypto_traits!(KeyMULTISIG);

/// Macro to implement `PublicKeyStorage` for types that can convert to `Vec<u8>`.
///
/// This macro implements both the `PublicKeyStorage` trait and the required
/// `From<&T> for Vec<u8>` conversion using the type's existing `Into<Vec<u8>>` implementation.
macro_rules! impl_public_key_storage {
	($type:ty) => {
		impl PublicKeyStorage for $type {}
	};
}

// Implement PublicKeyStorage for IdentifierKey
impl_public_key_storage!(IdentifierKey);
impl_public_key_storage!(crypto::Ed25519PublicKey);
impl_public_key_storage!(crypto::Secp256k1PublicKey);
impl_public_key_storage!(crypto::Secp256r1PublicKey);

#[cfg(test)]
mod tests {
	use super::*;

	use crypto::{Algorithm, Ed25519PrivateKey, Secp256k1PrivateKey, Secp256r1PrivateKey};

	/// Test data for key type detection methods
	#[allow(dead_code)]
	const CRYPTO_ACCOUNT_TYPES: &[KeyPairType] =
		&[KeyPairType::ECDSASECP256K1, KeyPairType::ED25519, KeyPairType::ECDSASECP256R1];

	/// Test data for identifier account types
	const IDENTIFIER_ACCOUNT_TYPES: &[KeyPairType] =
		&[KeyPairType::NETWORK, KeyPairType::TOKEN, KeyPairType::STORAGE, KeyPairType::MULTISIG];

	/// Centralized key type test data
	const KEY_TYPE_TEST_DATA: &[KeyTypeTestData] = &[
		KeyTypeTestData {
			key_type: KeyPairType::ECDSASECP256K1,
			is_identifier: false,
			supports_crypto: true,
			is_network: false,
			is_token: false,
			is_storage: false,
			is_multisig: false,
		},
		KeyTypeTestData {
			key_type: KeyPairType::ED25519,
			is_identifier: false,
			supports_crypto: true,
			is_network: false,
			is_token: false,
			is_storage: false,
			is_multisig: false,
		},
		KeyTypeTestData {
			key_type: KeyPairType::ECDSASECP256R1,
			is_identifier: false,
			supports_crypto: true,
			is_network: false,
			is_token: false,
			is_storage: false,
			is_multisig: false,
		},
		KeyTypeTestData {
			key_type: KeyPairType::NETWORK,
			is_identifier: true,
			supports_crypto: false,
			is_network: true,
			is_token: false,
			is_storage: false,
			is_multisig: false,
		},
		KeyTypeTestData {
			key_type: KeyPairType::TOKEN,
			is_identifier: true,
			supports_crypto: false,
			is_network: false,
			is_token: true,
			is_storage: false,
			is_multisig: false,
		},
		KeyTypeTestData {
			key_type: KeyPairType::STORAGE,
			is_identifier: true,
			supports_crypto: false,
			is_network: false,
			is_token: false,
			is_storage: true,
			is_multisig: false,
		},
		KeyTypeTestData {
			key_type: KeyPairType::MULTISIG,
			is_identifier: true,
			supports_crypto: false,
			is_network: false,
			is_token: false,
			is_storage: false,
			is_multisig: true,
		},
	];

	const TEST_PUBLIC_ACCOUNTS: &[TestPublicAccountData] = &[
		TestPublicAccountData {
			public_key: "020F2115FA0C9A10680AEECB64AB2E0564AED1AF821A72BF987AABF87A1AD68251",
			// cspell:disable-next-line
			encoded_public_key: "keeta_aaba6iiv7igjuediblxmwzflfycwjlwrv6bbu4v7tb5kx6d2dllieunedvq3cza",
			key_type: KeyPairType::ECDSASECP256K1,
			is_identifier: false,
		},
		TestPublicAccountData {
			public_key: "02A343D16E4557B1F8DE83C399F8926F42CF905AFD39C140BD3E5EB848941C124A",
			// cspell:disable-next-line
			encoded_public_key: "keeta_aybkgq6rnzcvpmpy32b4hgpysjxuft4qll6ttqkaxu7f5ocisqobesxrfuhyofi",
			key_type: KeyPairType::ECDSASECP256R1,
			is_identifier: false,
		},
		TestPublicAccountData {
			public_key: "C1DDA7698D58436DAB0D6DE9A482F1C3130498064793F1E26A8D09F88B555850",
			// cspell:disable-next-line
			encoded_public_key: "keeta_aha53j3jrvmeg3nlbvw6tjec6hbrgbeyazdzh4pcnkgqt6elkvmfbuue55hz4",
			key_type: KeyPairType::ED25519,
			is_identifier: false,
		},
		TestPublicAccountData {
			public_key: "372D46C3ADA9F897C74D349BBFE0E450C798167C9F580F8DAF85DEF57E96C3EA",
			// cspell:disable-next-line
			encoded_public_key: "keeta_ai3s2rwdvwu7rf6hju2jxp7a4rimpgawpspvqd4nv6c555l6s3b6uj6cr5klc",
			key_type: KeyPairType::NETWORK,
			is_identifier: true,
		},
		TestPublicAccountData {
			public_key: "724E371B944A48E95B91EE059B7CB7110E5866CA707915C287C49CAB9B774AF1",
			// cspell:disable-next-line
			encoded_public_key: "keeta_anze4ny3srfer2k3shxalg34w4iq4wdgzjyhsfocq7cjzk43o5fpc2igkuifg",
			key_type: KeyPairType::TOKEN,
			is_identifier: true,
		},
		TestPublicAccountData {
			public_key: "DF2D414F6702347EDBBD318DA8E319F1229F83E3B4DC2C8C135CF67C5952B07D",
			// cspell:disable-next-line
			encoded_public_key: "keeta_atps2qkpm4bdi7w3xuyy3khddhysfh4d4o2nylemcnopm7czkkyh2pbfk7svy",
			key_type: KeyPairType::STORAGE,
			is_identifier: true,
		},
		TestPublicAccountData {
			public_key: "1858E8B2F42EDD1072EA71E99D67407E56D1CB4B20A265252FACE1ABF8A76D19",
			// cspell:disable-next-line
			encoded_public_key: "keeta_a4mfr2fs6qxn2eds5jy6thlhib7fnuoljmqkezjff6wodk7yu5wrt52ks62sa",
			key_type: KeyPairType::MULTISIG,
			is_identifier: true,
		},
	];

	const SIGNATURE_TEST: SignatureTest = SignatureTest {
		// cspell:disable-next-line
		public_key_string: "keeta_aabm7moneqqjpaaee5vxjqoe5f2ay3dchgr2hysdfh4wg3ycylohabivswjyfci",
		test_data: b"Some random test data",
		expected_signature: &[
			0x5C, 0xDC, 0x7C, 0x59, 0xE0, 0x9C, 0xDD, 0x1A, 0xE1, 0xE5, 0xC8, 0xD5, 0x21, 0x1E, 0xFA, 0x09, 0x25, 0x31,
			0x92, 0x42, 0x50, 0xE1, 0x56, 0x26, 0x66, 0x00, 0xCB, 0xDC, 0x69, 0xBF, 0x9F, 0xED, 0x5C, 0x28, 0x5F, 0x33,
			0x9E, 0x17, 0xDA, 0xA2, 0xFC, 0xAC, 0xED, 0x7C, 0xD3, 0xAC, 0x40, 0x3C, 0x9E, 0xFE, 0x98, 0x39, 0x24, 0x87,
			0xF4, 0xEA, 0x15, 0x51, 0xEC, 0xCB, 0x5D, 0xBC, 0x97, 0x4F,
		],
	};

	const TEST_PRIVATE_ACCOUNT: TestPrivateAccountData = TestPrivateAccountData {
		seed: "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D",
		indexes: &[
			TestPrivateAccountIndex {
				encoded_public_key_ecdsa_secp256k1: // cspell:disable-next-line
					"keeta_aabbk6vq5mjvityvqnrvz6g3f3jr72oqfeqg4fqbaa4s5sisrdlfhkfr5p7chey",
				encoded_public_key_ecdsa_secp256r1: // cspell:disable-next-line
					"keeta_aybloaplxz7fmhhv3moeyr7flrfvltxt7co6rthmgeuevjogboiqss6pzmhgr6i",
				// cspell:disable-next-line
				encoded_public_key_ed25519: "keeta_ahcp4hwh26cinhsilat6tiolefkt5tlqk4ebrxjwpodkziuvxre3x3r2wf5l6",
			},
			TestPrivateAccountIndex {
				encoded_public_key_ecdsa_secp256k1: // cspell:disable-next-line
					"keeta_aabenomfdx4qdgspfmllant23pq5bqe6g74ecy5gc42htzcl5fg5zdr55yndzra",
				encoded_public_key_ecdsa_secp256r1: // cspell:disable-next-line
					"keeta_aybsfqikxnweg22um5ab223tkgh443nvvnrjcbaaneag3ryrhmlkhpd7awgj7ry",
				// cspell:disable-next-line
				encoded_public_key_ed25519: "keeta_agcgfuaq3lrjgtzj3vw2rcsy5afm2ky7nhmbqnhrih6cl6u4zxjntb2x72hc2",
			},
		],
	};

	// Test cases for invalid public key strings (should fail)
	const INVALID_PUBLIC_KEYS: &[&str] = &[
		// cspell:disable-next-line
		"0xaguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwui", // Invalid prefix
		// cspell:disable-next-line
		"notkeeta_aguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwui", // Wrong prefix
		// cspell:disable-next-line
		"keeta_cqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabibevehoy", // Invalid key type
		// cspell:disable-next-line
		"keeta_aguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwuk", // Invalid checksum
		// cspell:disable-next-line
		"keeta_aguijv77cohs3fks62isqa4ywdvwlyhfddwpq4pqnvl6lssoyug2k7vkqfwu", // Missing data
		"A884D7FF138F2D9552F691280398B0EB65E0E518ECF871F06D57E5CA4EC50DA5",   // Wrong format
	];

	const PRIVATE_ACCOUNT_TEST_DATA: PrivateAccountTestData = PrivateAccountTestData {
		seed: "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D",
		indexes: &[
			PrivateKeyTestCase {
				encoded_public_key_ecdsa_secp256k1:
				// cspell:disable-next-line
					"keeta_aabbk6vq5mjvityvqnrvz6g3f3jr72oqfeqg4fqbaa4s5sisrdlfhkfr5p7chey",
				// cspell:disable-next-line
				encoded_public_key_ecdsa_secp256r1: "keeta_aybloaplxz7fmhhv3moeyr7flrfvltxt7co6rthmgeuevjogboiqss6pzmhgr6i",
				// cspell:disable-next-line
				encoded_public_key_ed25519: "keeta_ahcp4hwh26cinhsilat6tiolefkt5tlqk4ebrxjwpodkziuvxre3x3r2wf5l6",
			},
			PrivateKeyTestCase {
				encoded_public_key_ecdsa_secp256k1:
				// cspell:disable-next-line
					"keeta_aabenomfdx4qdgspfmllant23pq5bqe6g74ecy5gc42htzcl5fg5zdr55yndzra",
				// cspell:disable-next-line
				encoded_public_key_ecdsa_secp256r1: "keeta_aybsfqikxnweg22um5ab223tkgh443nvvnrjcbaaneag3ryrhmlkhpd7awgj7ry",
				// cspell:disable-next-line
				encoded_public_key_ed25519: "keeta_agcgfuaq3lrjgtzj3vw2rcsy5afm2ky7nhmbqnhrih6cl6u4zxjntb2x72hc2",
			},
		],
	};

	const TEST_CASES: &[TestCase] = &[
		TestCase {
			hex_seed: "8C9CF402025839A0D7E568A375EBED1EEA2EFE6690C65FB015AD446FD299ABE2",
			passphrase: &[
				"public", "sketch", "attract", "blame", "verify", "faculty", "anchor", "bargain", "acid", "tonight",
				"speed", "spike", "source", "hire", "amused", "improve", "shaft", "phrase", "permit", "napkin",
				"video", "object", "finger", "waste",
			],
			// cspell:disable-next-line
			expected_secp256k1_pubkey: "keeta_aaboj3lndhqf5znsqsy5uu57wvcdxsmkzguhy7gvgrwxudhws2sy655fyeoco6y",
			// cspell:disable-next-line
			expected_ed25519_pubkey: "keeta_ahdd6kd5h7jznrflkabvo6t2s4gv37l4omnmhqa3cdqpya3q2tbf75ua5ays4",
			// cspell:disable-next-line
			expected_secp256r1_pubkey: "keeta_aybjr74yaz4ls5kxaybrtaecqylpkefpozprmx5movzkotrcknbffiauod7p6ga",
		},
		TestCase {
			hex_seed: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
			passphrase: &[
				"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
				"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
				"abandon", "abandon", "abandon", "abandon", "abandon", "art",
			],
			// cspell:disable-next-line
			expected_secp256k1_pubkey: "keeta_aab3mndobwgx7ovnrflw7gkd5y26m3y7rmvs42ozq6jfgsl53vybkfd7frcws7i",
			// cspell:disable-next-line
			expected_ed25519_pubkey: "keeta_ah6f6tuz7ngwjwr2t7fujiowjrqiwjdslq4imbfj2lzcfkol6qr6hyy3fgcuq",
			// cspell:disable-next-line
			expected_secp256r1_pubkey: "keeta_aybsoespx3vvbochl6g5vr4ibufupvqvp5dbrsvoykzhlsu6br2xu4otoj4la4a",
		},
	];

	const TEST_PUBLIC_ACCOUNT_DATA: ReferencePublicAccountData = ReferencePublicAccountData {
		ecdsa_secp256k1: (
			"020F2115FA0C9A10680AEECB64AB2E0564AED1AF821A72BF987AABF87A1AD68251",
			// cspell:disable-next-line
			"keeta_aaba6iiv7igjuediblxmwzflfycwjlwrv6bbu4v7tb5kx6d2dllieunedvq3cza",
			"6e125705c52cc4016df9b955a91672bfb342fee30be4344f8a2347b7f0435219",
		),
		ecdsa_secp256r1: (
			"02A343D16E4557B1F8DE83C399F8926F42CF905AFD39C140BD3E5EB848941C124A",
			// cspell:disable-next-line
			"keeta_aybkgq6rnzcvpmpy32b4hgpysjxuft4qll6ttqkaxu7f5ocisqobesxrfuhyofi",
			"84b1db2dd8a34716a6eecb0d9bfb5188af07d0393b8e7d831bfb2adc67e48609",
		),
		ed25519: (
			"C1DDA7698D58436DAB0D6DE9A482F1C3130498064793F1E26A8D09F88B555850",
			// cspell:disable-next-line
			"keeta_aha53j3jrvmeg3nlbvw6tjec6hbrgbeyazdzh4pcnkgqt6elkvmfbuue55hz4",
			"3eaad2b3691c03f006b3dc09e66eefc4df1f22131a600782362aa7ef6c803da4",
		),
		token: (
			"724E371B944A48E95B91EE059B7CB7110E5866CA707915C287C49CAB9B774AF1",
			// cspell:disable-next-line
			"keeta_anze4ny3srfer2k3shxalg34w4iq4wdgzjyhsfocq7cjzk43o5fpc2igkuifg",
			"aad386692e77d8a178af7f76f2d38f5daef3ab89359a0a64ed54636f58de86c2",
		),
		storage: (
			"DF2D414F6702347EDBBD318DA8E319F1229F83E3B4DC2C8C135CF67C5952B07D",
			// cspell:disable-next-line
			"keeta_atps2qkpm4bdi7w3xuyy3khddhysfh4d4o2nylemcnopm7czkkyh2pbfk7svy",
			"7eb9191b1ca787c368484ae428462fc436430db3d0cd006ed730029c2fadb5e2",
		),
	};

	// Comprehensive key type test data structure
	struct KeyTypeTestData {
		key_type: KeyPairType,
		is_identifier: bool,
		supports_crypto: bool,
		is_network: bool,
		is_token: bool,
		is_storage: bool,
		is_multisig: bool,
	}

	struct TestPublicAccountData {
		public_key: &'static str,
		encoded_public_key: &'static str,
		key_type: KeyPairType,
		is_identifier: bool,
	}

	struct TestPrivateAccountIndex {
		encoded_public_key_ecdsa_secp256k1: &'static str,
		encoded_public_key_ecdsa_secp256r1: &'static str,
		encoded_public_key_ed25519: &'static str,
	}

	struct TestPrivateAccountData {
		seed: &'static str,
		indexes: &'static [TestPrivateAccountIndex],
	}

	// Hard-coded signature test data
	struct SignatureTest {
		public_key_string: &'static str,
		test_data: &'static [u8],
		expected_signature: &'static [u8],
	}

	struct ReferencePublicAccountData {
		pub ecdsa_secp256k1: (&'static str, &'static str, &'static str),
		pub ecdsa_secp256r1: (&'static str, &'static str, &'static str),
		pub ed25519: (&'static str, &'static str, &'static str),
		pub token: (&'static str, &'static str, &'static str),
		pub storage: (&'static str, &'static str, &'static str),
	}

	// Test data structure for comprehensive data-driven testing
	struct TestCase {
		hex_seed: &'static str,
		passphrase: &'static [&'static str],
		expected_secp256k1_pubkey: &'static str,
		expected_ed25519_pubkey: &'static str,
		expected_secp256r1_pubkey: &'static str,
	}

	// Test data for private accounts with deterministic derivation
	struct PrivateAccountTestData {
		seed: &'static str,
		indexes: &'static [PrivateKeyTestCase],
	}

	// Only keep the fields we actually use in tests
	struct PrivateKeyTestCase {
		encoded_public_key_ecdsa_secp256k1: &'static str,
		encoded_public_key_ecdsa_secp256r1: &'static str,
		encoded_public_key_ed25519: &'static str,
	}

	/// Creates a standard 24-word mnemonic passphrase for testing
	fn create_test_passphrase() -> Vec<String> {
		vec![
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
			"abandon", "abandon", "abandon", "abandon", "abandon", "art",
		]
		.iter()
		.map(|s| s.to_string())
		.collect()
	}

	/// Test helper function to create an account with a specific key type and
	/// optional keyable input. If keyable is None, generates a passphrase and converts
	/// to seed. If keyable is provided, uses it directly.
	fn create_test_account<T>(keyable: Option<Keyable>) -> Account<T>
	where
		T: KeyPair,
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	{
		let keyable = match keyable {
			Some(k) => k,
			None => {
				let generated_passphrase = Account::<T>::generate_passphrase().unwrap();
				let passphrase = generated_passphrase.expose_secret().clone();
				let seed = Account::<T>::compute_seed_from_passphrase(passphrase).unwrap();

				Keyable::Seed((seed, 0))
			}
		};

		Account::<T>::try_from(Accountable::KeyAndType(keyable, T::keypair_type())).unwrap()
	}

	/// Test helper function to create an account from a public key string.
	/// This is useful for testing scenarios where you have hex-encoded public key strings.
	fn create_test_account_from_pub_key_string<T>(pub_key_string: &str) -> Account<T>
	where
		T: KeyPair,
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	{
		let keyable = Keyable::PublicKeyString(pub_key_string.to_string());
		Account::<T>::try_from(Accountable::KeyAndType(keyable, T::keypair_type())).unwrap()
	}

	/// Test helper function to create an identifier account from a string.
	/// This is useful for testing identifier-based accounts (TOKEN, STORAGE, MULTISIG).
	fn create_test_account_from_identifier<T>(identifier: &str) -> Account<T>
	where
		T: KeyPair,
		Account<T>: TryFrom<Accountable<T>, Error = AccountError>,
	{
		let keyable = Keyable::Identifier(identifier.to_string());
		Account::<T>::try_from(Accountable::KeyAndType(keyable, T::keypair_type())).unwrap()
	}

	/// Creates a test network account with the given ID.
	fn create_test_network_account(id: u64) -> Account<KeyNETWORK> {
		Account::<KeyNETWORK>::generate_network_address(id).unwrap()
	}

	#[test]
	fn test_basic_account_generation() {
		// Macro to test account generation for any key type
		macro_rules! test_account_generation {
			($key_type:ty, $expected_key_pair_type:expr) => {
				let account = create_test_account::<$key_type>(None);
				assert_eq!(account.keypair.to_keypair_type(), $expected_key_pair_type);
				assert_eq!(account.to_keypair_type(), $expected_key_pair_type);
			};
		}

		// Test all cryptographic key types
		macro_rules! test_all_crypto_types {
			($($key_type:ty, $key_pair_type:expr),* $(,)?) => {
				$(
					test_account_generation!($key_type, $key_pair_type);
				)*
			};
		}

		test_all_crypto_types!(
			KeyECDSASECP256K1,
			KeyPairType::ECDSASECP256K1,
			KeyED25519,
			KeyPairType::ED25519,
			KeyECDSASECP256R1,
			KeyPairType::ECDSASECP256R1,
		);
	}

	#[test]
	fn test_crypto_deterministic_behavior() {
		// Macro to test deterministic behavior for any crypto key type
		macro_rules! test_deterministic_crypto {
			($key_type:ty, $expected_prefix:expr) => {
				for test_case in TEST_CASES {
					let passphrase: Vec<String> = test_case.passphrase.iter().map(|s| s.to_string()).collect();

					// Test passphrase -> seed conversion
					let seed1 = Account::<$key_type>::compute_seed_from_passphrase(passphrase.clone()).unwrap();
					let account1 = create_test_account::<$key_type>(Some(passphrase.clone().into()));
					let public_key_string = account1.keypair.to_public_key_string();
					assert!(public_key_string.starts_with($expected_prefix));

					// Test hex seed with different construction methods
					let account2 = create_test_account::<$key_type>(Some(test_case.hex_seed.to_string().into()));
					let account3 = Account::<$key_type>::try_from(Accountable::Key(account2.clone().keypair)).unwrap();
					let account4 = Account::<$key_type>::try_from(Accountable::Account(account2.clone())).unwrap();

					// Test deterministic passphrase behavior
					let seed2 = Account::<$key_type>::compute_seed_from_passphrase(passphrase).unwrap();

					// Verify that the same passphrase produces the same seed
					assert_eq!(seed1.expose_secret(), seed2.expose_secret());
					// Verify deterministic behavior for different construction methods
					assert_eq!(account2.keypair.to_public_key_string(), account3.keypair.to_public_key_string());
					assert_eq!(account2.keypair.to_public_key_string(), account4.keypair.to_public_key_string());					// Verify against expected public key from test case
					let expected_pubkey = match stringify!($key_type) {
						"KeyECDSASECP256K1" => test_case.expected_secp256k1_pubkey,
						"KeyED25519" => test_case.expected_ed25519_pubkey,
						"KeyECDSASECP256R1" => test_case.expected_secp256r1_pubkey,
						_ => panic!("Unsupported key type for deterministic test"),
					};
					assert_eq!(account2.keypair.to_public_key_string(), expected_pubkey);
				}
			};
		}

		// Test all crypto algorithms for deterministic behavior
		test_deterministic_crypto!(KeyECDSASECP256K1, "keeta_");
		test_deterministic_crypto!(KeyED25519, "keeta_");
		test_deterministic_crypto!(KeyECDSASECP256R1, "keeta_");
	}

	#[test]
	fn test_algorithm_differences() {
		// Macro to create account and extract public key for any key type
		macro_rules! create_account_with_seed {
			($key_type:ty, $seed:expr) => {{
				let account = create_test_account::<$key_type>(Some($seed.clone().into()));
				account.keypair.to_public_key_string()
			}};
		}

		// Macro to test all algorithm types with their expected keys
		macro_rules! test_all_algorithms {
			($test_case:expr, $(($key_type:ty, $expected_field:ident)),* $(,)?) => {{
				let mut accounts = Vec::new();
				let seed = $test_case.hex_seed.to_string();

				$(
					let public_key = create_account_with_seed!($key_type, seed);
					accounts.push((public_key, $test_case.$expected_field));
				)*

				accounts
			}};
		}

		for test_case in TEST_CASES {
			let accounts = test_all_algorithms!(
				test_case,
				(KeyECDSASECP256K1, expected_secp256k1_pubkey),
				(KeyED25519, expected_ed25519_pubkey),
				(KeyECDSASECP256R1, expected_secp256r1_pubkey),
			);

			// Verify different algorithms produce different public keys
			for i in 0..accounts.len() {
				for j in i + 1..accounts.len() {
					assert_ne!(accounts[i].0, accounts[j].0);
				}
			}

			// Verify expected public keys match test case
			for (public_key, expected_key) in accounts {
				assert_eq!(public_key, expected_key);
			}
		}
	}

	#[test]
	fn test_identifier_key_types() {
		// Test invalid IdentifierKey construction with wrong sizes first
		let invalid_sizes = [0, 1, 3, 16, 31, 33, 64];
		for size in invalid_sizes {
			let invalid_bytes = vec![0u8; size];
			let result = IdentifierKey::try_from(invalid_bytes);
			assert!(result.is_err());
		}

		// Test IdentifierKey encryption/decryption not supported
		let valid_bytes = vec![0u8; 32];
		let identifier_key = IdentifierKey::try_from(valid_bytes).unwrap();

		let encrypt_result = identifier_key.encrypt(b"test data");
		assert!(encrypt_result.is_err());

		let decrypt_result = identifier_key.decrypt(b"test data");
		assert!(decrypt_result.is_err());

		// Macro to test identifier key creation for any key type
		macro_rules! test_identifier_key {
			($key_type:ty, $test_id:expr, $key_pair_type:expr) => {
				let key = <$key_type>::try_from(Keyable::Identifier($test_id.into())).unwrap();
				let public_key_string = key.to_public_key_string();

				// Verify the public key string format and that we can parse it
				let (parsed_bytes, algorithm) = parse_public_key(&public_key_string).unwrap();
				assert_eq!(parsed_bytes.len(), 32); // Should be 32 bytes after processing
				assert!(public_key_string.starts_with("keeta_"));
				assert_ne!(public_key_string, $test_id);
				assert_eq!(key.to_keypair_type(), $key_pair_type);
				assert!(algorithm.is_none());
				assert!(!$key_pair_type.supports_crypto());
				assert_eq!(key.signature_size(), 0);

				// Test Debug formatting
				let debug_str = format!("{:?}", key);
				assert!(!debug_str.is_empty()); // Test From<IdentifierKey> implementations
				let identifier_key = IdentifierKey::try_from(vec![0u8; 32]).unwrap();

				// Test From<IdentifierKey> for key type
				let key_from_identifier = <$key_type>::from(identifier_key.clone());
				assert_eq!(key_from_identifier.to_keypair_type(), $key_pair_type);

				// Test From<IdentifierKey> for Account<KeyType>
				let account_from_identifier = Account::<$key_type>::from(identifier_key);
				assert_eq!(account_from_identifier.to_keypair_type(), $key_pair_type);
				assert!(account_from_identifier.is_identifier());

				// Test invalid identifier generation for cryptographic types
				let invalid_types = [KeyPairType::ECDSASECP256K1, KeyPairType::ED25519, KeyPairType::ECDSASECP256R1];
				for invalid_type in invalid_types {
					let result = account_from_identifier.generate_identifier(invalid_type, None, 0);
					assert!(result.is_err());
				}

				// Test unsupported cryptographic operations
				let data = b"test data";
				let sign_result = key.sign(data, None);
				assert!(sign_result.is_err());

				// Test supports_encryption
				assert!(!key.supports_encryption());
				assert!(key.take_private_key().is_none());

				// Test seed_to_private_key
				let seed_array = [0u8; 32];
				let seed = seed_array.into_secret();
				assert!(<$key_type>::seed_to_private_key(&seed, 0).is_err());

				// Test derive_public_key_string
				let private_key = Ed25519PrivateKey::try_from([1u8; 32].as_slice()).unwrap();
				let dummy_private_key = AnyPrivateKey::Ed25519(private_key);
				assert!(<$key_type>::derive_public_key_string(&dummy_private_key).is_err());
			};
		}

		// Macro to test all identifier types
		macro_rules! test_all_identifier_types {
			($(($key_type:ty, $test_id:expr, $key_pair_type:expr)),* $(,)?) => {
				$(
					test_identifier_key!($key_type, $test_id, $key_pair_type);
				)*
			};
		}

		test_all_identifier_types!(
			(KeyNETWORK, "test-network-id", KeyPairType::NETWORK),
			(KeyTOKEN, "test-token-id", KeyPairType::TOKEN),
			(KeySTORAGE, "test-storage-id", KeyPairType::STORAGE),
			(KeyMULTISIG, "test-multisig-id", KeyPairType::MULTISIG),
		);

		let passphrase = vec!["test".into()];
		let keyable: Keyable = passphrase.into();

		// Test that identifier keys fail with non-identifier input
		let result = KeyNETWORK::try_from(keyable);
		assert!(result.is_err());
	}

	#[test]
	fn test_compatibility_private_accounts() {
		for (index, test_case) in PRIVATE_ACCOUNT_TEST_DATA.indexes.iter().enumerate() {
			let seed_bytes = hex::decode(PRIVATE_ACCOUNT_TEST_DATA.seed).unwrap();
			let seed_data: [u8; 32] = seed_bytes.try_into().unwrap();

			// Macro to test account derivation for any crypto key type
			macro_rules! test_crypto_derivation {
				($key_type:ty, $expected_field:ident) => {
					let account = create_test_account::<$key_type>(Some((seed_data, index as u32).into()));
					assert_eq!(account.keypair.to_public_key_string(), test_case.$expected_field);
				};
			}

			test_crypto_derivation!(KeyECDSASECP256K1, encoded_public_key_ecdsa_secp256k1);
			test_crypto_derivation!(KeyECDSASECP256R1, encoded_public_key_ecdsa_secp256r1);
			test_crypto_derivation!(KeyED25519, encoded_public_key_ed25519);
		}
	}

	#[test]
	fn test_key_type_identification() {
		for test_data in KEY_TYPE_TEST_DATA {
			assert_eq!(test_data.key_type.is_identifier(), test_data.is_identifier);
			assert_eq!(test_data.key_type.supports_crypto(), test_data.supports_crypto);
		}
	}

	#[test]
	fn test_key_type_algorithm_conversions() {
		// Macro to test bidirectional conversions between Algorithm and KeyPairType
		macro_rules! test_bidirectional_conversions {
			($(($algorithm:expr, $keypair_type:expr)),* $(,)?) => {
				$(
					// Test From<Algorithm> for KeyPairType
					assert_eq!(KeyPairType::from($algorithm), $keypair_type);
					// Test TryFrom<KeyPairType> for Algorithm
					assert_eq!(Algorithm::try_from($keypair_type).unwrap(), $algorithm);
				)*
			};
		}

		// Test all crypto algorithm conversions
		test_bidirectional_conversions!(
			(Algorithm::Secp256k1, KeyPairType::ECDSASECP256K1),
			(Algorithm::Ed25519, KeyPairType::ED25519),
			(Algorithm::Secp256r1, KeyPairType::ECDSASECP256R1),
		);

		// Test error cases for identifier types (cannot convert to Algorithm)
		for keypair_type in IDENTIFIER_ACCOUNT_TYPES {
			assert!(Algorithm::try_from(keypair_type.to_owned()).is_err());
		}
	}

	#[test]
	fn test_public_key_string_creation() {
		for test_case in TEST_CASES {
			// Macro to test public key string creation for any crypto key type
			macro_rules! test_pubkey_string_creation {
				($key_type:ty, $keypair_type:expr) => {{
					// Test creating account from formatted public key string
					let account = create_test_account::<$key_type>(Some(test_case.hex_seed.into()));
					let account_from_pubkey =
						create_test_account_from_pub_key_string::<$key_type>(&account.keypair.to_public_key_string());

					// Verify public keys match
					assert_eq!(account.keypair.public_key, account_from_pubkey.keypair.public_key);
					// Verify original account has private key, new one does not
					assert!(account.keypair.private_key.is_some());
					assert!(account_from_pubkey.keypair.private_key.is_none());
					// Cryptographic operations should be supported
					assert!($keypair_type.supports_crypto());

					// Test Debug formatting
					let debug_str = format!("{:?}", account.keypair);
					assert!(!debug_str.is_empty());
				}};
			}

			test_pubkey_string_creation!(KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1);
			test_pubkey_string_creation!(KeyED25519, KeyPairType::ED25519);
			test_pubkey_string_creation!(KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1);
		}
	}

	#[test]
	fn test_invalid_public_key_string_creation() {
		let invalid_keys = vec![
			// Invalid prefix
			"wrong_prefix",
			"bitcoin_address",
			"ethereum_0x123",
			"random_string",
			"",       // Empty string
			"keeta",  // Missing underscore
			"keeta_", // Missing rest
			// Invalid base32
			"keeta_invalid@base32!",
			// Too short
			"keeta_aa",
			// Invalid algorithm type
			// cspell:disable-next-line
			"keeta_akaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafaesuq53",
		];

		// Macro to test invalid public key strings for any crypto key type
		macro_rules! test_invalid_pubkey {
			($key_type:ty, $keypair_type:expr) => {
				for invalid_key in &invalid_keys {
					let result = Account::<$key_type>::try_from(Accountable::KeyAndType(
						Keyable::PublicKeyString(invalid_key.to_string()),
						$keypair_type,
					));
					assert!(result.is_err());

					// Specifically test for InvalidPrefix when appropriate
					if !invalid_key.starts_with("keeta_") {
						assert!(matches!(result, Err(AccountError::InvalidPrefix)));
					}
				}
			};
		}

		// Test invalid keys with all crypto algorithms
		test_invalid_pubkey!(KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1);
		test_invalid_pubkey!(KeyED25519, KeyPairType::ED25519);
		test_invalid_pubkey!(KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1);
	}

	#[test]
	fn test_wrong_algorithm_detection() {
		for test_case in TEST_CASES {
			// Create accounts for all crypto algorithms
			let secp256k1_account = create_test_account::<KeyECDSASECP256K1>(Some(test_case.hex_seed.into()));
			let ed25519_account = create_test_account::<KeyED25519>(Some(test_case.hex_seed.into()));
			let secp256r1_account = create_test_account::<KeyECDSASECP256R1>(Some(test_case.hex_seed.into()));

			// Macro to test wrong algorithm detection
			macro_rules! test_wrong_algorithm {
				($target_key_type:ty, $target_keypair_type:expr, $wrong_pubkey:expr) => {
					let result = Account::<$target_key_type>::try_from(Accountable::KeyAndType(
						Keyable::PublicKeyString($wrong_pubkey.clone()),
						$target_keypair_type,
					));
					assert!(result.is_err(),);
				};
			}

			// Test all wrong algorithm combinations
			test_wrong_algorithm!(
				KeyECDSASECP256K1,
				KeyPairType::ECDSASECP256K1,
				ed25519_account.keypair.to_public_key_string()
			);
			test_wrong_algorithm!(
				KeyECDSASECP256K1,
				KeyPairType::ECDSASECP256K1,
				secp256r1_account.keypair.to_public_key_string()
			);
			test_wrong_algorithm!(KeyED25519, KeyPairType::ED25519, secp256k1_account.keypair.to_public_key_string());
			test_wrong_algorithm!(KeyED25519, KeyPairType::ED25519, secp256r1_account.keypair.to_public_key_string());
			test_wrong_algorithm!(
				KeyECDSASECP256R1,
				KeyPairType::ECDSASECP256R1,
				secp256k1_account.keypair.to_public_key_string()
			);
			test_wrong_algorithm!(
				KeyECDSASECP256R1,
				KeyPairType::ECDSASECP256R1,
				ed25519_account.keypair.to_public_key_string()
			);
		}
	}

	#[test]
	fn test_identifier_generation_methods() {
		// Use a proper 24-word mnemonic passphrase
		let passphrase = create_test_passphrase();

		// Macro to test identifier generation for any crypto key type
		macro_rules! test_crypto_identifier_generation {
			($key_type:ty) => {{
				let crypto_account = create_test_account::<$key_type>(Some(passphrase.clone().into()));

				// Test crypto account to token generation (should succeed)
				let token_result = crypto_account.generate_identifier(KeyPairType::TOKEN, None, 0);
				let result = token_result.unwrap();
				let token_account = Account::<KeyTOKEN>::try_from(result).unwrap();
				assert_eq!(token_account.to_keypair_type(), KeyPairType::TOKEN);

				// Parse the public key string to verify it contains valid identifier data
				let public_key_string = token_account.keypair.to_public_key_string();
				let (parsed_bytes, _) = parse_public_key(&public_key_string).unwrap();
				assert!(!parsed_bytes.is_empty());
				assert!(public_key_string.starts_with("keeta_"));

				// The parsed bytes should match the raw identifier bytes
				let token_bytes: Vec<u8> = token_account.keypair.to_public_key().into();
				assert_eq!(token_bytes, parsed_bytes);

				crypto_account
			}};
		}

		// Test identifier generation with each crypto algorithm
		let secp256k1_account = test_crypto_identifier_generation!(KeyECDSASECP256K1);
		let ed25519_account = test_crypto_identifier_generation!(KeyED25519);
		let secp256r1_account = test_crypto_identifier_generation!(KeyECDSASECP256R1);

		// Create token account for testing invalid transitions
		let token_account = create_test_account_from_identifier::<KeyTOKEN>("test");

		// Macro to test invalid identifier construction cases
		macro_rules! test_invalid_identifier_construction {
			($account:expr, $keypair_type:expr) => {
				let result = $account.generate_identifier($keypair_type, None, 0);
				assert!(matches!(result, Err(AccountError::InvalidIdentifierConstruction)));
			};
		}

		// Test secp256k1
		test_invalid_identifier_construction!(secp256k1_account, KeyPairType::ECDSASECP256K1);
		test_invalid_identifier_construction!(secp256k1_account, KeyPairType::ED25519);
		test_invalid_identifier_construction!(secp256k1_account, KeyPairType::ECDSASECP256R1);
		// Test ed25519
		test_invalid_identifier_construction!(ed25519_account, KeyPairType::ECDSASECP256K1);
		test_invalid_identifier_construction!(ed25519_account, KeyPairType::ED25519);
		test_invalid_identifier_construction!(ed25519_account, KeyPairType::ECDSASECP256R1);
		// Test secp256r1
		test_invalid_identifier_construction!(secp256r1_account, KeyPairType::ECDSASECP256K1);
		test_invalid_identifier_construction!(secp256r1_account, KeyPairType::ED25519);
		test_invalid_identifier_construction!(secp256r1_account, KeyPairType::ECDSASECP256R1);
		// Test token account
		test_invalid_identifier_construction!(token_account, KeyPairType::STORAGE);

		// Macro to test invalid construction cases
		macro_rules! test_invalid_construction {
			($account:expr, $keypair_type:expr, $invalid_input:expr) => {
				let result = $account.generate_identifier($keypair_type, $invalid_input, 0);
				assert!(matches!(result, Err(AccountError::InvalidConstruction)));
			};
		}

		// Test cases that should fail with InvalidConstruction for all crypto types
		test_invalid_construction!(secp256k1_account, KeyPairType::TOKEN, Some("not_hex"));
		test_invalid_construction!(secp256k1_account, KeyPairType::TOKEN, Some(""));
		test_invalid_construction!(ed25519_account, KeyPairType::TOKEN, Some("not_hex"));
		test_invalid_construction!(ed25519_account, KeyPairType::TOKEN, Some(""));
		test_invalid_construction!(secp256r1_account, KeyPairType::TOKEN, Some("not_hex"));
		test_invalid_construction!(secp256r1_account, KeyPairType::TOKEN, Some(""));

		// Test network account generation - special case
		let network_account = create_test_network_account(12345);
		assert_eq!(network_account.to_keypair_type(), KeyPairType::NETWORK);

		// Parse the public key string to verify it contains valid identifier data
		let public_key_string = network_account.keypair.to_public_key_string();
		let (parsed_bytes, _) = parse_public_key(&public_key_string).unwrap();
		assert!(!parsed_bytes.is_empty());
		assert!(public_key_string.starts_with("keeta_"));

		// The parsed bytes should match the raw identifier bytes
		let public_key_bytes: Vec<u8> = network_account.keypair.to_public_key().into();
		assert_eq!(public_key_bytes, parsed_bytes);

		// Test network -> token generation (should succeed)
		let token_from_network = network_account.generate_identifier(KeyPairType::TOKEN, None, 0);
		assert!(token_from_network.is_ok());
	}

	#[test]
	fn test_type_guard_methods() {
		// Helper macro to test account type guard methods using centralized data
		macro_rules! test_account_guards {
			($account:expr, $test_data:expr) => {
				assert_eq!($account.is_identifier(), $test_data.is_identifier);
				assert_eq!($account.is_network(), $test_data.is_network);
				assert_eq!($account.is_token(), $test_data.is_token);
				assert_eq!($account.is_storage(), $test_data.is_storage);
				assert_eq!($account.is_multisig(), $test_data.is_multisig);
			};
		}

		// Macro to test cryptographic account type guards
		macro_rules! test_crypto_account {
			($key_type:ty, $test_data:expr, $seed:expr, $algorithm:expr) => {
				let account = create_test_account::<$key_type>(Some($seed.into()));
				test_account_guards!(account, $test_data);
				assert!(account.has_private_key());
				assert_eq!(account.keypair.to_algorithm(), $algorithm);
			};
		}

		// Macro to test identifier account type guards
		macro_rules! test_identifier_account {
			($key_type:ty, $test_data:expr, $identifier:expr) => {
				let account = create_test_account::<$key_type>(Some(Keyable::Identifier($identifier.to_string())));
				test_account_guards!(account, $test_data);
				assert!(!account.has_private_key());
			};
		}

		// Test cryptographic accounts using the first test case
		let test_case = &TEST_CASES[0];
		for test_data in KEY_TYPE_TEST_DATA.iter() {
			match test_data.key_type {
				// Cryptographic accounts (have private keys when created from seed)
				KeyPairType::ECDSASECP256K1 => {
					test_crypto_account!(KeyECDSASECP256K1, test_data, test_case.hex_seed, Algorithm::Secp256k1);
				}
				KeyPairType::ED25519 => {
					test_crypto_account!(KeyED25519, test_data, test_case.hex_seed, Algorithm::Ed25519);
				}
				KeyPairType::ECDSASECP256R1 => {
					test_crypto_account!(KeyECDSASECP256R1, test_data, test_case.hex_seed, Algorithm::Secp256r1);
				}
				// Identifier accounts (do not have private keys)
				KeyPairType::TOKEN => {
					test_identifier_account!(KeyTOKEN, test_data, "test-token");
				}
				KeyPairType::STORAGE => {
					test_identifier_account!(KeySTORAGE, test_data, "test-storage");
				}
				KeyPairType::MULTISIG => {
					test_identifier_account!(KeyMULTISIG, test_data, "test-multisig");
				}
				// Network account (special case, does not have private key)
				KeyPairType::NETWORK => {
					let network_account = create_test_network_account(12345);
					test_account_guards!(network_account, test_data);
					assert!(!network_account.has_private_key());
				}
			}
		}
	}

	#[test]
	fn test_public_key_string_accessor() {
		for test_case in TEST_CASES {
			// Macro to test public key string accessor for any crypto key type
			macro_rules! test_pubkey_accessor {
				($key_type:ty, $expected_field:ident) => {
					let account = create_test_account::<$key_type>(Some(test_case.hex_seed.into()));
					// Test that to_string() returns the properly formatted public key
					assert_eq!(account.to_string(), test_case.$expected_field);
					// Test that the public key string starts with the expected prefix
					assert!(account.to_string().starts_with("keeta_"));
				};
			}

			test_pubkey_accessor!(KeyECDSASECP256K1, expected_secp256k1_pubkey);
			test_pubkey_accessor!(KeyED25519, expected_ed25519_pubkey);
			test_pubkey_accessor!(KeyECDSASECP256R1, expected_secp256r1_pubkey);
		}

		// Test identifier public key strings
		let network_account = create_test_network_account(12345);
		assert!(network_account.to_string().starts_with("keeta_"));

		// Test token from conversion
		let token_account = create_test_account_from_identifier::<KeyTOKEN>("test-token");
		assert!(token_account.to_string().starts_with("keeta_"));
	}

	#[test]
	fn test_public_key_comparison() {
		for test_case in TEST_CASES {
			let secp256k1_account = create_test_account::<KeyECDSASECP256K1>(Some(test_case.hex_seed.into()));
			let ed25519_account = create_test_account::<KeyED25519>(Some(test_case.hex_seed.into()));
			let secp256r1_account = create_test_account::<KeyECDSASECP256R1>(Some(test_case.hex_seed.into()));

			// Test comparing with exact public key string
			assert!(secp256k1_account.compare_public_key(test_case.expected_secp256k1_pubkey));
			assert!(ed25519_account.compare_public_key(test_case.expected_ed25519_pubkey));
			assert!(secp256r1_account.compare_public_key(test_case.expected_secp256r1_pubkey));

			// Test comparing with different public key strings
			assert!(!secp256k1_account.compare_public_key(test_case.expected_ed25519_pubkey));
			assert!(!secp256k1_account.compare_public_key(test_case.expected_secp256r1_pubkey));
			assert!(!ed25519_account.compare_public_key(test_case.expected_secp256k1_pubkey));
			assert!(!ed25519_account.compare_public_key(test_case.expected_secp256r1_pubkey));
			assert!(!secp256r1_account.compare_public_key(test_case.expected_secp256k1_pubkey));
			assert!(!secp256r1_account.compare_public_key(test_case.expected_ed25519_pubkey));

			// Test comparing with invalid strings
			assert!(!secp256k1_account.compare_public_key("invalid_key"));
			assert!(!ed25519_account.compare_public_key(""));
			assert!(!secp256r1_account.compare_public_key("invalid_key"));

			// Test account-to-account comparison
			let secp256k1_account2 = create_test_account::<KeyECDSASECP256K1>(Some(test_case.hex_seed.into()));
			let secp256r1_account2 = create_test_account::<KeyECDSASECP256R1>(Some(test_case.hex_seed.into()));
			assert!(secp256k1_account.compare_account(&secp256k1_account2));
			assert!(secp256r1_account.compare_account(&secp256r1_account2));
			assert!(!secp256k1_account.compare_account(&ed25519_account));
			assert!(!secp256k1_account.compare_account(&secp256r1_account));
			assert!(!secp256r1_account.compare_account(&ed25519_account));
		}
	}

	#[test]
	fn test_account_from_to_string() {
		for test_case in TEST_CASES {
			// Macro to test account parsing from public key
			macro_rules! test_account_parsing {
				($account_type:ty, $key_type:expr, $pubkey:expr) => {{
					let result = $pubkey.parse::<$account_type>();
					assert!(result.is_ok());

					let account = result.unwrap();
					assert_eq!(account.to_keypair_type(), $key_type);
					assert_eq!(account.to_string(), $pubkey);
					assert!(!account.has_private_key());
				}};
			}

			// Test successful parsing for each algorithm
			test_account_parsing!(
				Account<KeyECDSASECP256K1>,
				KeyPairType::ECDSASECP256K1,
				test_case.expected_secp256k1_pubkey
			);
			test_account_parsing!(Account<KeyED25519>, KeyPairType::ED25519, test_case.expected_ed25519_pubkey);
			test_account_parsing!(
				Account<KeyECDSASECP256R1>,
				KeyPairType::ECDSASECP256R1,
				test_case.expected_secp256r1_pubkey
			);

			// Test cross-algorithm parsing errors (should all fail)
			assert!(test_case
				.expected_ed25519_pubkey
				.parse::<Account<KeyECDSASECP256K1>>()
				.is_err());
			assert!(test_case
				.expected_secp256r1_pubkey
				.parse::<Account<KeyECDSASECP256K1>>()
				.is_err());
			assert!(test_case
				.expected_secp256k1_pubkey
				.parse::<Account<KeyED25519>>()
				.is_err());
			assert!(test_case
				.expected_secp256r1_pubkey
				.parse::<Account<KeyED25519>>()
				.is_err());
			assert!(test_case
				.expected_secp256k1_pubkey
				.parse::<Account<KeyECDSASECP256R1>>()
				.is_err());
			assert!(test_case
				.expected_ed25519_pubkey
				.parse::<Account<KeyECDSASECP256R1>>()
				.is_err());
		}
	}

	#[test]
	fn test_private_key_presence() {
		// Test accounts created from seeds have private keys
		for test_case in TEST_CASES {
			let secp256k1_account = create_test_account::<KeyECDSASECP256K1>(Some(test_case.hex_seed.into()));
			assert!(secp256k1_account.has_private_key());
		}

		// Test accounts created from public key strings do not have private keys
		for test_case in TEST_CASES {
			let secp256k1_account = test_case
				.expected_secp256k1_pubkey
				.parse::<Account<KeyECDSASECP256K1>>()
				.unwrap();
			assert!(!secp256k1_account.has_private_key());
		}

		// Test identifier accounts never have private keys regardless of creation method
		let network_account = create_test_network_account(12345);
		assert!(!network_account.has_private_key());

		let token_account = create_test_account_from_identifier::<KeyTOKEN>("test");
		assert!(!token_account.has_private_key());

		// Macro to test parsing for any crypto key type
		macro_rules! test_parse_pubkey {
			($pubkey_string:expr, $key_type:ty) => {
				let account = $pubkey_string.parse::<Account<$key_type>>().unwrap();
				assert!(!account.has_private_key());
			};
		}

		// cspell:disable-next-line
		test_parse_pubkey!("keeta_aaba6iiv7igjuediblxmwzflfycwjlwrv6bbu4v7tb5kx6d2dllieunedvq3cza", KeyECDSASECP256K1);
		// cspell:disable-next-line
		test_parse_pubkey!("keeta_aha53j3jrvmeg3nlbvw6tjec6hbrgbeyazdzh4pcnkgqt6elkvmfbuue55hz4", KeyED25519);
		// cspell:disable-next-line
		test_parse_pubkey!("keeta_aybkgq6rnzcvpmpy32b4hgpysjxuft4qll6ttqkaxu7f5ocisqobesxrfuhyofi", KeyECDSASECP256R1);

		// Test identifier accounts created from seeds also do not have private keys
		let network_from_seed = create_test_account::<KeyNETWORK>(None);
		assert!(!network_from_seed.has_private_key());
	}

	#[test]
	fn test_seed_generation_methods() {
		// Macro to test seed generation for any crypto key type
		macro_rules! test_seed_generation {
			($key_type:ty, $keypair_type:expr) => {
				// Seeds should be 32 bytes
				let seed = Account::<$key_type>::generate_random_seed().unwrap();
				assert_eq!(seed.expose_secret().len(), 32);

				// Random seeds should be different
				let random_seed1 = Account::<$key_type>::generate_random_seed().unwrap();
				let random_seed2 = Account::<$key_type>::generate_random_seed().unwrap();
				assert_ne!(random_seed1.expose_secret(), random_seed2.expose_secret());
				assert_eq!(random_seed1.expose_secret().len(), 32);
				assert_eq!(random_seed2.expose_secret().len(), 32);

				// Test that accounts can be created from generated seeds
				let account = create_test_account::<$key_type>(Some(Keyable::Seed((seed, 0))));
				assert!(account.has_private_key());
				assert_eq!(account.to_keypair_type(), $keypair_type);
			};
		}

		// Test seed generation for all crypto algorithms
		test_seed_generation!(KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1);
		test_seed_generation!(KeyED25519, KeyPairType::ED25519);
		test_seed_generation!(KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1);
	}

	#[test]
	fn test_keypair_type_trait() {
		// Macro to test keypair type consistency for both Account<T> and T
		macro_rules! test_keypair_type {
			($key_type:ty, $expected:expr) => {
				assert_eq!(
					<Account<$key_type> as HasKeypairType>::KEYPAIR_TYPE,
					$expected,
					"Account<{}>::KEYPAIR_TYPE mismatch",
					stringify!($key_type)
				);
				assert_eq!(
					<$key_type as HasKeypairType>::KEYPAIR_TYPE,
					$expected,
					"{}::KEYPAIR_TYPE mismatch",
					stringify!($key_type)
				);
			};
		}

		for test_data in KEY_TYPE_TEST_DATA {
			match test_data.key_type {
				KeyPairType::ECDSASECP256K1 => {
					test_keypair_type!(KeyECDSASECP256K1, test_data.key_type);
				}
				KeyPairType::ED25519 => {
					test_keypair_type!(KeyED25519, test_data.key_type);
				}
				KeyPairType::ECDSASECP256R1 => {
					test_keypair_type!(KeyECDSASECP256R1, test_data.key_type);
				}
				KeyPairType::NETWORK => {
					test_keypair_type!(KeyNETWORK, test_data.key_type);
				}
				KeyPairType::TOKEN => {
					test_keypair_type!(KeyTOKEN, test_data.key_type);
				}
				KeyPairType::STORAGE => {
					test_keypair_type!(KeySTORAGE, test_data.key_type);
				}
				KeyPairType::MULTISIG => {
					test_keypair_type!(KeyMULTISIG, test_data.key_type);
				}
			}
		}
	}

	#[test]
	fn test_identifier_public_key_string_methods() {
		// Macro to test identifier account public key string methods
		macro_rules! test_identifier_pubkey {
			($key_type:ty, $identifier:expr) => {
				let key = <$key_type>::try_from(Keyable::Identifier($identifier.to_string())).unwrap();
				let account = Account::<$key_type>::try_from(Accountable::Key(key)).unwrap();

				let pubkey = account.to_string();
				let pubkey_to_string = account.keypair.to_public_key_string();
				assert!(pubkey.starts_with("keeta_"));
				assert_eq!(pubkey_to_string, pubkey);
			};
		}

		// Macro to test crypto account identifier errors
		macro_rules! test_crypto_identifier_error {
			($key_type:ty) => {
				let result = <$key_type>::try_from(Keyable::Identifier("should-fail".to_string()));
				assert!(result.is_err());
			};
		}

		for test_data in KEY_TYPE_TEST_DATA.iter() {
			match test_data.key_type {
				KeyPairType::TOKEN => {
					test_identifier_pubkey!(KeyTOKEN, "test-token");
				}
				KeyPairType::STORAGE => {
					test_identifier_pubkey!(KeySTORAGE, "test-storage");
				}
				KeyPairType::MULTISIG => {
					test_identifier_pubkey!(KeyMULTISIG, "test-multisig");
				}
				KeyPairType::ECDSASECP256K1 => {
					test_crypto_identifier_error!(KeyECDSASECP256K1);
				}
				KeyPairType::ECDSASECP256R1 => {
					test_crypto_identifier_error!(KeyECDSASECP256R1);
				}
				KeyPairType::ED25519 => {
					test_crypto_identifier_error!(KeyED25519);
				}
				// Special case
				KeyPairType::NETWORK => {
					let network_account = create_test_network_account(12345);
					let network_pubkey = network_account.to_string();
					let network_pubkey_to_string = network_account.keypair.to_public_key_string();
					assert!(network_pubkey.starts_with("keeta_"));
					assert_eq!(network_pubkey, network_pubkey_to_string);
				}
			}
		}
	}

	#[test]
	fn test_debug_trait_implementation() {
		// Macro to test crypto account types
		macro_rules! test_crypto_debug {
			($key_type:ty, $type_name:literal, $keyable:expr) => {
				let account = create_test_account::<$key_type>(Some($keyable));
				let debug_output = format!("{account:?}");
				assert!(debug_output.contains($type_name));
				assert!(debug_output.contains("public_key"));
				assert!(!debug_output.contains("private_key"));
			};
		}

		// Macro to test identifier account types
		macro_rules! test_identifier_debug {
			($key_type:ty, $type_name:literal, $identifier:literal) => {
				let account = create_test_account::<$key_type>(Some(Keyable::Identifier($identifier.to_string())));
				let debug_string = format!("{account:?}");
				assert!(debug_string.contains($type_name));
				assert!(debug_string.contains("public_key"));
				// The identifier is now properly formatted as a keeta_ string, not the raw identifier
				assert!(debug_string.contains("keeta_"));
			};
		}

		// Test Debug trait for all account types
		for test_case in TEST_CASES {
			for test_data in KEY_TYPE_TEST_DATA.iter() {
				// Macro to handle all crypto types uniformly
				macro_rules! test_crypto_types {
					($($key_type:ty, $type_name:literal),*) => {
						$(
							if test_data.key_type == <$key_type>::keypair_type() && test_data.supports_crypto {
								test_crypto_debug!($key_type, $type_name, test_case.hex_seed.into());
							}
						)*
					};
				}

				// Macro to handle all identifier types uniformly
				macro_rules! test_identifier_types {
					($($key_type:ty, $type_name:literal, $identifier:literal),*) => {
						$(
							if test_data.key_type == <$key_type>::keypair_type() && test_data.is_identifier {
								test_identifier_debug!($key_type, $type_name, $identifier);
							}
						)*
					};
				}

				// Test all crypto types
				test_crypto_types!(
					KeyECDSASECP256K1,
					"ECDSASECP256K1",
					KeyECDSASECP256R1,
					"ECDSASECP256R1",
					KeyED25519,
					"ED25519"
				);

				// Test identifier types
				test_identifier_types!(
					KeyTOKEN,
					"TOKEN",
					"test-token",
					KeySTORAGE,
					"STORAGE",
					"test-storage",
					KeyMULTISIG,
					"MULTISIG",
					"test-multisig"
				);

				// Special case for NETWORK
				if test_data.key_type == KeyPairType::NETWORK && test_data.is_identifier {
					let account = create_test_network_account(12345);
					let debug_string = format!("{account:?}");
					assert!(debug_string.contains("NETWORK"));
					assert!(debug_string.contains("public_key"));
					assert!(debug_string.contains("keeta_"));
				}
			}
		}
	}

	#[test]
	fn test_clone_trait_implementation() {
		// Macro to test cloning for any account type with appropriate security checks
		macro_rules! test_clone {
			($key_type:ty, $keyable:expr) => {
				let original_account = create_test_account::<$key_type>(Some($keyable));

				// Basic equality checks
				let cloned_account = original_account.clone();
				assert_eq!(original_account.to_string(), cloned_account.to_string());
				assert_eq!(original_account.to_keypair_type(), cloned_account.to_keypair_type());
				assert_eq!(original_account.is_identifier(), cloned_account.is_identifier());
				// For crypto accounts, cloned should not have private key
				// For identifier accounts they never have a private key
				assert!(!cloned_account.has_private_key());
			};
		}

		for test_case in TEST_CASES {
			// Test cloning crypto accounts
			test_clone!(KeyECDSASECP256K1, test_case.hex_seed.into());
			test_clone!(KeyED25519, test_case.hex_seed.into());
			test_clone!(KeyECDSASECP256R1, test_case.hex_seed.into());

			// Test cloning identifier accounts
			test_clone!(KeyTOKEN, Keyable::Identifier("test-token".to_string()));
			test_clone!(KeySTORAGE, Keyable::Identifier("test-storage".to_string()));
			test_clone!(KeyMULTISIG, Keyable::Identifier("test-multisig".to_string()));
		}

		// Test cloning network account
		let network_account = create_test_network_account(12345);
		let cloned_network = network_account.clone();
		assert_eq!(network_account.to_string(), cloned_network.to_string());
		assert_eq!(network_account.is_identifier(), cloned_network.is_identifier());
		assert_eq!(network_account.has_private_key(), cloned_network.has_private_key());
	}

	#[test]
	fn test_generic_account_conversions_and_cloning() {
		// Macro to test both TryFrom conversions and cloning for each account type
		macro_rules! test_generic_account_roundtrip {
			($key_type:ty, $variant:ident, $keyable:expr) => {{
				// Create account using the helper function
				let original_account = create_test_account::<$key_type>($keyable);
				// Create GenericAccount variant
				let generic_account = GenericAccount::$variant(original_account.clone());

				// Test successful conversion back to specific type
				let converted_account: Account<$key_type> = generic_account.clone().try_into().unwrap();
				assert_eq!(
					converted_account.keypair.to_public_key_string(),
					original_account.keypair.to_public_key_string()
				);

				// Test cloning behavior
				let cloned = generic_account.clone();
				if let (GenericAccount::$variant(cloned_acc), GenericAccount::$variant(orig_acc)) =
					(&cloned, &generic_account)
				{
					assert_eq!(cloned_acc.to_string(), orig_acc.to_string());
					assert_eq!(cloned_acc.to_keypair_type(), orig_acc.to_keypair_type());
					assert_eq!(cloned_acc.is_identifier(), orig_acc.is_identifier());
					assert_eq!(cloned_acc.has_private_key(), orig_acc.has_private_key());
				}

				// Return the accounts for error testing
				(original_account, generic_account)
			}};
		}

		// Test all account types using a macro to reduce repetition
		macro_rules! test_all_variants {
			($(($key_type:ty, $variant:ident, $keyable:expr)),+ $(,)?) => {
				// Test each variant
				$(
					test_generic_account_roundtrip!($key_type, $variant, $keyable);
				)+

				// Get specific variants for error testing
				let (_, generic_secp256k1) = test_generic_account_roundtrip!(KeyECDSASECP256K1, EcdsaSecp256k1, None);
				let (_, generic_network) = test_generic_account_roundtrip!(KeyNETWORK, Network, Some(Keyable::Identifier("test-network".to_string())));

				// Test error cases - wrong variant conversions
				let secp256k1_result: Result<Account<KeyECDSASECP256K1>, _> = generic_network.try_into();
				assert!(secp256k1_result.is_err());
				assert!(matches!(secp256k1_result.unwrap_err(), AccountError::InvalidConstruction));

				let network_result: Result<Account<KeyNETWORK>, _> = generic_secp256k1.try_into();
				assert!(network_result.is_err());
				assert!(matches!(network_result.unwrap_err(), AccountError::InvalidConstruction));
			};
		}

		test_all_variants!(
			(KeyECDSASECP256K1, EcdsaSecp256k1, None),
			(KeyED25519, Ed25519, None),
			(KeyECDSASECP256R1, EcdsaSecp256r1, None),
			(KeyNETWORK, Network, Some(Keyable::Identifier("test-network".to_string()))),
			(KeyTOKEN, Token, Some(Keyable::Identifier("test-token".to_string()))),
			(KeySTORAGE, Storage, Some(Keyable::Identifier("test-storage".to_string()))),
			(KeyMULTISIG, Multisig, Some(Keyable::Identifier("test-multisig".to_string()))),
		);

		// Test with TEST_PUBLIC_ACCOUNTS data as well
		for test_case in TEST_PUBLIC_ACCOUNTS {
			let original_account: GenericAccount = test_case.encoded_public_key.parse().unwrap();
			// Use individual match statements for each variant to avoid catch-all
			let cloned = original_account.clone();

			// Macro to test cloning for a specific variant
			macro_rules! test_specific_variant {
				($variant:ident) => {
					if let (GenericAccount::$variant(cloned_acc), GenericAccount::$variant(orig_acc)) =
						(&cloned, &original_account)
					{
						assert_eq!(cloned_acc.to_string(), orig_acc.to_string());
						assert_eq!(cloned_acc.to_keypair_type(), orig_acc.to_keypair_type());
						assert_eq!(cloned_acc.is_identifier(), orig_acc.is_identifier());
						assert_eq!(cloned_acc.has_private_key(), orig_acc.has_private_key());
						return; // Exit early since we found the matching variant
					}
				};
			}

			// Test each variant
			test_specific_variant!(EcdsaSecp256k1);
			test_specific_variant!(EcdsaSecp256r1);
			test_specific_variant!(Ed25519);
			test_specific_variant!(Network);
			test_specific_variant!(Token);
			test_specific_variant!(Storage);
			test_specific_variant!(Multisig);
		}
	}

	#[test]
	fn test_try_from_trait_implementations() {
		let passphrase = create_test_passphrase();
		let seed_bytes = hex::decode(TEST_PRIVATE_ACCOUNT.seed).unwrap();
		let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();

		// Test error cases for crypto keys with invalid passphrases
		let invalid_passphrase = vec!["too".to_string(), "short".to_string()];
		let passphrase_secret = invalid_passphrase.into_secret();
		let invalid_result = KeyECDSASECP256K1::try_from(Keyable::Passphrase((passphrase_secret, 0)));
		assert!(invalid_result.is_err());

		// Macro to test TryFrom for crypto key types
		macro_rules! test_crypto_key_type {
			($key_type:ty, $expected_type:expr) => {
				// Find the test data for this key type
				let public_test_data = TEST_PUBLIC_ACCOUNTS
					.iter()
					.find(|data| data.key_type == $expected_type)
					.expect(&format!("Should have test data for {:?}", $expected_type));
				let valid_pubkey = hex::decode(public_test_data.public_key).expect("Valid hex");

				// Test passphrase variant
				let passphrase_secret = passphrase.clone().into_secret();
				let key_from_passphrase = <$key_type>::try_from(Keyable::Passphrase((passphrase_secret, 0)));
				assert!(key_from_passphrase.is_ok());

				// Test private key variant using existing test data
				let key_from_priv = <$key_type>::try_from(Keyable::PrivateKey(seed_array.to_vec()));
				assert!(key_from_priv.is_ok());

				// Test public key variant with key-specific data
				let key_from_pub = <$key_type>::try_from(Keyable::PublicKey(valid_pubkey));
				assert!(key_from_pub.is_ok());

				// Test error cases - invalid key lengths
				let invalid_key = vec![0x12, 0x34]; // Too short
				assert!(<$key_type>::try_from(Keyable::PublicKey(invalid_key.clone())).is_err());
				assert!(<$key_type>::try_from(Keyable::PrivateKey(invalid_key)).is_err());

				// Test Account creation from successful key
				let account = Account::<$key_type>::try_from(Accountable::Key(key_from_priv.unwrap())).unwrap();
				assert_eq!(account.to_keypair_type(), $expected_type);
			};
		}

		// Macro to test TryFrom for identifier key types
		macro_rules! test_identifier_key_type {
			($key_type:ty, $identifier:expr, $expected_type:expr) => {
				let key = <$key_type>::try_from(Keyable::Identifier($identifier.to_string()));
				assert!(key.is_ok());

				// Test that passphrase doesn't work for identifier types
				let passphrase_secret = vec!["test".to_string()].into_secret();
				let invalid_result = <$key_type>::try_from(Keyable::Passphrase((passphrase_secret, 0)));
				assert!(invalid_result.is_err());

				// Test Account creation
				let account = Account::<$key_type>::try_from(Accountable::Key(key.unwrap())).unwrap();
				assert_eq!(account.to_keypair_type(), $expected_type);
			};
		}

		// Macro to test TryFrom for AnyPrivateKey to GenericAccount conversions
		macro_rules! test_private_key_to_generic_account {
			($private_key_type:ty, $any_variant:ident, $expected_type:expr) => {
				let test_private_key_bytes = [0x42u8; 32];
				let private_key = <$private_key_type>::try_from(test_private_key_bytes.as_slice()).unwrap();
				let any_private_key = AnyPrivateKey::$any_variant(private_key);

				let generic_account = GenericAccount::try_from(any_private_key).unwrap();
				assert_eq!(generic_account.to_keypair_type(), $expected_type);
			};
		}

		// Test all crypto key types
		test_crypto_key_type!(KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1);
		test_crypto_key_type!(KeyED25519, KeyPairType::ED25519);
		test_crypto_key_type!(KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1);

		// Test all identifier key types
		test_identifier_key_type!(KeyNETWORK, "test-network", KeyPairType::NETWORK);
		test_identifier_key_type!(KeyTOKEN, "test-token", KeyPairType::TOKEN);
		test_identifier_key_type!(KeySTORAGE, "test-storage", KeyPairType::STORAGE);
		test_identifier_key_type!(KeyMULTISIG, "test-multisig", KeyPairType::MULTISIG);

		// Test private key to GenericAccount conversions
		test_private_key_to_generic_account!(Ed25519PrivateKey, Ed25519, KeyPairType::ED25519);
		test_private_key_to_generic_account!(Secp256k1PrivateKey, Secp256k1, KeyPairType::ECDSASECP256K1);
		test_private_key_to_generic_account!(Secp256r1PrivateKey, Secp256r1, KeyPairType::ECDSASECP256R1);

		// Macro to test TryFrom for AnyPublicKey to GenericAccount conversions
		macro_rules! test_public_key_to_generic_account {
			($test_case:expr, $public_key_type:ty, $any_variant:ident) => {
				// Parse the public key hex string to bytes
				let public_key_bytes = hex::decode($test_case.public_key).unwrap();
				let public_key = <$public_key_type>::try_from(public_key_bytes.as_slice()).unwrap();
				let any_public_key = AnyPublicKey::$any_variant(public_key);

				let generic_account = GenericAccount::try_from(any_public_key).unwrap();
				assert_eq!(generic_account.to_keypair_type(), $test_case.key_type);
			};
		}

		// Test public key to GenericAccount conversions using existing test data
		for test_case in TEST_PUBLIC_ACCOUNTS {
			if !test_case.is_identifier {
				match test_case.key_type {
					KeyPairType::ED25519 => {
						test_public_key_to_generic_account!(test_case, Ed25519PublicKey, Ed25519);
					}
					KeyPairType::ECDSASECP256K1 => {
						test_public_key_to_generic_account!(test_case, Secp256k1PublicKey, Secp256k1);
					}
					KeyPairType::ECDSASECP256R1 => {
						test_public_key_to_generic_account!(test_case, Secp256r1PublicKey, Secp256r1);
					}
					_ => continue, // Skip non-crypto key types
				}
			}
		}
	}

	#[test]
	fn test_account_try_from_accountable() {
		let passphrase = create_test_passphrase();

		// Macro to test Accountable::KeyAndType variant
		macro_rules! test_key_and_type {
			($key_type:ty, $keypair_type:expr) => {
				let accountable = Accountable::KeyAndType(passphrase.clone().into(), $keypair_type);
				let account: Result<Account<$key_type>, AccountError> = Account::try_from(accountable);
				assert!(account.is_ok(), "Failed to create account for {:?}", $keypair_type);

				// Test consistency
				let accountable2 = Accountable::KeyAndType(passphrase.clone().into(), $keypair_type);
				let account_new = Account::<$key_type>::try_from(accountable2);
				assert!(account_new.is_ok(), "Inconsistent behavior for {:?}", $keypair_type);
			};
		}

		// Test all crypto key types
		test_key_and_type!(KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1);
		test_key_and_type!(KeyED25519, KeyPairType::ED25519);
		test_key_and_type!(KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1);

		// Test Accountable::Key and Accountable::Account variants
		let key = KeyNETWORK::try_from(Keyable::Identifier("test-network".to_string())).unwrap();

		// Test Key variant
		let accountable_key = Accountable::Key(key);
		let account_from_key: Result<Account<KeyNETWORK>, AccountError> = Account::try_from(accountable_key);
		assert!(account_from_key.is_ok());

		// Test Account variant (should clone the keypair)
		let original_account = account_from_key.unwrap();
		let accountable_account = Accountable::Account(original_account.clone());
		let account_from_account: Result<Account<KeyNETWORK>, AccountError> = Account::try_from(accountable_account);
		assert!(account_from_account.is_ok());
		assert_eq!(original_account.to_string(), account_from_account.unwrap().to_string());

		// Test error case: wrong key type for identifier
		let accountable_wrong_type = Accountable::KeyAndType(
			Keyable::Identifier("test".to_string()),
			KeyPairType::ECDSASECP256K1, // Wrong type for identifier
		);
		let account_wrong: Result<Account<KeyNETWORK>, AccountError> = Account::try_from(accountable_wrong_type);
		assert!(account_wrong.is_err());
	}

	#[test]
	fn test_account_from_public_key() {
		// Macro to parse and test account properties for specific key types
		macro_rules! test_account_from_public_key {
			($test_case:expr, $key_type:ty, $key_pair_type:expr) => {{
				let account = $test_case
					.encoded_public_key
					.parse::<Account<$key_type>>()
					.unwrap();
				assert_eq!(account.to_string(), $test_case.encoded_public_key);
				assert_eq!(account.to_keypair_type(), $key_pair_type);
				assert_eq!(account.is_identifier(), $test_case.is_identifier);
				assert!(account.compare_public_key($test_case.encoded_public_key));
			}};
		}

		// Test invalid public key strings (should fail)
		for invalid_key in INVALID_PUBLIC_KEYS {
			let result = invalid_key.parse::<Account<KeyECDSASECP256K1>>();
			assert!(result.is_err(), "Invalid key should fail: {invalid_key}");
		}

		// Test valid public key strings (should pass)
		for test_case in TEST_PUBLIC_ACCOUNTS {
			// Test specific algorithm methods and verify account properties
			match test_case.key_type {
				KeyPairType::ECDSASECP256K1 => {
					test_account_from_public_key!(test_case, KeyECDSASECP256K1, KeyPairType::ECDSASECP256K1)
				}
				KeyPairType::ECDSASECP256R1 => {
					test_account_from_public_key!(test_case, KeyECDSASECP256R1, KeyPairType::ECDSASECP256R1)
				}
				KeyPairType::ED25519 => test_account_from_public_key!(test_case, KeyED25519, KeyPairType::ED25519),
				KeyPairType::NETWORK => test_account_from_public_key!(test_case, KeyNETWORK, KeyPairType::NETWORK),
				KeyPairType::TOKEN => test_account_from_public_key!(test_case, KeyTOKEN, KeyPairType::TOKEN),
				KeyPairType::STORAGE => test_account_from_public_key!(test_case, KeySTORAGE, KeyPairType::STORAGE),
				KeyPairType::MULTISIG => test_account_from_public_key!(test_case, KeyMULTISIG, KeyPairType::MULTISIG),
			}

			// Test round-trip: encoded -> account -> raw hex public key (for non-identifiers only)
			if !test_case.is_identifier {
				// Parse the encoded public key to get raw bytes and verify they match expected hex
				let (parsed_public_key_bytes, _) = parse_public_key(test_case.encoded_public_key).unwrap();
				let parsed_hex = hex::encode(&parsed_public_key_bytes).to_uppercase();
				assert_eq!(parsed_hex, test_case.public_key,);
			}
		}
	}

	#[test]
	fn test_account_from_seed_private() {
		// Macro to test account creation from seed and verify properties
		macro_rules! test_account_from_seed {
			($seed_array:expr, $index:expr, $key_type:ty, $key_pair_type:expr, $expected_pubkey:expr) => {{
				let seed = $seed_array.into_secret();
				let account = Account::<$key_type>::try_from(Accountable::KeyAndType(
					Keyable::Seed((seed, $index as u32)),
					$key_pair_type,
				))
				.unwrap();
				assert!(account.compare_public_key($expected_pubkey));
				assert_eq!(account.to_keypair_type(), $key_pair_type);
				assert!(account.has_private_key());
				assert!(!account.is_identifier());
			}};
		}

		// Test account creation from seed
		let seed_bytes = hex::decode(TEST_PRIVATE_ACCOUNT.seed).unwrap();
		let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();

		for (index_number, test_index) in TEST_PRIVATE_ACCOUNT.indexes.iter().enumerate() {
			// Use macros to reduce repetition
			test_account_from_seed!(
				seed_array,
				index_number,
				KeyECDSASECP256K1,
				KeyPairType::ECDSASECP256K1,
				test_index.encoded_public_key_ecdsa_secp256k1
			);
			test_account_from_seed!(
				seed_array,
				index_number,
				KeyECDSASECP256R1,
				KeyPairType::ECDSASECP256R1,
				test_index.encoded_public_key_ecdsa_secp256r1
			);
			test_account_from_seed!(
				seed_array,
				index_number,
				KeyED25519,
				KeyPairType::ED25519,
				test_index.encoded_public_key_ed25519
			);
		}
	}

	#[test]
	fn test_account_type_detection() {
		// Macro to test account type detection methods
		macro_rules! test_account_type_detection {
			($account:expr, $is_network:expr, $is_token:expr, $is_storage:expr, $is_multisig:expr, $is_identifier:expr) => {
				assert_eq!($account.is_network(), $is_network);
				assert_eq!($account.is_token(), $is_token);
				assert_eq!($account.is_storage(), $is_storage);
				assert_eq!($account.is_multisig(), $is_multisig);
				assert_eq!($account.is_identifier(), $is_identifier);
			};
		}

		// Test account type detection methods using the macro
		let network_account = create_test_network_account(1);
		test_account_type_detection!(network_account, true, false, false, false, true);

		let token_account = create_test_account_from_pub_key_string::<KeyTOKEN>(TEST_PUBLIC_ACCOUNT_DATA.token.1);
		test_account_type_detection!(token_account, false, true, false, false, true);

		let storage_account = create_test_account_from_pub_key_string::<KeySTORAGE>(TEST_PUBLIC_ACCOUNT_DATA.storage.1);
		test_account_type_detection!(storage_account, false, false, true, false, true);

		let seed_array: [u8; 32] = [0u8; 32];
		let seed = seed_array.into_secret();
		let ecdsa_account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
			Keyable::Seed((seed, 0)),
			KeyPairType::ECDSASECP256K1,
		))
		.unwrap();
		test_account_type_detection!(ecdsa_account, false, false, false, false, false);
	}

	#[test]
	fn test_account_sign() {
		let test_data = b"Some random test data";
		let seed_bytes = hex::decode(TEST_PRIVATE_ACCOUNT.seed).unwrap();
		let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();

		// Macro to test signing for crypto algorithms
		macro_rules! test_crypto_signing {
			($key_type:ty) => {
				for (index_number, _test_index) in TEST_PRIVATE_ACCOUNT.indexes.iter().enumerate() {
					let account = create_test_account::<$key_type>(Some((seed_array, index_number as u32).into()));

					// Generate a valid signature and validate it
					let signature = account.sign(test_data, None).unwrap();
					let is_valid = account.verify(test_data, &signature, None);
					assert!(is_valid.is_ok());

					// Modify signature and verify it fails
					let mut invalid_signature = signature.clone();
					invalid_signature[1] = invalid_signature[1].wrapping_add(1);
					let is_invalid = account.verify(test_data, &invalid_signature, None);
					assert!(is_invalid.is_err());

					// Modify data and verify signature fails
					let mut invalid_data = test_data.to_vec();
					invalid_data[1] = invalid_data[1].wrapping_add(1);
					let is_invalid_data = account.verify(&invalid_data, &signature, None);
					assert!(is_invalid_data.is_err());
				}
			};
		}

		test_crypto_signing!(KeyECDSASECP256K1);
		test_crypto_signing!(KeyECDSASECP256R1);
		test_crypto_signing!(KeyED25519);
	}

	#[test]
	fn test_identifier_sign_verify_should_fail() {
		let data = b"Random Test Data";
		let sig = b"fake signature";

		// Macro to test identifier signing failures
		macro_rules! test_identifier_sign_fail {
			($key_type:ty, $account_creation:expr) => {
				let account = $account_creation;
				assert!(matches!(account.sign(data, None), Err(AccountError::NoIdentifierSign)));
				assert!(matches!(account.verify(data, sig, None), Err(AccountError::NoIdentifierVerify)));
			};
		}

		test_identifier_sign_fail!(KeyNETWORK, create_test_network_account(5));
		test_identifier_sign_fail!(KeyTOKEN, create_test_account_from_identifier::<KeyTOKEN>("test-token"));
		test_identifier_sign_fail!(KeySTORAGE, create_test_account_from_identifier::<KeySTORAGE>("test-storage"));
		test_identifier_sign_fail!(KeyMULTISIG, create_test_account_from_identifier::<KeyMULTISIG>("test-multisig"));
	}

	#[test]
	fn test_network_address_generation() {
		// Different network IDs should produce different accounts
		let network_account1 = create_test_network_account(1);
		let network_account2 = create_test_network_account(2);
		assert!(!network_account1.compare_account(&network_account2));

		// Same network ID should produce identical accounts
		let network_account1_verify = create_test_network_account(1);
		assert!(network_account1.compare_account(&network_account1_verify));
		assert_eq!(network_account1.to_string(), network_account1_verify.to_string());
	}

	#[test]
	fn test_encryption_support_indicators() {
		// Test encryption support flags
		let seed_array: [u8; 32] = [0u8; 32]; // Use a simple seed for this test
		let seed_array2: [u8; 32] = [1u8; 32]; // Different seed

		// Macro to test crypto accounts that support encryption
		macro_rules! test_crypto_encryption_support {
			($key_type:ty, $seed:expr) => {
				let account = create_test_account::<$key_type>(Some($seed.into()));
				assert!(account.supports_encryption());
			};
		}

		// Macro to test accounts that should not support encryption
		macro_rules! test_no_encryption {
			($account_creation:expr) => {
				let account = $account_creation;
				assert!(!account.supports_encryption());
			};
		}

		// Test crypto algorithms - all should support encryption
		test_crypto_encryption_support!(KeyECDSASECP256K1, seed_array);
		test_crypto_encryption_support!(KeyECDSASECP256R1, seed_array);
		test_crypto_encryption_support!(KeyED25519, seed_array2);

		// Test identifier types - none should support encryption
		test_no_encryption!(create_test_network_account(1));
		test_no_encryption!(create_test_account_from_pub_key_string::<KeyTOKEN>(TEST_PUBLIC_ACCOUNT_DATA.token.1));
		test_no_encryption!(create_test_account_from_pub_key_string::<KeySTORAGE>(TEST_PUBLIC_ACCOUNT_DATA.storage.1));
	}

	#[test]
	fn test_signature_verification() {
		// Test with SECP256K1 using the known signature test data
		let account = SIGNATURE_TEST
			.public_key_string
			.parse::<Account<KeyECDSASECP256K1>>()
			.unwrap();
		let verification_result = account.verify(SIGNATURE_TEST.test_data, SIGNATURE_TEST.expected_signature, None);
		assert!(verification_result.is_ok());

		// Macro to test signature generation and verification for crypto algorithms
		macro_rules! test_signature_verification {
			($key_type:ty) => {
				let account = create_test_account::<$key_type>(None);
				let test_data = b"Test signature data";

				// Generate signature and verify it
				let signature = account.sign(test_data, None).unwrap();
				let verification_result = account.verify(test_data, &signature, None);
				assert!(verification_result.is_ok());

				let crypto_signature = account.keypair.try_sign(test_data);
				assert!(crypto_signature.is_ok());

				let sig = crypto_signature.unwrap();
				let verification = <dyn Verifier<_>>::verify(&account.keypair, test_data, &sig);
				assert!(verification.is_ok());
			};
		}

		// Test signature verification for all crypto algorithms
		test_signature_verification!(KeyECDSASECP256K1);
		test_signature_verification!(KeyECDSASECP256R1);
		test_signature_verification!(KeyED25519);
	}

	#[test]
	fn test_signature_verification_error_paths() {
		// Macro to test signature error paths for crypto algorithms
		macro_rules! test_signature_errors {
			($key_type:ty) => {
				let account = create_test_account::<$key_type>(None);
				let test_data = b"Test signature data";
				let signature = account.sign(test_data, None).unwrap();

				// Test with corrupted signature
				let mut corrupted_signature = signature.clone();
				corrupted_signature[0] = !corrupted_signature[0];
				let result = account.verify(test_data, &corrupted_signature, None);
				assert!(result.is_err());

				// Test with invalid signature length - should error for parsing failure
				let invalid_sig = vec![0u8; 5];
				let error_result = account.verify(test_data, &invalid_sig, None);
				assert!(error_result.is_err());
			};
		}

		// Test error paths for all crypto algorithms
		test_signature_errors!(KeyECDSASECP256K1);
		test_signature_errors!(KeyECDSASECP256R1);
		test_signature_errors!(KeyED25519);
	}

	#[test]
	fn test_account_identifier_methods() {
		// Macro to test account type detection methods
		macro_rules! test_account_type_flags {
			($account:expr, $is_identifier:expr, $is_network:expr, $is_token:expr, $is_storage:expr, $is_multisig:expr) => {
				assert_eq!($account.is_identifier(), $is_identifier);
				assert_eq!($account.is_network(), $is_network);
				assert_eq!($account.is_token(), $is_token);
				assert_eq!($account.is_storage(), $is_storage);
				assert_eq!($account.is_multisig(), $is_multisig);
			};
		}

		// Test identifier account types
		let network_account = create_test_network_account(1);
		test_account_type_flags!(network_account, true, true, false, false, false);

		let token_account = create_test_account_from_pub_key_string::<KeyTOKEN>(TEST_PUBLIC_ACCOUNT_DATA.token.1);
		test_account_type_flags!(token_account, true, false, true, false, false);

		let storage_account = create_test_account_from_pub_key_string::<KeySTORAGE>(TEST_PUBLIC_ACCOUNT_DATA.storage.1);
		test_account_type_flags!(storage_account, true, false, false, true, false);

		let multisig_account = create_test_account_from_identifier::<KeyMULTISIG>("test-multisig");
		test_account_type_flags!(multisig_account, true, false, false, false, true);

		// Macro to test crypto accounts - all should be non-identifier
		macro_rules! test_crypto_account_flags {
			($public_key_string:expr, $key_type:ty) => {
				let account = $public_key_string.parse::<Account<$key_type>>().unwrap();
				test_account_type_flags!(account, false, false, false, false, false);
			};
		}

		// Test all cryptographic account types
		test_crypto_account_flags!(TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256k1.1, KeyECDSASECP256K1);
		test_crypto_account_flags!(TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256r1.1, KeyECDSASECP256R1);
		test_crypto_account_flags!(TEST_PUBLIC_ACCOUNT_DATA.ed25519.1, KeyED25519);
	}

	#[test]
	fn test_account_comparison_methods() {
		// Macro to test account comparison methods for crypto accounts
		macro_rules! test_crypto_account_comparison {
			($public_key_string:expr, $key_type:ty, $different_key_string:expr) => {
				let account1 = $public_key_string.parse::<Account<$key_type>>().unwrap();
				let account2 = $public_key_string.parse::<Account<$key_type>>().unwrap();

				// Test compare_public_key - same algorithm
				assert!(account1.compare_public_key($public_key_string));
				// Test compare_public_key - different algorithm
				assert!(!account1.compare_public_key($different_key_string));
				// Test compare_public_key - invalid keys
				assert!(!account1.compare_public_key("invalid_key"));
				assert!(!account1.compare_public_key(""));
				// Test compare_account - same accounts
				assert!(account1.compare_account(&account2));
			};
		}

		// Test comparison methods for all crypto algorithms
		test_crypto_account_comparison!(
			TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256k1.1,
			KeyECDSASECP256K1,
			TEST_PUBLIC_ACCOUNT_DATA.ed25519.1
		);
		test_crypto_account_comparison!(
			TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256r1.1,
			KeyECDSASECP256R1,
			TEST_PUBLIC_ACCOUNT_DATA.ed25519.1
		);
		test_crypto_account_comparison!(
			TEST_PUBLIC_ACCOUNT_DATA.ed25519.1,
			KeyED25519,
			TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256k1.1
		);

		// Test cross-algorithm comparison (should fail)
		let secp256k1_account = TEST_PUBLIC_ACCOUNT_DATA
			.ecdsa_secp256k1
			.1
			.parse::<Account<KeyECDSASECP256K1>>()
			.unwrap();
		let secp256r1_account = TEST_PUBLIC_ACCOUNT_DATA
			.ecdsa_secp256r1
			.1
			.parse::<Account<KeyECDSASECP256R1>>()
			.unwrap();
		let ed25519_account = TEST_PUBLIC_ACCOUNT_DATA
			.ed25519
			.1
			.parse::<Account<KeyED25519>>()
			.unwrap();

		assert!(!secp256k1_account.compare_account(&secp256r1_account));
		assert!(!secp256k1_account.compare_account(&ed25519_account));
		assert!(!secp256r1_account.compare_account(&ed25519_account));

		// Test with identifier accounts
		let network1 = create_test_network_account(1);
		let network2 = create_test_network_account(1);
		let network3 = create_test_network_account(2);
		assert!(network1.compare_account(&network2));
		assert!(!network1.compare_account(&network3));
	}

	#[test]
	fn test_has_private_key_detection() {
		macro_rules! test_has_private_key {
			($key_type:ident, $seed:expr) => {
				let account = create_test_account::<$key_type>(Some(($seed, 0).into()));
				assert!(account.has_private_key());
				assert!(account.keypair.has_private_key());
				assert!(account.keypair.to_public_key_string().len() > 0);
				assert!(account.keypair.to_public_key_string().len() > 0);
				assert!(!account.public_key_bytes().is_empty());
				assert!(!account.keypair.public_key_bytes().is_empty());
			};
		}

		macro_rules! test_no_private_key_crypto {
			($key_type:ident, $pubkey_string:expr) => {
				let account = $pubkey_string.parse::<Account<$key_type>>().unwrap();
				assert!(!account.has_private_key());
				assert!(!account.keypair.has_private_key());
			};
		}

		macro_rules! test_no_private_key_identifier {
			($key_type:ident, $identifier:expr) => {
				let account = create_test_account_from_identifier::<$key_type>($identifier);
				assert!(!account.has_private_key());

				// Test AccountSigner/AccountVerifier error behavior
				let test_data = b"test data";
				let sign_result = account.sign(test_data, None);
				assert!(matches!(sign_result, Err(AccountError::NoIdentifierSign)));

				let fake_sig = b"fake signature";
				let verify_result = account.verify(test_data, fake_sig, None);
				assert!(matches!(verify_result, Err(AccountError::NoIdentifierVerify)));
			};
		}

		// Test accounts created from seeds should have private keys
		test_has_private_key!(KeyECDSASECP256K1, [1u8; 32]);
		test_has_private_key!(KeyED25519, [2u8; 32]);
		test_has_private_key!(KeyECDSASECP256R1, [3u8; 32]);

		// Test cryptographic accounts from public key strings should not have private keys
		test_no_private_key_crypto!(KeyECDSASECP256K1, TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256k1.1);
		test_no_private_key_crypto!(KeyED25519, TEST_PUBLIC_ACCOUNT_DATA.ed25519.1);
		test_no_private_key_crypto!(KeyECDSASECP256R1, TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256r1.1);

		test_no_private_key_identifier!(KeyTOKEN, "test-token");
		test_no_private_key_identifier!(KeySTORAGE, "test-storage");
		test_no_private_key_identifier!(KeyMULTISIG, "test-multisig");

		// Test identifier accounts should never have private keys
		let network_account = create_test_network_account(1);
		assert!(!network_account.has_private_key());
	}

	#[test]
	fn test_encryption_round_trip() {
		let test_data = b"Hello, encryption world!";

		macro_rules! test_crypto_encryption {
			($key_type:ident, $seed:expr) => {
				let account = create_test_account::<$key_type>(Some(($seed, 0).into()));
				assert!(account.supports_encryption());

				let encrypted = account.encrypt(test_data).unwrap();
				assert_ne!(encrypted.as_slice(), test_data);
				let decrypted = account.decrypt(&encrypted).unwrap();
				assert_eq!(decrypted.as_slice(), test_data);
			};
		}

		macro_rules! test_identifier_no_encryption {
			($key_type:ident, $identifier:expr) => {
				let account = create_test_account_from_identifier::<$key_type>($identifier);
				assert!(!account.supports_encryption());
				assert!(account.encrypt(test_data).is_err());
				assert!(account.decrypt(test_data).is_err());
			};
		}

		// Test encryption support for cryptographic accounts
		test_crypto_encryption!(KeyECDSASECP256K1, [1u8; 32]);
		test_crypto_encryption!(KeyED25519, [2u8; 32]);
		test_crypto_encryption!(KeyECDSASECP256R1, [3u8; 32]);

		// Test no encryption support for identifier accounts
		test_identifier_no_encryption!(KeyTOKEN, "test-token");
		test_identifier_no_encryption!(KeySTORAGE, "test-storage");
		test_identifier_no_encryption!(KeyMULTISIG, "test-multisig");

		// Test no encryption support for identifier accounts
		let network_account = create_test_network_account(1);
		assert!(!network_account.supports_encryption());
		assert!(network_account.encrypt(test_data).is_err());
		assert!(network_account.decrypt(test_data).is_err());
	}

	#[test]
	fn test_signature_size_consistency() {
		macro_rules! test_signature_size {
			($key_type:ident, $expected_size:expr) => {
				let account = create_test_account::<$key_type>(Some(([1u8; 32], 0).into()));
				assert_eq!(account.signature_size(), $expected_size);

				// Test that signature size matches actual signature length
				let test_data = b"test signature size";
				let signature = account.sign(test_data, None).unwrap();
				assert_eq!(signature.len(), account.signature_size());
			};
		}

		// Test that signature sizes are consistent across crypto key types
		test_signature_size!(KeyECDSASECP256K1, 64);
		test_signature_size!(KeyECDSASECP256R1, 64);
		test_signature_size!(KeyED25519, 64);

		macro_rules! test_signature_size_identifier {
			($key_type:ident, $expected_size:expr) => {
				let account = create_test_account::<$key_type>(Some(([1u8; 32], 0).into()));
				assert_eq!(account.signature_size(), $expected_size);
			};
		}

		// Identifier types should have size 0
		test_signature_size_identifier!(KeyTOKEN, 0);
		test_signature_size_identifier!(KeySTORAGE, 0);
		test_signature_size_identifier!(KeyMULTISIG, 0);

		// Identifier accounts have signature size 0
		let network_account = create_test_network_account(1);
		assert_eq!(network_account.signature_size(), 0);
	}

	#[test]
	fn test_take_private_key_from_account() {
		macro_rules! test_take_private_key {
			($key_type:ident) => {
				// Generate a test account
				let account = create_test_account::<$key_type>(Some(([1u8; 32], 0).into()));
				assert!(account.has_private_key());

				// Take the private key
				let private_key = account.keypair.take_private_key();
				assert!(private_key.is_some());
			};
		}

		test_take_private_key!(KeyECDSASECP256K1);
		test_take_private_key!(KeyECDSASECP256R1);
		test_take_private_key!(KeyED25519);
	}

	#[test]
	fn test_identifier_key_utils() {
		let seed = [1u8; 32].into_secret();
		let dummy_key = AnyPrivateKey::Ed25519(Ed25519PrivateKey::try_from([1u8; 32].as_slice()).unwrap());

		// Macro to test identifier key methods
		macro_rules! test_identifier_methods {
			($key_type:ident) => {
				assert!(matches!($key_type::seed_to_private_key(&seed, 0), Err(AccountError::InvalidConstruction)));
				assert!(matches!(
					$key_type::derive_public_key_string(&dummy_key),
					Err(AccountError::InvalidConstruction)
				));
			};
		}

		// Test all identifier types return InvalidConstruction errors
		test_identifier_methods!(KeyNETWORK);
		test_identifier_methods!(KeyTOKEN);
		test_identifier_methods!(KeySTORAGE);
		test_identifier_methods!(KeyMULTISIG);
	}

	#[test]
	fn test_specific_public_key_string_methods() {
		macro_rules! test_public_key_parsing {
			($key_type:ident, $test_data:expr, $expected_type:expr) => {
				let account = $test_data.parse::<Account<$key_type>>().unwrap();
				assert_eq!(account.to_keypair_type(), $expected_type);
				assert_eq!(account.to_string(), $test_data);
			};
		}

		// Test parsing and string conversion for each key type
		test_public_key_parsing!(
			KeyECDSASECP256K1,
			TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256k1.1,
			KeyPairType::ECDSASECP256K1
		);
		test_public_key_parsing!(
			KeyECDSASECP256R1,
			TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256r1.1,
			KeyPairType::ECDSASECP256R1
		);
		test_public_key_parsing!(KeyED25519, TEST_PUBLIC_ACCOUNT_DATA.ed25519.1, KeyPairType::ED25519);

		// Test error cases - wrong algorithm for method
		assert!(TEST_PUBLIC_ACCOUNT_DATA
			.ed25519
			.1
			.parse::<Account<KeyECDSASECP256K1>>()
			.is_err());
		assert!(TEST_PUBLIC_ACCOUNT_DATA
			.ecdsa_secp256k1
			.1
			.parse::<Account<KeyED25519>>()
			.is_err());
		assert!(TEST_PUBLIC_ACCOUNT_DATA
			.ecdsa_secp256r1
			.1
			.parse::<Account<KeyECDSASECP256K1>>()
			.is_err());
	}

	#[test]
	fn test_multisig_account_functionality() {
		let multisig_account = create_test_account_from_identifier::<KeyMULTISIG>("test-multisig");
		assert_eq!(multisig_account.to_keypair_type(), KeyPairType::MULTISIG);
		assert!(multisig_account.is_multisig());
		assert!(multisig_account.is_identifier());
		assert!(!multisig_account.is_network());
		assert!(!multisig_account.is_token());
		assert!(!multisig_account.is_storage());
		assert!(!multisig_account.has_private_key());
		assert!(!multisig_account.supports_encryption());
		assert_eq!(multisig_account.signature_size(), 0);

		// Test that multisig accounts cannot sign or verify
		let test_data = b"test data";
		assert!(multisig_account.sign(test_data, None).is_err());
		assert!(multisig_account
			.verify(test_data, b"fake signature", None)
			.is_err());
		assert!(multisig_account.encrypt(test_data).is_err());
		assert!(multisig_account.decrypt(test_data).is_err());

		// Test creation from identifier
		let multisig_from_id = Account::<KeyMULTISIG>::try_from(Accountable::KeyAndType(
			Keyable::Identifier("multisig-test".to_string()),
			KeyPairType::MULTISIG,
		))
		.unwrap();
		assert!(multisig_from_id.is_multisig());
		assert!(multisig_from_id.is_identifier());

		// Test auto-detection from public key string
		let multisig_public_key = multisig_account.to_string();
		let auto_result = multisig_public_key.parse::<Account<KeyMULTISIG>>();
		assert!(auto_result.is_ok());
		let account = auto_result.unwrap();
		assert!(account.is_multisig());

		// Test invalid multisig public key string
		let invalid_result = "keeta_aa_not_multisig".parse::<Account<KeyMULTISIG>>();
		assert!(invalid_result.is_err());
	}

	#[test]
	fn test_public_key_string_prefixes() {
		// Test identifier accounts have correct prefixes
		let network_account = create_test_account_from_identifier::<KeyNETWORK>("test-network");
		let token_account = create_test_account_from_identifier::<KeyTOKEN>("test-token");
		let storage_account = create_test_account_from_identifier::<KeySTORAGE>("test-storage");
		let multisig_account = create_test_account_from_identifier::<KeyMULTISIG>("test-multisig");

		// All should start with keeta_
		assert!(network_account.to_string().starts_with("keeta_"));
		assert!(token_account.to_string().starts_with("keeta_"));
		assert!(storage_account.to_string().starts_with("keeta_"));
		assert!(multisig_account.to_string().starts_with("keeta_"));

		// Test that invalid keys are rejected
		let invalid_key = "invalid_key_format";
		assert!(invalid_key.parse::<Account<KeyECDSASECP256K1>>().is_err());
		assert!(invalid_key.parse::<Account<KeyECDSASECP256R1>>().is_err());
		assert!(invalid_key.parse::<Account<KeyED25519>>().is_err());
		assert!(invalid_key.parse::<Account<KeyNETWORK>>().is_err());
		assert!(invalid_key.parse::<Account<KeyTOKEN>>().is_err());
		assert!(invalid_key.parse::<Account<KeySTORAGE>>().is_err());
		assert!(invalid_key.parse::<Account<KeyMULTISIG>>().is_err());
	}

	#[test]
	fn test_from_str_implementations() {
		macro_rules! test_parsing {
			($key_struct:ident, $key_enum:ident, $test_data:expr) => {{
				let account = $test_data.parse::<Account<$key_struct>>().unwrap();
				assert_eq!(account.to_keypair_type(), KeyPairType::$key_enum);
			}};
		}

		// Test each account type directly using TEST_PUBLIC_ACCOUNTS data
		for test_case in TEST_PUBLIC_ACCOUNTS {
			match test_case.key_type {
				KeyPairType::ECDSASECP256K1 => {
					test_parsing!(KeyECDSASECP256K1, ECDSASECP256K1, test_case.encoded_public_key)
				}
				KeyPairType::ECDSASECP256R1 => {
					test_parsing!(KeyECDSASECP256R1, ECDSASECP256R1, test_case.encoded_public_key)
				}
				KeyPairType::ED25519 => test_parsing!(KeyED25519, ED25519, test_case.encoded_public_key),
				KeyPairType::NETWORK => test_parsing!(KeyNETWORK, NETWORK, test_case.encoded_public_key),
				KeyPairType::TOKEN => test_parsing!(KeyTOKEN, TOKEN, test_case.encoded_public_key),
				KeyPairType::STORAGE => test_parsing!(KeySTORAGE, STORAGE, test_case.encoded_public_key),
				KeyPairType::MULTISIG => {
					test_parsing!(KeyMULTISIG, MULTISIG, test_case.encoded_public_key)
				}
			}
		}

		assert!("invalid_key".parse::<Account<KeyECDSASECP256K1>>().is_err());
	}

	#[test]
	fn test_invalid_key_material_error_handling() {
		// Test invalid hex seed lengths and formats
		let invalid_hex_cases = [
			("too_short", "Too short"),
			("not_hex_at_all", "Invalid hex"),
			("12345", "Way too short"),
			("", "Empty"),
			("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00", "Too long"),
		];

		for (invalid_hex, _) in invalid_hex_cases {
			let hex_seed_secret = invalid_hex.to_string().into_secret();
			let result = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret, 0)),
				KeyPairType::ECDSASECP256K1,
			));
			assert!(result.is_err());
		}

		// Test wrong key type scenarios
		let test_seed = [1u8; 32];

		macro_rules! test_wrong_key_type {
			($account_type:ident, $wrong_key_type:ident, $keyable:expr) => {
				let wrong_type_result =
					Account::<$account_type>::try_from(Accountable::KeyAndType($keyable, KeyPairType::$wrong_key_type));
				assert!(matches!(wrong_type_result, Err(AccountError::InvalidKeyType)));
			};
		}

		// Try to create SECP256K1 account with ED25519 key type
		test_wrong_key_type!(KeyECDSASECP256K1, ED25519, Keyable::Seed((test_seed.into_secret(), 0)));
		// Try to create Network account with SECP256K1 key type
		test_wrong_key_type!(KeyNETWORK, ECDSASECP256K1, Keyable::Identifier("test".to_string()));

		// Test encryption not supported errors
		let secp256r1_account = create_test_account::<KeyECDSASECP256R1>(Some(test_seed.into()));
		assert!(secp256r1_account.encrypt(b"test").is_ok());
		// Decryption with invalid data should fail
		assert!(secp256r1_account.decrypt(b"invalid").is_err());

		// Test identifier accounts do not support signing/verification
		let test_data = b"test message";
		let fake_signature = b"fake signature";

		let network_account = create_test_network_account(1);
		assert!(matches!(network_account.sign(test_data, None), Err(AccountError::NoIdentifierSign)));
		assert!(matches!(
			network_account.verify(test_data, fake_signature, None),
			Err(AccountError::NoIdentifierVerify)
		));

		macro_rules! test_crypto_with_identifier_fails {
			($key_type:ident) => {
				let result = $key_type::try_from(Keyable::Identifier("test-id".to_string()));
				assert!(matches!(result, Err(AccountError::InvalidIdentifierConstruction)));
			};
		}

		macro_rules! test_identifier_with_passphrase_fails {
			($key_type:ident) => {
				let phrase = vec!["test".to_string()];
				let result = $key_type::try_from(Keyable::Passphrase((phrase.into_secret(), 0)));
				assert!(result.is_err());
			};
		}

		// Test creating crypto keys with identifier input (should fail)
		test_crypto_with_identifier_fails!(KeyECDSASECP256K1);
		test_crypto_with_identifier_fails!(KeyED25519);
		test_crypto_with_identifier_fails!(KeyECDSASECP256R1);

		// Test creating identifier keys with crypto input (should fail for passphrase)
		test_identifier_with_passphrase_fails!(KeyNETWORK);
		test_identifier_with_passphrase_fails!(KeyTOKEN);
		test_identifier_with_passphrase_fails!(KeySTORAGE);
	}

	#[test]
	fn test_keyable_from_implementations() {
		macro_rules! test_keyable_conversion {
			($input:expr, $index:expr, $variant:ident, $expected_value:expr) => {
				let keyable: Keyable = ($input, $index).into();
				assert!(matches!(keyable, Keyable::$variant(_)));
				let Keyable::$variant((value, index)) = keyable else {
					// This should never happen
					unreachable!()
				};
				assert_eq!(*value.expose_secret(), $expected_value);
				assert_eq!(index, $index);
			};
		}

		// Test From implementations with indices
		let seed_array = [1u8; 32];
		test_keyable_conversion!(seed_array, 5, Seed, seed_array);

		let hex_string = "deadbeef";
		test_keyable_conversion!(hex_string, 10, HexSeed, hex_string);

		let hex_string_owned = "deadbeef".to_string();
		test_keyable_conversion!(hex_string_owned.clone(), 15, HexSeed, hex_string_owned);

		let passphrase_vec = vec!["word1".to_string(), "word2".to_string()];
		test_keyable_conversion!(passphrase_vec.clone(), 20, Passphrase, passphrase_vec);
	}

	#[test]
	fn test_hex_format_parsing_and_conversion() {
		// Use existing test data instead of redefining
		for test_case in TEST_PUBLIC_ACCOUNTS {
			// Skip identifier types as they use different hex format handling
			if test_case.is_identifier {
				continue;
			}

			// Test parsing keeta format
			let account_from_keeta: GenericAccount = test_case.encoded_public_key.parse().unwrap();
			assert_eq!(account_from_keeta.to_keypair_type(), test_case.key_type);

			// Test conversion to hex format using ToHex trait
			let hex_string: String = account_from_keeta.encode_hex();
			assert!(!hex_string.is_empty());

			// Test parsing hex format using FromHex trait
			let account_from_hex = GenericAccount::from_hex(&hex_string).unwrap();
			assert_eq!(account_from_hex.to_keypair_type(), test_case.key_type);

			// Test round-trip consistency (keeta -> hex -> keeta)
			let back_to_keeta = account_from_hex.to_string();
			let final_account: GenericAccount = back_to_keeta.parse().unwrap();
			assert_eq!(final_account.to_keypair_type(), test_case.key_type);
		}
	}

	#[test]
	fn test_hex_format_invalid_cases() {
		let invalid_hex_cases = [
			"",         // Empty
			"1",        // No public key data
			"FF123456", // Invalid key type
			"GG123456", // Invalid hex characters
		];

		for invalid_hex in invalid_hex_cases {
			let result = GenericAccount::from_hex(invalid_hex);
			assert!(result.is_err(), "Expected error for: {invalid_hex}");
		}
	}

	#[test]
	fn test_hex_format_all_key_types() {
		for test_case in TEST_PUBLIC_ACCOUNTS {
			// Parse the test account
			let account: GenericAccount = test_case.encoded_public_key.parse().unwrap();
			assert_eq!(account.to_keypair_type(), test_case.key_type);

			// Convert to hex format using ToHex trait
			let hex_string: String = account.encode_hex();
			assert!(!hex_string.is_empty());

			// Parse back from hex using FromHex trait
			let parsed_back = GenericAccount::from_hex(&hex_string).unwrap();
			assert_eq!(parsed_back.to_keypair_type(), test_case.key_type);

			// Verify the type byte is correct
			let hex_bytes = hex::decode(&hex_string).unwrap();
			assert_eq!(hex_bytes[0], test_case.key_type as u8);
		}
	}

	#[test]
	fn test_account_specific_hex_format() {
		// Macro to test hex format for specific account types
		macro_rules! test_hex_format {
			($key_type:ty, $test_data:expr) => {
				let account: Account<$key_type> = $test_data.parse().unwrap();
				let hex_string: String = account.encode_hex();
				let from_hex = Account::<$key_type>::from_hex(&hex_string).unwrap();
				assert_eq!(account.to_string(), from_hex.to_string());
			};
		}

		// Test all cryptographic account types
		test_hex_format!(KeyECDSASECP256K1, TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256k1.1);
		test_hex_format!(KeyED25519, TEST_PUBLIC_ACCOUNT_DATA.ed25519.1);
		test_hex_format!(KeyECDSASECP256R1, TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256r1.1);
	}

	#[test]
	fn test_account_opening_hash() {
		// Test opening hash against known test data
		macro_rules! test_opening_hash {
			($key_type:ty, $test_data:expr) => {
				let account: Account<$key_type> = $test_data.1.parse().unwrap();
				let opening_hash = account.to_opening_hash();
				let expected_hash = hex::decode($test_data.2).unwrap();
				assert_eq!(opening_hash, expected_hash);
			};
		}

		// Test all key types with their expected opening hashes
		test_opening_hash!(KeyECDSASECP256K1, TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256k1);
		test_opening_hash!(KeyECDSASECP256R1, TEST_PUBLIC_ACCOUNT_DATA.ecdsa_secp256r1);
		test_opening_hash!(KeyED25519, TEST_PUBLIC_ACCOUNT_DATA.ed25519);
		test_opening_hash!(KeyTOKEN, TEST_PUBLIC_ACCOUNT_DATA.token);
		test_opening_hash!(KeySTORAGE, TEST_PUBLIC_ACCOUNT_DATA.storage);
	}
}
