use crypto::{
	algorithms::{Algorithm, Ed25519Derivation, KeyDerivation, PrivateKey, PublicKey, Secp256k1Derivation},
	AnyPrivateKey,
};
use secrecy::SecretBox;
use zeroize::Zeroize;

use crate::error::AccountError;
use crate::utils::*;
use crate::{Index, Seed};

/// Account encoding prefixes for different account types
pub const ACCOUNT_PREFIXES: &[&str] = &["keeta_", "tyblocks_"];

/// Supported cryptographic key pair types
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// Identifier key types (non-cryptographic)
pub const IDENTIFIER_KEY_TYPES: &[KeyPairType] = &[KeyPairType::NETWORK, KeyPairType::TOKEN, KeyPairType::STORAGE];

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

impl From<KeyPairType> for Algorithm {
	fn from(key_type: KeyPairType) -> Self {
		match key_type {
			KeyPairType::ECDSASECP256K1 => Algorithm::Secp256k1,
			KeyPairType::ED25519 => Algorithm::Ed25519,
			KeyPairType::ECDSASECP256R1 => Algorithm::Secp256r1,
			// Identifier types don't map to crypto algorithms
			KeyPairType::NETWORK | KeyPairType::TOKEN | KeyPairType::STORAGE => {
				panic!("Identifier key types cannot be converted to crypto algorithms")
			}
		}
	}
}

/// Signature storage for cryptographic signatures
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct SignatureStorage {
	data: [u8; 64],
}

impl SignatureStorage {
	/// Create a new signature from bytes
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccountError> {
		if bytes.len() != 64 {
			return Err(AccountError::InvalidConstruction);
		}
		let mut data = [0u8; 64];
		data.copy_from_slice(bytes);
		Ok(Self { data })
	}

	/// Get signature as bytes
	pub fn as_bytes(&self) -> &[u8; 64] {
		&self.data
	}
}

/// ECDSA signature wrapper
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct EcdsaSignature(SignatureStorage);

impl EcdsaSignature {
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccountError> {
		Ok(Self(SignatureStorage::from_bytes(bytes)?))
	}

	pub fn as_bytes(&self) -> &[u8; 64] {
		self.0.as_bytes()
	}
}

/// Ed25519 signature wrapper  
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Ed25519Signature(SignatureStorage);

impl Ed25519Signature {
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccountError> {
		Ok(Self(SignatureStorage::from_bytes(bytes)?))
	}

	pub fn as_bytes(&self) -> &[u8; 64] {
		self.0.as_bytes()
	}
}

/// Options for signing and verification operations
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
	/// Perform signing/verification on raw data (skip hashing)
	pub raw: bool,
	/// Format for X.509 certificate compatibility
	pub for_cert: bool,
}

/// Encryption/decryption capability marker
pub trait SupportsEncryption {
	/// Encrypt data
	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, AccountError>;

	/// Decrypt data  
	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, AccountError>;
}

/// Core cryptographic operations trait
pub trait CryptoOperations {
	/// The signature type this implementation produces
	type Signature;

	/// Sign data with optional configuration
	fn sign(&self, data: &[u8], options: Option<SignOptions>) -> Result<Self::Signature, AccountError>;

	/// Verify a signature against data
	fn verify(&self, data: &[u8], signature: &Self::Signature, options: Option<SignOptions>) -> bool;

	/// Check if this implementation has a private key
	fn has_private_key(&self) -> bool;

	/// Get the key pair type
	fn key_type(&self) -> KeyPairType;
}

/// Trait defining the interface for cryptographic key pairs.
///
/// Provides methods for key generation, derivation, and type identification.
pub trait KeyPair: Send + Sync {
	/// Creates a new key pair from the given input.
	fn new(input: Keyable) -> Result<Self, AccountError>
	where
		Self: Sized;
	/// Deterministically derives a private key from a seed and index.
	///
	/// Uses HKDF with retry logic to ensure the derived key is valid.
	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError>;
	/// Converts a private key into a formatted public key string.
	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError>;
	/// Returns the key pair type for this instance.
	fn keypair_type(&self) -> KeyPairType;
	/// Returns the static key pair type for this implementation.
	fn keypair_type_static() -> KeyPairType;
}

/// Type alias for a passphrase and its derivation index.
pub type PassphraseAndIndex = (Vec<String>, Index);
/// Type alias for a seed and its derivation index.
pub type SeedAndIndex = (Seed, Index);
/// Type alias for a hex-encoded seed and its derivation index.
pub type HexSeedAndIndex = (String, Index);

#[derive(Zeroize)]
/// Different types of key material that can be used to create key pairs.
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

/// ECDSA key pair using the secp256k1 curve.
///
/// This is the primary key type used for cryptographic operations.
/// Private keys are stored securely and public keys are formatted as strings.
#[derive(Clone)]
pub struct KeyECDSASECP256K1 {
	_private_key: Option<AnyPrivateKey>,
	pub public_key: String,
}

impl core::fmt::Debug for KeyECDSASECP256K1 {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("KeyECDSASECP256K1").field("public_key", &self.public_key).finish()
	}
}

impl KeyPair for KeyECDSASECP256K1 {
	fn new(input: Keyable) -> Result<Self, AccountError> {
		let (private_key, public_key) = match input {
			Keyable::Passphrase((_, index)) | Keyable::Seed((_, index)) | Keyable::HexSeed((_, index)) => {
				let seed = match input {
					Keyable::Passphrase((passphrase, _)) => seed_from_passphrase(&passphrase.join(" "))?,
					Keyable::Seed((seed, _)) => seed,
					Keyable::HexSeed((seed, _)) => hex::decode(seed)
						.or(Err(AccountError::InvalidConstruction))?
						.try_into()
						.or(Err(AccountError::InvalidConstruction))?,
					_ => unreachable!(),
				};

				let private_key = KeyECDSASECP256K1::seed_to_private_key(&seed, index)?;
				let public_key_string = KeyECDSASECP256K1::derive_public_key_string(&private_key)?;

				(Some(private_key), public_key_string)
			}
			Keyable::PublicKeyString(_) | Keyable::PublicKey(_) => {
				panic!("not implemented");
			}
			Keyable::PrivateKey(_) => {
				panic!("not implemented");
			}
			Keyable::Identifier(_) => {
				return Err(AccountError::InvalidConstruction);
			}
		};

		Ok(KeyECDSASECP256K1 { _private_key: private_key, public_key })
	}

	fn keypair_type(&self) -> KeyPairType {
		KeyPairType::ECDSASECP256K1
	}

	fn keypair_type_static() -> KeyPairType {
		KeyPairType::ECDSASECP256K1
	}

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Convert seed and index to bytes for HKDF
		let seed_buffer = combine_seed_and_index(seed, index);
		// Use the crypto crate's secp256k1 derivation
		let private_key = Secp256k1Derivation::derive_from_seed(&seed_buffer)?;

		Ok(AnyPrivateKey::Secp256k1(private_key))
	}

	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError> {
		match key {
			AnyPrivateKey::Secp256k1(secp_key) => {
				let public_key = secp_key.derive_public_key();
				Ok(public_key.to_formatted_string()?)
			}
			_ => Err(AccountError::InvalidConstruction),
		}
	}
}

#[derive(Debug)]
pub struct KeyECDSASECP256R1 {
	_private_key: Option<String>,
	pub public_key: [u8; 65],
}

impl Clone for KeyECDSASECP256R1 {
	fn clone(&self) -> Self {
		KeyECDSASECP256R1 { _private_key: None, public_key: self.public_key }
	}
}

impl KeyPair for KeyECDSASECP256R1 {
	fn new(_input: Keyable) -> Result<Self, AccountError> {
		Err(AccountError::InvalidConstruction)
	}

	fn keypair_type(&self) -> KeyPairType {
		KeyPairType::ECDSASECP256R1
	}

	fn keypair_type_static() -> KeyPairType {
		KeyPairType::ECDSASECP256R1
	}

	fn seed_to_private_key(_seed: &Seed, _index: Index) -> Result<AnyPrivateKey, AccountError> {
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
	}
}

/// Ed25519 key pair implementation.
///
/// Provides Ed25519 digital signature algorithm support.
#[derive(Clone)]
pub struct KeyED25519 {
	_private_key: Option<AnyPrivateKey>,
	pub public_key: String,
}

impl core::fmt::Debug for KeyED25519 {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("KeyED25519").field("public_key", &self.public_key).finish()
	}
}

impl KeyPair for KeyED25519 {
	fn new(input: Keyable) -> Result<Self, AccountError> {
		let (private_key, public_key) = match input {
			Keyable::Passphrase((_, index)) | Keyable::Seed((_, index)) | Keyable::HexSeed((_, index)) => {
				let seed = match input {
					Keyable::Passphrase((passphrase, _)) => seed_from_passphrase(&passphrase.join(" "))?,
					Keyable::Seed((seed, _)) => seed,
					Keyable::HexSeed((seed, _)) => hex::decode(seed)
						.or(Err(AccountError::InvalidConstruction))?
						.try_into()
						.or(Err(AccountError::InvalidConstruction))?,
					_ => unreachable!(),
				};

				let private_key = KeyED25519::seed_to_private_key(&seed, index)?;
				let public_key_string = KeyED25519::derive_public_key_string(&private_key)?;

				(Some(private_key), public_key_string)
			}
			Keyable::PublicKeyString(_) | Keyable::PublicKey(_) => {
				panic!("not implemented");
			}
			Keyable::PrivateKey(_) => {
				panic!("not implemented");
			}
			Keyable::Identifier(_) => {
				return Err(AccountError::InvalidConstruction);
			}
		};

		Ok(KeyED25519 { _private_key: private_key, public_key })
	}

	fn keypair_type(&self) -> KeyPairType {
		KeyPairType::ED25519
	}

	fn keypair_type_static() -> KeyPairType {
		KeyPairType::ED25519
	}

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Convert seed and index to bytes for HKDF
		let seed_buffer = combine_seed_and_index(seed, index);
		// Use the crypto crate's Ed25519 derivation
		let private_key = Ed25519Derivation::derive_from_seed(&seed_buffer)?;

		Ok(AnyPrivateKey::Ed25519(private_key))
	}

	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError> {
		match key {
			AnyPrivateKey::Ed25519(ed_key) => {
				let public_key = ed_key.derive_public_key();
				Ok(public_key.to_formatted_string()?)
			}
			_ => Err(AccountError::InvalidConstruction),
		}
	}
}

/// Network identifier key implementation.
///
/// Used for network identification and validation.
#[derive(Clone)]
pub struct KeyNETWORK {
	pub identifier: String,
	pub public_key: String,
}

impl core::fmt::Debug for KeyNETWORK {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("KeyNETWORK")
			.field("identifier", &self.identifier)
			.field("public_key", &self.public_key)
			.finish()
	}
}

impl KeyPair for KeyNETWORK {
	fn new(input: Keyable) -> Result<Self, AccountError> {
		match input {
			Keyable::Identifier(id) => Ok(KeyNETWORK { identifier: id.clone(), public_key: format!("network_{id}") }),
			_ => Err(AccountError::InvalidConstruction),
		}
	}

	fn keypair_type(&self) -> KeyPairType {
		KeyPairType::NETWORK
	}

	fn keypair_type_static() -> KeyPairType {
		KeyPairType::NETWORK
	}

	fn seed_to_private_key(_seed: &Seed, _index: Index) -> Result<AnyPrivateKey, AccountError> {
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
	}
}

/// Token identifier key implementation.
///
/// Used for token-based authentication and identification.
#[derive(Clone)]
pub struct KeyTOKEN {
	pub identifier: String,
	pub public_key: String,
}

impl core::fmt::Debug for KeyTOKEN {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("KeyTOKEN").field("identifier", &self.identifier).field("public_key", &self.public_key).finish()
	}
}

impl KeyPair for KeyTOKEN {
	fn new(input: Keyable) -> Result<Self, AccountError> {
		match input {
			Keyable::Identifier(id) => Ok(KeyTOKEN { identifier: id.clone(), public_key: format!("token_{id}") }),
			_ => Err(AccountError::InvalidConstruction),
		}
	}

	fn keypair_type(&self) -> KeyPairType {
		KeyPairType::TOKEN
	}

	fn keypair_type_static() -> KeyPairType {
		KeyPairType::TOKEN
	}

	fn seed_to_private_key(_seed: &Seed, _index: Index) -> Result<AnyPrivateKey, AccountError> {
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
	}
}

/// Storage identifier key implementation.
///
/// Used for storage access and encryption key identification.
#[derive(Clone)]
pub struct KeySTORAGE {
	pub identifier: String,
	pub public_key: String,
}

impl core::fmt::Debug for KeySTORAGE {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("KeySTORAGE")
			.field("identifier", &self.identifier)
			.field("public_key", &self.public_key)
			.finish()
	}
}

impl KeyPair for KeySTORAGE {
	fn new(input: Keyable) -> Result<Self, AccountError> {
		match input {
			Keyable::Identifier(id) => Ok(KeySTORAGE { identifier: id.clone(), public_key: format!("storage_{id}") }),
			_ => Err(AccountError::InvalidConstruction),
		}
	}

	fn keypair_type(&self) -> KeyPairType {
		KeyPairType::STORAGE
	}

	fn keypair_type_static() -> KeyPairType {
		KeyPairType::STORAGE
	}

	fn seed_to_private_key(_seed: &Seed, _index: Index) -> Result<AnyPrivateKey, AccountError> {
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
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

/// A generic account object, which represents a keypair
#[derive(Debug, Clone, Default)]
pub struct Account<KEYTYPE>
where
	KEYTYPE: KeyPair,
{
	pub keypair: KEYTYPE,
}

pub trait FromAccountable<KEYTYPE>
where
	KEYTYPE: KeyPair,
{
	fn try_from_accountable(input: Accountable<KEYTYPE>) -> Option<KEYTYPE>;
}

impl FromAccountable<KeyECDSASECP256K1> for KeyECDSASECP256K1 {
	fn try_from_accountable(input: Accountable<KeyECDSASECP256K1>) -> Option<Self> {
		match input {
			Accountable::Key(k) => Some(k),
			_ => None,
		}
	}
}

impl FromAccountable<KeyECDSASECP256R1> for KeyECDSASECP256R1 {
	fn try_from_accountable(input: Accountable<KeyECDSASECP256R1>) -> Option<Self> {
		match input {
			Accountable::Key(k) => Some(k),
			_ => None,
		}
	}
}

impl FromAccountable<KeyED25519> for KeyED25519 {
	fn try_from_accountable(input: Accountable<KeyED25519>) -> Option<Self> {
		match input {
			Accountable::Key(k) => Some(k),
			_ => None,
		}
	}
}

impl FromAccountable<KeyNETWORK> for KeyNETWORK {
	fn try_from_accountable(input: Accountable<KeyNETWORK>) -> Option<Self> {
		match input {
			Accountable::Key(k) => Some(k),
			_ => None,
		}
	}
}

impl FromAccountable<KeyTOKEN> for KeyTOKEN {
	fn try_from_accountable(input: Accountable<KeyTOKEN>) -> Option<Self> {
		match input {
			Accountable::Key(k) => Some(k),
			_ => None,
		}
	}
}

impl FromAccountable<KeySTORAGE> for KeySTORAGE {
	fn try_from_accountable(input: Accountable<KeySTORAGE>) -> Option<Self> {
		match input {
			Accountable::Key(k) => Some(k),
			_ => None,
		}
	}
}

impl FromAccountable<KeyECDSASECP256K1> for Account<KeyECDSASECP256K1> {
	fn try_from_accountable(input: Accountable<KeyECDSASECP256K1>) -> Option<KeyECDSASECP256K1> {
		match input {
			Accountable::Account(account) => Some(account.keypair),
			_ => None,
		}
	}
}

impl FromAccountable<KeyECDSASECP256R1> for Account<KeyECDSASECP256R1> {
	fn try_from_accountable(input: Accountable<KeyECDSASECP256R1>) -> Option<KeyECDSASECP256R1> {
		match input {
			Accountable::Account(account) => Some(account.keypair),
			_ => None,
		}
	}
}

impl FromAccountable<KeyED25519> for Account<KeyED25519> {
	fn try_from_accountable(input: Accountable<KeyED25519>) -> Option<KeyED25519> {
		match input {
			Accountable::Account(account) => Some(account.keypair),
			_ => None,
		}
	}
}

impl<KEYTYPE> Account<KEYTYPE>
where
	KEYTYPE: KeyPair + FromAccountable<KEYTYPE> + Clone,
{
	pub fn new(input: Accountable<KEYTYPE>) -> Result<Self, AccountError> {
		let account: Result<Self, AccountError> = match input {
			Accountable::Account(account) => {
				let keypair = KEYTYPE::try_from_accountable(Accountable::Key(account.keypair.clone()));
				if keypair.is_none() {
					return Err(AccountError::InvalidKeyType);
				}

				Ok(Account::<KEYTYPE> { keypair: keypair.unwrap() })
			}
			Accountable::KeyAndType(key, key_type) => {
				let keypair: Result<KEYTYPE, AccountError> = if key_type == KEYTYPE::keypair_type_static() {
					KEYTYPE::new(key)
				} else {
					Err(AccountError::InvalidKeyType)
				};

				Ok(Account::<KEYTYPE> { keypair: keypair? })
			}
			keypair_accountable => {
				let keypair = KEYTYPE::try_from_accountable(keypair_accountable);
				if keypair.is_none() {
					return Err(AccountError::InvalidConstruction);
				}

				Ok(Account::<KEYTYPE> { keypair: keypair.unwrap() })
			}
		};

		account
	}

	pub fn keypair_type(&self) -> KeyPairType {
		self.keypair.keypair_type()
	}

	pub fn keypair_type_static() -> KeyPairType {
		KEYTYPE::keypair_type_static()
	}

	pub fn compute_seed_from_passphrase(passphrase: Vec<String>) -> Result<Seed, AccountError> {
		seed_from_passphrase(passphrase.join(" ").as_str())
	}

	pub fn generate_passphrase() -> Result<SecretBox<Vec<String>>, AccountError> {
		generate_random_passphrase()
	}

	pub fn generate_seed() -> Result<SecretBox<Seed>, AccountError> {
		generate_random_seed()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use secrecy::ExposeSecret;

	// Test data structure for comprehensive data-driven testing
	struct TestCase {
		hex_seed: &'static str,
		passphrase: &'static [&'static str],
		expected_secp256k1_pubkey: &'static str,
		expected_ed25519_pubkey: &'static str,
	}

	// Test data for private accounts with deterministic derivation
	struct PrivateAccountTestData {
		seed: &'static str,
		indexes: &'static [PrivateKeyTestCase],
	}

	// Only keep the fields we actually use in tests
	struct PrivateKeyTestCase {
		encoded_public_key_ecdsa_secp256k1: &'static str,
		encoded_public_key_ed25519: &'static str,
	}

	const PRIVATE_ACCOUNT_TEST_DATA: PrivateAccountTestData = PrivateAccountTestData {
		seed: "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D",
		indexes: &[
			PrivateKeyTestCase {
				encoded_public_key_ecdsa_secp256k1:
				// cspell:disable-next-line
					"keeta_aabbk6vq5mjvityvqnrvz6g3f3jr72oqfeqg4fqbaa4s5sisrdlfhkfr5p7chey",
				// cspell:disable-next-line
				encoded_public_key_ed25519: "keeta_ahcp4hwh26cinhsilat6tiolefkt5tlqk4ebrxjwpodkziuvxre3x3r2wf5l6",
			},
			PrivateKeyTestCase {
				encoded_public_key_ecdsa_secp256k1:
				// cspell:disable-next-line
					"keeta_aabenomfdx4qdgspfmllant23pq5bqe6g74ecy5gc42htzcl5fg5zdr55yndzra",
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
		},
	];

	#[test]
	fn test_basic_account_generation() {
		/*
		 * Basic test that generating an account from a random passphrase works
		 */
		{
			let passphrase = Account::<KeyECDSASECP256K1>::generate_passphrase().unwrap();
			let passphrase = passphrase.expose_secret();
			let account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase.to_owned(), 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			assert_eq!(account.keypair.keypair_type(), KeyPairType::ECDSASECP256K1);
			assert_eq!(account.keypair_type(), KeyPairType::ECDSASECP256K1);
		}

		// Test Ed25519 as well
		{
			let passphrase = Account::<KeyED25519>::generate_passphrase().unwrap();
			let passphrase = passphrase.expose_secret();
			let account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase.to_owned(), 0)),
				KeyPairType::ED25519,
			))
			.unwrap();

			assert_eq!(account.keypair.keypair_type(), KeyPairType::ED25519);
			assert_eq!(account.keypair_type(), KeyPairType::ED25519);
		}
	}

	#[test]
	fn test_secp256k1_deterministic() {
		for test_case in TEST_CASES {
			let passphrase: Vec<String> = test_case.passphrase.iter().map(|s| s.to_string()).collect();

			// Test passphrase -> seed conversion (expect consistent results)
			let seed1 = Account::<KeyECDSASECP256K1>::compute_seed_from_passphrase(passphrase.clone()).unwrap();
			let account1 = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase, 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			assert!(
				account1.keypair.public_key.starts_with("keeta_"),
				"Passphrase-derived key should be properly formatted"
			);

			// Test hex seed
			let account2 = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::HexSeed((test_case.hex_seed.to_string(), 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();
			let account3 = Account::<KeyECDSASECP256K1>::new(Accountable::Key(account2.clone().keypair)).unwrap();
			let account4 = Account::<KeyECDSASECP256K1>::new(Accountable::Account(account2.clone())).unwrap();

			// Test deterministic passphrase behavior
			let seed2 = Account::<KeyECDSASECP256K1>::compute_seed_from_passphrase(
				test_case.passphrase.iter().map(|s| s.to_string()).collect(),
			)
			.unwrap();

			// Verify that the same passphrase produces the same seed
			assert_eq!(seed1, seed2, "Same passphrase should produce same seed");
			// Verify deterministic behavior for different construction methods
			assert_eq!(account2.keypair.public_key, account3.keypair.public_key);
			assert_eq!(account2.keypair.public_key, account4.keypair.public_key);
			// Verify expected public key format (this tests our crypto integration)
			assert_eq!(account2.keypair.public_key, test_case.expected_secp256k1_pubkey);
		}
	}
	#[test]
	fn test_ed25519_deterministic() {
		for test_case in TEST_CASES {
			let passphrase: Vec<String> = test_case.passphrase.iter().map(|s| s.to_string()).collect();

			// Test passphrase -> seed conversion (expect consistent results)
			let seed1 = Account::<KeyED25519>::compute_seed_from_passphrase(passphrase.clone()).unwrap();
			let account1 = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase, 0)),
				KeyPairType::ED25519,
			))
			.unwrap();

			assert!(
				account1.keypair.public_key.starts_with("keeta_"),
				"Passphrase-derived key should be properly formatted"
			);

			// Test hex seed
			let account2 = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::HexSeed((test_case.hex_seed.to_string(), 0)),
				KeyPairType::ED25519,
			))
			.unwrap();
			let account3 = Account::<KeyED25519>::new(Accountable::Key(account2.clone().keypair)).unwrap();
			let account4 = Account::<KeyED25519>::new(Accountable::Account(account2.clone())).unwrap();

			// Test deterministic passphrase behavior
			let seed2 = Account::<KeyED25519>::compute_seed_from_passphrase(
				test_case.passphrase.iter().map(|s| s.to_string()).collect(),
			)
			.unwrap();

			// Verify that the same passphrase produces the same seed
			assert_eq!(seed1, seed2, "Same passphrase should produce same seed");
			// Verify deterministic behavior for different construction methods
			assert_eq!(account2.keypair.public_key, account3.keypair.public_key);
			assert_eq!(account2.keypair.public_key, account4.keypair.public_key);
			// Verify expected public key format (this tests our crypto integration)
			assert_eq!(account2.keypair.public_key, test_case.expected_ed25519_pubkey);
		}
	}

	#[test]
	fn test_algorithm_differences() {
		for test_case in TEST_CASES {
			// Create accounts with the same seed but different algorithms
			let secp256k1_account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::HexSeed((test_case.hex_seed.to_string(), 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			let ed25519_account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::HexSeed((test_case.hex_seed.to_string(), 0)),
				KeyPairType::ED25519,
			))
			.unwrap();

			// Verify that different algorithms produce different public keys
			assert_ne!(secp256k1_account.keypair.public_key, ed25519_account.keypair.public_key);
			// Verify each matches expected output
			assert_eq!(secp256k1_account.keypair.public_key, test_case.expected_secp256k1_pubkey);
			assert_eq!(ed25519_account.keypair.public_key, test_case.expected_ed25519_pubkey);
		}
	}

	#[test]
	fn test_identifier_key_types() {
		// Test NETWORK identifier key
		let network_key = KeyNETWORK::new(Keyable::Identifier("test-network-id".to_string())).unwrap();
		assert_eq!(network_key.identifier, "test-network-id");
		assert_eq!(network_key.public_key, "network_test-network-id");
		assert_eq!(network_key.keypair_type(), KeyPairType::NETWORK);

		// Test TOKEN identifier key
		let token_key = KeyTOKEN::new(Keyable::Identifier("test-token-id".to_string())).unwrap();
		assert_eq!(token_key.identifier, "test-token-id");
		assert_eq!(token_key.public_key, "token_test-token-id");
		assert_eq!(token_key.keypair_type(), KeyPairType::TOKEN);

		// Test STORAGE identifier key
		let storage_key = KeySTORAGE::new(Keyable::Identifier("test-storage-id".to_string())).unwrap();
		assert_eq!(storage_key.identifier, "test-storage-id");
		assert_eq!(storage_key.public_key, "storage_test-storage-id");
		assert_eq!(storage_key.keypair_type(), KeyPairType::STORAGE);

		// Test that identifier keys fail with non-identifier input
		let result = KeyNETWORK::new(Keyable::Passphrase((vec!["test".to_string()], 0)));
		assert!(result.is_err());
	}

	#[test]
	fn test_typescript_compatibility_private_accounts() {
		// Test deterministic key derivation from seed matches TypeScript results
		for (index, test_case) in PRIVATE_ACCOUNT_TEST_DATA.indexes.iter().enumerate() {
			let seed_bytes = hex::decode(PRIVATE_ACCOUNT_TEST_DATA.seed).unwrap();
			let seed: [u8; 32] = seed_bytes.try_into().unwrap();

			// Test ECDSA SECP256K1 derivation
			let secp256k1_account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::Seed((seed, index as u32)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			// Test Ed25519 derivation
			let ed25519_account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::Seed((seed, index as u32)),
				KeyPairType::ED25519,
			))
			.unwrap();

			// Verify public key format matches TypeScript
			assert_eq!(
				secp256k1_account.keypair.public_key, test_case.encoded_public_key_ecdsa_secp256k1,
				"SECP256K1 public key mismatch at index {index}"
			);
			assert_eq!(
				ed25519_account.keypair.public_key, test_case.encoded_public_key_ed25519,
				"Ed25519 public key mismatch at index {index}"
			);
		}
	}

	#[test]
	fn test_key_type_identification() {
		// Test KeyPairType identification methods
		assert!(KeyPairType::NETWORK.is_identifier());
		assert!(KeyPairType::TOKEN.is_identifier());
		assert!(KeyPairType::STORAGE.is_identifier());
		assert!(!KeyPairType::ECDSASECP256K1.is_identifier());
		assert!(!KeyPairType::ED25519.is_identifier());
		assert!(!KeyPairType::ECDSASECP256R1.is_identifier());

		assert!(KeyPairType::ECDSASECP256K1.supports_crypto());
		assert!(KeyPairType::ED25519.supports_crypto());
		assert!(KeyPairType::ECDSASECP256R1.supports_crypto());
		assert!(!KeyPairType::NETWORK.supports_crypto());
		assert!(!KeyPairType::TOKEN.supports_crypto());
		assert!(!KeyPairType::STORAGE.supports_crypto());
	}

	#[test]
	fn test_passphrase_to_seed_compatibility() {
		// Test passphrase derivation matches TypeScript
		// Based on TypeScript 'Seed Derivation from Passphrase' test
		struct PassphraseTest {
			passphrase: &'static str,
			expected_seed: &'static str,
		}

		let passphrase_tests = &[
			PassphraseTest {
				passphrase: "this is the example length for a sufficient passphrase to be set secured",
				expected_seed: "df6ad96e3900ea44eca45d01362a32bfa875e8b1cccc4b4b8758926a68698e42",
			},
			PassphraseTest {
				passphrase: "one one one one one one one one one one one one one one one one one one one one",
				expected_seed: "d1d26dce216ae8633c98d8ebe9b4048ae4ef9fa51db317328d9e0ab11ac79717",
			},
		];

		for test in passphrase_tests {
			let result_seed = seed_from_passphrase(test.passphrase).unwrap();
			let result_hex = hex::encode(result_seed).to_lowercase();
			assert_eq!(result_hex, test.expected_seed, "Passphrase seed mismatch for: {}", test.passphrase);
		}
	}
}
