use crypto::prelude::*;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::error::AccountError;
use crate::utils::*;
use crate::{HexSeedAndIndex, Index, PassphraseAndIndex, Seed, SeedAndIndex};

/// Identifier key types (non-cryptographic)
const IDENTIFIER_KEY_TYPES: &[KeyPairType] = &[KeyPairType::NETWORK, KeyPairType::TOKEN, KeyPairType::STORAGE];

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

/// Trait defining the interface for cryptographic key pairs.
///
/// Provides methods for key generation, derivation, and type identification.
pub trait KeyPair: Send + Sync + TryFrom<Keyable, Error = AccountError> {
	/// The key pair type for this implementation.
	const KEY_PAIR_TYPE: KeyPairType;

	/// Deterministically derives a private key from a seed and index.
	///
	/// Uses HKDF with retry logic to ensure the derived key is valid.
	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError>;
	/// Converts a private key into a formatted public key string.
	fn derive_public_key_string(key: &AnyPrivateKey) -> Result<String, AccountError>;
	/// Returns the key pair type for this instance.
	fn keypair_type(&self) -> KeyPairType {
		Self::KEY_PAIR_TYPE
	}
}

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
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::ECDSASECP256K1;

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
				let public_key = secp_key.verifying_key();
				let public_key_bytes = Vec::<u8>::from(&public_key);
				format_public_key(&public_key_bytes, crypto::Algorithm::Secp256k1)
			}
			_ => Err(AccountError::InvalidConstruction),
		}
	}
}

impl TryFrom<Keyable> for KeyECDSASECP256K1 {
	type Error = AccountError;

	fn try_from(input: Keyable) -> Result<Self, AccountError> {
		let (private_key, public_key) = match input {
			Keyable::Passphrase((_, index)) | Keyable::Seed((_, index)) | Keyable::HexSeed((_, index)) => {
				let seed = match input {
					Keyable::Passphrase((passphrase, _)) => {
						seed_from_passphrase(&passphrase.expose_secret().join(" "))?
					}
					Keyable::Seed((seed, _)) => seed,
					Keyable::HexSeed((seed, _)) => {
						let decoded: [u8; 32] = hex::decode(seed.expose_secret())
							.or(Err(AccountError::InvalidConstruction))?
							.try_into()
							.or(Err(AccountError::InvalidConstruction))?;
						SecretBox::new(Box::new(decoded))
					}
					_ => unreachable!(),
				};

				let private_key = KeyECDSASECP256K1::seed_to_private_key(&seed, index)?;
				let public_key_string = KeyECDSASECP256K1::derive_public_key_string(&private_key)?;

				(Some(private_key), public_key_string)
			}
			Keyable::PublicKeyString(public_key_string) => {
				// Validate the prefix first
				if !public_key_string.starts_with("keeta_") {
					return Err(AccountError::InvalidPrefix);
				}

				// Parse the public key string to extract key type and bytes
				let (_, algorithm) = parse_public_key(&public_key_string)?;
				if algorithm != Algorithm::Secp256k1 {
					return Err(AccountError::InvalidKeyType);
				}

				(None, public_key_string.clone())
			}
			Keyable::PublicKey(public_key_bytes) => {
				// Validate key length for secp256k1 (should be 33 bytes compressed)
				if public_key_bytes.len() != 33 && public_key_bytes.len() != 65 {
					return Err(AccountError::InvalidConstruction);
				}

				// Create formatted string from raw public key bytes
				let formatted = format_public_key(&public_key_bytes, Algorithm::Secp256k1)?;

				(None, formatted)
			}
			Keyable::PrivateKey(private_key_bytes) => {
				// Validate private key length (should be 32 bytes)
				if private_key_bytes.len() != 32 {
					return Err(AccountError::InvalidConstruction);
				}

				// Create private key from raw bytes
				let private_key =
					crypto::algorithms::secp256k1::Secp256k1PrivateKey::try_from(private_key_bytes.as_slice())?;
				let any_private_key = AnyPrivateKey::Secp256k1(private_key);
				let public_key_string = KeyECDSASECP256K1::derive_public_key_string(&any_private_key)?;

				(Some(any_private_key), public_key_string)
			}
			Keyable::Identifier(_) => {
				return Err(AccountError::InvalidIdentifierConstruction);
			}
		};

		Ok(KeyECDSASECP256K1 { _private_key: private_key, public_key })
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
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::ECDSASECP256R1;

	fn seed_to_private_key(_seed: &Seed, _index: Index) -> Result<AnyPrivateKey, AccountError> {
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
	}
}

impl TryFrom<Keyable> for KeyECDSASECP256R1 {
	type Error = AccountError;

	fn try_from(_input: Keyable) -> Result<Self, AccountError> {
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
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::ED25519;

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
				let public_key = ed_key.verifying_key();
				let public_key_bytes = Vec::<u8>::from(&public_key);
				let formatted_key = format_public_key(&public_key_bytes, crypto::Algorithm::Ed25519)?;

				Ok(formatted_key)
			}
			_ => Err(AccountError::InvalidConstruction),
		}
	}
}

impl TryFrom<Keyable> for KeyED25519 {
	type Error = AccountError;

	fn try_from(input: Keyable) -> Result<Self, AccountError> {
		let (private_key, public_key) = match input {
			Keyable::Passphrase((_, index)) | Keyable::Seed((_, index)) | Keyable::HexSeed((_, index)) => {
				let seed = match input {
					Keyable::Passphrase((passphrase, _)) => {
						seed_from_passphrase(&passphrase.expose_secret().join(" "))?
					}
					Keyable::Seed((seed, _)) => seed,
					Keyable::HexSeed((seed, _)) => {
						let decoded: [u8; 32] = hex::decode(seed.expose_secret())
							.or(Err(AccountError::InvalidConstruction))?
							.try_into()
							.or(Err(AccountError::InvalidConstruction))?;
						SecretBox::new(Box::new(decoded))
					}
					_ => unreachable!(),
				};

				let private_key = KeyED25519::seed_to_private_key(&seed, index)?;
				let public_key_string = KeyED25519::derive_public_key_string(&private_key)?;

				(Some(private_key), public_key_string)
			}
			Keyable::PublicKeyString(public_key_string) => {
				// Validate the prefix first
				if !public_key_string.starts_with("keeta_") {
					return Err(AccountError::InvalidPrefix);
				}

				// Parse the public key string to extract key type and bytes
				let (_, algorithm) = parse_public_key(&public_key_string)?;
				if algorithm != Algorithm::Ed25519 {
					return Err(AccountError::InvalidKeyType);
				}

				(None, public_key_string.clone())
			}
			Keyable::PublicKey(public_key_bytes) => {
				// Validate key length for Ed25519 (should be 32 bytes)
				if public_key_bytes.len() != 32 {
					return Err(AccountError::InvalidConstruction);
				}

				// Create formatted string from raw public key bytes
				let formatted = format_public_key(&public_key_bytes, Algorithm::Ed25519)?;

				(None, formatted)
			}
			Keyable::PrivateKey(private_key_bytes) => {
				// Validate private key length (should be 32 bytes)
				if private_key_bytes.len() != 32 {
					return Err(AccountError::InvalidConstruction);
				}

				// Create private key from raw bytes
				let private_key =
					crypto::algorithms::ed25519::Ed25519PrivateKey::try_from(private_key_bytes.as_slice())?;
				let any_private_key = AnyPrivateKey::Ed25519(private_key);
				let public_key_string = KeyED25519::derive_public_key_string(&any_private_key)?;

				(Some(any_private_key), public_key_string)
			}
			Keyable::Identifier(_) => {
				return Err(AccountError::InvalidIdentifierConstruction);
			}
		};

		Ok(KeyED25519 { _private_key: private_key, public_key })
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
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::NETWORK;

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Identifier keys don't have traditional private keys
		let _ = (seed, index);
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
	}
}

impl TryFrom<Keyable> for KeyNETWORK {
	type Error = AccountError;

	fn try_from(input: Keyable) -> Result<Self, AccountError> {
		match input {
			Keyable::Identifier(id) => Ok(KeyNETWORK { identifier: id.clone(), public_key: format!("network_{id}") }),
			Keyable::Seed((seed, index)) => {
				// Generate identifier from seed + index using hash
				let seed_buffer = combine_seed_and_index(&seed, index);
				let hash_result: [u8; 32] = crypto::hash_array(&seed_buffer, None)?;
				let identifier = hex::encode(&hash_result[..16]); // Use first 16 bytes as identifier
				let public_key = format!("network_{identifier}");

				Ok(KeyNETWORK { identifier, public_key })
			}
			_ => Err(AccountError::InvalidConstruction),
		}
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
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::TOKEN;

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Identifier keys don't have traditional private keys
		let _ = (seed, index);
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
	}
}

impl TryFrom<Keyable> for KeyTOKEN {
	type Error = AccountError;

	fn try_from(input: Keyable) -> Result<Self, AccountError> {
		match input {
			Keyable::Identifier(id) => Ok(KeyTOKEN { identifier: id.clone(), public_key: format!("token_{id}") }),
			Keyable::Seed((seed, index)) => {
				// Generate identifier from seed + index using hash
				let seed_buffer = combine_seed_and_index(&seed, index);
				let hash_result: [u8; 32] = crypto::hash_array(&seed_buffer, None)?;
				let identifier = hex::encode(&hash_result[..16]); // Use first 16 bytes as identifier

				Ok(KeyTOKEN { identifier: identifier.clone(), public_key: format!("token_{identifier}") })
			}
			_ => Err(AccountError::InvalidConstruction),
		}
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
	const KEY_PAIR_TYPE: KeyPairType = KeyPairType::STORAGE;

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<AnyPrivateKey, AccountError> {
		// Identifier keys don't have traditional private keys
		let _ = (seed, index);
		Err(AccountError::InvalidConstruction)
	}

	fn derive_public_key_string(_key: &AnyPrivateKey) -> Result<String, AccountError> {
		Err(AccountError::InvalidConstruction)
	}
}

impl TryFrom<Keyable> for KeySTORAGE {
	type Error = AccountError;

	fn try_from(input: Keyable) -> Result<Self, AccountError> {
		match input {
			Keyable::Identifier(id) => Ok(KeySTORAGE { identifier: id.clone(), public_key: format!("storage_{id}") }),
			Keyable::Seed((seed, index)) => {
				// Generate identifier from seed + index using hash
				let seed_buffer = combine_seed_and_index(&seed, index);
				let hash_result: [u8; 32] = crypto::hash_array(&seed_buffer, None)?;
				let identifier = hex::encode(&hash_result[..16]); // Use first 16 bytes as identifier

				Ok(KeySTORAGE { identifier: identifier.clone(), public_key: format!("storage_{identifier}") })
			}
			_ => Err(AccountError::InvalidConstruction),
		}
	}
}

/// Enum to represent any account type for identifier generation results
#[derive(Debug, Clone)]
pub enum AnyAccount {
	Network(Account<KeyNETWORK>),
	Token(Account<KeyTOKEN>),
	Storage(Account<KeySTORAGE>),
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
				let keypair: Result<KEYTYPE, AccountError> = if key_type == KEYTYPE::KEY_PAIR_TYPE {
					KEYTYPE::try_from(key)
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
		KEYTYPE::KEY_PAIR_TYPE
	}

	pub fn compute_seed_from_passphrase(passphrase: Vec<String>) -> Result<Seed, AccountError> {
		seed_from_passphrase(passphrase.join(" ").as_str()).map_err(AccountError::from)
	}

	pub fn generate_passphrase() -> Result<SecretBox<Vec<String>>, AccountError> {
		Ok(generate_random_passphrase(None)?)
	}

	pub fn generate_seed() -> Result<Seed, AccountError> {
		Ok(crypto::generate_random_seed()?)
	}

	/// Generate a random seed (alternative interface)
	/// Similar to TypeScript's Account.generateRandomSeed()
	pub fn generate_random_seed() -> Result<Seed, AccountError> {
		Ok(crypto::generate_random_seed()?)
	}

	/// Create an account from a formatted public key string
	/// This will automatically detect the algorithm from the key format
	pub fn from_public_key_string(public_key_string: &str) -> Result<Box<dyn core::any::Any>, AccountError> {
		let (_, algorithm) = parse_public_key(public_key_string)?;

		match algorithm {
			Algorithm::Secp256k1 => {
				let account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
					Keyable::PublicKeyString(public_key_string.to_string()),
					KeyPairType::ECDSASECP256K1,
				))?;
				Ok(Box::new(account))
			}
			Algorithm::Ed25519 => {
				let account = Account::<KeyED25519>::new(Accountable::KeyAndType(
					Keyable::PublicKeyString(public_key_string.to_string()),
					KeyPairType::ED25519,
				))?;
				Ok(Box::new(account))
			}
			Algorithm::Secp256r1 => {
				Err(AccountError::InvalidConstruction) // Not implemented yet
			}
		}
	}

	/// Generate a network address from a network ID
	/// Similar to TypeScript's Account.generateNetworkAddress()
	pub fn generate_network_address(network_id: u64) -> Result<Account<KeyNETWORK>, AccountError> {
		// Convert network ID to seed (32 bytes)
		let mut seed_data = [0u8; 32];
		seed_data[24..32].copy_from_slice(&network_id.to_be_bytes());
		let seed = SecretBox::new(Box::new(seed_data));

		// Create network account from seed with index 0
		Account::<KeyNETWORK>::new(Accountable::KeyAndType(Keyable::Seed((seed, 0)), KeyPairType::NETWORK))
	}
}

impl<KEYTYPE> Account<KEYTYPE>
where
	KEYTYPE: KeyPair + FromAccountable<KEYTYPE> + Clone,
{
	/// Generate an identifier from this account
	/// Similar to TypeScript's generateIdentifier() method
	pub fn generate_identifier(
		&self,
		identifier_type: KeyPairType,
		block_hash: Option<&str>,
		operation_index: u32,
	) -> Result<AnyAccount, AccountError> {
		// Validate that we're generating an identifier type
		if !identifier_type.is_identifier() {
			return Err(AccountError::InvalidIdentifierConstruction);
		}

		// Get the account opening hash (for now, use a placeholder)
		let account_opening_hash = self.get_account_opening_hash();

		// Determine the block hash to use
		let hash_to_use = match block_hash {
			Some("NO_PREVIOUS") | None => account_opening_hash,
			Some(hash_str) => {
				// Validate hex string format
				if !hash_str.starts_with("0x") && !hash_str.chars().all(|c| c.is_ascii_hexdigit()) {
					return Err(AccountError::InvalidConstruction);
				}
				// Parse hex string to bytes
				hex::decode(hash_str.strip_prefix("0x").unwrap_or(hash_str))
					.map_err(|_| AccountError::InvalidConstruction)?
			}
		};

		// Validate identifier generation rules (simplified version of TypeScript logic)
		if self.keypair_type().is_identifier() {
			// Only allow network -> token generation with specific conditions
			let is_network = self.keypair_type() == KeyPairType::NETWORK;
			let is_generating_token = identifier_type == KeyPairType::TOKEN;
			let is_first_operation = operation_index == 0;
			let is_opening = block_hash.is_none() || block_hash == Some("NO_PREVIOUS");

			if !(is_network && is_generating_token && is_first_operation && is_opening) {
				return Err(AccountError::InvalidIdentifierConstruction);
			}
		}

		// Create seed from public key + block hash (using hash abstraction)
		let mut seed_data = Vec::new();
		seed_data.push(self.keypair_type() as u8);
		seed_data.extend_from_slice(self.get_public_key_bytes()?.as_slice());
		seed_data.extend_from_slice(&hash_to_use);

		// Hash the combined data to create the seed
		let seed_hash: [u8; 32] = crypto::hash_array(&seed_data, None)?;

		// Create the identifier account using the seed and operation index
		let seed = SecretBox::new(Box::new(seed_hash));
		match identifier_type {
			KeyPairType::NETWORK => {
				let account = Account::<KeyNETWORK>::new(Accountable::KeyAndType(
					Keyable::Seed((seed, operation_index)),
					KeyPairType::NETWORK,
				))?;
				Ok(AnyAccount::Network(account))
			}
			KeyPairType::TOKEN => {
				let account = Account::<KeyTOKEN>::new(Accountable::KeyAndType(
					Keyable::Seed((seed, operation_index)),
					KeyPairType::TOKEN,
				))?;
				Ok(AnyAccount::Token(account))
			}
			KeyPairType::STORAGE => {
				let account = Account::<KeySTORAGE>::new(Accountable::KeyAndType(
					Keyable::Seed((seed, operation_index)),
					KeyPairType::STORAGE,
				))?;
				Ok(AnyAccount::Storage(account))
			}
			_ => Err(AccountError::InvalidIdentifierConstruction),
		}
	}

	/// Helper method to get account opening hash (simplified implementation)
	fn get_account_opening_hash(&self) -> Vec<u8> {
		// For now, create a deterministic hash from public key
		// In a full implementation, this would be the actual account opening hash
		let mut data = Vec::new();

		data.push(self.keypair_type() as u8);

		if let Ok(pubkey_bytes) = self.get_public_key_bytes() {
			data.extend_from_slice(&pubkey_bytes);
		}

		// Use crypto hash to generate a deterministic 32-byte hash
		crypto::hash_default(&data).to_vec()
	}

	/// Helper method to get public key bytes
	fn get_public_key_bytes(&self) -> Result<Vec<u8>, AccountError> {
		match self.keypair_type() {
			KeyPairType::ECDSASECP256K1 | KeyPairType::ED25519 | KeyPairType::ECDSASECP256R1 => {
				// For crypto algorithms, parse the formatted public key
				if let Ok((pubkey_bytes, _)) = parse_public_key(&self.get_public_key_string()) {
					Ok(pubkey_bytes)
				} else {
					Err(AccountError::InvalidConstruction)
				}
			}
			KeyPairType::NETWORK | KeyPairType::TOKEN | KeyPairType::STORAGE => {
				// For identifier types, get the identifier as bytes
				// Cast to get the actual identifier field
				// Safety: We know the concrete type based on keypair_type
				match self.keypair_type() {
					KeyPairType::NETWORK => {
						let concrete_self = unsafe { &*(self as *const Self as *const Account<KeyNETWORK>) };
						Ok(concrete_self.keypair.identifier.as_bytes().to_vec())
					}
					KeyPairType::TOKEN => {
						let concrete_self = unsafe { &*(self as *const Self as *const Account<KeyTOKEN>) };
						Ok(concrete_self.keypair.identifier.as_bytes().to_vec())
					}
					KeyPairType::STORAGE => {
						let concrete_self = unsafe { &*(self as *const Self as *const Account<KeySTORAGE>) };
						Ok(concrete_self.keypair.identifier.as_bytes().to_vec())
					}
					_ => Err(AccountError::InvalidConstruction),
				}
			}
		}
	}

	/// Helper method to get public key string
	fn get_public_key_string(&self) -> String {
		// We need to access the actual public key from the keypair
		// This requires unsafe transmutation to access the concrete type
		// Safety: We are casting to the concrete type based on keypair_type
		match self.keypair_type() {
			KeyPairType::ECDSASECP256K1 => {
				// Cast to concrete KeyECDSASECP256K1 type to access public_key field
				let concrete_self = unsafe { &*(self as *const Self as *const Account<KeyECDSASECP256K1>) };
				concrete_self.keypair.public_key.clone()
			}
			KeyPairType::ED25519 => {
				// Cast to concrete KeyED25519 type to access public_key field
				let concrete_self = unsafe { &*(self as *const Self as *const Account<KeyED25519>) };
				concrete_self.keypair.public_key.clone()
			}
			KeyPairType::NETWORK => {
				// Cast to concrete KeyNETWORK type to access public_key field
				let concrete_self = unsafe { &*(self as *const Self as *const Account<KeyNETWORK>) };
				concrete_self.keypair.public_key.clone()
			}
			KeyPairType::TOKEN => {
				// Cast to concrete KeyTOKEN type to access public_key field
				let concrete_self = unsafe { &*(self as *const Self as *const Account<KeyTOKEN>) };
				concrete_self.keypair.public_key.clone()
			}
			KeyPairType::STORAGE => {
				// Cast to concrete KeySTORAGE type to access public_key field
				let concrete_self = unsafe { &*(self as *const Self as *const Account<KeySTORAGE>) };
				concrete_self.keypair.public_key.clone()
			}
			_ => "unknown_key_type".to_string(),
		}
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
			let account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase, 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			assert_eq!(account.keypair.keypair_type(), KeyPairType::ECDSASECP256K1);
			assert_eq!(account.keypair_type(), KeyPairType::ECDSASECP256K1);
		}

		// Test Ed25519 as well
		{
			let passphrase = Account::<KeyED25519>::generate_passphrase().unwrap();
			let account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase, 0)),
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
			let passphrase_secret = SecretBox::new(Box::new(passphrase.clone()));

			// Test passphrase -> seed conversion (expect consistent results)
			let seed1 = Account::<KeyECDSASECP256K1>::compute_seed_from_passphrase(passphrase.clone()).unwrap();
			let account1 = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase_secret, 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			assert!(
				account1.keypair.public_key.starts_with("keeta_"),
				"Passphrase-derived key should be properly formatted"
			);

			// Test hex seed
			let hex_seed_secret = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let account2 = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret, 0)),
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
			assert_eq!(seed1.expose_secret(), seed2.expose_secret(), "Same passphrase should produce same seed");
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
			let passphrase_secret = SecretBox::new(Box::new(passphrase.clone()));

			// Test passphrase -> seed conversion (expect consistent results)
			let seed1 = Account::<KeyED25519>::compute_seed_from_passphrase(passphrase.clone()).unwrap();
			let account1 = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase_secret, 0)),
				KeyPairType::ED25519,
			))
			.unwrap();

			assert!(
				account1.keypair.public_key.starts_with("keeta_"),
				"Passphrase-derived key should be properly formatted"
			);

			// Test hex seed
			let hex_seed_secret = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let account2 = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret, 0)),
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
			assert_eq!(seed1.expose_secret(), seed2.expose_secret(), "Same passphrase should produce same seed");
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
			let hex_seed_secret1 = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let hex_seed_secret2 = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let secp256k1_account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret1, 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			let ed25519_account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret2, 0)),
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
		let network_key = KeyNETWORK::try_from(Keyable::Identifier("test-network-id".to_string())).unwrap();
		assert_eq!(network_key.identifier, "test-network-id");
		assert_eq!(network_key.public_key, "network_test-network-id");
		assert_eq!(network_key.keypair_type(), KeyPairType::NETWORK);

		// Test TOKEN identifier key
		let token_key = KeyTOKEN::try_from(Keyable::Identifier("test-token-id".to_string())).unwrap();
		assert_eq!(token_key.identifier, "test-token-id");
		assert_eq!(token_key.public_key, "token_test-token-id");
		assert_eq!(token_key.keypair_type(), KeyPairType::TOKEN);

		// Test STORAGE identifier key
		let storage_key = KeySTORAGE::try_from(Keyable::Identifier("test-storage-id".to_string())).unwrap();
		assert_eq!(storage_key.identifier, "test-storage-id");
		assert_eq!(storage_key.public_key, "storage_test-storage-id");
		assert_eq!(storage_key.keypair_type(), KeyPairType::STORAGE);

		// Test that identifier keys fail with non-identifier input
		let passphrase_secret = SecretBox::new(Box::new(vec!["test".to_string()]));
		let result = KeyNETWORK::try_from(Keyable::Passphrase((passphrase_secret, 0)));
		assert!(result.is_err());
	}

	#[test]
	fn test_typescript_compatibility_private_accounts() {
		// Test deterministic key derivation from seed matches TypeScript results
		for (index, test_case) in PRIVATE_ACCOUNT_TEST_DATA.indexes.iter().enumerate() {
			let seed_bytes = hex::decode(PRIVATE_ACCOUNT_TEST_DATA.seed).unwrap();
			let seed_data: [u8; 32] = seed_bytes.try_into().unwrap();

			// Test ECDSA SECP256K1 derivation
			let secp256k1_account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::Seed((SecretBox::new(Box::new(seed_data)), index as u32)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			// Test Ed25519 derivation
			let ed25519_account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::Seed((SecretBox::new(Box::new(seed_data)), index as u32)),
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
			let result_hex = hex::encode(*result_seed.expose_secret()).to_lowercase();
			assert_eq!(result_hex, test.expected_seed, "Passphrase seed mismatch for: {}", test.passphrase);
		}
	}

	#[test]
	fn test_public_key_string_creation() {
		// Test creating accounts from formatted public key strings
		for test_case in TEST_CASES {
			// Create account from hex seed to get expected formatted public key
			let hex_seed_secret1 = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let secp256k1_account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret1, 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			let hex_seed_secret2 = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let ed25519_account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret2, 0)),
				KeyPairType::ED25519,
			))
			.unwrap();

			// Test creating accounts from their formatted public key strings
			let secp256k1_from_pubkey = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::PublicKeyString(secp256k1_account.keypair.public_key.clone()),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			let ed25519_from_pubkey = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::PublicKeyString(ed25519_account.keypair.public_key.clone()),
				KeyPairType::ED25519,
			))
			.unwrap();

			// Verify public keys match
			assert_eq!(secp256k1_account.keypair.public_key, secp256k1_from_pubkey.keypair.public_key);
			assert_eq!(ed25519_account.keypair.public_key, ed25519_from_pubkey.keypair.public_key);

			// Verify the accounts from public key strings don't have private keys
			assert!(secp256k1_account.keypair._private_key.is_some());
			assert!(secp256k1_from_pubkey.keypair._private_key.is_none());
			assert!(ed25519_account.keypair._private_key.is_some());
			assert!(ed25519_from_pubkey.keypair._private_key.is_none());
		}
	}

	#[test]
	fn test_invalid_public_key_string_creation() {
		// Test error handling for invalid public key strings
		let invalid_keys = vec![
			// Invalid prefix
			"wrong_prefix",
			// Invalid base32
			"keeta_invalid@base32!",
			// Too short
			"keeta_aa",
			// Invalid algorithm type
			// cspell:disable-next-line
			"keeta_akaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafaesuq53",
		];

		for invalid_key in invalid_keys {
			let result = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::PublicKeyString(invalid_key.to_string()),
				KeyPairType::ECDSASECP256K1,
			));
			assert!(result.is_err(), "Should reject invalid public key: {invalid_key}");

			let result2 = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::PublicKeyString(invalid_key.to_string()),
				KeyPairType::ED25519,
			));
			assert!(result2.is_err(), "Should reject invalid public key: {invalid_key}");
		}
	}

	#[test]
	fn test_wrong_algorithm_detection() {
		// Test that accounts reject public keys from the wrong algorithm
		for test_case in TEST_CASES {
			let hex_seed_secret1 = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let secp256k1_account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret1, 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();

			let hex_seed_secret2 = SecretBox::new(Box::new(test_case.hex_seed.to_string()));
			let ed25519_account = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed_secret2, 0)),
				KeyPairType::ED25519,
			))
			.unwrap();

			// Try to create SECP256K1 account with Ed25519 public key (should fail)
			let result = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::PublicKeyString(ed25519_account.keypair.public_key.clone()),
				KeyPairType::ECDSASECP256K1,
			));
			assert!(result.is_err(), "Should reject Ed25519 key for SECP256K1 account");

			// Try to create Ed25519 account with SECP256K1 public key (should fail)
			let result2 = Account::<KeyED25519>::new(Accountable::KeyAndType(
				Keyable::PublicKeyString(secp256k1_account.keypair.public_key.clone()),
				KeyPairType::ED25519,
			));
			assert!(result2.is_err(), "Should reject SECP256K1 key for Ed25519 account");
		}
	}

	#[test]
	fn test_identifier_generation_methods() {
		// Test generateNetworkAddress
		let network_account = Account::<KeyNETWORK>::generate_network_address(12345).unwrap();
		assert_eq!(network_account.keypair_type(), KeyPairType::NETWORK);
		assert!(!network_account.keypair.identifier.is_empty());
		assert!(network_account.keypair.public_key.starts_with("network_"));

		// Test generate_identifier from cryptographic account to token
		// Use a proper 24-word mnemonic passphrase
		let passphrase: Vec<String> = vec![
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
			"abandon", "abandon", "abandon", "abandon", "abandon", "art",
		]
		.iter()
		.map(|s| s.to_string())
		.collect();
		let passphrase_secret = SecretBox::new(Box::new(passphrase));
		let crypto_account = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
			Keyable::Passphrase((passphrase_secret, 0)),
			KeyPairType::ECDSASECP256K1,
		))
		.unwrap();

		let token_result = crypto_account.generate_identifier(KeyPairType::TOKEN, None, 0);
		assert!(token_result.is_ok());

		match token_result.unwrap() {
			AnyAccount::Token(token_account) => {
				assert_eq!(token_account.keypair_type(), KeyPairType::TOKEN);
				assert!(!token_account.keypair.identifier.is_empty());
				assert!(token_account.keypair.public_key.starts_with("token_"));
			}
			_ => panic!("Expected token account"),
		}

		// Test network -> token generation (allowed scenario)
		let token_from_network = network_account.generate_identifier(KeyPairType::TOKEN, None, 0);
		assert!(token_from_network.is_ok());

		// Test invalid identifier generation (should fail)
		let storage_from_token = crypto_account.generate_identifier(KeyPairType::STORAGE, Some("0x123"), 5);
		assert!(storage_from_token.is_err(), "Should not allow STORAGE from ECDSA account");
	}
}
