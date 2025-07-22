use crypto::{
	algorithms::{Algorithm, Ed25519Derivation, KeyDerivation, PrivateKey, PublicKey, Secp256k1Derivation},
	AnyPrivateKey,
};
use secrecy::SecretBox;
use zeroize::Zeroize;

use crate::error::AccountError;
use crate::utils::*;
use crate::{Index, Seed};

/// Supported cryptographic key pair types.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyPairType {
	/// ECDSA over secp256k1 curve
	ECDSASECP256K1 = 0,
	/// ECDSA over secp256r1 curve
	ECDSASECP256R1 = 6,
	/// Ed25519 digital signature algorithm
	ED25519 = 1,
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
		}
	}
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

	// XXX:TODO Make this more generic and move to the Account object
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

pub enum Accountable<T>
where
	T: KeyPair,
{
	Key(T),
	Account(Account<T>),
	KeyAndType(Keyable, KeyPairType),
}

/**
 * A generic account object, which represents a keypair
 */
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

	// Test data structure for data-driven testing
	struct TestCase {
		name: &'static str,
		hex_seed: &'static str,
		passphrase: &'static [&'static str],
		expected_secp256k1_pubkey: &'static str,
		expected_ed25519_pubkey: &'static str,
	}

	const TEST_CASES: &[TestCase] = &[
		TestCase {
			name: "original test case",
			hex_seed: "8C9CF402025839A0D7E568A375EBED1EEA2EFE6690C65FB015AD446FD299ABE2",
			passphrase: &[
				"public", "sketch", "attract", "blame", "verify", "faculty", "anchor", "bargain", "acid", "tonight",
				"speed", "spike", "source", "hire", "amused", "improve", "shaft", "phrase", "permit", "napkin",
				"video", "object", "finger", "waste",
			],
			// cspell:disable-next-line
			expected_secp256k1_pubkey: "keeta_aabpyhesa7uahwgemfb2r2w3pqmd3valso7oemwqiplt35uiyedasxnk67s6sia",
			// cspell:disable-next-line
			expected_ed25519_pubkey: "keeta_ahyzjf3rq5gzrxt24ydbzuzdpxpn55fxuoeuenkggqle3cshqkf4unv4v5bys",
		},
		TestCase {
			name: "second test case",
			hex_seed: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
			passphrase: &[
				"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
				"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
				"abandon", "abandon", "abandon", "abandon", "abandon", "art",
			],
			// cspell:disable-next-line
			expected_secp256k1_pubkey: "keeta_aabagboefeiaiy4pk3ot4dbwcy446hfxberxeopubiqlyxhlilmeahajcpf5oby",
			// cspell:disable-next-line
			expected_ed25519_pubkey: "keeta_ae6ykqqqlcnmzqgpdkfnd3l75z5n6f7t4scfmowfnurqkfu4h64b3gon3md5m",
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
			println!("Testing secp256k1 with: {}", test_case.name);

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
			println!("Testing Ed25519 with: {}", test_case.name);

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
			println!("Testing algorithm differences with: {}", test_case.name);

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
}
