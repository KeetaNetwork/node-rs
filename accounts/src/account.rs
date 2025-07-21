use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ops::Reduce;
use k256::{NonZeroScalar, Scalar, SecretKey as K256SecretKey, U256};
use secrecy::SecretBox;
use sha3::Digest as _;

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
	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<K256SecretKey, AccountError>;
	/// Converts a private key into a formatted public key string.
	fn derive_public_key_string(key: &K256SecretKey) -> Result<String, AccountError>;
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
	_private_key: Option<K256SecretKey>,
	pub public_key: String, //[u8; 65],
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

	fn seed_to_private_key(seed: &Seed, index: Index) -> Result<K256SecretKey, AccountError> {
		for attempt in 0..1000 {
			let seed_buffer = combine_seed_and_index(seed, index.wrapping_add(attempt));
			let mut key_bytes: [u8; 32] = [0u8; 32];

			let hkdf_object =
				hkdf::Hkdf::<sha3::Sha3_256>::from_prk(&seed_buffer).map_err(|_| AccountError::InvalidConstruction)?;

			hkdf_object.expand(&[0u8; 0], &mut key_bytes).map_err(|_| AccountError::InvalidConstruction)?;

			// Convert bytes to U256 and reduce modulo curve order
			let x = U256::from_be_slice(&key_bytes);
			let scalar = Scalar::reduce(x);

			// Try to create NonZeroScalar (handles zero check automatically)
			if let Some(nonzero_scalar) = NonZeroScalar::new(scalar).into_option() {
				let secret_key = K256SecretKey::from(nonzero_scalar);
				return Ok(secret_key);
			}

			// If scalar was zero, continue to next attempt
		}

		// If we've tried 1000 attempts and all were zero (extremely unlikely)
		Err(AccountError::InvalidConstruction)
	}

	// XXX:TODO Make this more generic and move to the Account object
	fn derive_public_key_string(key: &K256SecretKey) -> Result<String, AccountError> {
		// Get the verifying (public) key from the secret key
		let signing_key = SigningKey::from(key.clone());
		let verifying_key = signing_key.verifying_key();
		// Get the compressed public key bytes (33 bytes, 0x02/0x03 prefix)
		let encoded_point = verifying_key.to_encoded_point(true); // true = compressed
		let serialized = encoded_point.as_bytes();

		let mut pub_key_values = vec![0u8; 1];
		pub_key_values.extend_from_slice(serialized);

		let checksum_of = Vec::from(&pub_key_values[..]);
		let mut hasher = sha3::Sha3_256::new();
		hasher.update(&checksum_of);

		let checksum = hasher.finalize();

		// Copy the first 5 bytes of the checksum to the public key
		pub_key_values.extend_from_slice(&checksum[..5]);
		if pub_key_values.len() != 38 && pub_key_values.len() != 39 {
			return Err(AccountError::InvalidConstruction);
		}

		let pub_key_formatted = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &pub_key_values);

		Ok(format!("keeta_{pub_key_formatted}"))
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

	// XXX:This needs to be more generic and not just for secp256k1
	fn seed_to_private_key(_seed: &Seed, _index: Index) -> Result<K256SecretKey, AccountError> {
		panic!("not implemented");
	}

	fn derive_public_key_string(_key: &K256SecretKey) -> Result<String, AccountError> {
		panic!("not implemented");
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

	#[test]
	fn account() {
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

		/*
		 * Ensure that generating an account from a passphrase, hex seed,
		 * keypair, and account all produces the same result
		 */
		{
			let hex_seed = "8C9CF402025839A0D7E568A375EBED1EEA2EFE6690C65FB015AD446FD299ABE2".to_string();
			let passphrase: Vec<String> = [
				"public", "sketch", "attract", "blame", "verify", "faculty", "anchor", "bargain", "acid", "tonight",
				"speed", "spike", "source", "hire", "amused", "improve", "shaft", "phrase", "permit", "napkin",
				"video", "object", "finger", "waste",
			]
			.to_vec()
			.into_iter()
			.map(|s| s.to_string())
			.collect();

			let seed1 = Account::<KeyECDSASECP256K1>::compute_seed_from_passphrase(passphrase.clone()).unwrap();
			let account1 = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::Passphrase((passphrase, 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();
			let account2 = Account::<KeyECDSASECP256K1>::new(Accountable::KeyAndType(
				Keyable::HexSeed((hex_seed.clone(), 0)),
				KeyPairType::ECDSASECP256K1,
			))
			.unwrap();
			let account3 = Account::<KeyECDSASECP256K1>::new(Accountable::Key(account2.clone().keypair)).unwrap();
			let account4 = Account::<KeyECDSASECP256K1>::new(Accountable::Account(account2.clone())).unwrap();

			assert_eq!(hex::encode(seed1).to_ascii_uppercase(), hex_seed);
			assert_eq!(account1.keypair.public_key, account2.keypair.public_key);
			assert_eq!(account1.keypair.public_key, account3.keypair.public_key);
			assert_eq!(account1.keypair.public_key, account4.keypair.public_key);
		}
	}
}
