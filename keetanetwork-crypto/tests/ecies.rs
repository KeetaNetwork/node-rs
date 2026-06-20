#![allow(unused_imports)]
#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

#[cfg(feature = "encryption")]
use keetanetwork_crypto::algorithms::ecies::{Ecies, EciesSecp256k1, EciesSecp256r1, EciesX25519};
use keetanetwork_crypto::algorithms::ed25519::ed25519_to_x25519_private;
use keetanetwork_crypto::algorithms::ed25519::Ed25519Derivation;
use keetanetwork_crypto::algorithms::secp256k1::Secp256k1Derivation;
use keetanetwork_crypto::algorithms::secp256r1::Secp256r1Derivation;
use keetanetwork_crypto::algorithms::{Algorithm, KeyDerivation, PrivateKey};
use keetanetwork_crypto::IntoSecret;

struct TypeScriptTestCase {
	seed_hex: &'static str,
	encrypted_data_base64: &'static str,
	expected_plaintext: &'static str,
	algorithm: Algorithm,
}

const TEST_CASES: &[TypeScriptTestCase] = &[
	TypeScriptTestCase {
		seed_hex: "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D",
		encrypted_data_base64: "BI8ePLqAhgOQvUXsTqW8ifQ77eRhg7Z6FpxX5wd6xJfE+ErjHyuXFKNjSDMBgTAG6iKylZITJajh6Zdgcbpdvb3+pBN17zCaaOzAgpId4hcOG3P/ueHMRWolYQPJ5jGqM1xmBO64sa3nodxDwEtAI5dA3CG4mg==",
		expected_plaintext: "Hello",
		algorithm: Algorithm::Secp256k1,
	},
	TypeScriptTestCase {
		seed_hex: "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D",
		encrypted_data_base64: "fZazrME6jGTTj2Dp1o9imAuri5s3MxeE0ZnK8HP2dK4TgnAJ3825UWKFaQnW0E0tETD0iyo8B1Zex4JUB7Ab83RnJrWBxGfoho6YqaKdHTWYfAPPJ1G2EBkDo1qoiGpO8t1Tb3o9JiOQf6jAMp2VKg==",
		expected_plaintext: "Ed25519 Encryption",
		algorithm: Algorithm::Ed25519,
	},
	TypeScriptTestCase {
		seed_hex: "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D",
		encrypted_data_base64: "BBF2ML5v5BMyOu/BMChxa984vGgED2rjaM5I0QP01MmjdMWnHx/00AfpxSCaVkFx3qYbl4cpxBM3WcHo9PIZG5P1CMv36lv8wmMMus+xQ/KrUozna8hLRlJN9ez3i+vzOZeMKYm9EfkpMZ2eQv1y1clevkvKicA8V+Zt3CVog0MhT9HYuTwWWN9yoxfshAlqGpODSFiHabdLG3E4er2d9q8=",
		expected_plaintext: "Hello",
		algorithm: Algorithm::Secp256r1,
	},
];

/// Combine a 32-byte seed with a big-endian index exactly as the
/// accounts module does before key derivation.
#[cfg(feature = "encryption")]
fn indexed_seed(seed: &[u8], index: u32) -> [u8; 36] {
	let mut indexed = [0u8; 36];
	indexed[..32].copy_from_slice(seed);
	indexed[32..].copy_from_slice(&index.to_be_bytes());
	indexed
}

/// Decrypt the TypeScript-produced ciphertext, then prove a Rust
/// encrypt/decrypt round-trip yields the same plaintext.
#[cfg(feature = "encryption")]
fn assert_ecies_round_trip<E: Ecies>(
	private_key: &E::PrivateKey,
	public_key: &E::PublicKey,
	encrypted_data: &[u8],
	expected_plaintext: &[u8],
) -> Result<(), Box<dyn core::error::Error>> {
	let decrypted = E::decrypt(private_key, encrypted_data)?;
	assert_eq!(decrypted, expected_plaintext);

	let rust_encrypted = E::encrypt(public_key, expected_plaintext)?;
	let rust_decrypted = E::decrypt(private_key, &rust_encrypted)?;
	assert_eq!(rust_decrypted, expected_plaintext);
	Ok(())
}

#[cfg(feature = "encryption")]
#[test]
fn test_ecies_typescript_compatibility() -> Result<(), Box<dyn core::error::Error>> {
	for test_case in TEST_CASES {
		let seed = hex::decode(test_case.seed_hex)?;
		let encrypted_data = BASE64.decode(test_case.encrypted_data_base64)?;
		let expected_plaintext = test_case.expected_plaintext.as_bytes();

		match test_case.algorithm {
			Algorithm::Secp256k1 => {
				let private_key = Secp256k1Derivation::derive_from_seed(indexed_seed(&seed, 0).into_secret())?;
				let public_key = private_key.as_public_key();
				assert_ecies_round_trip::<EciesSecp256k1>(
					&private_key,
					&public_key,
					&encrypted_data,
					expected_plaintext,
				)?;
			}
			Algorithm::Ed25519 => {
				let ed25519_private = Ed25519Derivation::derive_from_seed(indexed_seed(&seed, 0).into_secret())?;
				let x25519_private = ed25519_to_x25519_private(&ed25519_private)?;
				let x25519_public = x25519_private.derive_public_key();
				assert_ecies_round_trip::<EciesX25519>(
					&x25519_private,
					&x25519_public,
					&encrypted_data,
					expected_plaintext,
				)?;
			}
			Algorithm::Secp256r1 => {
				let private_key = Secp256r1Derivation::derive_from_seed(seed.into_secret())?;
				let public_key = private_key.as_public_key();
				assert_ecies_round_trip::<EciesSecp256r1>(
					&private_key,
					&public_key,
					&encrypted_data,
					expected_plaintext,
				)?;
			}
		}
	}
	Ok(())
}
