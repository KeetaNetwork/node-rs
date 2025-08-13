#![allow(unused_imports)]
#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crypto::algorithms::ed25519::ed25519_to_x25519_private;
#[cfg(feature = "encryption")]
use crypto::algorithms::{Ecies, EciesSecp256k1, EciesSecp256r1, EciesX25519};
use crypto::{Algorithm, Ed25519Derivation, KeyDerivation, PrivateKey, Secp256k1Derivation, Secp256r1Derivation};

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

#[cfg(feature = "encryption")]
#[test]
fn test_ecies_typescript_compatibility() {
	for test_case in TEST_CASES {
		let seed = hex::decode(test_case.seed_hex).unwrap();
		let encrypted_data = BASE64.decode(test_case.encrypted_data_base64).unwrap();

		match test_case.algorithm {
			Algorithm::Secp256k1 => {
				let index = 0u32;
				// Combine seed and index like the accounts module does
				let mut indexed_seed = [0u8; 36];
				indexed_seed[..32].copy_from_slice(&seed);
				indexed_seed[32..].copy_from_slice(&index.to_be_bytes());

				let private_key = Secp256k1Derivation::derive_from_seed(indexed_seed).unwrap();
				let public_key = private_key.as_public_key();

				// Test decryption of TypeScript data
				let decrypted = EciesSecp256k1::decrypt(&private_key, &encrypted_data).unwrap();
				assert_eq!(decrypted, test_case.expected_plaintext.as_bytes());

				// Test round-trip encryption/decryption
				let rust_encrypted =
					EciesSecp256k1::encrypt(&public_key, test_case.expected_plaintext.as_bytes()).unwrap();
				let rust_decrypted = EciesSecp256k1::decrypt(&private_key, &rust_encrypted).unwrap();
				assert_eq!(rust_decrypted, test_case.expected_plaintext.as_bytes());
			}
			Algorithm::Ed25519 => {
				let index = 0u32;
				// Combine seed and index like the accounts module does
				let mut indexed_seed = [0u8; 36];
				indexed_seed[..32].copy_from_slice(&seed);
				indexed_seed[32..].copy_from_slice(&index.to_be_bytes());

				// Derive Ed25519 key first, then convert to X25519
				let ed25519_private = Ed25519Derivation::derive_from_seed(indexed_seed).unwrap();
				let x25519_private = ed25519_to_x25519_private(&ed25519_private).unwrap();
				let x25519_public = x25519_private.derive_public_key();

				// Test decryption of TypeScript data
				let decrypted = EciesX25519::decrypt(&x25519_private, &encrypted_data).unwrap();
				assert_eq!(decrypted, test_case.expected_plaintext.as_bytes());

				// Test round-trip encryption/decryption
				let rust_encrypted =
					EciesX25519::encrypt(&x25519_public, test_case.expected_plaintext.as_bytes()).unwrap();
				let rust_decrypted = EciesX25519::decrypt(&x25519_private, &rust_encrypted).unwrap();
				assert_eq!(rust_decrypted, test_case.expected_plaintext.as_bytes());
			}
			Algorithm::Secp256r1 => {
				let private_key = Secp256r1Derivation::derive_from_seed(&seed).unwrap();
				let public_key = private_key.as_public_key();

				// Test decryption of TypeScript data
				let decrypted = EciesSecp256r1::decrypt(&private_key, &encrypted_data).unwrap();
				assert_eq!(decrypted, test_case.expected_plaintext.as_bytes());

				// Test round-trip encryption/decryption
				let rust_encrypted =
					EciesSecp256r1::encrypt(&public_key, test_case.expected_plaintext.as_bytes()).unwrap();
				let rust_decrypted = EciesSecp256r1::decrypt(&private_key, &rust_encrypted).unwrap();
				assert_eq!(rust_decrypted, test_case.expected_plaintext.as_bytes());
			}
		}
	}
}
