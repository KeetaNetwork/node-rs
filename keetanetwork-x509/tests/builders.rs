mod common;

use chrono::{TimeZone, Utc};
use der::{Decode, Encode};
use keetanetwork_account::{Account, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyPair};
use keetanetwork_asn1::{BitString, SubjectPublicKeyInfo};
use keetanetwork_crypto::algorithms::secp256k1::Secp256k1Derivation;
use keetanetwork_crypto::algorithms::secp256r1::Secp256r1Derivation;
use keetanetwork_crypto::prelude::Algorithm;
use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret, KeyDerivation};
use keetanetwork_crypto::utils::generate_random_seed;
use keetanetwork_x509::certificates::*;
use keetanetwork_x509::{oids, utils};
use keetanetwork_x509::{SerialNumber, SubjectPublicKeyInfoOwned, Version};

#[cfg(all(feature = "rasn", not(feature = "der")))]
use keetanetwork_asn1::BitStringExt;

use common::*;

#[test]
fn test_certificate_builder_basic() {
	let cert_moment = test_moment();
	let valid_from = cert_moment - chrono::Duration::hours(12);
	let valid_to = cert_moment + chrono::Duration::hours(12);

	// Test building certificates from test keys
	for (index, algorithm) in [(0, Algorithm::Ed25519), (1, Algorithm::Secp256r1), (2, Algorithm::Secp256k1)] {
		let public_key = create_test_public_key(index, algorithm).unwrap();
		let issuer_public_key = create_test_public_key(index + 10, algorithm).unwrap();

		// Create a proper TBS certificate
		let tbs = create_certificate_tbs(
			&public_key,
			&issuer_public_key,
			index as u64 + 1,
			valid_from,
			valid_to,
			false,
			algorithm,
		)
		.unwrap();

		// Verify the certificate can be encoded
		let tbs_der = tbs.to_der().unwrap();
		assert!(!tbs_der.is_empty());

		// Verify it can be decoded back
		let decoded_tbs = TbsCertificate::from_der(&tbs_der).unwrap();
		assert_eq!(decoded_tbs.serial_number, tbs.serial_number);

		// Verify the public key info matches
		#[cfg(feature = "der")]
		assert_eq!(
			decoded_tbs
				.subject_public_key_info
				.subject_public_key
				.as_bytes()
				.unwrap()
				.to_vec(),
			public_key
		);
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		assert_eq!(
			decoded_tbs
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
			&public_key
		);

		// Verify correct algorithm OID
		let expected_oid = match algorithm {
			Algorithm::Ed25519 => oids::ED25519,
			Algorithm::Secp256r1 | Algorithm::Secp256k1 => oids::ECDSA_WITH_SHA256,
		};
		assert_eq!(
			decoded_tbs
				.subject_public_key_info
				.algorithm
				.oid
				.to_string(),
			expected_oid
		);
	}
}

#[test]
fn test_certificate_builder_ca() {
	let cert_moment = test_moment();
	let valid_from = cert_moment - chrono::Duration::hours(12);
	let valid_to = cert_moment + chrono::Duration::hours(12);

	// Test creating actual CA certificate
	let root_public_key = create_test_public_key(0, Algorithm::Ed25519).unwrap();
	let root_tbs = create_certificate_tbs(
		&root_public_key,
		&root_public_key, // Self-signed
		1,
		valid_from,
		valid_to,
		true, // CA certificate
		Algorithm::Ed25519,
	)
	.unwrap();

	// Verify CA extensions are properly set
	if let Some(extensions) = &root_tbs.extensions {
		let extension_oids: Vec<String> = extensions
			.iter()
			.map(|ext| ext.extn_id.to_string())
			.collect();
		assert!(extension_oids.contains(&oids::BASIC_CONSTRAINTS.to_string()));
		assert!(extension_oids.contains(&oids::KEY_USAGE.to_string()));
		assert!(extension_oids.contains(&oids::SUBJECT_KEY_IDENTIFIER.to_string()));
		assert!(extension_oids.contains(&oids::AUTHORITY_KEY_IDENTIFIER.to_string()));
	}
}

#[test]
fn test_certificate_compatibility() {
	// Test certificate creation compatibility with different algorithms
	let test_cases = [
		(false, oids::ED25519, &RAW_ED25519_PUBLIC_KEY[..], "Ed25519 User", "Ed25519 CA"),
		(false, oids::ECDSA_WITH_SHA256, &RAW_SECP256R1_PUBLIC_KEY[..], "secp256r1 User", "secp256r1 CA"),
		(false, oids::ECDSA_WITH_SHA256, &RAW_SECP256R1_PUBLIC_KEY[..], "secp256k1 User", "secp256k1 CA"),
	];

	for (is_ca, algorithm_oid, public_key, subject_name, issuer_name) in test_cases {
		let subject_dn = utils::create_dn(&[(oids::CN, subject_name)]).unwrap();
		let issuer_dn = utils::create_dn(&[(oids::CN, issuer_name)]).unwrap();
		let algorithm = algorithm_oid.parse().unwrap();
		let subject_public_key = BitString::from_bytes(public_key).unwrap();
		let public_key_info = SubjectPublicKeyInfo { algorithm, subject_public_key };

		let serial = 1u64;
		let not_before = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
		let not_after = not_before + chrono::Duration::days(365);

		let builder = CertificateBuilder::new()
			.with_subject_public_key(public_key_info.clone())
			.with_subject_dn(subject_dn.clone())
			.with_issuer_dn(issuer_dn.clone())
			.with_validity(not_before, not_after)
			.with_serial_number(SerialNumber::from(serial))
			.with_is_ca(is_ca);

		let tbs = builder.build_tbs().unwrap();

		// Verify TBS certificate properties
		let expected_serial = SerialNumber::from(serial);
		assert_eq!(tbs.serial_number, expected_serial);
		assert_eq!(tbs.subject, subject_dn);
		assert_eq!(tbs.issuer, issuer_dn);

		let spki_public_key_info = SubjectPublicKeyInfoOwned::from(public_key_info);
		assert_eq!(tbs.subject_public_key_info, spki_public_key_info);
		assert_eq!(tbs.version, Version::V3);
		assert!(tbs.extensions.is_some());

		// Verify round trip
		let tbs_der = tbs.to_der().unwrap();
		assert!(!tbs_der.is_empty());
		let tbs_re_parsed = TbsCertificate::from_der(&tbs_der).unwrap();
		assert_eq!(tbs, tbs_re_parsed);
	}
}

#[test]
fn test_algorithm_chains() {
	// Test algorithm-specific certificate chains
	let algorithms = TEST_ALGORITHMS;
	for algorithm in algorithms {
		let root_pub = create_test_public_key(0, algorithm).unwrap();
		let intermediate_pub = create_test_public_key(1, algorithm).unwrap();
		let leaf_pub = create_test_public_key(2, algorithm).unwrap();

		let cert_moment = test_moment();
		let valid_from = cert_moment - chrono::Duration::hours(12);
		let valid_to = cert_moment + chrono::Duration::hours(12);

		let root_tbs = create_certificate_tbs(&root_pub, &root_pub, 1, valid_from, valid_to, true, algorithm).unwrap();
		let intermediate_tbs =
			create_certificate_tbs(&intermediate_pub, &root_pub, 2, valid_from, valid_to, true, algorithm).unwrap();
		let leaf_tbs =
			create_certificate_tbs(&leaf_pub, &intermediate_pub, 3, valid_from, valid_to, false, algorithm).unwrap();

		// Verify certificate chain
		let certificates = [&root_tbs, &intermediate_tbs, &leaf_tbs];
		let expected_serials = [1u64, 2u64, 3u64];

		for (tbs, &expected_serial) in certificates.iter().zip(expected_serials.iter()) {
			let expected_serial_num = SerialNumber::from(expected_serial);
			assert_eq!(tbs.serial_number, expected_serial_num);

			// Verify round trip
			let tbs_der = tbs.to_der().unwrap();
			assert!(!tbs_der.is_empty());
			let tbs_re_parsed = TbsCertificate::from_der(&tbs_der).unwrap();
			assert_eq!(**tbs, tbs_re_parsed);
		}
	}
}

#[test]
fn test_ecdsa_signature_der_encoding() {
	// Macro to eliminate code duplication for testing different ECDSA curves
	macro_rules! test_ecdsa_curve {
		($curve_name:expr, $key_type:ty, $derivation:ty) => {{
			let seed = generate_random_seed().unwrap();
			let private_key = <$derivation>::derive_from_seed(seed.expose_secret().clone().into_secret()).unwrap();
			let account = Account::<$key_type>::from(private_key);
			let public_key = account.keypair.to_public_key();
			let public_key_info = SubjectPublicKeyInfo::from(public_key);

			// Create the distinguished name
			let cn = format!("Test Certificate {}", $curve_name);
			let o = "Test Organization".to_string();
			let c = "US".to_string();
			let subject_dn = utils::create_dn(&[(oids::CN, &cn), (oids::O, &o), (oids::C, &c)]).unwrap();

			// Build a certificate
			let certificate = keetanetwork_x509::builder::CertificateBuilder::new()
				.with_subject_public_key(public_key_info.clone())
				.with_subject_dn(subject_dn.clone())
				.with_issuer_dn(subject_dn)
				.with_serial_number(SerialNumber::from(1u64))
				.with_validity_days(365)
				.build(&account)
				.unwrap();

			// Verify the certificate has a valid signature
			assert!(
				certificate.verify_signature(&public_key_info).is_ok(),
				"{} certificate signature verification failed",
				$curve_name
			);

			// Get the raw signature bytes
			let signature_bytes = certificate.signature.raw_bytes();

			// For ECDSA signatures, verify they start with DER SEQUENCE tag (0x30)
			// This confirms they are DER-encoded, not raw format
			assert_eq!(
				signature_bytes[0], 0x30,
				"{} signature should be DER-encoded (start with SEQUENCE tag 0x30)",
				$curve_name
			);

			// Verify we can parse the signature as DER
			assert!(
				keetanetwork_crypto::utils::parse_der_ecdsa_signature(signature_bytes).is_ok(),
				"Should be able to parse DER-encoded {} signature",
				$curve_name
			);

			// Verify the certificate can be converted to DER and PEM formats
			let der_bytes = certificate.to_der().unwrap();
			assert!(!der_bytes.is_empty(), "{} certificate DER should not be empty", $curve_name);

			let pem_string = certificate.to_pem().unwrap();
			assert!(
				pem_string.starts_with("-----BEGIN CERTIFICATE-----"),
				"{} certificate PEM should start with BEGIN CERTIFICATE",
				$curve_name
			);
			assert!(
				pem_string.ends_with("-----END CERTIFICATE-----\n"),
				"{} certificate PEM should end with END CERTIFICATE",
				$curve_name
			);
		}};
	}

	// Test both ECDSA curves
	test_ecdsa_curve!("secp256k1", KeyECDSASECP256K1, Secp256k1Derivation);
	test_ecdsa_curve!("secp256r1", KeyECDSASECP256R1, Secp256r1Derivation);
}
