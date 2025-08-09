#![allow(dead_code)]

use asn1::oids;
use asn1::{AlgorithmIdentifier, BitString, SubjectPublicKeyInfo};
use chrono::{DateTime, TimeZone, Utc};
use crypto::{bigint::U256, prelude::Algorithm};
use x509::certificates::{Certificate, CertificateBuilder, TbsCertificate};
use x509::utils;

// Test key data
pub const RAW_ED25519_PUBLIC_KEY: [u8; 32] = [
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

pub const RAW_SECP256R1_PUBLIC_KEY: [u8; 66] = [
	0x04, // Uncompressed point indicator
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
];

// Test CA certificate
pub const CA_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIB1jCCAXugAwIBAgIBAzALBglghkgBZQMEAwowUDFOMEwGA1UEAxZFa2VldGFf
YWRhaHhlcXpxZnRiYmZtN2dqa2pidzM0b3RiMm9xa3A2cnpoNWRybndoazV0Mmt5
YmR1ZHF5Z3Njbmp4YW9uMB4XDTI0MTEwMTE2MDQ0M1oXDTI0MTEwMjE2MDQ0M1ow
UDFOMEwGA1UEAxZFa2VldGFfYWRhaHhlcXpxZnRiYmZtN2dqa2pidzM0b3RiMm9x
a3A2cnpoNWRybndoazV0Mmt5YmR1ZHF5Z3Njbmp4YW9uMDkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDIgAD3JDMCzCErPmSpIbb46YdOgp/o5P0cW2Ors9KwEdBwwajZTBj
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgDGMCEGA1UdIwQaMBigFgQU
ahPODjyDyyxby6ySJEQX9zOgB+wwHQYDVR0OBBYEFGoTzg48g8ssW8uskiREF/cz
oAfsMAsGCWCGSAFlAwQDCgNIADBFAiEAhMHKvbUqFVURW4oetU2/CkBocmBro9bA
XR+ujQgL9pYCIEiEn+F4GaArxThV535UIvO2Jg1aeyHu+MCNrxhHEDPu
-----END CERTIFICATE-----"#;

// Test User certificate
pub const USER_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIII0TCCCHegAwIBAgIBBDALBglghkgBZQMEAwowUDFOMEwGA1UEAxZFa2VldGFf
YWRhaHhlcXpxZnRiYmZtN2dqa2pidzM0b3RiMm9xa3A2cnpoNWRybndoazV0Mmt5
YmR1ZHF5Z3Njbmp4YW9uMB4XDTI0MTEwMTE2MDQ0M1oXDTI0MTEwMjE2MDQ0M1ow
UDFOMEwGA1UEAxZFa2VldGFfYWRhZmkybGNvbXA0dXdsdm5rYmg1M3d5aHZ3Z2h3
dWFtb3o0NWhodDUybWFqNjVpd2lzdDV2a3U3eWtqNXpuMDkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDIgACo0sTmP5Sy6tUE/d2wetjHtQDHZ505590wCfdRZEp9qqjggdf
MIIHWzAOBgNVHQ8BAf8EBAMCAMAwIQYDVR0jBBowGKAWBBRqE84OPIPLLFvLrJIk
RBf3M6AH7DAdBgNVHQ4EFgQU3JvD83gCz0+3FTkcOY0j4p6UQ+QwggcFBgorBgEE
AYnfLAAABIIG9TCCBvEwggFXBgorBgEEAYnfLAEAoYIBRwSCAUMwggE/AgEAMIHd
BglghkgBZQMEAS4EDEpOGHdz3z0LdJoPNQSBwQSrLGG+e5AqBYNIk5iiOz5ODfam
SCpjwnAo9MGwTl40ERu6i2VnUWh37sWviOXzaxt/vl/XWjVDuq8OQ9tRa0ZCg1r1
sW3Uo7qUGp6v6a0cKt6Ejcw8Z6af0ttndfxoghJFMz+nKlhhU4VqSxHvFIwW2dyu
AgvR6hT0/EjuRNzKg2X/6yOJmuxN/tDjDGWCjayV0v9LKMC0IFd750nTSIJzv5r4
YaJcqqB158O1F+TNVKOaqSEuRB9v/v9P6/felYowTwQgA/zKGcF5Mz5FU2/Mp75r
4+548puaSqJnPvTj1yIWA7sGCWCGSAFlAwQCCAQgfERdRhKCcALgQHjBl+3GRUWb
7C637Zh0CU5ilApzxQIECUR5MC6LBLk1hjCCAV4GCisGAQQBid8sAQOhggFOBIIB
SjCCAUYCAQAwgd0GCWCGSAFlAwQBLgQM89djVFtq6aTRZCmCBIHBBDZIcLD34h7m
donBIOhya7rrwGMoZbCmBBi/fLvNfCypfCe73MuhpccFR2UXjxbZlY+kxjrKbb50
M8CI/VqrMSn+kcbquN3qfbqrI5YTI4jUlThvOz9W5cI6lMcIZZEnFAUHbXyxE8qU
59La3uHvtUloRLK4+Ujx6kpFHUeELA4isc0JS/dmsJgGjcrHffs88F0onPtHWJYE
R7Vss8apqi92KDM6s6rMcx78BuUYeUs/Mntab/CYjkY7iyf4sQtMlzBPBCAi/pRV
LMGtF7iEEnZ8GmfEHxx7iWKO2MYElquVwSFA+wYJYIZIAWUDBAIIBCA+vyoJQWxg
xsQ/UV/gArKKQmPOCKvGV4hzOg0eMXl1KwQQzt0GYkQE0Ae1njDM/RMZIjCCAV0G
CisGAQQBid8sAQShggFNBIIBSTCCAUUCAQAwgd0GCWCGSAFlAwQBLgQMhglIR1YX
w+Xu1SApBIHBBCx+i/dw+rmmaG3JsJX64ofRwPgGT9BTe2htcu6KoGNr/K19kWsg
+edRuM6U0gI8HoJPj/8izGZGf96EDX+v6oT5spI0ZXl7SXIz08dwtjEm3zux1TMr
x1Z7DlKZZyagHuC9yKwdc+DaeznjzFbELPzLuSKGmQOo+8RC8NHXlSmv9z9cA/+y
XIY7kU1sOyeCW+7TZor5oYoXLOZ9s2piX/edLKDTwygNCdxN4JkXwF8bM9D8hNs3
5vRgOjyQtz/XiTBPBCD9MN0UMBHYyM6HuYjl4N9VOMBWDORiu+kzBJtJ6umGxQYJ
YIZIAWUDBAIIBCBD0l3HQ3Ur0OZFZNCoNdzcr3kTqHHJ+baKaNcJW8RY4AQPAn4f
DDvhou0VOQZ4ZWx0MIIBcwYKKwYBBAGJ3ywBAqGCAWMEggFfMIIBWwIBADCB3QYJ
YIZIAWUDBAEuBAxBTr6E2q0Yt/fr8KcEgcEEAdYU5trRBKIqPmJ/LHcC2AKgyGFG
LMzTkCY6CHvWdn9YiUUlhg8Pdgl9/fHWdHByr+6Lo1p6x0gr+YOUJwml18E8gXwK
RPGNuAhhUSkQUyoPvXbECJKkeYhPnsYSCDwB92sQ+QF43J7KqI+x0Z59hqzh4FWP
orYNRjsHB7l2MFTun2f4dt1HjT/IMi1m/4apqFzIBytrKDOdGf/20fKsvCKhwqZr
dgDTwMsij6oqEFbLedMc5IVBuvpRZn+1yM9LME8EIAgS1YvvsY/sUi+HYpJA00jE
Z0eLxgd5sycHDR2D1SqEBglghkgBZQMEAggEINSHGyy2mvftN0ZcvwmPshGkLQVr
Y93z1lBjHMW8eiMKBCUJ9E2ywWGYB+GHjAVt8G3YVLjvH6W9gdbQEbWWSitgoipV
C92uMIIBWAYKKwYBBAGJ3ywBAaGCAUgEggFEMIIBQAIBADCB3QYJYIZIAWUDBAEu
BAzWu5N5aeFyhq5aFAsEgcEEYJQKtoFMb/qiw/oxGBe7RPy9MNsJ/iOTjXn70u0N
h5NtmD4r6a1rQAaDLtd/IEHJkFLGbtQku8PboJygy0JknzU3kXDStzQkfxLcX0Bw
mMPAHojVSyIcMF/LvvcwSNlcKTdpZksFCIxXlXeY/fKnF+Vb7YQVYVvNWT8nJ7s1
88hfquMCV6zpy2XeEgOPoaxjYjJuKjeiMV8dCrystbpQxtLl3++PqtGivt/nCT4Z
LN60AS6c+joyR7VNgcExNZNnME8EICCcoGbSlG3ViuNOJkgUliihVGQ/p9zTRvii
x3ui0YkMBglghkgBZQMEAggEINNaGsdcplT/Q73ppiL4OddX8b1xCWZzQBOcnccY
oAX4BAooHLnyTHnreb1wMAsGCWCGSAFlAwQDCgNHADBEAiB5znN4Fec3CwtwQu08
Avsc+8aSlODesjxz3wO+1UvTwwIgLwRAFb28AssYvelz5+4z12uCEVGOy8cgI4Xj
FmnXzDU=
-----END CERTIFICATE-----"#;

// Test moment timestamp from TypeScript tests
pub const CERT_MOMENT_TIMESTAMP: i64 = 1730520283;

// Test seed from TypeScript tests
pub const TEST_SEED: &str = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

// Common test algorithms
pub const TEST_ALGORITHMS: [Algorithm; 3] = [Algorithm::Ed25519, Algorithm::Secp256r1, Algorithm::Secp256k1];

/// Helper functions for creating test data
pub fn test_moment() -> DateTime<Utc> {
	Utc.timestamp_opt(CERT_MOMENT_TIMESTAMP, 0).unwrap()
}

pub fn ca_certificate() -> Certificate {
	Certificate::from_pem(CA_CERT_PEM).unwrap()
}

pub fn user_certificate() -> Certificate {
	Certificate::from_pem(USER_CERT_PEM).unwrap()
}

/// Creates test public key bytes based on algorithm and index
pub fn create_test_public_key(index: u32, algorithm: Algorithm) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let seed_bytes = hex::decode(TEST_SEED)?;
	let mut extended_seed = seed_bytes;
	extended_seed.extend_from_slice(&index.to_be_bytes());

	match algorithm {
		Algorithm::Ed25519 => {
			let mut public_key = [0u8; 32];
			for (i, &byte) in extended_seed.iter().take(32).enumerate() {
				public_key[i] = byte;
			}
			Ok(public_key.to_vec())
		}
		Algorithm::Secp256r1 | Algorithm::Secp256k1 => {
			let mut public_key = [0u8; 65];
			public_key[0] = 0x04; // Uncompressed point indicator
			for (i, &byte) in extended_seed.iter().take(64).enumerate() {
				public_key[i + 1] = byte;
			}
			Ok(public_key.to_vec())
		}
	}
}

/// Creates a test certificate for error testing scenarios
pub fn create_test_certificate(
	index: u32,
	algorithm: Algorithm,
	is_ca: bool,
) -> Result<Certificate, Box<dyn std::error::Error>> {
	let public_key = create_test_public_key(index, algorithm)?;
	let valid_from = test_moment() - chrono::Duration::hours(1);
	let valid_to = test_moment() + chrono::Duration::days(30);

	// Create a test certificate TBS
	let _tbs = create_certificate_tbs(
		&public_key,
		&public_key, // Self-signed for simplicity
		index as u64,
		valid_from,
		valid_to,
		is_ca,
		algorithm,
	)?;

	// For testing purposes, we'd need to actually sign this
	// For now, just use the existing test certificates
	match index {
		0 => Ok(ca_certificate()),
		_ => Ok(user_certificate()),
	}
}

// Helper function to create certificate TBS
pub fn create_certificate_tbs(
	subject_public_key: &[u8],
	issuer_public_key: &[u8],
	serial: u64,
	valid_from: DateTime<Utc>,
	valid_to: DateTime<Utc>,
	is_ca: bool,
	algorithm: Algorithm,
) -> Result<TbsCertificate, Box<dyn std::error::Error>> {
	// Create subject and issuer DNs based on the public keys
	let subject_key_id = hex::encode(&subject_public_key[..8]);
	let issuer_key_id = hex::encode(&issuer_public_key[..8]);

	let subject_dn = utils::create_dn(&[(oids::CN, &format!("keeta_{subject_key_id}"))])?;
	let issuer_dn = utils::create_dn(&[(oids::CN, &format!("keeta_{issuer_key_id}"))])?;

	// Determine algorithm OID based on key type
	let algorithm_oid = match algorithm {
		Algorithm::Ed25519 => oids::ED25519,
		Algorithm::Secp256r1 => oids::ECDSA_WITH_SHA256,
		Algorithm::Secp256k1 => oids::ECDSA_WITH_SHA256,
	};

	let algorithm_id = AlgorithmIdentifier::try_from(algorithm_oid)?;
	let subject_public_key_bitstring = BitString::from_bytes(subject_public_key)?;
	let public_key_info =
		SubjectPublicKeyInfo { algorithm: algorithm_id, subject_public_key: subject_public_key_bitstring };

	let builder = CertificateBuilder::new()
		.with_subject_public_key(public_key_info)
		.with_subject_dn(subject_dn)
		.with_issuer_dn(issuer_dn)
		.with_validity(valid_from, valid_to)
		.with_serial_number(U256::from(serial))
		.with_is_ca(is_ca);

	let tbs = builder.build_tbs()?;
	Ok(tbs)
}
