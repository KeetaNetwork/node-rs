//! Test utilities and shared test data for x509 crate tests.
//!
//! This module provides common test data structures, constants, and utility
//! functions that are shared across multiple test modules in the x509 crate.

use crate::oids;
use crypto::prelude::Algorithm;

/// Test seed used for deterministic key generation in tests
pub const TEST_SEED: &str = "test_seed_for_certificate_generation_12345";

/// Alternative test seed used in certificate tests
pub const TEST_SEED_MNEMONIC: &str =
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

/// Certificate chain data structure for certificate tests
#[derive(Debug, Clone)]
pub struct CertificateChain {
	pub root: &'static str,
	pub intermediate: &'static str,
	pub client: &'static str,
}

/// Key data for certificate tests
#[derive(Debug, Clone)]
pub struct KeyData {
	pub public_key: &'static [u8],
	pub oid: &'static str,
}

/// Extended test certificate set that includes certificate chains
#[derive(Debug, Clone)]
pub struct CertificateTestSet {
	pub algorithm: Algorithm,
	pub oid: &'static str,
	pub chain: CertificateChain,
	pub key_data: Option<KeyData>,
}

/// Test data structure to hold algorithm-specific information for builders
#[derive(Debug, Clone)]
pub struct TestCertificateSet {
	pub algorithm: Algorithm,
	pub oid: &'static str,
	pub key_data: Option<TestKeyData>,
}

/// Test key data for algorithms
#[derive(Debug, Clone)]
pub struct TestKeyData {
	pub public_key: &'static [u8],
}

/// Static test data for each algorithm used in builder tests
pub const TEST_CERTIFICATE_SETS: &[TestCertificateSet] = &[
	TestCertificateSet {
		algorithm: Algorithm::Ed25519,
		oid: oids::ED25519,
		key_data: Some(TestKeyData {
			public_key: &[
				0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x8b, 0x2c, 0x1b, 0x8a, 0x3a,
				0x4f, 0x2c, 0x8b, 0x6d, 0x7e, 0x9f, 0x3a, 0x1b, 0x2c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x1d, 0x2e,
				0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x0a, 0x1b,
			],
		}),
	},
	TestCertificateSet {
		algorithm: Algorithm::Secp256k1,
		oid: oids::ECDSA_WITH_SHA256,
		key_data: Some(TestKeyData {
			public_key: &[
				0x04, 0x8b, 0x2c, 0x1b, 0x8a, 0x3a, 0x4f, 0x2c, 0x8b, 0x6d, 0x7e, 0x9f, 0x3a, 0x1b, 0x2c, 0x4d, 0x5e,
				0x6f, 0x7a, 0x8b, 0x9c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d,
				0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x8a, 0x9b, 0x0c,
				0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e,
			],
		}),
	},
	TestCertificateSet {
		algorithm: Algorithm::Secp256r1,
		oid: oids::ECDSA_WITH_SHA256,
		key_data: Some(TestKeyData {
			public_key: &[
				0x04, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e,
				0x7f, 0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d,
				0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x8a, 0x9b, 0x0c,
				0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e,
			],
		}),
	},
];

/// Raw Ed25519 public key for testing
pub const RAW_ED25519_PUBLIC_KEY: [u8; 32] = [
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Raw secp256r1 public key for testing
pub const RAW_SECP256R1_PUBLIC_KEY: [u8; 65] = [
	0x04, // Uncompressed point indicator
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Raw secp256k1 public key for testing
pub const RAW_SECP256K1_PUBLIC_KEY: [u8; 65] = [
	0x04, 0x15, 0x7a, 0xb0, 0xeb, 0x13, 0x54, 0x4f, 0x15, 0x83, 0x63, 0x5c, 0xf8, 0xdb, 0x2e, 0xd3, 0x1f, 0xe9, 0xd0,
	0x29, 0x20, 0x6e, 0x16, 0x01, 0x00, 0x39, 0x2e, 0xc9, 0x12, 0x88, 0xd6, 0x53, 0xa8, 0x97, 0xcf, 0xb1, 0x47, 0x62,
	0x04, 0xd7, 0x2f, 0x7e, 0xa3, 0x1e, 0xf1, 0x6a, 0x62, 0x81, 0xec, 0xd7, 0x6f, 0x1d, 0x60, 0xce, 0x31, 0xf1, 0x0f,
	0x6d, 0x62, 0x15, 0xba, 0xfc, 0x6c, 0xdd, 0xcc,
];

/// Data-driven test certificate sets organized by algorithm with certificate chains
pub static CERTIFICATE_TEST_SETS: &[CertificateTestSet] = &[
	CertificateTestSet {
		algorithm: Algorithm::Secp256k1,
		oid: oids::ECDSA_WITH_SHA256,
		chain: CertificateChain {
			root: r#"-----BEGIN CERTIFICATE-----
MIIB8DCCAZWgAwIBAgIJAOQFula8pzhMMAoGCCqGSM49BAMCMFQxCzAJBgNVBAYT
AlVTMQswCQYDVQQIEwJDQTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxDjAMBgNVBAoT
BUtlZXRhMRIwEAYDVQQDEwlrZWV0YS5jb20wHhcNMjIxMTAyMjE0NzMwWhcNMzIx
MDMwMjE0NzMwWjBUMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFDASBgNVBAcT
C0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTESMBAGA1UEAxMJa2VldGEuY29t
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEFXqw6xNUTxWDY1z42y7TH+nQKSBuFgEA
OS7JEojWU6iXz7FHYgTXL36jHvFqYoHs128dYM4x8Q9tYhW6/GzdzKNTMFEwHQYD
VR0OBBYEFNB4UOk1stu7q7nmEfiIeN4ZtMaYMB8GA1UdIwQYMBaAFNB4UOk1stu7
q7nmEfiIeN4ZtMaYMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIh
APpGBwnYm+P/m5uzICFpZjmV55Y1vK2I+8Aoa+sOmQ28AiEAwkmsOoNRNxwSYsKE
wW0cCBKGS0ieSFZftyNLFYI1YvI=
-----END CERTIFICATE-----"#,
			intermediate: r#"-----BEGIN CERTIFICATE-----
MIIB6TCCAZCgAwIBAgIBATAKBggqhkjOPQQDAjBUMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExFDASBgNVBAcTC0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTES
MBAGA1UEAxMJa2VldGEuY29tMB4XDTIyMTEwMjIyMDE1MloXDTMwMDIwMzIyMDE1
MlowRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ4wDAYDVQQKEwVLZWV0YTEY
MBYGA1UEAxMPbm9kZTEua2VldGEuY29tMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE
RrmFHfkBmk8rFrA2etvh0MCeN/hBY6YXNHnkS+lN3I4m/ou8zOP4lrvrfaB6TIlH
+3n+P1W9wQag28nByMgVyqNmMGQwHQYDVR0OBBYEFHqplpYPZnUJ1w7RYlfLl4Ig
gvMrMB8GA1UdIwQYMBaAFNB4UOk1stu7q7nmEfiIeN4ZtMaYMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIH9qE0E4
jRN9FHnJbDglV2knXd/YG9EfytcrCnq8lpAsAiBruKTcu4NVUVXs/WXPcsMrDYm/
4gahA5CqK0VlqmA3TA==
-----END CERTIFICATE-----"#,
			client: r#"-----BEGIN CERTIFICATE-----
MIIB3jCCAYWgAwIBAgIBATAKBggqhkjOPQQDAjBEMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExDjAMBgNVBAoTBUtlZXRhMRgwFgYDVQQDEw9ub2RlMS5rZWV0YS5j
b20wHhcNMjIxMTAzMDEyOTU4WhcNMjcwNTExMDEyOTU4WjBiMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC0xvcyBBbmdlbGVzMQ4wDAYDVQQKDAVL
ZWV0YTEgMB4GA1UEAwwXY2xpZW50MS5ub2RlMS5rZWV0YS5jb20wVjAQBgcqhkjO
PQIBBgUrgQQACgNCAAQ3605beUhS+2ZGuk4OkQ2utb239l2gkAl4tgKp1JFyujP8
aNZ5Zh7nnfB64eWCOHtaGIXHYeXlYf+rZ9KfnULdo00wSzAdBgNVHQ4EFgQUGKqt
zLuSNICC4hIdFc3a7QdIkhMwHwYDVR0jBBgwFoAUeqmWlg9mdQnXDtFiV8uXgiCC
8yswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNHADBEAiB/sWgSvLZSddTHD64sWgPD
gQSnWXxjfIzcoP1W48lZngIgazAF+38D5aIrcmtnD2YEp5i1ydiYzxKCU1RFAZf5
40c=
-----END CERTIFICATE-----"#,
		},
		key_data: Some(KeyData { public_key: &RAW_SECP256K1_PUBLIC_KEY, oid: oids::EC_PUBLIC_KEY }),
	},
	CertificateTestSet {
		algorithm: Algorithm::Secp256r1,
		oid: oids::ECDSA_WITH_SHA256,
		chain: CertificateChain {
			root: r#"-----BEGIN CERTIFICATE-----
MIIB/TCCAaOgAwIBAgIUWT6KAkJd/vGnEaMpmzzBnR0adLMwCgYIKoZIzj0EAwIw
VDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRQwEgYDVQQHEwtMb3MgQW5nZWxl
czEOMAwGA1UEChMFS2VldGExEjAQBgNVBAMTCWtlZXRhLmNvbTAeFw0yMzA0Mjcx
NjU1NTBaFw0zMzA0MjQxNjU1NTBaMFQxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxDjAMBgNVBAoTBUtlZXRhMRIwEAYDVQQD
EwlrZWV0YS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATI0DTRcpiIYTuN
Blb4D0bkq8LtKOs6YZKFC5DBT8Tx5bgA53Vey1WaQu5S7tVUifcnRCw7DEBsmjf6
i0Kk+VOeo1MwUTAdBgNVHQ4EFgQUksGKPnEwhukWVJ1WUi84dlf6LAgwHwYDVR0j
BBgwFoAUksGKPnEwhukWVJ1WUi84dlf6LAgwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNIADBFAiEA/lS4Ofqn7KTuglEWT/qExfhhNmRGudGuGlygQpDufxIC
IGt06yHwG3iv0egp8nqgbrcS4sXWltY25atPhalwd7vN
-----END CERTIFICATE-----"#,
			intermediate: r#"-----BEGIN CERTIFICATE-----
MIIB7TCCAZOgAwIBAgIBATAKBggqhkjOPQQDAjBUMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExFDASBgNVBAcTC0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTES
MBAGA1UEAxMJa2VldGEuY29tMB4XDTIzMDQyODIzMzk0OFoXDTMwMDczMDIzMzk0
OFowRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ4wDAYDVQQKEwVLZWV0YTEY
MBYGA1UEAxMPbm9kZTEua2VldGEuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEKI6k6eNQwSlKZirGyvBwAT1qY908+tsHfbO4pNLeUF7TOje9YBLUmeI0vw2v
+EAzOFcvFZ+ADe8yYoZ6TAKkJ6NmMGQwHQYDVR0OBBYEFN6Gg86IhS98OidKd/uN
M5wqxQ/IMB8GA1UdIwQYMBaAFJLBij5xMIbpFlSdVlIvOHZX+iwIMBIGA1UdEwEB
/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0gAMEUCIFfN
eqS1mGcNz2C5voo63nnV88aI2C+Yth9ygRT+lz/tAiEAvUJ27e59NBmhZSnlydEc
k88mudtednU6sPAQroQ5Wqs=
-----END CERTIFICATE-----"#,
			client: r#"-----BEGIN CERTIFICATE-----
MIIB4TCCAYigAwIBAgIBATAKBggqhkjOPQQDAjBEMQswCQYDVQQGEwJVUzELMAkG
A1UECBMCQ0ExDjAMBgNVBAoTBUtlZXRhMRgwFgYDVQQDEw9ub2RlMS5rZWV0YS5j
b20wHhcNMjMwNDI5MDQwMDA5WhcNMjcxMTA0MDQwMDA5WjBiMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC0xvcyBBbmdlbGVzMQ4wDAYDVQQKDAVL
ZWV0YTEgMB4GA1UEAwwXY2xpZW50MS5ub2RlMS5rZWV0YS5jb20wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASu2fGSPSgdnCrzZSPag/HYnQAtj5aHf4yM1KI6dM+g
VO64zcjZM1tSGSRFuJ6dqegCA/mHal9lQLWjpwipussDo00wSzAdBgNVHQ4EFgQU
Di/e49jFkYuS2LLj/4+nXuWCi80wHwYDVR0jBBgwFoAU3oaDzoiFL3w6J0p3+40z
nCrFD8gwCQYDVR0TBAIwADAKBggqhkjOPQQDAgNHADBEAiBdy/XyPecBS+HovnKh
1h4kQrF81Y9mi74wTU8TyrnZ1wIgcHik2KQyKcTRO3O/86W6h6kjB0TI2L9q8DM2
zFR9Uxw=
-----END CERTIFICATE-----"#,
		},
		key_data: Some(KeyData { public_key: &RAW_SECP256R1_PUBLIC_KEY, oid: oids::EC_PUBLIC_KEY }),
	},
	CertificateTestSet {
		algorithm: Algorithm::Ed25519,
		oid: oids::ED25519,
		chain: CertificateChain {
			root: r#"-----BEGIN CERTIFICATE-----
MIIBvTCCAW+gAwIBAgIUcKymEHTsE7V20eIRhoWPjzIEl6IwBQYDK2VwMFQxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIEwJDQTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxDjAM
BgNVBAoTBUtlZXRhMRIwEAYDVQQDEwlrZWV0YS5jb20wHhcNMjIxMTA3MjA1MTU0
WhcNMzIxMTA0MjA1MTU0WjBUMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFDAS
BgNVBAcTC0xvcyBBbmdlbGVzMQ4wDAYDVQQKEwVLZWV0YTESMBAGA1UEAxMJa2Vl
dGEuY29tMCowBQYDK2VwAyEAxP4ex9eEhp5IWCfpocshVT7NcFcIGN02e4asopW8
SbujUzBRMB0GA1UdDgQWBBQvx8bncF/SC0JUqUpj2g5wlWWLBDAfBgNVHSMEGDAW
gBQvx8bncF/SC0JUqUpj2g5wlWWLBDAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANB
AM/PDdzZ6Fmhlvb4sl+6q3dbl/g4hehhOod1Q2qoHLNsuAE91RAvZFw300MoE2Fz
KQ4u8DPSJYvt9Dmc9mVTDgk=
-----END CERTIFICATE-----"#,
			intermediate: r#"-----BEGIN CERTIFICATE-----
MIIBsDCCAWKgAwIBAgIEEAAAADAFBgMrZXAwVDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgTAkNBMRQwEgYDVQQHEwtMb3MgQW5nZWxlczEOMAwGA1UEChMFS2VldGExEjAQ
BgNVBAMTCWtlZXRhLmNvbTAeFw0yMjExMDcyMDUzMzNaFw0zMDAyMDgyMDUzMzNa
MEQxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEOMAwGA1UEChMFS2VldGExGDAW
BgNVBAMTD25vZGUxLmtlZXRhLmNvbTAqMAUGAytlcAMhAIRi0BDa4pNPKd1tqIpY
6ArNKx9p2Bg08UH8JfqczdLZo2YwZDAdBgNVHQ4EFgQUF1uoyLC6PaX2UuIrolGH
9/PydNIwHwYDVR0jBBgwFoAUL8fG53Bf0gtCVKlKY9oOcJVliwQwEgYDVR0TAQH/
BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwBQYDK2VwA0EAAfWCD0PJ+7iWpUqS
ki3MoY+bWUgWRaHRY2cAa8MZcaK3P4uiW+00NC40CkMqIl5tTGVRNof5mc1xf4zl
XTLIDA==
-----END CERTIFICATE-----"#,
			client: r#"-----BEGIN CERTIFICATE-----
MIIBpTCCAVegAwIBAgIEEAAAADAFBgMrZXAwRDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgTAkNBMQ4wDAYDVQQKEwVLZWV0YTEYMBYGA1UEAxMPbm9kZTEua2VldGEuY29t
MB4XDTIyMTEwNzIwNTQ1MloXDTI3MDUxNTIwNTQ1MlowYjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtMb3MgQW5nZWxlczEOMAwGA1UECgwFS2Vl
dGExIDAeBgNVBAMMF2NsaWVudDEubm9kZTEua2VldGEuY29tMCowBQYDK2VwAyEA
NMbgMpJ8D2Bo24HXD7quMF0QB+wTMhRTu/C0+KqgsLajTTBLMB0GA1UdDgQWBBSX
BEkhHzClJegI9DOeMbFHYrpZwzAfBgNVHSMEGDAWgBQXW6jIsLo9pfZS4iuiUYf3
8/J00jAJBgNVHRMEAjAAMAUGAytlcANBAEiVATSVlYxJ33rgcEfGjFgKtVFB8v2H
/63NVVO3k09vb25ouL80suLD9sLVzpYwD7UoBQfuWqwQEe1Sb7DLygc=
-----END CERTIFICATE-----"#,
		},
		key_data: Some(KeyData { public_key: &RAW_ED25519_PUBLIC_KEY, oid: oids::ED25519 }),
	},
];
