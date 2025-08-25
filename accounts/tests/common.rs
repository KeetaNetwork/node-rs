//! Common test utilities and data shared across integration tests

use core::convert::TryFrom;

use accounts::{Account, Accountable, KeyPairType, Keyable};
use crypto::prelude::IntoSecret;

#[allow(dead_code)]
pub struct PublicAccountTestData {
	pub ecdsa_secp256k1: PublicKeyData,
	pub ecdsa_secp256r1: PublicKeyData,
	pub ed25519: PublicKeyData,
	pub network: PublicKeyData,
	pub token: PublicKeyData,
	pub storage: PublicKeyData,
	pub multisig: PublicKeyData,
}

#[allow(dead_code)]
pub struct PublicKeyData {
	pub public_key: &'static str,
	pub encoded_public_key: &'static str,
}

#[allow(dead_code)]
pub struct IndexTestData {
	pub public_key_ecdsa_secp256k1: &'static str,
	pub public_key_ecdsa_secp256r1: &'static str,
	pub public_key_ed25519: &'static str,
	pub private_key_ecdsa_secp256k1: &'static str,
	pub private_key_ecdsa_secp256r1: &'static str,
	pub private_key_ed25519: &'static str,
	pub encoded_public_key_ecdsa_secp256k1: &'static str,
	pub encoded_public_key_ecdsa_secp256r1: &'static str,
	pub encoded_public_key_ed25519: &'static str,
}

#[allow(dead_code)]
pub struct PrivateAccountTestData {
	pub seed: &'static str,
	pub indexes: [IndexTestData; 2],
}

#[allow(dead_code)]
pub const TEST_PUBLIC_ACCOUNT: PublicAccountTestData = PublicAccountTestData {
	ecdsa_secp256k1: PublicKeyData {
		public_key: "020F2115FA0C9A10680AEECB64AB2E0564AED1AF821A72BF987AABF87A1AD68251",
		// cspell:disable-next-line
		encoded_public_key: "keeta_aaba6iiv7igjuediblxmwzflfycwjlwrv6bbu4v7tb5kx6d2dllieunedvq3cza",
	},
	// Rust p256 does not like this
	// ecdsa_secp256r1: PublicKeyData {
	// 	public_key: "03A79FEB218FF321F9EC29DC42E52074E658432F2F595EE770E74B8EE7E23EE4EE",
	// 	// cspell:disable-next-line
	// 	encoded_public_key: "keeta_ayb2ph7legh7gipz5qu5yqxfeb2omwcdf4xvsxxhodtuxdxh4i7oj3uyxwmldii",
	// },
	ecdsa_secp256r1: PublicKeyData {
		public_key: "02B701EBBE7E561CF5DB1C4C47E55C4B55CEF3F89DE8CCEC31284AA5C60B91094B",
		// cspell:disable-next-line
		encoded_public_key: "keeta_aybloaplxz7fmhhv3moeyr7flrfvltxt7co6rthmgeuevjogboiqss6pzmhgr6i",
	},
	// Rust ed25519_dalek does not like this
	// ed25519: PublicKeyData {
	// 	public_key: "0F2115FA0C9A10680AEECB64AB2E0564AED1AF821A72BF987AABF87A1AD68251",
	// 	// cspell:disable-next-line
	// 	encoded_public_key: "keeta_aehscfp2bsnba2ak53fwjkzoavsk5unpqinhfp4ypkv7q6q222bfcko6njrbw",
	// },
	ed25519: PublicKeyData {
		public_key: "F0FAAE6AF2A3B84296F5B3216B4A7CB30228FC4593AAA10317D16C6412C9F05F",
		// cspell:disable-next-line
		encoded_public_key: "keeta_ahcp4hwh26cinhsilat6tiolefkt5tlqk4ebrxjwpodkziuvxre3x3r2wf5l6",
	},
	network: PublicKeyData {
		public_key: "372D46C3ADA9F897C74D349BBFE0E450C798167C9F580F8DAF85DEF57E96C3EA",
		// cspell:disable-next-line
		encoded_public_key: "keeta_ai3s2rwdvwu7rf6hju2jxp7a4rimpgawpspvqd4nv6c555l6s3b6uj6cr5klc",
	},
	token: PublicKeyData {
		public_key: "724E371B944A48E95B91EE059B7CB7110E5866CA707915C287C49CAB9B774AF1",
		// cspell:disable-next-line
		encoded_public_key: "keeta_anze4ny3srfer2k3shxalg34w4iq4wdgzjyhsfocq7cjzk43o5fpc2igkuifg",
	},
	storage: PublicKeyData {
		public_key: "DF2D414F6702347EDBBD318DA8E319F1229F83E3B4DC2C8C135CF67C5952B07D",
		// cspell:disable-next-line
		encoded_public_key: "keeta_atps2qkpm4bdi7w3xuyy3khddhysfh4d4o2nylemcnopm7czkkyh2pbfk7svy",
	},
	multisig: PublicKeyData {
		public_key: "1858E8B2F42EDD1072EA71E99D67407E56D1CB4B20A265252FACE1ABF8A76D19",
		// cspell:disable-next-line
		encoded_public_key: "keeta_a4mfr2fs6qxn2eds5jy6thlhib7fnuoljmqkezjff6wodk7yu5wrt52ks62sa",
	},
};

#[allow(dead_code)]
pub const TEST_PRIVATE_ACCOUNT: PrivateAccountTestData = PrivateAccountTestData {
	seed: "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D",
	indexes: [
		IndexTestData {
			public_key_ecdsa_secp256k1: "02157AB0EB13544F1583635CF8DB2ED31FE9D029206E160100392EC91288D653A8",
			public_key_ecdsa_secp256r1: "02B701EBBE7E561CF5DB1C4C47E55C4B55CEF3F89DE8CCEC31284AA5C60B91094B",
			public_key_ed25519: "C4FE1EC7D784869E485827E9A1CB21553ECD70570818DD367B86ACA295BC49BB",
			private_key_ecdsa_secp256k1: "EEE6ABBC24F7FBB5A7035ABF27D6C389E94E4FF06D1A8948FDA56B4DC2D05794",
			private_key_ecdsa_secp256r1: "EEE6ABBC24F7FBB5A7035ABF27D6C389E94E4FF06D1A8948FDA56B4DC2D05794",
			private_key_ed25519: "F0FAAE6AF2A3B84296F5B3216B4A7CB30228FC4593AAA10317D16C6412C9F05F",
			encoded_public_key_ecdsa_secp256k1: // cspell:disable-next-line
				"keeta_aabbk6vq5mjvityvqnrvz6g3f3jr72oqfeqg4fqbaa4s5sisrdlfhkfr5p7chey",
			encoded_public_key_ecdsa_secp256r1: // cspell:disable-next-line
				"keeta_aybloaplxz7fmhhv3moeyr7flrfvltxt7co6rthmgeuevjogboiqss6pzmhgr6i",
			// cspell:disable-next-line
			encoded_public_key_ed25519: "keeta_ahcp4hwh26cinhsilat6tiolefkt5tlqk4ebrxjwpodkziuvxre3x3r2wf5l6",
		},
		IndexTestData {
			public_key_ecdsa_secp256k1: "0246B9851DF9019A4F2B16B0367ADBE1D0C09E37F84163A6173479E44BE94DDC8E",
			public_key_ecdsa_secp256r1: "0322C10ABB6C436B5467401D6B73518FCE6DB5AB6291040069006DC7113B16A3BC",
			public_key_ed25519: "8462D010DAE2934F29DD6DA88A58E80ACD2B1F69D81834F141FC25FA9CCDD2D9",
			private_key_ecdsa_secp256k1: "6FF01C1B8092A715DF4231AD531CA1101FA941E49BD76EADE0DA047D5333E20E",
			private_key_ecdsa_secp256r1: "6FF01C1B8092A715DF4231AD531CA1101FA941E49BD76EADE0DA047D5333E20E",
			private_key_ed25519: "6823B06E9A84281499ADDFF3719B7A530B8E8C9764629858C73DCA7844675346",
			encoded_public_key_ecdsa_secp256k1: // cspell:disable-next-line
				"keeta_aabenomfdx4qdgspfmllant23pq5bqe6g74ecy5gc42htzcl5fg5zdr55yndzra",
			encoded_public_key_ecdsa_secp256r1: // cspell:disable-next-line
				"keeta_aybsfqikxnweg22um5ab223tkgh443nvvnrjcbaaneag3ryrhmlkhpd7awgj7ry",
			// cspell:disable-next-line
			encoded_public_key_ed25519: "keeta_agcgfuaq3lrjgtzj3vw2rcsy5afm2ky7nhmbqnhrih6cl6u4zxjntb2x72hc2",
		},
	],
};

/// Helper function to create a test seed array from the test data
#[allow(dead_code)]
pub fn create_test_seed_array() -> [u8; 32] {
	let seed_bytes = hex::decode(TEST_PRIVATE_ACCOUNT.seed).unwrap();
	seed_bytes.try_into().unwrap()
}

/// Helper function to create an account from seed for different key types
#[allow(dead_code)]
pub fn create_account_from_seed<T>(key_type: KeyPairType, index: u32) -> Account<T>
where
	T: accounts::KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = accounts::AccountError>,
{
	let seed_array = create_test_seed_array();
	let keyable = Keyable::Seed((seed_array.into_secret(), index));
	Account::<T>::try_from(Accountable::KeyAndType(keyable, key_type)).unwrap()
}

/// Helper function to create an account from a hex seed string for different key types
#[allow(dead_code)]
pub fn create_account_from_seed_hex<T>(key_type: KeyPairType, seed_hex: &str, index: u32) -> Account<T>
where
	T: accounts::KeyPair,
	Account<T>: TryFrom<Accountable<T>, Error = accounts::AccountError>,
{
	// Convert hex string to bytes
	let seed_bytes = hex::decode(seed_hex).expect("Invalid hex seed");
	let mut seed_array = [0u8; 32];
	seed_array.copy_from_slice(&seed_bytes[..32]);

	let keyable = Keyable::Seed((seed_array.into_secret(), index));
	Account::<T>::try_from(Accountable::KeyAndType(keyable, key_type)).unwrap()
}
