//! Live round-trip compatibility tests against the reference TypeScript
//! implementation.

use keetanetwork_account::KeyPairType;
use keetanetwork_block::testing::{derive_identifier, generate_ed25519_ref};
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, BaseFlag, Block, BlockBuilder, BlockPurpose, BlockTime, BlockVersion,
	CertificateDer, CertificateOrHash, CreateIdentifier, Hashable, IntermediateCertificates, ManageCertificate,
	ModifyPermissions, ModifyPermissionsPrincipal, Permissions, Receive, Send, SetInfo, SetRep, Signer,
	TokenAdminModifyBalance, TokenAdminSupply, UnsignedBlock,
};
use keetanetwork_utils::node_harness::{run_node_script, script_path};

/// The path of a compiled harness helper script.
fn script(name: &str) -> std::path::PathBuf {
	script_path(name).expect("harness scripts must be built (run `make node-harness`)")
}

/// Parse blocks with the reference implementation, returning `(hash,
/// re-serialized hex)` per block.
fn ts_parse(blocks_hex: &[String]) -> Vec<(String, String)> {
	let stdin = blocks_hex.join("\n") + "\n";
	let output = run_node_script(script("ts-verify"), [] as [&str; 0], Some(stdin.as_bytes()))
		.expect("the reference implementation must parse every Rust-built block");

	let stdout = String::from_utf8(output.stdout).expect("node output must be UTF-8");
	stdout
		.lines()
		.map(|line| {
			let value: serde_json::Value = serde_json::from_str(line).expect("node output must be JSON");
			let hash = value["hash"]
				.as_str()
				.expect("hash must be a string")
				.to_string();
			let bytes = value["bytes"]
				.as_str()
				.expect("bytes must be a string")
				.to_string();

			(hash, bytes)
		})
		.collect()
}

/// Mint a deterministic X.509 certificate for `subject` with the
/// reference implementation, returning the DER bytes.
fn ts_mint_certificate(subject: &AccountRef) -> Vec<u8> {
	let output = run_node_script(script("ts-mint-cert"), [subject.to_string()], None)
		.expect("certificate minting via the reference implementation must succeed");

	let stdout = String::from_utf8(output.stdout).expect("node output must be UTF-8");
	hex::decode(stdout.trim()).expect("minted certificate must be hex")
}

fn fixed_date() -> BlockTime {
	BlockTime::from_unix_millis(1_748_781_296_789).expect("fixed test date must be valid")
}

/// Build then sign a block, attributing any failure to `label`.
fn seal(builder: BlockBuilder, label: &str) -> Block {
	let unsigned = builder
		.build()
		.unwrap_or_else(|error| panic!("{label} block must build: {error}"));

	unsigned
		.sign()
		.unwrap_or_else(|error| panic!("{label} block must sign: {error}"))
}

/// The deterministic cast of accounts shared across every fixture block.
struct Actors {
	alice: AccountRef,
	bob: AccountRef,
	carol: AccountRef,
	token: AccountRef,
	multisig_outer: AccountRef,
	multisig_inner: AccountRef,
}

impl Actors {
	fn sample() -> Self {
		let alice = generate_ed25519_ref(0x21);
		let token = derive_identifier(&alice, KeyPairType::TOKEN, 0);
		let multisig_outer = derive_identifier(&alice, KeyPairType::MULTISIG, 1);
		let multisig_inner = derive_identifier(&alice, KeyPairType::MULTISIG, 2);

		Self {
			bob: generate_ed25519_ref(0x22),
			carol: generate_ed25519_ref(0x23),
			alice,
			token,
			multisig_outer,
			multisig_inner,
		}
	}

	/// The `Send` operation reused across the v2, fee, and multisig fixtures.
	fn send(&self) -> Send {
		Send {
			to: self.bob.clone(),
			amount: Amount::from(12345u64),
			token: self.token.clone(),
			external: Some("ref 7".to_string()),
		}
	}

	/// V2 block carrying the full optional header (subnet + idempotent).
	fn v2(&self) -> Block {
		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_subnet(77u8)
				.with_idempotent([1u8, 2, 3, 4])
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(self.send()),
			"v2",
		)
	}

	fn v1(&self) -> Block {
		seal(
			BlockBuilder::default()
				.with_version(BlockVersion::V1)
				.with_network(0u8)
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(Receive {
					amount: Amount::from(9u64),
					token: self.token.clone(),
					from: self.bob.clone(),
					exact: false,
					forward: None,
				}),
			"v1",
		)
	}

	fn fee(&self) -> Block {
		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_purpose(BlockPurpose::Fee)
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(self.send()),
			"fee",
		)
	}

	/// Nested multisig signer tree producing multiple signatures.
	fn multisig(&self) -> Block {
		let signer = Signer::Multisig {
			address: self.multisig_outer.clone(),
			signers: vec![
				Signer::Single(self.bob.clone()),
				Signer::Multisig {
					address: self.multisig_inner.clone(),
					signers: vec![Signer::Single(self.carol.clone()), Signer::Single(self.alice.clone())],
				},
			],
		};

		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.with_signer(signer)
				.as_opening()
				.with_operation(self.send()),
			"multisig",
		)
	}

	/// Several operation types in one block; the older date permits the
	/// negative balance adjustment.
	fn multi_op(&self) -> Block {
		let date = BlockTime::from_unix_millis(1_704_164_645_000).expect("old date must be valid");

		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_date(date)
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(SetRep { to: self.bob.clone() })
				.with_operation(SetInfo {
					name: "RUST_BLOCK".to_string(),
					description: "Built by the Rust implementation".to_string(),
					metadata: "bWV0YQ==".to_string(),
					default_permission: None,
				})
				.with_operation(TokenAdminModifyBalance {
					token: self.token.clone(),
					amount: Amount::from(-3i64),
					method: AdjustMethod::Add,
				})
				.with_operation(Receive {
					amount: Amount::from(77u64),
					token: self.token.clone(),
					from: self.bob.clone(),
					exact: true,
					forward: Some(self.bob.clone()),
				}),
			"multi-op",
		)
	}

	fn modify_permissions(&self) -> Block {
		let permissions =
			Permissions::from_flags(&[BaseFlag::Access, BaseFlag::UpdateInfo], &[]).expect("permissions must build");

		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(ModifyPermissions {
					principal: ModifyPermissionsPrincipal::Account(self.bob.clone()),
					method: AdjustMethod::Set,
					permissions: Some(permissions),
					target: None,
				}),
			"modify-permissions",
		)
	}

	/// Opening block whose derivation (no previous, operation index 0)
	/// matches the `token` helper derivation.
	fn create_identifier(&self) -> Block {
		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(CreateIdentifier { identifier: self.token.clone(), create_arguments: None }),
			"create-identifier",
		)
	}

	/// Token-account supply adjustment authorized by a delegate signer.
	fn token_admin_supply(&self) -> Block {
		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_date(fixed_date())
				.with_account(self.token.clone())
				.with_signer(self.alice.clone())
				.as_opening()
				.with_operation(TokenAdminSupply { amount: Amount::from(1_000_000u64), method: AdjustMethod::Add }),
			"token-admin-supply",
		)
	}

	fn manage_certificate_removal(&self) -> Block {
		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(ManageCertificate {
					method: AdjustMethod::Subtract,
					certificate_or_hash: CertificateOrHash::Hash([0x42u8; 32]),
					intermediate_certificates: None,
				}),
			"manage-certificate",
		)
	}

	fn manage_certificate_addition(&self, certificate: Vec<u8>) -> Block {
		seal(
			BlockBuilder::default()
				.with_network(0u8)
				.with_date(fixed_date())
				.with_account(self.alice.clone())
				.as_opening()
				.with_operation(ManageCertificate {
					method: AdjustMethod::Add,
					certificate_or_hash: CertificateOrHash::Certificate(CertificateDer::from(certificate)),
					intermediate_certificates: Some(IntermediateCertificates::None),
				}),
			"manage-certificate-add",
		)
	}
}

fn rust_built_blocks() -> Vec<Block> {
	let actors = Actors::sample();
	let certificate = ts_mint_certificate(&actors.alice);

	vec![
		actors.v2(),
		actors.v1(),
		actors.fee(),
		actors.multisig(),
		actors.multi_op(),
		actors.modify_permissions(),
		actors.create_identifier(),
		actors.token_admin_supply(),
		actors.manage_certificate_removal(),
		actors.manage_certificate_addition(certificate),
	]
}

#[test]
fn test_rust_blocks_parse_in_typescript() {
	let blocks = rust_built_blocks();
	let hex_blocks: Vec<String> = blocks
		.iter()
		.map(|block| hex::encode_upper(block.to_bytes()))
		.collect();

	let parsed = ts_parse(&hex_blocks);
	assert_eq!(parsed.len(), blocks.len(), "reference implementation must parse every block");

	for (block, (ts_hash, ts_bytes)) in blocks.iter().zip(&parsed) {
		let hash = block.hash().to_string();
		let encoded = hex::encode_upper(block.to_bytes());
		assert_eq!(&hash, ts_hash, "hashes must agree across implementations");
		assert_eq!(&encoded, ts_bytes, "bytes must round-trip unchanged");
	}
}

#[test]
fn test_typescript_blocks_parse_in_rust() {
	let out_dir = std::env::temp_dir().join(format!("keetanet-block-compat-{}", std::process::id()));
	std::fs::create_dir_all(&out_dir).expect("temp dir must be creatable");

	// Re-generate fixtures live so this covers the current reference
	// implementation, not just the checked-in vectors.
	let out_file = out_dir.join("blocks.json");
	run_node_script(script("generate-fixtures"), [&out_file], None)
		.expect("fixture generation against the live reference must succeed");

	let raw = std::fs::read_to_string(&out_file).expect("live fixtures must exist");
	let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("fixtures must parse");

	for fixture in fixtures.as_array().expect("fixtures must be an array") {
		let name = fixture["name"].as_str().expect("fixture name");
		let expected_hex = fixture["bytes"].as_str().expect("fixture bytes");
		let bytes = hex::decode(expected_hex).expect("fixture hex");

		let block = Block::try_from(bytes.as_slice())
			.unwrap_or_else(|error| panic!("live fixture {name} must decode: {error}"));

		let re_encoded = hex::encode_upper(block.to_bytes());
		assert_eq!(re_encoded, expected_hex, "live fixture {name} must re-encode identically");
	}
}

#[test]
fn test_rust_unsigned_block_hash_matches_typescript_signed_hash() {
	// An unsigned block and its sealed form must share the same hash, and
	// that hash is what the reference implementation reports.
	let blocks = rust_built_blocks();
	for block in &blocks {
		let unsigned = UnsignedBlock::try_from(block.data().clone()).expect("unsigned form must rebuild");
		assert_eq!(block.hash(), unsigned.hash(), "signed and unsigned hash must agree");
	}
}
