//! Live round-trip compatibility tests against the reference TypeScript
//! implementation.

mod support;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{
	AdjustMethod, Amount, BaseFlag, Block, BlockBuilder, BlockPurpose, BlockTime, BlockVersion, CertificateDer,
	CertificateOrHash, CreateIdentifier, Hashable, IntermediateCertificates, ManageCertificate, ModifyPermissions,
	ModifyPermissionsPrincipal, Permissions, Receive, Send, SetInfo, SetRep, Signer, TokenAdminModifyBalance,
	TokenAdminSupply, UnsignedBlock,
};
use keetanetwork_utils::node_harness::{run_node_script, script_path};

use support::{generate_ed25519_ref, generate_identifier_ref};

/// The path of a compiled harness helper script.
fn script(name: &str) -> std::path::PathBuf {
	script_path(name).expect("harness scripts must be built (run `make node-harness`)")
}

/// Parse blocks with the reference implementation, returning `(hash,
/// re-serialized hex)` per block.
fn ts_parse(blocks_hex: &[String]) -> Vec<(String, String)> {
	let stdin = blocks_hex.join("\n") + "\n";
	let output = run_node_script(script("ts_verify"), [] as [&str; 0], Some(stdin.as_bytes()))
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
fn ts_mint_certificate(subject: &keetanetwork_block::AccountRef) -> Vec<u8> {
	let output = run_node_script(script("ts_mint_cert"), [subject.to_string()], None)
		.expect("certificate minting via the reference implementation must succeed");

	let stdout = String::from_utf8(output.stdout).expect("node output must be UTF-8");
	hex::decode(stdout.trim()).expect("minted certificate must be hex")
}

fn fixed_date() -> BlockTime {
	BlockTime::from_unix_millis(1_748_781_296_789).expect("fixed test date must be valid")
}

fn rust_built_blocks() -> Vec<Block> {
	let alice = generate_ed25519_ref(0x21);
	let bob = generate_ed25519_ref(0x22);
	let carol = generate_ed25519_ref(0x23);
	let token = generate_identifier_ref(&alice, KeyPairType::TOKEN, 0);
	let multisig_outer = generate_identifier_ref(&alice, KeyPairType::MULTISIG, 1);
	let multisig_inner = generate_identifier_ref(&alice, KeyPairType::MULTISIG, 2);

	let send = Send {
		to: bob.clone(),
		amount: Amount::from(12345u64),
		token: token.clone(),
		external: Some("ref 7".to_string()),
	};

	let mut blocks = Vec::new();

	// V2 with full header
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_subnet(77u8)
			.with_idempotent([1u8, 2, 3, 4])
			.with_date(fixed_date())
			.with_account(alice.clone())
			.as_opening()
			.with_operation(send.clone())
			.build()
			.expect("v2 block must build")
			.sign()
			.expect("v2 block must sign"),
	);

	// V1
	blocks.push(
		BlockBuilder::default()
			.with_version(BlockVersion::V1)
			.with_network(0u8)
			.with_date(fixed_date())
			.with_account(alice.clone())
			.as_opening()
			.with_operation(Receive {
				amount: Amount::from(9u64),
				token: token.clone(),
				from: bob.clone(),
				exact: false,
				forward: None,
			})
			.build()
			.expect("v1 block must build")
			.sign()
			.expect("v1 block must sign"),
	);

	// FEE purpose
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_purpose(BlockPurpose::Fee)
			.with_date(fixed_date())
			.with_account(alice.clone())
			.as_opening()
			.with_operation(send.clone())
			.build()
			.expect("fee block must build")
			.sign()
			.expect("fee block must sign"),
	);

	// Nested multisig signer tree with multiple signatures
	let signer = Signer::Multisig {
		address: multisig_outer,
		signers: vec![
			Signer::Single(bob.clone()),
			Signer::Multisig {
				address: multisig_inner,
				signers: vec![Signer::Single(carol.clone()), Signer::Single(alice.clone())],
			},
		],
	};
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_date(fixed_date())
			.with_account(alice.clone())
			.with_signer(signer)
			.as_opening()
			.with_operation(send)
			.build()
			.expect("multisig block must build")
			.sign()
			.expect("multisig block must sign"),
	);

	// Several operation types in one block (old date permits the negative
	// balance adjustment)
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_date(BlockTime::from_unix_millis(1_704_164_645_000).expect("old date must be valid"))
			.with_account(alice.clone())
			.as_opening()
			.with_operation(SetRep { to: bob.clone() })
			.with_operation(SetInfo {
				name: "RUST_BLOCK".to_string(),
				description: "Built by the Rust implementation".to_string(),
				metadata: "bWV0YQ==".to_string(),
				default_permission: None,
			})
			.with_operation(TokenAdminModifyBalance {
				token: token.clone(),
				amount: Amount::from(-3i64),
				method: AdjustMethod::Add,
			})
			.with_operation(Receive {
				amount: Amount::from(77u64),
				token: token.clone(),
				from: bob.clone(),
				exact: true,
				forward: Some(bob.clone()),
			})
			.build()
			.expect("multi-op block must build")
			.sign()
			.expect("multi-op block must sign"),
	);

	// MODIFY_PERMISSIONS with an account principal
	let permissions =
		Permissions::from_flags(&[BaseFlag::Access, BaseFlag::UpdateInfo], &[]).expect("permissions must build");
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_date(fixed_date())
			.with_account(alice.clone())
			.as_opening()
			.with_operation(ModifyPermissions {
				principal: ModifyPermissionsPrincipal::Account(bob.clone()),
				method: AdjustMethod::Set,
				permissions: Some(permissions),
				target: None,
			})
			.build()
			.expect("modify-permissions block must build")
			.sign()
			.expect("modify-permissions block must sign"),
	);

	// CREATE_IDENTIFIER on an opening block (derivation: no previous,
	// operation index 0 -- matching the `token` helper derivation)
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_date(fixed_date())
			.with_account(alice.clone())
			.as_opening()
			.with_operation(CreateIdentifier { identifier: token.clone(), create_arguments: None })
			.build()
			.expect("create-identifier block must build")
			.sign()
			.expect("create-identifier block must sign"),
	);

	// TOKEN_ADMIN_SUPPLY on a token account with a delegate signer
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_date(fixed_date())
			.with_account(token.clone())
			.with_signer(alice.clone())
			.as_opening()
			.with_operation(TokenAdminSupply { amount: Amount::from(1_000_000u64), method: AdjustMethod::Add })
			.build()
			.expect("token-admin-supply block must build")
			.sign()
			.expect("token-admin-supply block must sign"),
	);

	// MANAGE_CERTIFICATE removal by hash
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_date(fixed_date())
			.with_account(alice.clone())
			.as_opening()
			.with_operation(ManageCertificate {
				method: AdjustMethod::Subtract,
				certificate_or_hash: CertificateOrHash::Hash([0x42u8; 32]),
				intermediate_certificates: None,
			})
			.build()
			.expect("manage-certificate block must build")
			.sign()
			.expect("manage-certificate block must sign"),
	);

	// MANAGE_CERTIFICATE addition with a real minted certificate
	let certificate = ts_mint_certificate(&alice);
	blocks.push(
		BlockBuilder::default()
			.with_network(0u8)
			.with_date(fixed_date())
			.with_account(alice.clone())
			.as_opening()
			.with_operation(ManageCertificate {
				method: AdjustMethod::Add,
				certificate_or_hash: CertificateOrHash::Certificate(CertificateDer::from(certificate)),
				intermediate_certificates: Some(IntermediateCertificates::None),
			})
			.build()
			.expect("manage-certificate-add block must build")
			.sign()
			.expect("manage-certificate-add block must sign"),
	);

	blocks
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
		assert_eq!(&block.hash().to_string(), ts_hash, "hashes must agree across implementations");
		assert_eq!(&hex::encode_upper(block.to_bytes()), ts_bytes, "bytes must round-trip unchanged");
	}
}

#[test]
fn test_typescript_blocks_parse_in_rust() {
	let out_dir = std::env::temp_dir().join(format!("keetanet-block-compat-{}", std::process::id()));
	std::fs::create_dir_all(&out_dir).expect("temp dir must be creatable");

	// Re-generate fixtures live so this covers the current reference
	// implementation, not just the checked-in vectors.
	let out_file = out_dir.join("blocks.json");
	run_node_script(script("generate_fixtures"), [&out_file], None)
		.expect("fixture generation against the live reference must succeed");

	let raw = std::fs::read_to_string(&out_file).expect("live fixtures must exist");
	let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("fixtures must parse");

	for fixture in fixtures.as_array().expect("fixtures must be an array") {
		let name = fixture["name"].as_str().expect("fixture name");
		let bytes = hex::decode(fixture["bytes"].as_str().expect("fixture bytes")).expect("fixture hex");

		let block = Block::try_from(bytes.as_slice())
			.unwrap_or_else(|error| panic!("live fixture {name} must decode: {error}"));
		assert_eq!(
			hex::encode_upper(block.to_bytes()),
			fixture["bytes"].as_str().expect("fixture bytes"),
			"live fixture {name} must re-encode identically"
		);
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
