//! Offline integration tests for `UserClient` signing semantics and the
//! builder's empty-block elision, exercised through public interfaces only.

use std::sync::Arc;

use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_block::{Amount, Operation, SetInfo};
use keetanetwork_client::{ClientError, KeetaClient, UserClient};

fn offline_client() -> KeetaClient {
	KeetaClient::new("http://127.0.0.1:0/api").with_network(1u8)
}

#[tokio::test]
async fn delegated_writes_are_signed_by_the_bound_signer() -> Result<(), ClientError> {
	let client = offline_client();
	let account = generate_ed25519_ref(0x40);
	let signer = generate_ed25519_ref(0x41);
	let rep = generate_ed25519_ref(0x43);
	let user = UserClient::from_parts(client, Some(Arc::clone(&signer))).with_account(Arc::clone(&account));

	let mut builder = user.init_builder()?;
	builder.with_previous(account.to_opening_hash());
	builder.set_rep(&rep);

	let blocks = builder.build().await?;
	assert_eq!(blocks.len(), 1, "one send must render to one block");

	let data = blocks[0].data();
	assert_eq!(data.account().to_string(), account.to_string(), "the block must originate for the operating account");
	assert_eq!(
		data.signer().principal().to_string(),
		signer.to_string(),
		"the block must be signed by the bound signer, not the operating account"
	);

	Ok(())
}

#[tokio::test]
async fn build_elides_groups_that_render_to_no_operations() -> Result<(), ClientError> {
	let client = offline_client();
	let signer = generate_ed25519_ref(0x44);
	let token = generate_ed25519_ref(0x45);
	let recipient = generate_ed25519_ref(0x46);
	let user = UserClient::from_parts(client, Some(Arc::clone(&signer)));

	let mut builder = user.init_builder()?;
	builder.with_previous(signer.to_opening_hash());
	builder.send(&recipient, &token, Amount::from(0u64));

	let blocks = builder.build().await?;
	assert!(blocks.is_empty(), "a group of only zero-amount transfers must not seal a no-op block");

	Ok(())
}

#[tokio::test]
async fn set_info_merges_repeated_calls_into_one_operation() -> Result<(), ClientError> {
	// SET_INFO carries network-parameterized text rules, so seal against a
	// known network (TestDefault, id 0) to exercise operation validation.
	let client = KeetaClient::new("http://127.0.0.1:0/api").with_network(0u8);
	let signer = generate_ed25519_ref(0x47);
	let user = UserClient::from_parts(client, Some(Arc::clone(&signer)));

	let mut builder = user.init_builder()?;
	builder.with_previous(signer.to_opening_hash());
	builder.set_info(SetInfo {
		name: "ALPHA".to_string(),
		description: String::new(),
		metadata: String::new(),
		default_permission: None,
	});
	builder.set_info(SetInfo {
		name: String::new(),
		description: "the_second_call".to_string(),
		metadata: String::new(),
		default_permission: None,
	});

	let blocks = builder.build().await?;
	assert_eq!(blocks.len(), 1, "the merged info must render to a single block");

	let infos: Vec<&SetInfo> = blocks[0]
		.data()
		.operations()
		.iter()
		.filter_map(|op| match op {
			Operation::SetInfo(info) => Some(info),
			_ => None,
		})
		.collect();
	assert_eq!(infos.len(), 1, "repeated set_info calls must merge into a single SET_INFO operation");
	assert_eq!(infos[0].name, "ALPHA", "the first call's name must survive the field merge");
	assert_eq!(infos[0].description, "the_second_call", "the second call's description must survive the field merge");

	Ok(())
}

#[test]
fn read_only_client_rejects_builder_construction() {
	let client = offline_client();
	let user = UserClient::from_parts(client, None);
	assert!(
		matches!(user.init_builder(), Err(ClientError::SignerRequired)),
		"a read-only client must refuse to start a write builder"
	);
}
