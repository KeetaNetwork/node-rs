# keetanetwork-client

This crate owns `KeetaClient`, `UserClient`, and `TransactionBuilder`. HTTP transport is generated from `keetanetwork-client/openapi/keetanet-node.yaml`.

## Quickstart

Default features include `std`. Feature `http` pairs with a runtime. Native builds enable `std`. Browser builds enable `wasm`.

```bash
cargo test -p keetanetwork-client --test user_signing
```

`make test` runs the workspace tests after the node harness. [Workspace Quickstart](../../docs/QUICKSTART.md) holds the Packages gate.

## Examples

### KeetaClient builder

From `keetanetwork-client/src/lib.rs` rustdoc.

```rust
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_account::doc_utils::create_ed25519_test_keys;
use keetanetwork_block::AccountRef;
use keetanetwork_client::KeetaClient;

let client = KeetaClient::new("http://localhost:8080/api").with_network(0u8);
let (_, _, signer) = create_ed25519_test_keys(None);
let account: AccountRef = Arc::new(GenericAccount::Ed25519(signer));

let blocks = client
	.builder(&account)
	.with_previous(account.to_opening_hash())
	.set_rep(&account)
	.build()
	.await?;
assert_eq!(blocks.len(), 1);
# Ok::<(), keetanetwork_client::ClientError>(())
```

### UserClient signing

From `keetanetwork-client/tests/user_signing.rs` `delegated_writes_are_signed_by_the_bound_signer`.

```rust
use std::sync::Arc;

use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_client::{KeetaClient, UserClient};

let client = KeetaClient::new("http://127.0.0.1:0/api").with_network(1u8);
let account = generate_ed25519_ref(0x40);
let signer = generate_ed25519_ref(0x41);
let rep = generate_ed25519_ref(0x43);
let user = UserClient::from_parts(client, Some(Arc::clone(&signer))).with_account(Arc::clone(&account));

let mut builder = user.init_builder()?;
builder.with_previous(account.to_opening_hash());
builder.set_rep(&rep);
let blocks = builder.build().await?;
assert_eq!(blocks[0].data().signer().principal().to_string(), signer.to_string());
# Ok::<(), keetanetwork_client::ClientError>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
