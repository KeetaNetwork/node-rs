# keetanetwork-client

This crate owns `KeetaClient`, `UserClient`, and `TransactionBuilder`. HTTP transport is generated from `keetanetwork-client/openapi/keetanet-node.yaml`. The crate re-exports the consumer-facing vote types.

## Quickstart

Default features include `std`. Feature `std` enables `http` and a native Tokio runtime. Feature `wasm` enables `http` on `wasm32-unknown-unknown`. Feature `http` pairs with a runtime.

```bash
cargo test -p keetanetwork-client --test user_signing
```

`make test` runs the workspace tests after the node harness. That path needs GitHub Packages read. [Workspace Quickstart](../../docs/QUICKSTART.md) holds the cargo-only path.

## Example

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

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
