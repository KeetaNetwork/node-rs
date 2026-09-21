# keetanetwork-block

This crate owns `Block`, `BlockBuilder`, `Operation`, and `AccountRef`. Opening-hash and signing rules live here. The client builder uses the same rules when it assembles a first block or a successor.

## Quickstart

Default features are `std` and `rasn`. `std` implies `alloc`.

```bash
cargo test -p keetanetwork-block
```

`make test-feat` also runs this crate with `std,der` and `std,rasn`.

## Example

From `keetanetwork-block/src/lib.rs` rustdoc.

```rust
use keetanetwork_account::{Account, Accountable, GenericAccount, KeyED25519, KeyPairType, Keyable};
use keetanetwork_block::{AccountRef, Block, BlockBuilder, Receive};
use keetanetwork_crypto::hash::Hashable;
use keetanetwork_crypto::prelude::IntoSecret;

let seed = [7u8; 32].into_secret();
let account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
	Keyable::Seed((seed, 0)),
	KeyPairType::ED25519,
))?;
let token = account.generate_identifier(KeyPairType::TOKEN, None, 0)?;
let account = AccountRef::from(GenericAccount::Ed25519(account));

let unsigned = BlockBuilder::default()
	.with_network(0u8)
	.with_account(account.clone())
	.as_opening()
	.with_operation(Receive {
		amount: 10u64.into(),
		token: token.into(),
		from: account.clone(),
		exact: false,
		forward: None,
	})
	.build()?;

let block = unsigned.sign()?;
let decoded = Block::try_from(block.to_bytes())?;
assert_eq!(decoded.hash(), block.hash());
# Ok::<(), keetanetwork_block::BlockError>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
