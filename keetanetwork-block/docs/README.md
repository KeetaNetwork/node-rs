# keetanetwork-block

This crate owns `Block`, `BlockBuilder`, `Operation`, and `AccountRef`. Opening-hash and signing rules live here. The client builder uses the same rules.

## Quickstart

Default features are `std` and `rasn`.

```bash
cargo test -p keetanetwork-block
```

`make test-feat` also runs this crate with `std,der` and `std,rasn`.

## Examples

### Opening block and sign

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

### Successor with previous hash

From `keetanetwork-block/src/lib.rs` rustdoc for the opening, plus `keetanetwork-block/tests/e2e.rs` successor `Send`.

```rust
use keetanetwork_account::{Account, Accountable, GenericAccount, KeyED25519, KeyPairType, Keyable};
use keetanetwork_block::{AccountRef, BlockBuilder, Receive, Send};
use keetanetwork_crypto::hash::Hashable;
use keetanetwork_crypto::prelude::IntoSecret;

let seed = [7u8; 32].into_secret();
let account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
	Keyable::Seed((seed, 0)),
	KeyPairType::ED25519,
))?;
let token = account.generate_identifier(KeyPairType::TOKEN, None, 0)?;
let account = AccountRef::from(GenericAccount::Ed25519(account));

let opening = BlockBuilder::default()
	.with_network(0u8)
	.with_account(account.clone())
	.as_opening()
	.with_operation(Receive {
		amount: 10u64.into(),
		token: token.clone().into(),
		from: account.clone(),
		exact: false,
		forward: None,
	})
	.build()?
	.sign()?;

let successor = BlockBuilder::default()
	.with_network(0u8)
	.with_account(account.clone())
	.with_previous(opening.hash())
	.with_operation(Send {
		to: account.clone(),
		amount: 1u64.into(),
		token: token.into(),
		external: None,
	})
	.build()?
	.sign()?;
assert_ne!(successor.hash(), opening.hash());
# Ok::<(), keetanetwork_block::BlockError>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
