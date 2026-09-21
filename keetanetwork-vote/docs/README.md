# keetanetwork-vote

This crate owns `Vote`, `VoteQuote`, `VoteStaple`, and `PossiblyExpiredVote`. A quote is for fee negotiation. A staple is the bundle that operators transmit. The client re-exports the consumer-facing vote types.

## Quickstart

Default features are `std` and `rasn`. `std` implies `alloc`.

```bash
cargo test -p keetanetwork-vote
```

## Example

From `keetanetwork-vote/src/lib.rs` rustdoc.

```rust
use std::sync::Arc;

use keetanetwork_account::GenericAccount;
use keetanetwork_account::doc_utils::create_ed25519_test_keys;
use keetanetwork_block::{AccountRef, BlockTime};
use keetanetwork_vote::VoteBuilder;

let (_, _, signer) = create_ed25519_test_keys(None);
let issuer: AccountRef = Arc::new(GenericAccount::Ed25519(signer));

let from = BlockTime::from_unix_millis(1_000_000).expect("moment in range");
let to = BlockTime::from_unix_millis(2_000_000).expect("moment in range");

let vote = VoteBuilder::new()
	.serial(1u64)
	.issuer(issuer.clone())
	.validity(from, to)
	.add_block(issuer.to_opening_hash())
	.build_signed(issuer.as_ref())?;

assert!(!vote.as_bytes().is_empty());
# Ok::<(), keetanetwork_vote::VoteError>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
