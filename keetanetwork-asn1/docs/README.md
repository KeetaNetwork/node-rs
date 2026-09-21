# keetanetwork-asn1

This crate owns the encoding codecs that identity, certificate, block, and vote types share. A build enables at least one of `der` or `rasn`. Both features may be on together.

## Quickstart

Default features are `std`, `serde`, and `rasn`. Enable at least one of `der` or `rasn`.

```bash
cargo test -p keetanetwork-asn1
```

`make test-feat` also runs this crate with `std,der` and `std,rasn`.

## Examples

### Encode a vote staple

From `keetanetwork-asn1/tests/vote_codec_vectors.rs` `test_vote_staple_reference_bytes`.

```rust
use keetanetwork_asn1::vote::{codec, VoteStapleBundle};

let bundle = VoteStapleBundle {
	blocks: vec![vec![1, 2, 3]],
	votes: vec![vec![4, 5, 6]],
};
let encoded = codec::encode_vote_staple(&bundle).expect("encode staple");
assert!(!encoded.is_empty());
```

### Decode a vote staple

From `keetanetwork-asn1/tests/vote_codec_vectors.rs` `test_vote_staple_reference_bytes`.

```rust
use keetanetwork_asn1::vote::{codec, VoteStapleBundle};

let bundle = VoteStapleBundle {
	blocks: vec![vec![1, 2, 3]],
	votes: vec![vec![4, 5, 6]],
};
let encoded = codec::encode_vote_staple(&bundle).expect("encode staple");
let decoded = codec::decode_vote_staple(&encoded).expect("decode staple");
assert_eq!(decoded, bundle);
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
