# ASN.1

## Abstract

This page is the consumer contract for `keetanetwork-asn1`. The crate owns the encoding codecs that identity, certificate, block, and vote types share. A build enables at least one of `der` or `rasn`.

## Purpose

An engineer reads this page before changing a codec feature or adding a third ASN.1 stack. After reading, the engineer knows the at-least-one feature contract and which crates forward `der` and `rasn` into this crate.

## Ownership

`keetanetwork-asn1` owns ASN.1 structures and codec utilities used by certificates and related encodings. Crate rustdoc in `keetanetwork-asn1/src/lib.rs` lists the features and states the at-least-one contract.

This crate depends on `keetanetwork-utils`. The `build` feature on that crate supplies generation helpers. [Utils](../../keetanetwork-utils/docs/ARCHITECTURE.md) holds that helper.

## Feature contract

A consumer enables at least one of `der` or `rasn`. Both features may be on together. The `compile_error!` in `keetanetwork-asn1/src/lib.rs` is the enforcement point.

Default features are `std`, `serde`, and `rasn`. `std` implies `alloc`.

Higher crates expose `der` and `rasn` under the same names and forward them here. Those crates include `keetanetwork-account`, `keetanetwork-crypto`, `keetanetwork-x509`, `keetanetwork-block`, and `keetanetwork-vote`.

## Who consumes this crate

Block, vote, x509, account, crypto, and bindings crates depend on this crate when they encode or decode shared structures. [Architecture](../../docs/ARCHITECTURE.md) holds the collaboration graph.

## Example

From `keetanetwork-asn1/tests/vote_codec_vectors.rs` `test_vote_staple_reference_bytes`.

```rust
use keetanetwork_asn1::vote::{codec, VoteStapleBundle};

let bundle = VoteStapleBundle { blocks: vec![vec![1, 2, 3]], votes: vec![vec![4, 5, 6]] };
let encoded = codec::encode_vote_staple(&bundle).expect("encode staple");
assert!(!encoded.is_empty());
```

## Falsified by

A change to the `compile_error!` in `keetanetwork-asn1/src/lib.rs` that no longer requires at least one of `der` or `rasn`. A change that adds a third codec feature without updating this page and the rustdoc feature list. A change that stops `keetanetwork-account`, `keetanetwork-block`, or `keetanetwork-vote` from forwarding `der` and `rasn` here.
