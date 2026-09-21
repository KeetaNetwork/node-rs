# Vote

## Abstract

This page is the consumer contract for `keetanetwork-vote`. The crate owns `Vote`, `VoteQuote`, `VoteStaple`, and `PossiblyExpiredVote`. The client re-exports the consumer-facing vote types. A quote is for fee negotiation. A staple is the bundle that operators transmit.

## Purpose

An engineer reads this page before changing vote construction or adding a second staple type in the client. After reading, the engineer knows which vote kinds this crate owns and which crate re-exports them.

## Ownership

A `Vote` is a representative's signed commitment that named block hashes should enter the ledger. A `VoteQuote` is a non-binding vote whose fees field has `quote = true`. A quote cannot be stapled or used to confirm blocks. A `PossiblyExpiredVote` is a parsed and signature-verified vote whose validity window may have ended. A `VoteStaple` is the compressed bundle of votes and the blocks they cover.

`VoteBuilder`, `VoteQuoteBuilder`, and `VoteStapleBuilder` assemble those types. Crate rustdoc in `keetanetwork-vote/src/lib.rs` holds the rustdoc example and the verification contract. This crate denies missing docs.

Cookbooks live in `keetanetwork-vote/tests/e2e_node.rs`, `keetanetwork-vote/tests/typescript_compat.rs`, and `keetanetwork-vote/tests/wire_corruption.rs`.

## Who consumes this crate

`keetanetwork-client` depends on this crate and re-exports `Vote`, `VoteQuote`, `VoteStaple`, and `VoteBlockHash` from `keetanetwork-client/src/lib.rs`. `keetanetwork-bindings` and `keetanetwork-client-wasi` depend on this crate so host ABIs can project vote types.

[Block](block.md) holds the hashes a vote covers. [Client](client.md) holds the transmit path. [Architecture](../ARCHITECTURE.md) holds the collaboration path.

## Feature contract

Default features are `std` and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1`, `keetanetwork-account`, `keetanetwork-crypto`, and `keetanetwork-block`.

This crate depends on `keetanetwork-error`, `keetanetwork-utils`, `keetanetwork-crypto` with `signature`, `keetanetwork-account`, `keetanetwork-asn1`, and `keetanetwork-block`.

A `no_std` consumer enables `alloc` and at least one of `der` or `rasn`. [ASN.1](asn1.md) holds the codec contract.

## Falsified by

A change to `Vote`, `VoteQuote`, `VoteStaple`, or `PossiblyExpiredVote` ownership. A change that drops the client re-export of `Vote`, `VoteQuote`, or `VoteStaple` from `keetanetwork-client/src/lib.rs`. A change to the rustdoc example in `keetanetwork-vote/src/lib.rs`.
