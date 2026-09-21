# Utils

## Abstract

This page is the consumer contract for `keetanetwork-utils`. The crate owns shared test macros, optional ASN.1 build helpers, and the `node-harness` feature that talks to the private GitHub Packages package. [Quickstart](../../docs/QUICKSTART.md) holds the operator steps for that gate.

## Purpose

An engineer reads this page before adding a workspace-wide test helper or changing the harness feature. After reading, the engineer knows which features this crate owns and which pages hold the install steps.

## Ownership

`keetanetwork-utils` owns reusable `macro_rules!` macros, a `testing` module, an optional `build` module, and an optional `node_harness` module. Crate rustdoc in `keetanetwork-utils/src/lib.rs` is the module reference.

Feature `build` enables `rasn-compiler` and the `build` module. `keetanetwork-asn1` and `keetanetwork-x509` use that feature from their build scripts.

Feature `node-harness` enables the harness client. `keetanetwork-utils/node-harness/.npmrc` sets `@keetanetwork:registry=https://npm.pkg.github.com`. [Quickstart](../../docs/QUICKSTART.md) holds the Packages token steps and the cargo-only path.

## Who consumes this crate

Account, crypto, asn1, x509, block, and vote crates depend on this crate for shared helpers. Test binaries enable `std` and `node-harness` when they talk to a live node.

This crate is not on the signed-write collaboration path in [Architecture](../../docs/ARCHITECTURE.md). It is the shared tooling under that path.

## Feature contract

Default features include `std`. Feature `build` is opt-in. Feature `node-harness` is opt-in and pulls `serde_json` and `snafu`.

A docs or compile-only change does not need `node-harness`. `make test`, `make test-wasm`, and `make test-wasi` do.

## Example

From `keetanetwork-utils/src/testing.rs` `test_error_variants`.

```rust
use keetanetwork_utils::test_error_variants;

#[derive(Debug, PartialEq, Eq)]
enum TestError {
	Simple,
}

impl std::fmt::Display for TestError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Simple error")
	}
}

test_error_variants! {
	test_error_formatting, [TestError::Simple]
}
```

## Falsified by

A change to the `build` or `node-harness` features in `keetanetwork-utils/Cargo.toml`. A change to the registry line in `keetanetwork-utils/node-harness/.npmrc`. A change that moves workspace test macros out of `keetanetwork-utils/src/lib.rs`.
