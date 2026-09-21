# Quickstart

## Abstract

This page is the install and first-build path for the `node-rs` workspace. It records the Makefile targets a reader uses on this tip. A later pass adds the Packages gate and the first-use snippet.

## Purpose

Read this page when you clone the repository or when you need the correct build command. After reading you can set up the toolchain and run a debug or release build.

## Pin the toolchain

Use Rust `1.94.0` from `rust-toolchain.toml`. After you clone, that pin wins over a default rustup toolchain.

The file also requests `rustfmt`, `clippy`, and `llvm-tools-preview`. It also requests the `wasm32-unknown-unknown`, `wasm32-wasip1`, and `wasm32-wasip2` targets.

## Set up the tree

Run first-time setup.

```bash
make developer
```

`make developer` installs rustc through `scripts/rustup-init.sh` when rustc is missing. That script requests the `stable` toolchain. The repo pin still selects `1.94.0` for this tree after clone.

## Build

Use the Make targets. Use `make build release=1` for a release build.

| Target | What you get |
| --- | --- |
| `make developer` | First-time toolchain and tool setup |
| `make build` | Debug build through `cargo build` |
| `make build release=1` | Release build through `cargo build --release` |
| `make check` | Compilation check through `cargo check` |

Release build:

```bash
make build release=1
```

`make release` runs `scripts/release.sh` and publishes crates. That target is a publish path. It is not a release build.

## Later install notes

A later pass adds the GitHub Packages gate, the cargo-only path, the test matrix, and the first-use snippet. Until that pass lands, use `make build` and `make check` on this tree.

## Falsified by

A change to the `build`, `check`, `developer`, or `release` targets in `Makefile`. A change to the channel in `rust-toolchain.toml`.
