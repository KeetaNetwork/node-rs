# keetanetwork-client-wasi

This crate is the WASI ABI over a shared `pure` module. A WASI build selects exactly one of `p1` or `p2`. Feature `p2` pulls `keetanetwork-client`. Feature `p1` stays on the pure surface.

## Quickstart

Select exactly one of `p1` or `p2` per WASI build.

```bash
make build-wasi
make test-wasi
```

Those Make targets select `p1` for `wasm32-wasip1` and `p2` for `wasm32-wasip2`. They need GitHub Packages read. Off a WASI target both features compile out and leave `pure`.

```bash
cargo test -p keetanetwork-client-wasi
```

## Example

From `keetanetwork-client-wasi/src/pure.rs` re-export of `keetanetwork-bindings/src/account.rs` `generated_seed_is_32_byte_hex`.

```rust
use keetanetwork_client_wasi::pure;

let seed = pure::generate_seed().expect("seed generation must succeed");
assert_eq!(seed.len(), 64);
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
