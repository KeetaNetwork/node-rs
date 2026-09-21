# keetanetwork-client-wasi

This crate is the WASI ABI over a shared `pure` module. A WASI build selects exactly one of `p1` or `p2`. Feature `p2` pulls `keetanetwork-client`. Feature `p1` stays on the pure surface.

## Quickstart

Select exactly one of `p1` or `p2` per WASI build.

```bash
make build-wasi
make test-wasi
```

Those Make targets select `p1` for `wasm32-wasip1` and `p2` for `wasm32-wasip2`. Off a WASI target both features compile out and leave `pure`.

```bash
cargo test -p keetanetwork-client-wasi
```

## Examples

### Seed and account on the pure surface

From `keetanetwork-bindings/src/account.rs` `account_round_trips_through_seed_and_public_key_string`, re-exported by `keetanetwork-client-wasi/src/pure.rs`.

```rust
use keetanetwork_client_wasi::pure;

let seed = pure::generate_seed().expect("seed generation must succeed");
let account = pure::account_from_seed(&seed, 0, pure::DEFAULT_ALGORITHM)
	.expect("account derivation must succeed");
let public_key_string = pure::account_public_key_string(&account);
assert!(!public_key_string.is_empty());
```

### Identifier from a pure account

From `keetanetwork-client-wasi/src/pure.rs` `generate_identifier`.

```rust
use keetanetwork_account::KeyPairType;
use keetanetwork_client_wasi::pure;

let seed = pure::generate_seed().expect("seed generation must succeed");
let account = pure::account_from_seed(&seed, 0, pure::DEFAULT_ALGORITHM)
	.expect("account derivation must succeed");
let token = pure::generate_identifier(&account, KeyPairType::TOKEN, None, 0)
	.expect("identifier derivation must succeed");
assert_ne!(pure::account_public_key_string(&account), pure::account_public_key_string(&token));
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
