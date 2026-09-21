# keetanetwork-bindings

This crate is the shared, target-agnostic projection used by the browser and WASI ABIs. It owns input parsing, account-algorithm mapping, and core-error reduction.

## Quickstart

Default features include `std`. Feature `client` is opt-in.

```bash
cargo test -p keetanetwork-bindings
```

## Examples

### Parse amount

From `keetanetwork-bindings/src/parse.rs` `amount_round_trips_decimal_strings`.

```rust
use keetanetwork_bindings::parse::{amount, amount_to_string};

let parsed = amount("1000").expect("a decimal string must parse");
assert_eq!(amount_to_string(parsed), "1000");
```

### Algorithm map

From `keetanetwork-bindings/src/account.rs` `algorithm_names_round_trip_every_crypto_type`.

```rust
use keetanetwork_account::KeyPairType;
use keetanetwork_bindings::account::{algorithm_name, CRYPTO_ALGORITHMS};

assert_eq!(algorithm_name(KeyPairType::ED25519), "ed25519");
assert_eq!(algorithm_name(KeyPairType::TOKEN), "other");
assert_eq!(CRYPTO_ALGORITHMS[1].0, "ecdsa_secp256k1");
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
