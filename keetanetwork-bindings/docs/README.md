# keetanetwork-bindings

This crate is the shared, target-agnostic projection used by the browser and WASI ABIs. It owns input parsing, account-algorithm mapping, and core-error reduction so those ABIs do not each grow a second copy.

## Quickstart

Default features include `std`. Feature `client` is opt-in and enables `keetanetwork-client`.

```bash
cargo test -p keetanetwork-bindings
```

## Example

From `keetanetwork-bindings/src/parse.rs` `amount_round_trips_decimal_strings`.

```rust
use keetanetwork_bindings::parse::{amount, amount_to_string};

let parsed = amount("1000").expect("a decimal string must parse");
assert_eq!(amount_to_string(parsed), "1000");
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
