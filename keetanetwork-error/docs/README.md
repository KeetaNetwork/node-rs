# keetanetwork-error

This crate owns shared error types that higher crates return. `KeetaNetError` carries an internal failure or a node-emitted coded error. `NodeErrorType` is the category taken from the `type` field of a node error envelope. `keetanetwork-client` re-exports both types.

## Quickstart

Default features include `std`. `std` implies `alloc`. The crate builds under `no_std` with `alloc`.

```bash
cargo test -p keetanetwork-error
```

## Example

From `keetanetwork-error/src/lib.rs` `non_ledger_collapses_to_code`.

```rust
use keetanetwork_error::{KeetaNetError, NodeErrorParts, NodeErrorType};

let parts = NodeErrorParts {
	kind: NodeErrorType::Api,
	code: "API_INVALID_SIDE".into(),
	message: "boom".into(),
	..Default::default()
};
let error = KeetaNetError::from(parts);
assert!(matches!(error, KeetaNetError::Code { code, .. } if code == "API_INVALID_SIDE"));
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
