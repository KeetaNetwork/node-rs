# keetanetwork-utils

This crate owns shared test macros, optional ASN.1 build helpers, and the `node-harness` feature that talks to the private GitHub Packages package.

## Quickstart

Default features include `std`. Feature `build` is opt-in. Feature `node-harness` is opt-in.

```bash
cargo test -p keetanetwork-utils
```

[Workspace Quickstart](../../docs/QUICKSTART.md) holds the Packages token steps for `node-harness`.

## Examples

### Error variant tests

From `keetanetwork-utils/src/testing.rs` `test_error_variants`.

```rust
use keetanetwork_utils::test_error_variants;

#[derive(Debug, PartialEq, Eq)]
enum TestError {
	Simple,
	WithData { message: String },
}

impl std::fmt::Display for TestError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			TestError::Simple => write!(f, "Simple error"),
			TestError::WithData { message } => write!(f, "Error: {message}"),
		}
	}
}

test_error_variants! {
	test_error_formatting, [
		TestError::Simple,
		TestError::WithData { message: "test".to_string() },
	]
}
```

### Source error From impls

From `keetanetwork-utils/src/errors.rs` rustdoc on `impl_source_error_from`.

```rust
use keetanetwork_utils::impl_source_error_from;

#[derive(Debug)]
enum MyError {
	IoError { source: std::io::Error },
	ParseError { source: std::num::ParseIntError },
}

impl_source_error_from!(MyError, {
	std::io::Error => IoError,
	std::num::ParseIntError => ParseError,
});
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
