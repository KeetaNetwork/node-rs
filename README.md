# node-rs

This repository is a Rust workspace for Keeta Network node crates.

The toolchain pin is Rust `1.94.0` in `rust-toolchain.toml`.

## Commands

First-time setup:

```bash
make developer
```

Debug build:

```bash
make build
```

Release build:

```bash
make build release=1
```

Check compilation without a full build:

```bash
make check
```

## Documentation

- [Overview](docs/README.md)
- [Quickstart](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Documentation Standard](docs/STANDARD.md)
