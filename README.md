# node-rs

A Rust implementation of KeetaNet node

## Development

### Prerequisites

- Rust 1.70+ (MSRV)
- Cargo
- Make

### Building

```bash
# Debug build
make build

# Release build
make release

# Check compilation without building
make check
```

### Testing

```bash
make test
```

### Code Coverage

```bash
# Generate HTML coverage report (opens in browser)
make coverage

# Generate LCOV coverage report for CI
make coverage-ci
```

### Linting

```bash
# Format code and run clippy
make lint
```

### Other Commands

```bash
# Clean build artifacts
make clean

# Show all available commands
make help
```
