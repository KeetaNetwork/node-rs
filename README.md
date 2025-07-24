# node-rs

A Rust implementation of KeetaNet node

## Development

### Quick Start

For first-time setup, simply run:

```bash
make developer
```

This will:

- Install Rust (if not already installed)
- Install development tools
- Run initial build and tests

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
