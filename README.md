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
# Test defaults with all features
make test

# Test all features individually from packages with features
make test-feat

# Test everything
make test-all
```

### Code Coverage

```bash
# Generate HTML coverage report (opens in browser)
make coverage
```

### Linting

```bash
# Format code and run clippy
make do-lint
```

### Documentation

```bash
# Generate documentation and open it
make do-docs
```

### Other Commands

```bash
# Clean build artifacts
make clean

# Show all available commands
make help
```

### CI Commands

```bash
# Generate LCOV coverage report for CI
make coverage-ci

# Format code and clippy without fixes
make do-lint-ci
```
