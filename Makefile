.PHONY: build clean do-docs do-docs-ci do-lint do-lint-ci test test-feat test-all all help check release coverage coverage-check coverage-ci coverage-setup audit docs developer node-harness node-harness-lint

# Project name
PROJ_NAME := node-rs

# Build configuration
release ?=

ifdef release
	release_flag := --release
	target := release
else
	release_flag :=
	target := debug
endif

# Default target
default: build

# Build everything
all: clean build test

# Just check compilation without building
check:
	cargo check

# Build the project
build:
	cargo build $(release_flag)

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/
	rm -rf build/

# Generate documentation without dependencies and open it
do-docs:
	cargo doc --no-deps --document-private-items --all-features --open

# Generate documentation without opening it (for CI)
do-docs-ci:
	cargo doc --no-deps --document-private-items --all-features

# Lint code
do-lint: do-docs-ci node-harness-lint
	cargo clippy --fix --allow-staged --allow-dirty --all-targets --all-features -- -D warnings
	cargo fmt

# Lint code for CI (check only, no fixes)
do-lint-ci: node-harness-lint
	cargo check --all-targets --all-features
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

# Test crate packages features
test-feat:
	cargo test -p keetanetwork-crypto --no-default-features --features signature
	cargo test -p keetanetwork-crypto --no-default-features --features encryption
	cargo test -p keetanetwork-crypto --no-default-features --features der
	cargo test -p keetanetwork-account --no-default-features --features der
	cargo test -p keetanetwork-account --no-default-features --features rasn
	cargo test -p keetanetwork-x509 --no-default-features --features der
	cargo test -p keetanetwork-x509 --no-default-features --features rasn
	cargo test -p keetanetwork-x509 --no-default-features --features der, serde
	cargo test -p keetanetwork-x509 --no-default-features --features rasn, serde
	cargo test -p keetanetwork-asn1 --no-default-features --features der
	cargo test -p keetanetwork-asn1 --no-default-features --features rasn
	cargo test -p keetanetwork-asn1 --no-default-features --features der,serde
	cargo test -p keetanetwork-asn1 --no-default-features --features rasn,serde
	cargo test -p keetanetwork-block --no-default-features --features der
	cargo test -p keetanetwork-block --no-default-features --features rasn
	cargo test -p keetanetwork-block --no-default-features --features der,rasn
	cargo test -p keetanetwork-crypto -p keetanetwork-x509 --all-features
	cargo test -p keetanetwork-crypto --no-default-features

# Reference implementation harness (required by compatibility/e2e tests)
HARNESS_DIR := keetanetwork-utils/node-harness
HARNESS_SOURCES := $(wildcard $(HARNESS_DIR)/src/*.ts) $(HARNESS_DIR)/tsconfig.json

$(HARNESS_DIR)/node_modules/.package-lock.json: $(HARNESS_DIR)/package-lock.json
	cd $(HARNESS_DIR) && npm ci

$(HARNESS_DIR)/dist/e2e_node.js: $(HARNESS_DIR)/node_modules/.package-lock.json $(HARNESS_SOURCES)
	cd $(HARNESS_DIR) && npm run build

node-harness: $(HARNESS_DIR)/dist/e2e_node.js

node-harness-lint: node-harness
	cd $(HARNESS_DIR) && npm run lint

# Run tests with host system's default target
test: node-harness
	# Use a shell script to unset CARGO_BUILD_TARGET and run tests
	sh -c 'unset CARGO_BUILD_TARGET; cargo test --all-features --workspace'

test-all: test test-feat

# Set up coverage tools (internal helper target)
coverage-setup:
	# Install cargo-llvm-cov if not present (quiet)
	@cargo install cargo-llvm-cov --quiet || true
	# Install llvm-tools-preview component (force, no prompts)
	@rustup component add llvm-tools-preview 2>/dev/null || true

# Generate code coverage report
coverage: coverage-setup
	# Clean previous coverage data
	@cargo llvm-cov clean --workspace || true
	# Generate HTML coverage report
	cargo llvm-cov --all-features --workspace --html --ignore-filename-regex 'build\.rs'
	# Generate LCOV coverage report (reusing the same coverage data)
	cargo llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex 'build\.rs'
	# Open HTML report in browser (macOS) if it exists
	@if [ -f target/llvm-cov/html/index.html ]; then \
		open target/llvm-cov/html/index.html; \
	else \
		echo "HTML report not found at target/llvm-cov/html/index.html"; \
		echo "Trying alternative location..."; \
		find target -name "index.html" -path "*/llvm-cov/*" 2>/dev/null | head -1 | xargs open || echo "No HTML report found"; \
	fi

# Check coverage percentage and fail if below threshold
coverage-check: coverage-setup
	# Generate coverage and check threshold
	@echo "Generating coverage report..."
	@cargo llvm-cov --all-features --workspace --summary-only > coverage_summary.txt 2>&1
	@COVERAGE=$$(grep "TOTAL" coverage_summary.txt | grep -oE '[0-9]+\.[0-9]+%' | tail -1 | sed 's/%//'); \
	THRESHOLD=90.0; \
	if [ -z "$$COVERAGE" ]; then \
		echo "❌ Could not extract total coverage percentage"; \
		cat coverage_summary.txt; \
		rm -f coverage_summary.txt; \
		exit 1; \
	fi; \
	echo "Current coverage: $${COVERAGE}%"; \
	echo "Minimum threshold: $${THRESHOLD}%"; \
	if [ $$(echo "$${COVERAGE} < $${THRESHOLD}" | bc -l) -eq 1 ]; then \
		echo "❌ Coverage $${COVERAGE}% is below threshold $${THRESHOLD}%"; \
		rm -f coverage_summary.txt; \
		exit 1; \
	else \
		echo "✅ Coverage $${COVERAGE}% meets threshold $${THRESHOLD}%"; \
		rm -f coverage_summary.txt; \
	fi

# Generate coverage report for CI (LCOV format for SonarCloud)
coverage-ci: coverage-setup
	# Generate LCOV coverage report for CI/SonarCloud
	cargo llvm-cov --all-features --workspace --lcov --output-path coverage.lcov

# Run security audit
audit:
	cargo audit

# Generate and open documentation
docs:
	cargo doc --no-deps --document-private-items --all-features --open

# Developer setup - install Rust and set up development environment
developer:
	@echo "🚀 Setting up development environment..."
	@if command -v rustc > /dev/null 2>&1; then \
		echo "✅ Rust is already installed (version: $$(rustc --version))"; \
	else \
		echo "📦 Installing Rust via rustup (automated)..."; \
		if [ -f scripts/rustup-init.sh ]; then \
			chmod +x scripts/rustup-init.sh; \
			./scripts/rustup-init.sh -y --default-toolchain stable; \
			echo "🔄 Rust installed! Sourcing environment..."; \
			. "$$HOME/.cargo/env" 2>/dev/null || true; \
		else \
			echo "❌ scripts/rustup-init.sh not found in project root."; \
			echo "   Please download it from: https://sh.rustup.rs/"; \
			exit 1; \
		fi; \
	fi
	@echo "🔧 Setting up development tools..."
	@if command -v rustc > /dev/null 2>&1; then \
		echo "📋 Rust version: $$(rustc --version)"; \
		echo "📋 Cargo version: $$(cargo --version)"; \
		echo "🧪 Installing development tools..."; \
		$(MAKE) coverage-setup; \
		cargo install cargo-audit --quiet || echo "⚠️  cargo-audit installation failed or already installed"; \
		echo "🔧 Installing script dependencies..."; \
		if ! command -v jq > /dev/null 2>&1; then \
			echo "📦 Installing jq..."; \
			if command -v brew > /dev/null 2>&1; then \
				brew install jq; \
			else \
				echo "⚠️  Please install jq manually: https://stedolan.github.io/jq/download/"; \
			fi; \
		else \
			echo "✅ jq is already installed"; \
		fi; \
		if ! command -v curl > /dev/null 2>&1; then \
			echo "📦 Installing curl..."; \
			if command -v brew > /dev/null 2>&1; then \
				brew install curl; \
			else \
				echo "⚠️  Please install curl manually"; \
			fi; \
		else \
			echo "✅ curl is already installed"; \
		fi; \
		echo "🏗️  Running initial build and test..."; \
		$(MAKE) check; \
		$(MAKE) test; \
		echo ""; \
		echo "✅ Development environment setup complete!"; \
	else \
		echo "⚠️  Rust installation completed but not available in current shell."; \
		echo "🔄 Please restart your shell or run:"; \
		echo "   source $$HOME/.cargo/env"; \
		echo "   make developer"; \
	fi
	$(MAKE) help

# Publish packages and create release
release:
	@echo "Running release script..."
	@./scripts/release.sh $(filter-out $@,$(MAKECMDGOALS))

# Allow flags to be passed as fake targets
--%:
	@:

# Help information
help:
	@echo "Makefile"
	@echo "=================================="
	@echo "Developer commands:"
	@echo "  make                - Build in debug mode"
	@echo "  make help           - Show this help message"
	@echo "  make developer      - Set up development environment (install Rust, tools, etc.)"
	@echo "  make build          - Build in debug mode"
	@echo "  make build release=1 - Build in release mode"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make check          - Check compilation without building"
	@echo "  make do-docs        - Generate and open documentation"
	@echo "  make do-lint        - Lint code with clippy and format (with fixes)"
	@echo "  make test           - Run tests (includes all crypto feature combinations)"
	@echo "  make test-feat      - Run crypto crate tests with specific features"
	@echo "  make test-all       - Run all tests including feature tests"
	@echo "  make audit          - Run security audit"
	@echo "  make docs           - Generate and open documentation"
	@echo "  make coverage       - Generate code coverage report (HTML + LCOV)"
	@echo "  make coverage-check - Check coverage percentage and fail if below threshold"
	@echo "  make all            - Clean, build, and test"
	@echo ""
	@echo "CI Commands:"
	@echo "  make do-lint-ci     - Lint code for CI (check only, no fixes)"
	@echo "  make do-docs-ci     - Generate documentation without opening it"
	@echo "  make coverage-ci    - Generate LCOV coverage report for CI/SonarCloud"
	@echo ""
	@echo "Release Commands:"
	@echo "  make release        - Publish all packages to crates.io and create signed release tag"
