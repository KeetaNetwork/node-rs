.PHONY: build clean lint test all help check release coverage coverage-check coverage-setup developer

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
all: clean build

# Just check compilation without building
check:
	cargo check

# Build the project
build:
	cargo build $(release_flag)

# Build for release
release:
	$(MAKE) build release=1

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/
	rm -rf build/

# Lint code
lint:
	cargo clippy --fix --allow-staged --allow-dirty
	cargo fmt

# Run tests with host system's default target
test:
	# Use a shell script to unset CARGO_BUILD_TARGET and run tests
	sh -c 'unset CARGO_BUILD_TARGET; cargo test --all-features --workspace'

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
	cargo llvm-cov --all-features --workspace --html
	# Generate LCOV coverage report (reusing the same coverage data)
	cargo llvm-cov --all-features --workspace --lcov --output-path coverage.lcov --no-run
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

# Developer setup - install Rust and set up development environment
developer:
	@echo "🚀 Setting up development environment..."
	@if command -v rustc > /dev/null 2>&1; then \
		echo "✅ Rust is already installed (version: $$(rustc --version))"; \
	else \
		echo "📦 Installing Rust via rustup (automated)..."; \
		if [ -f rustup-init.sh ]; then \
			chmod +x rustup-init.sh; \
			./rustup-init.sh -y --default-toolchain stable; \
			echo "🔄 Rust installed! Sourcing environment..."; \
			. "$$HOME/.cargo/env" 2>/dev/null || true; \
		else \
			echo "❌ rustup-init.sh not found in project root."; \
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
	@echo ""
	@echo "🎯 Quick start commands:"
	@echo "  make build    - Build the project"
	@echo "  make test     - Run tests"
	@echo "  make lint     - Format and lint code"
	@echo "  make coverage - Generate test coverage report"
	@echo "  make help     - Show all available commands"

# Help information
help:
	@echo "Makefile"
	@echo "=================================="
	@echo "Available commands:"
	@echo "  make              - Build in debug mode"
	@echo "  make developer    - Set up development environment (install Rust, tools, etc.)"
	@echo "  make build        - Build in debug mode"
	@echo "  make release      - Build in release mode"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make check        - Check compilation without building"
	@echo "  make lint         - Lint code with clippy and format"
	@echo "  make test         - Run tests"
	@echo "  make coverage     - Generate code coverage report (HTML + LCOV)"
	@echo "  make coverage-check - Check coverage percentage and fail if below threshold"
	@echo "  make all          - Clean, build, and test"
	@echo "  make help         - Show this help message"
