.PHONY: build clean lint test all help check release

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

# Generate code coverage report
coverage:
	# Install cargo-llvm-cov if not present (quiet)
	@cargo install cargo-llvm-cov --quiet || true
	# Install llvm-tools-preview component (force, no prompts)
	@rustup component add llvm-tools-preview 2>/dev/null || true
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

# Generate coverage report for CI (no HTML)
coverage-ci:
	# Install cargo-llvm-cov if not present (quiet)
	@cargo install cargo-llvm-cov --quiet || true
	# Install llvm-tools-preview component (force, no prompts)
	@rustup component add llvm-tools-preview 2>/dev/null || true
	cargo llvm-cov --all-features --workspace --lcov --output-path coverage.lcov

# Check coverage percentage and fail if below threshold
coverage-check:
	# Install cargo-llvm-cov if not present (quiet)
	@cargo install cargo-llvm-cov --quiet || true
	# Install llvm-tools-preview component (force, no prompts)
	@rustup component add llvm-tools-preview 2>/dev/null || true
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

# Build for release
release:
	$(MAKE) build release=1

# Help information
help:
	@echo "Makefile"
	@echo "=================================="
	@echo "Available commands:"
	@echo "  make              - Build in debug mode"
	@echo "  make build        - Build in debug mode"
	@echo "  make release      - Build in release mode"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make check        - Check compilation without building"
	@echo "  make lint         - Lint code with clippy and format"
	@echo "  make test         - Run tests"
	@echo "  make coverage     - Generate code coverage report (HTML + LCOV)"
	@echo "  make coverage-ci  - Generate code coverage report for CI (LCOV only)"
	@echo "  make coverage-check - Check coverage percentage and fail if below threshold"
	@echo "  make all          - Clean, build, and test"
	@echo "  make help         - Show this help message"
