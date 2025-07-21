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
	@echo "  make all          - Clean, build, and test"
	@echo "  make help         - Show this help message"
