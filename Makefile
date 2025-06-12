.PHONY: help init build test test-parallel test-unit test-hash test-mcp test-analysis test-integration test-legacy install clean run-debug run-release docker-build docker-run lint fmt check deps update security-audit dev dev-full ci ci-full prepare-release

# Default target
help:
	@echo "File Scanner - Makefile Commands"
	@echo "================================"
	@echo "BUILD COMMANDS:"
	@echo "  init          - Initialize project dependencies"
	@echo "  build         - Build the project in debug mode"
	@echo "  release       - Build the project in release mode"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "TEST COMMANDS (OPTIMIZED):"
	@echo "  test          - Run fast unit tests (~2s, 70% faster)"
	@echo "  test-parallel - Run comprehensive parallel tests (~60s)"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-hash     - Run hash tests"
	@echo "  test-mcp      - Run MCP tests"
	@echo "  test-analysis - Run analysis tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-legacy   - Run legacy test command (compatibility)"
	@echo ""
	@echo "QUALITY COMMANDS:"
	@echo "  lint          - Run clippy linter"
	@echo "  fmt           - Format code with rustfmt"
	@echo "  check         - Run cargo check"
	@echo "  security-audit - Run security audit"
	@echo ""
	@echo "RUN COMMANDS:"
	@echo "  install       - Install the binary to ~/.cargo/bin"
	@echo "  run-debug     - Run in debug mode with example file"
	@echo "  run-release   - Run in release mode with example file"
	@echo ""
	@echo "DOCKER COMMANDS:"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo ""
	@echo "MISC COMMANDS:"
	@echo "  deps          - Update dependencies"
	@echo "  test-programs - Compile all test programs"
	@echo "  mcp-test      - Test MCP server functionality"

# Initialize project
init:
	@echo "Initializing project..."
	rustup update stable
	rustup component add clippy rustfmt
	cargo fetch
	@echo "Project initialized successfully!"

# Build debug version
build:
	@echo "Building debug version..."
	cargo build

# Build release version
release:
	@echo "Building release version..."
	cargo build --release

# Run tests (fast unit tests)
test:
	@echo "Running fast unit tests..."
	./scripts/test-fast.sh

# Run parallel tests (comprehensive)
test-parallel:
	@echo "Running comprehensive parallel tests..."
	./scripts/test-parallel.sh

# Run categorized tests
test-unit:
	@echo "Running unit tests only..."
	./scripts/test-categories.sh unit

test-hash:
	@echo "Running hash tests..."
	./scripts/test-categories.sh hash

test-mcp:
	@echo "Running MCP tests..."
	./scripts/test-categories.sh mcp

test-analysis:
	@echo "Running analysis tests..."
	./scripts/test-categories.sh analysis

test-integration:
	@echo "Running integration tests..."
	./scripts/test-categories.sh integration

# Legacy test command for compatibility
test-legacy:
	@echo "Running legacy test command..."
	cargo test --all-features

# Install binary
install: release
	@echo "Installing file-scanner..."
	cargo install --path .
	@echo "Installed to ~/.cargo/bin/file-scanner"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/

# Run debug build with example
run-debug: build
	@echo "Running debug build..."
	./target/debug/file-scanner /bin/ls --format yaml

# Run release build with example
run-release: release
	@echo "Running release build..."
	./target/release/file-scanner /bin/ls --format yaml

# Docker operations
docker-build:
	@echo "Building Docker image..."
	docker build -t threatflux/file-scanner:latest .

docker-run:
	@echo "Running Docker container..."
	docker run --rm -v /bin:/data:ro threatflux/file-scanner:latest /data/ls

# Code quality
lint:
	@echo "Running clippy..."
	cargo clippy -- -D warnings

fmt:
	@echo "Formatting code..."
	cargo fmt

fmt-check:
	@echo "Checking code formatting..."
	cargo fmt -- --check

check:
	@echo "Running cargo check..."
	cargo check --all-features

# Dependency management
deps:
	@echo "Updating dependencies..."
	cargo update

deps-tree:
	@echo "Showing dependency tree..."
	cargo tree

# Security audit
security-audit:
	@echo "Running security audit..."
	cargo audit

# Test programs
test-programs:
	@echo "Compiling test programs..."
	cd test_programs && bash compile_all.sh

# MCP testing
mcp-test: release
	@echo "Testing MCP server..."
	@echo "Testing tools/list..."
	npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/list
	@echo ""
	@echo "Testing get_file_metadata..."
	npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name get_file_metadata --tool-arg file_path=/bin/ls

# Development workflow (fast)
dev: fmt lint test
	@echo "Development checks passed!"

# Development workflow (comprehensive)
dev-full: fmt lint test-parallel
	@echo "Comprehensive development checks passed!"

# CI/CD preparation (fast for quick checks)
ci: fmt-check lint test
	@echo "CI checks passed!"

# CI/CD preparation (comprehensive for full validation)
ci-full: fmt-check lint test-parallel security-audit
	@echo "Comprehensive CI checks passed!"

# Release workflow
prepare-release: clean release test-parallel security-audit
	@echo "Release preparation complete!"
	@echo "Binary location: ./target/release/file-scanner"

# Benchmarks (if added in future)
bench:
	@echo "Running benchmarks..."
	cargo bench

# Documentation
docs:
	@echo "Building documentation..."
	cargo doc --no-deps --open

# Version info
version:
	@echo "File Scanner version:"
	@cargo pkgid | cut -d# -f2
