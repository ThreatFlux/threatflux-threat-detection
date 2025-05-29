.PHONY: help init build test install clean run-debug run-release docker-build docker-run lint fmt check deps update security-audit

# Default target
help:
	@echo "File Scanner - Makefile Commands"
	@echo "================================"
	@echo "init          - Initialize project dependencies"
	@echo "build         - Build the project in debug mode"
	@echo "release       - Build the project in release mode"
	@echo "test          - Run all tests"
	@echo "install       - Install the binary to ~/.cargo/bin"
	@echo "clean         - Clean build artifacts"
	@echo "run-debug     - Run in debug mode with example file"
	@echo "run-release   - Run in release mode with example file"
	@echo "docker-build  - Build Docker image"
	@echo "docker-run    - Run Docker container"
	@echo "lint          - Run clippy linter"
	@echo "fmt           - Format code with rustfmt"
	@echo "check         - Run cargo check"
	@echo "deps          - Update dependencies"
	@echo "security-audit - Run security audit"
	@echo "test-programs - Compile all test programs"
	@echo "mcp-test      - Test MCP server functionality"

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

# Run tests
test:
	@echo "Running tests..."
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

# Development workflow
dev: fmt lint test
	@echo "Development checks passed!"

# CI/CD preparation
ci: fmt-check lint test
	@echo "CI checks passed!"

# Release workflow
prepare-release: clean release test security-audit
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