# ThreatFlux String Analysis Library Makefile
# Provides consistent build, test, and quality commands across all ThreatFlux libraries

.PHONY: help build test check fmt clippy clean doc bench examples install release pre-commit all

# Default target
all: fmt clippy test build

# Help target
help:
	@echo "ThreatFlux String Analysis Library - Available targets:"
	@echo ""
	@echo "  Build targets:"
	@echo "    build          - Build the library in debug mode"
	@echo "    release        - Build the library in release mode"
	@echo "    check          - Fast compilation check without optimization"
	@echo ""
	@echo "  Quality targets:"
	@echo "    fmt            - Format code with rustfmt"
	@echo "    clippy         - Run clippy lints"
	@echo "    test           - Run all tests"
	@echo "    bench          - Run benchmarks (when available)"
	@echo "    doc            - Generate documentation"
	@echo ""
	@echo "  Maintenance targets:"
	@echo "    clean          - Clean build artifacts"
	@echo "    install        - Install from source"
	@echo "    examples       - Run all examples"
	@echo "    pre-commit     - Run pre-commit checks (fmt + clippy + test)"
	@echo ""
	@echo "  Meta targets:"
	@echo "    all            - Run fmt + clippy + test + build"
	@echo "    help           - Show this help message"

# Build targets
build:
	@echo "🔨 Building threatflux-string-analysis..."
	cargo build

release:
	@echo "🚀 Building threatflux-string-analysis in release mode..."
	cargo build --release

check:
	@echo "✅ Checking threatflux-string-analysis compilation..."
	cargo check

# Quality targets
fmt:
	@echo "🎨 Formatting threatflux-string-analysis code..."
	cargo fmt

clippy:
	@echo "📎 Running clippy on threatflux-string-analysis..."
	cargo clippy -- -D warnings

test:
	@echo "🧪 Running threatflux-string-analysis tests..."
	cargo test

bench:
	@echo "⚡ Benchmarks not yet implemented for threatflux-string-analysis"

doc:
	@echo "📚 Generating threatflux-string-analysis documentation..."
	cargo doc --no-deps --open

# Maintenance targets
clean:
	@echo "🧹 Cleaning threatflux-string-analysis build artifacts..."
	cargo clean

install:
	@echo "📦 Installing threatflux-string-analysis..."
	cargo install --path .

examples:
	@echo "💡 Running threatflux-string-analysis examples..."
	@for example in $$(cargo run --example 2>&1 | grep -E "^\s+" | awk '{print $$1}'); do \
		echo "Running example: $$example"; \
		cargo run --example $$example; \
	done

# Pre-commit checks
pre-commit: fmt clippy test
	@echo "✅ All pre-commit checks passed for threatflux-string-analysis!"

# Development workflow
dev: fmt clippy test build
	@echo "🎯 Development cycle complete for threatflux-string-analysis!"