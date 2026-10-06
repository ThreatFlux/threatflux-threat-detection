# ThreatFlux Threat Detection Makefile
# Provides consistent build, test, and quality commands across all ThreatFlux libraries

.PHONY: help build test check fmt clippy clean doc bench examples install release sbom pre-commit all

# Default target
all: fmt clippy test build

# Help target
help:
	@echo "ThreatFlux Threat Detection - Available targets:"
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
	@echo "    sbom           - Generate a CycloneDX SBOM (needs cargo-cyclonedx)"
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
	@echo "🔨 Building threatflux-threat-detection..."
	cargo build

release:
	@echo "🚀 Building threatflux-threat-detection in release mode..."
	cargo build --release

check:
	@echo "✅ Checking threatflux-threat-detection compilation..."
	cargo check

# Quality targets
fmt:
	@echo "🎨 Formatting threatflux-threat-detection code..."
	cargo fmt

clippy:
	@echo "📎 Running clippy on threatflux-threat-detection..."
	cargo clippy -- -D warnings

test:
	@echo "🧪 Running threatflux-threat-detection tests..."
	cargo test

bench:
	@echo "⚡ Benchmarks not yet implemented for threatflux-threat-detection"

doc:
	@echo "📚 Generating threatflux-threat-detection documentation..."
	cargo doc --no-deps --open

# CycloneDX SBOM for every feature and every target platform (consumers build
# this crate on Linux, macOS and Windows), written to
# sbom/threatflux-threat-detection-sbom.json. The release workflow attaches it
# to each GitHub release.
sbom:
	@echo "🧾 Generating threatflux-threat-detection SBOM..."
	@mkdir -p sbom
	@rm -f sbom/*.json
	cargo cyclonedx --manifest-path Cargo.toml --all-features --target all --format json --spec-version 1.5 --override-filename threatflux-threat-detection-sbom
	mv threatflux-threat-detection-sbom.json sbom/

# Maintenance targets
clean:
	@echo "🧹 Cleaning threatflux-threat-detection build artifacts..."
	cargo clean

install:
	@echo "📦 Installing threatflux-threat-detection..."
	cargo install --path .

examples:
	@echo "💡 Running threatflux-threat-detection examples..."
	@for example in $$(cargo run --example 2>&1 | grep -E "^\s+" | awk '{print $$1}'); do \
		echo "Running example: $$example"; \
		cargo run --example $$example; \
	done

# Pre-commit checks
pre-commit: fmt clippy test
	@echo "✅ All pre-commit checks passed for threatflux-threat-detection!"

# Development workflow
dev: fmt clippy test build
	@echo "🎯 Development cycle complete for threatflux-threat-detection!"