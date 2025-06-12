#!/bin/bash
# Categorized test runner
# Allows running specific test categories for faster feedback

set -e

show_help() {
    echo "Usage: $0 [CATEGORY]"
    echo ""
    echo "Categories:"
    echo "  unit       - Fast unit tests only (libs, no file I/O)"
    echo "  hash       - Hash calculation tests"
    echo "  mcp        - MCP server and transport tests"
    echo "  analysis   - File analysis tests (binary, npm, python)"
    echo "  integration - Full integration tests"
    echo "  all        - All tests (default)"
    echo ""
    echo "Examples:"
    echo "  $0 unit      # Run only unit tests (~30 seconds)"
    echo "  $0 hash      # Run hash tests (~1 minute)"
    echo "  $0 mcp       # Run MCP tests (~2 minutes)"
    echo "  $0 all       # Run all tests (~5+ minutes)"
}

CATEGORY=${1:-all}

case $CATEGORY in
    unit)
        echo "🔬 Running unit tests only..."
        cargo test --lib --profile test --quiet
        ;;
    hash)
        echo "🔐 Running hash calculation tests..."
        cargo test hash_test --profile test --quiet
        ;;
    mcp)
        echo "🔌 Running MCP server tests..."
        cargo test mcp_ --profile test --quiet
        ;;
    analysis)
        echo "📊 Running file analysis tests..."
        cargo test \
            binary_parser \
            npm_analysis \
            python_analysis \
            dependency_analysis \
            --profile test --quiet
        ;;
    integration)
        echo "🧪 Running integration tests..."
        cargo test integration --profile test --quiet
        ;;
    all)
        echo "🚀 Running all tests..."
        cargo test --profile test --quiet
        ;;
    help|--help|-h)
        show_help
        exit 0
        ;;
    *)
        echo "❌ Unknown category: $CATEGORY"
        show_help
        exit 1
        ;;
esac

echo "✅ Tests completed successfully!"