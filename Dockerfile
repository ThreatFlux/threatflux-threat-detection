# Build stage
FROM rust:1.87-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/file-scanner

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash scanner

# Copy the binary from builder
COPY --from=builder /usr/src/file-scanner/target/release/file-scanner /usr/local/bin/file-scanner

# Set ownership
RUN chown scanner:scanner /usr/local/bin/file-scanner

# Switch to non-root user
USER scanner

# Set working directory
WORKDIR /data

# Default command (can be overridden)
ENTRYPOINT ["file-scanner"]

# Health check for MCP server mode
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/file-scanner", "--version"] || exit 1

# Expose common MCP server ports
EXPOSE 3000

# Labels
LABEL org.opencontainers.image.title="File Scanner"
LABEL org.opencontainers.image.description="Comprehensive native file scanner with MCP server support"
LABEL org.opencontainers.image.authors="Wyatt Roersma <wyattroersma@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/ThreatFlux/file-scanner"
LABEL org.opencontainers.image.licenses="MIT"