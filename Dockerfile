# multi-proxy Dockerfile
# Multi-channel proxy with HTTP/SOCKS5/SSH tunnel support

# ============ Build Stage ============
FROM rust:slim-bookworm as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Build release binary
RUN cargo build --release --bin multi-proxy

# ============ Runtime Stage ============
FROM debian:bookworm-slim
# (rust:1.88-slim-bookworm builder above; runtime = debian slim)

# Install runtime dependencies (curl for HEALTHCHECK)
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash proxy

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/multi-proxy /app/multi-proxy

# Copy default config
COPY config-test.toml /app/config.toml

# Set ownership
RUN chown -R proxy:proxy /app

# Switch to non-root user
USER proxy

# Expose proxy port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/http://127.0.0.1 || exit 1

ENTRYPOINT ["/app/multi-proxy"]
CMD ["-c", "/app/config.toml"]