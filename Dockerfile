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

# Default bind (HOST=0.0.0.0 so port-mapping can reach the container).
# Override either or both at runtime: docker run -e PORT=9090 -e HOST=0.0.0.0 ...
ENV HOST=0.0.0.0
ENV PORT=12380

# Install runtime dependencies (TLS roots for HTTPS)
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (skip if already exists)
RUN getent passwd proxy || useradd -m -s /bin/bash proxy

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/multi-proxy /app/multi-proxy

# Copy default config
COPY config.toml /app/config.toml

# Set ownership
RUN chown -R proxy:proxy /app

# Switch to non-root user
USER proxy

# Expose proxy port (matches default PORT; override -e PORT=… at runtime)
EXPOSE 12380

ENTRYPOINT ["/app/multi-proxy"]
CMD ["-c", "/app/config.toml"]