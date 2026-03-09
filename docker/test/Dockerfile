# Multi-stage Dockerfile for testing Xray proxy configurations
# Usage: docker build -f Dockerfile.test -t proxy-harvest-rs:test .

# ============================================
# Stage 1: Build the Rust application
# ============================================
FROM rust:1.92-slim as builder

WORKDIR /app

# Install dependencies for building
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# ============================================
# Stage 2: Runtime with Xray and test tools
# ============================================
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies and Xray
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    jq \
    netcat-openbsd \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Xray-core manually (without systemd dependency)
RUN XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name"' | cut -d'"' -f4 | sed 's/v//') && \
    curl -L -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" && \
    unzip /tmp/xray.zip -d /usr/local/bin/ && \
    rm /tmp/xray.zip && \
    chmod +x /usr/local/bin/xray

# Copy the proxy-harvest-rs binary from builder
COPY --from=builder /app/target/release/proxy-harvest-rs /usr/local/bin/xray-config-gen

# Copy test scripts
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

# Create output directory
RUN mkdir -p /app/configs

# Set environment variables
ENV TEST_TIMEOUT=10
ENV PARALLEL_TESTS=5
ENV OUTPUT_FORMAT=text
ENV XRAY_LOG_LEVEL=info

# Default command
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["all"]
