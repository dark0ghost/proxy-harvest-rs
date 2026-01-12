# Multi-stage Dockerfile for Rust CLI application
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

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/proxy-harvest-rs /usr/local/bin/xray-config-gen

# Create output directory
RUN mkdir -p /app/configs

# Set the binary as entrypoint
ENTRYPOINT ["xray-config-gen"]
CMD ["--help"]
