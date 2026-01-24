# Xray Config Generator

A Rust-based CLI utility for generating Xray configuration files from a list of VPN server links.

## Features

- Parses server URLs with `ss://` and `vless://` protocols
- Generates ready-to-use Xray configuration files
- Automatic server grouping and load balancing (Cloudflare, WARP, and others)
- **Proxy availability checking** before adding servers to configuration
- Configurable timeout settings for availability checks
- Comprehensive execution logging
- Robust error handling and data validation

## Installation

```bash
cargo build --release
```

## Usage

```bash
cargo run -- --url "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS" --output "./configs"
```

### Parameters

- `--url` / `-u` - URL to the file containing server list
- `--output` / `-o` - Directory for saving configuration files (default: `./configs`)
- `--check-availability` / `-c` - Enable proxy availability checking before adding to configuration (default: `false`)
- `--timeout` / `-t` - Timeout for availability checks in seconds (default: `5`)

### Usage Examples

Basic usage without availability checking:
```bash
cargo run -- --url "https://example.com/servers.txt" --output "./configs"
```

With availability checking (5-second timeout):
```bash
cargo run -- --url "https://example.com/servers.txt" --output "./configs" --check-availability
```

With availability checking and custom timeout:
```bash
cargo run -- --url "https://example.com/servers.txt" --output "./configs" -c -t 10
```

## Output Files

### 04_outbounds.json
Contains configuration for all outbound servers:
- Shadowsocks servers
- VLESS servers with Reality/TLS support
- Standard `direct` and `block` outbound settings

### 05_routing.json
Contains routing rules and balancers:
- `claude-balance` - for Cloudflare servers
- `warp-balance` - for WARP servers
- `proxy-balance` - for remaining proxies
- Ad-blocking rules
- Local address routing rules

## Supported Protocols

- **Shadowsocks** (`ss://`)
  - Base64 decoding
  - All encryption methods

- **VLESS** (`vless://`)
  - Reality protocol with fingerprint, SNI, publicKey, shortId, spiderX support
  - TLS with ALPN, fingerprint, and allowInsecure options
  - WebSocket, gRPC, and TCP transports

## Examples

Test URLs for validation:

```
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#TEST
vless://uuid@host:443?encryption=none&security=reality&sni=example.com&fp=firefox&pbk=key&sid=id&type=grpc&serviceName=grpc#TEST
```

## Logging

Control the logging level using environment variables:

```bash
RUST_LOG=debug cargo run -- --url "..." --output "./configs"
```

## Project Structure

```
src/
├── main.rs           # CLI interface and main logic
├── parser.rs         # Server URL parsing
├── checker.rs        # Proxy availability checking
└── config/
    ├── mod.rs        # Module exports
    ├── outbound.rs   # Outbound configuration generation
    └── routing.rs    # Routing configuration generation
```

## Proxy Availability Checking

When using the `--check-availability` flag, the utility checks TCP connectivity to each proxy server:

- ✓ Successful connection - server is included in the configuration
- ✗ Failed connection - server is excluded from the configuration

The logging system displays check results for each server:
```
✓ Server vless-server-1 is available
✗ Server ss-server-2 is unavailable: Connection timed out
```

**Optimization:** Checks are performed in parallel using the Rayon library, significantly speeding up the process when handling large numbers of servers.

**Note:** Availability checking increases configuration generation time. With parallel processing, total time ≈ timeout + DNS resolution time, rather than (number_of_servers × timeout).

## CI/CD

The project uses GitHub Actions for automated configuration generation:
- 🕐 Scheduled runs (daily at 00:00 UTC)
- 🔘 Manual triggering via GitHub UI
- 📦 Automatic releases with artifacts

See details in [.github/workflows/build-and-release.yml](.github/workflows/build-and-release.yml)

## Docker

A multi-stage Dockerfile is available:

```bash
docker build -t xray-config-gen .
docker run --rm -v $(pwd)/output:/app/configs xray-config-gen \
  --url "https://example.com/servers.txt" \
  --output /app/configs
```