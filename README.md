# Xray Config Generator

A Rust CLI utility for generating Xray configuration files from VPN server URLs.

## Features

- Parse server URLs with protocols: `ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://`
- Generate configuration files for Xray
- Automatic load balancing across server groups (Cloudflare, WARP, others)
- **Proxy server availability checking** before adding to configuration
- Configurable timeout for availability checks
- Support for all major transport protocols (WebSocket, gRPC, TCP)
- Support for Reality and TLS encryption
- Execution logging
- Error handling and data validation

## Installation

```bash
cargo build --release
```

## Usage

```bash
cargo run -- --url "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS" --output "./configs"
```

### Command Line Options

- `--url` / `-u` - URL to the server list file
- `--output` / `-o` - Directory for saving configuration files (default: `./configs`)
- `--check-availability` / `-c` - Enable proxy availability checking before adding to configuration (default: `false`)
- `--timeout` / `-t` - Timeout for availability checks in seconds (default: `5`)

### Usage Examples

Basic usage without availability checking:
```bash
cargo run -- --url "https://example.com/servers.txt" --output "./configs"
```

With availability checking (5 second timeout):
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
- VMess servers with WebSocket/gRPC support
- Trojan servers with TLS/Reality
- Hysteria2 servers with obfuscation
- Standard `direct` and `block` servers

### 05_routing.json
Contains routing rules and load balancers:
- `claude-balance` - for Cloudflare servers
- `warp-balance` - for WARP servers
- `proxy-balance` - for other proxies
- Ad blocking rules
- Local address rules

## Supported Protocols

Full documentation: [docs/SUPPORTED_PROTOCOLS.md](docs/SUPPORTED_PROTOCOLS.md)

### Shadowsocks (`ss://`)
- ✅ URL-encoded and standard base64
- ✅ All base64 formats (STANDARD, URL_SAFE, NO_PAD)
- ✅ Query parameters (e.g., `?prefix=...`)
- ✅ All encryption methods

### VLESS (`vless://`)
- ✅ Reality with fingerprint, SNI, publicKey, shortId, spiderX
- ✅ TLS with ALPN, fingerprint, allowInsecure
- ✅ WebSocket, gRPC, TCP transports
- ✅ Support for `/?` URL format

### VMess (`vmess://`)
- ✅ Base64-encoded JSON configuration
- ✅ WebSocket, gRPC, TCP transports
- ✅ TLS encryption
- ✅ AlterID and custom security methods

### Trojan (`trojan://`)
- ✅ WebSocket, gRPC, TCP transports
- ✅ TLS and Reality encryption
- ✅ Passwords with special characters
- ✅ Support for `/?` URL format

### Hysteria2 (`hysteria2://` or `hy2://`)
- ✅ Email addresses as passwords
- ✅ Obfuscation (salamander)
- ✅ SNI customization
- ✅ Certificate pinning
- ✅ Support for `/?` URL format

### Statistics
- **43 tests** - 100% passing
- **5 protocols** fully supported
- **Edge cases** handled (URL encoding, various formats)

## Examples

Test URLs for verification:

```
# Shadowsocks
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388#server

# VLESS with Reality
vless://uuid@example.com:443?type=grpc&security=reality&sni=example.com&fp=firefox&pbk=key&sid=id#server

# VMess
vmess://base64_encoded_json

# Trojan
trojan://password@example.com:443/?type=ws&path=/trojan&security=tls#server

# Hysteria2
hysteria2://auth@example.com:443?obfs=salamander&sni=example.com#server
```

More examples in [docs/SUPPORTED_PROTOCOLS.md](docs/SUPPORTED_PROTOCOLS.md)

## Logging

To control logging level, use the environment variable:

```bash
RUST_LOG=debug cargo run -- --url "..." --output "./configs"
```

## Project Structure

```
src/
├── main.rs           # CLI and main logic
├── parser.rs         # Server URL parsing
├── checker.rs        # Proxy availability checking
└── config/
    ├── mod.rs        # Module exports
    ├── outbound.rs   # Outbound configuration generation
    └── routing.rs    # Routing configuration generation
```

## Proxy Availability Checking

When using the `--check-availability` flag, the utility checks TCP connectivity to each proxy server:

- ✓ Successful connection - server is added to configuration
- ✗ Failed connection - server is excluded from the list

Logging shows check results for each server:
```
✓ Server vless-server-1 is available
✗ Server ss-server-2 is unavailable: Connection timed out
```

**Optimization:** Checks are performed in parallel using the Rayon library, significantly speeding up the process with many servers.

**Note:** Availability checking increases configuration generation time. With parallel processing, time ≈ timeout + DNS resolution time, instead of (number_of_servers × timeout).

## CI/CD

The project uses GitHub Actions for automatic configuration generation:
- 🕐 Scheduled runs (daily at 00:00 UTC)
- 🔘 Manual triggering via GitHub UI
- 📦 Automatic releases with artifacts

See [.github/workflows/build-and-release.yml](.github/workflows/build-and-release.yml) for details

## Docker

A multi-stage Dockerfile is available:

```bash
docker build -t xray-config-gen .
docker run --rm -v $(pwd)/output:/app/configs xray-config-gen \
  --url "https://example.com/servers.txt" \
  --output /app/configs
```

## License

MIT OR Apache-2.0
