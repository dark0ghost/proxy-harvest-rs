# Supported Protocols

This document describes all supported proxy protocols and their URL formats.

## Overview

proxy-harvest-rs supports the following protocols:
- **Shadowsocks** (ss://)
- **VLESS** (vless://)
- **VMess** (vmess://)
- **Trojan** (trojan://)
- **Hysteria2** (hysteria2:// or hy2://)

---

## Shadowsocks (SS)

### URL Format
```
ss://base64(method:password)@host:port[?params][#tag]
```

### Features
- ✅ Standard base64 encoding
- ✅ URL-encoded base64 (`%2B`, `%2F`, `%3D`)
- ✅ Multiple base64 formats (STANDARD, URL_SAFE, NO_PAD)
- ✅ Optional query parameters (e.g., `?prefix=...`)
- ✅ Optional `?` before tag

### Examples
```
# Basic
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388#my-server

# With query parameters
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388?prefix=%16%03%01#server

# With optional ?
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388?#server
```

### Supported Methods
- chacha20-ietf-poly1305
- aes-256-gcm
- aes-128-gcm
- And more...

---

## VLESS

### URL Format
```
vless://uuid@host:port[/]?params#tag
```

### Features
- ✅ WebSocket transport
- ✅ gRPC transport
- ✅ TCP transport
- ✅ TLS encryption
- ✅ Reality protocol
- ✅ Optional `/` before `?`

### Query Parameters
- `encryption` - Encryption method (default: none)
- `flow` - Flow control (e.g., xtls-rprx-vision)
- `security` - Security type (none, tls, reality)
- `type` - Network type (tcp, ws, grpc)
- `host` - WebSocket/gRPC host
- `path` - WebSocket path or gRPC service name
- `sni` - Server Name Indication
- `fp` - TLS fingerprint
- `pbk` - Reality public key
- `sid` - Reality short ID

### Examples
```
# WebSocket + TLS
vless://uuid@example.com:443?type=ws&security=tls&sni=example.com&path=/ws#server

# WebSocket with /? format
vless://uuid@example.com:443/?type=ws&security=tls&path=/vless#server

# Reality + gRPC
vless://uuid@example.com:443?type=grpc&security=reality&pbk=key&sid=short#server
```

---

## VMess

### URL Format
```
vmess://base64(json_config)
```

### JSON Config Fields
```json
{
  "add": "server_address",
  "port": "443",
  "id": "user_uuid",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "example.com",
  "path": "/path",
  "tls": "tls",
  "sni": "example.com",
  "alpn": "h2,http/1.1",
  "ps": "server_name"
}
```

### Features
- ✅ WebSocket transport
- ✅ gRPC transport
- ✅ TCP transport
- ✅ TLS encryption
- ✅ AlterID support
- ✅ Custom security methods

### Network Types
- `tcp` - TCP transport
- `ws` - WebSocket
- `grpc` - gRPC

### Security Methods
- `auto` - Automatic
- `none` - No encryption
- `aes-128-gcm`
- `chacha20-poly1305`

---

## Trojan

### URL Format
```
trojan://password@host:port[/]?params#tag
```

### Features
- ✅ WebSocket transport
- ✅ gRPC transport
- ✅ TCP transport
- ✅ TLS encryption
- ✅ Reality protocol
- ✅ Passwords with special characters (`.`, `=`)
- ✅ Optional `/` before `?`

### Query Parameters
- `type` - Network type (tcp, ws, grpc)
- `security` - Security type (tls, reality)
- `sni` - Server Name Indication
- `host` - WebSocket/gRPC host
- `path` - WebSocket path
- `serviceName` - gRPC service name
- `allowInsecure` - Allow insecure connections (0/1)
- `fp` - TLS fingerprint

### Examples
```
# Basic TLS
trojan://password@example.com:443#server

# WebSocket + TLS
trojan://password@example.com:443/?type=ws&path=/trojan&security=tls#server

# With special chars in password
trojan://pass.word=123@example.com:443/?type=tcp&security=tls#server
```

---

## Hysteria2

### URL Format
```
hysteria2://[auth@]host:port[/]?params#tag
hy2://[auth@]host:port[/]?params#tag
```

### Features
- ✅ Email addresses as passwords
- ✅ Obfuscation support
- ✅ SNI customization
- ✅ Certificate pinning
- ✅ Optional `/` before `?`

### Query Parameters
- `obfs` - Obfuscation type (salamander)
- `obfs-password` - Obfuscation password
- `sni` - Server Name Indication
- `insecure` - Allow insecure connections (0/1)
- `pinSHA256` - Certificate SHA256 pin

### Examples
```
# Basic
hysteria2://password@example.com:443#server

# With obfuscation
hysteria2://auth@example.com:8443?obfs=salamander&obfs-password=secret#server

# Email as password
hysteria2://user@domain.com@example.com:443/?sni=example.com#server

# With certificate pinning
hysteria2://auth@example.com:443/?pinSHA256=hash&insecure=1#server
```

---

## URL Format Edge Cases

All protocols support these common variations:

### Optional Slash Before Query
```
protocol://...@host:port/?params  # ← slash before ?
protocol://...@host:port?params   # ← no slash
```

### Optional Question Mark Before Tag
```
protocol://...@host:port?#tag     # ← empty query
protocol://...@host:port#tag      # ← no query
```

### URL Encoding
Special characters in any part of the URL are properly decoded:
- `%20` → space
- `%2B` → +
- `%2F` → /
- `%3D` → =
- Emoji characters (e.g., `%F0%9F%87%BA%F0%9F%87%B8`)

---

## Testing

All protocol implementations include comprehensive tests:

```bash
# Run all parser tests
cargo test --lib parser::tests

# Run tests for specific protocol
cargo test test_parse_shadowsocks
cargo test test_parse_vless
cargo test test_parse_vmess
cargo test test_parse_trojan
cargo test test_parse_hysteria2
```

Current test coverage: **43 tests, 100% passing**

---

## Error Handling

The parser provides detailed error messages for common issues:

- Invalid URL format
- Missing required fields
- Failed base64 decoding
- Invalid port numbers
- Malformed query parameters

All errors include context about what went wrong and where in the URL.

---

## Configuration Output

All parsed servers are converted to Xray-compatible JSON configuration:

```json
{
  "outbounds": [
    {
      "tag": "server-name",
      "protocol": "protocol-name",
      "settings": { /* protocol-specific */ },
      "streamSettings": { /* transport-specific */ }
    }
  ]
}
```

See `src/config/outbound.rs` for implementation details.
