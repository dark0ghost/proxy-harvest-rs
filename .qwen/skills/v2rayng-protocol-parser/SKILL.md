# Skill: Proxy Protocol URI Parser

## Purpose

This skill provides agents with knowledge for parsing, generating, and converting proxy protocol URI links into structured configuration objects. This is a **language-agnostic** specification that can be implemented in any programming language.

## Scope

- Parsing protocol URI links (VMess, VLESS, Shadowsocks, Trojan, Hysteria2, WireGuard, SOCKS)
- Converting to structured configuration objects
- Generating URI links from configuration objects
- Understanding common query parameters and protocol-specific fields

---

## Common URI Structure

All proxy URIs follow a general pattern:

```
scheme://[userinfo@]host:port[?query_parameters][#fragment]
```

Where:
- `scheme` - protocol identifier (e.g., `vmess`, `vless`, `ss`, `trojan`)
- `userinfo` - authentication data (password, UUID, username:password)
- `host` - server address (domain or IP)
- `port` - server port
- `query` - configuration parameters
- `fragment` - human-readable name/remarks

---

## Common Query Parameters

These parameters are shared across multiple protocols:

| Parameter | Description | Values |
|-----------|-------------|--------|
| `security` | Security/encryption layer | `tls`, `reality`, `none` |
| `sni` | Server Name Indication | domain name |
| `fp` / `fingerPrint` | Browser fingerprint for TLS | `chrome`, `firefox`, `randomized` |
| `alpn` | Application-Layer Protocol Negotiation | comma-separated (e.g., `h2,http/1.1`) |
| `insecure` / `allowInsecure` | Allow insecure TLS connections | `0` or `1` |
| `type` | Transport type | `tcp`, `ws`, `grpc`, `http`, `kcp`, `xhttp` |
| `headerType` | Transport header type | `none`, `http` |
| `host` | Host header for HTTP transports | domain name |
| `path` | Path for HTTP-based transports | URL path |
| `serviceName` | gRPC service name | string |
| `mode` | Transport mode (gRPC/xHTTP) | `gun`, `auto`, `packet` |
| `authority` | gRPC authority header | domain name |
| `seed` | KCP obfuscation seed | string |
| `pbk` | Reality public key | base64-encoded |
| `sid` | Reality short ID | hex string |
| `spx` | Reality spider X | URL-encoded path |
| `flow` | Traffic flow control | `xtls-rprx-vision`, `xtls-rprx-vision-udp443` |
| `ech` | Encrypted Client Hello config | base64-encoded |
| `pcs` | Pinned certificate SHA256 | hex string |
| `pqv` | Post-quantum verification | `ML-DSA-65` |

---

## Protocols Specification

### 1. VMess

**Scheme:** `vmess://`

**Formats:**

#### Format A: Classic (Base64-encoded JSON)
```
vmess://base64_encoded_json_object
```

The JSON object contains:
```json
{
  "v": "2",           // version
  "ps": "Remarks",    // profile name
  "add": "server.com",// address
  "port": "443",      // port
  "id": "uuid",       // user UUID
  "aid": "0",         // alterId
  "scy": "auto",      // security/auto encryption
  "net": "ws",        // network/transport
  "type": "none",     // header type
  "host": "server.com",
  "path": "/path",
  "tls": "tls",       // security layer
  "sni": "server.com",
  "alpn": "h2,http/1.1",
  "fp": "chrome",
  "insecure": "0"
}
```

#### Format B: Standard URI
```
vmess://uuid@server:port?security=tls&sni=server.com&type=ws&host=server.com&path=%2Fpath#Remarks
```

**Fields:**
- `userinfo` = UUID (user ID)
- `security` = encryption method (`auto`, `aes-256-gcm`, `none`, `zero`)
- `network` = transport type (`tcp`, `ws`, `grpc`, `kcp`, `http`, `quic`)
- `headerType` = HTTP header type (`none`, `http`)
- `host`, `path` = transport-specific settings

---

### 2. VLESS

**Scheme:** `vless://`

**Format:**
```
vless://uuid@server:port?encryption=none&security=tls&sni=server.com&type=ws&host=server.com&path=%2Fpath#Remarks
```

**Fields:**
- `userinfo` = UUID
- `encryption` = encryption method (typically `none`)
- `flow` = traffic flow (`xtls-rprx-vision`, `xtls-rprx-vision-udp443`)
- `security` = `tls`, `reality`, `none`
- `type` = transport type

**Query Parameters:**
- `encryption` - usually `none`
- `flow` - optional, for XTLS
- `security` - `tls`, `reality`, `none`
- `sni`, `fp`, `alpn`, `pbk`, `sid`, `spx` - for TLS/Reality

---

### 3. Shadowsocks

**Scheme:** `ss://`

**Formats:**

#### Format A: SIP002 (Modern)
```
ss://base64(method:password)@server:port#Remarks
```

#### Format B: Legacy
```
ss://base64(method:password@server:port)#Remarks
```

#### Format C: With Plugin
```
ss://base64(method:password)@server:port?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#Remarks
```

**Fields:**
- `method` = encryption cipher (`aes-256-gcm`, `chacha20-ietf-poly1305`, `none`)
- `password` = password
- `plugin` = optional obfuscation plugin

**Plugin Format:**
```
plugin=obfs-local;obfs=http;obfs-host=example.com;obfs-uri=/path
```

---

### 4. Trojan

**Scheme:** `trojan://`

**Format:**
```
trojan://password@server:port?security=tls&sni=server.com&type=tcp#Remarks
```

**Fields:**
- `userinfo` = password
- `security` = typically `tls` (default if not specified)
- `type` = transport type

**Default Behavior:**
- If no query parameters, assume `security=tls` and `type=tcp`

---

### 5. Hysteria2

**Scheme:** `hysteria2://` or `hy2://`

**Format:**
```
hysteria2://password@server:port?security=tls&sni=server.com&obfs=salamander&obfs-password=pass&mport=443,80#Remarks
```

**Fields:**
- `userinfo` = authentication password
- `security` = typically `tls`
- `network` = `hysteria`

**Protocol-Specific Parameters:**

| Parameter | Description |
|-----------|-------------|
| `obfs-password` | Password for salamander obfuscation |
| `mport` | Multi-port specification (e.g., `443,80,8000-9000`) |
| `mportHopInt` | Port hopping interval in seconds |
| `pinSHA256` | Pinned certificate SHA256 fingerprint |
| `bandwidthDown` | Download bandwidth limit |
| `bandwidthUp` | Upload bandwidth limit |

---

### 6. WireGuard

**Scheme:** `wireguard://`

**Formats:**

#### Format A: URI
```
wireguard://privatekey@server:port?address=172.16.0.2%2F32&publickey=serverpublickey&presharedkey=psk&mtu=1420&reserved=0,0,0#Remarks
```

#### Format B: Configuration File (INI-style)
```ini
[Interface]
PrivateKey = <private key>
Address = 172.16.0.2/32
MTU = 1420

[Peer]
PublicKey = <server public key>
PresharedKey = <optional PSK>
Endpoint = server.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
```

**Fields:**
- `userinfo` = private key (base64-encoded)
- `address` = client IP address in CIDR notation
- `publickey` = server public key (base64-encoded)
- `presharedkey` = optional shared key (base64-encoded)
- `mtu` = Maximum Transmission Unit (default: 1420)
- `reserved` = reserved bytes as comma-separated values

---

### 7. SOCKS

**Scheme:** `socks://`

**Format:**
```
socks://base64(username:password)@server:port#Remarks
```

**Fields:**
- `userinfo` = base64-encoded `username:password`
- If no userinfo, authentication is not required

---

### 8. HTTP

**Scheme:** `http://` or `https://`

**Format:**
```
http://username:password@server:port#Remarks
```

---

## Configuration Object Structure

A language-agnostic representation of a parsed proxy configuration:

```
Configuration
├── Basic Fields
│   ├── configVersion: integer (default: 4)
│   ├── configType: enum (VMESS, VLESS, SHADOWSOCKS, TROJAN, HYSTERIA2, WIREGUARD, SOCKS, HTTP, CUSTOM)
│   ├── subscriptionId: string
│   ├── addedTime: timestamp
│   ├── remarks: string (human-readable name)
│   ├── description: string (optional)
│   ├── server: string (hostname or IP)
│   └── serverPort: string
│
├── Authentication
│   ├── password: string
│   ├── method: string (encryption cipher)
│   ├── flow: string (traffic flow)
│   └── username: string
│
├── Transport
│   ├── network: string (tcp, ws, grpc, kcp, http, h2, xhttp, hysteria)
│   ├── headerType: string
│   ├── host: string
│   ├── path: string
│   ├── seed: string (kcp)
│   ├── quicSecurity: string
│   ├── quicKey: string
│   ├── mode: string (grpc/xhttp)
│   ├── serviceName: string (grpc)
│   ├── authority: string (grpc)
│   ├── xhttpMode: string
│   └── xhttpExtra: string
│
├── TLS/Security
│   ├── security: string (tls, reality, none)
│   ├── sni: string
│   ├── alpn: string (comma-separated)
│   ├── fingerPrint: string
│   ├── insecure: boolean
│   ├── echConfigList: string
│   ├── pinnedCA256: string
│   ├── publicKey: string (reality)
│   ├── shortId: string (reality)
│   ├── spiderX: string (reality)
│   └── mldsa65Verify: string (post-quantum)
│
├── WireGuard Specific
│   ├── secretKey: string (private key)
│   ├── preSharedKey: string
│   ├── localAddress: string (CIDR)
│   ├── reserved: string (comma-separated)
│   └── mtu: integer
│
└── Hysteria2 Specific
    ├── obfsPassword: string
    ├── portHopping: string (comma-separated ranges)
    ├── portHoppingInterval: string
    ├── pinSHA256: string
    ├── bandwidthDown: string
    └── bandwidthUp: string
```

---

## Enumerations

### ConfigType Enum
```
VMESS
CUSTOM
SHADOWSOCKS
SOCKS
VLESS
TROJAN
WIREGUARD
HYSTERIA2
HYSTERIA
HTTP
POLICYGROUP
```

### NetworkType Enum
```
TCP       -> "tcp"
KCP       -> "kcp"
WS        -> "ws"
HTTP      -> "http"
H2        -> "h2"
GRPC      -> "grpc"
HTTP_UPGRADE -> "httpupgrade"
XHTTP     -> "xhttp"
HYSTERIA  -> "hysteria"
```

### Security Types
```
TLS      -> "tls"
REALITY  -> "reality"
NONE     -> "none"
```

---

## Protocol Detection

To detect the protocol type from a URI string:

```
if uri starts with "vmess://"     -> VMESS
if uri starts with "vless://"     -> VLESS
if uri starts with "ss://"        -> SHADOWSOCKS
if uri starts with "socks://"     -> SOCKS
if uri starts with "trojan://"    -> TROJAN
if uri starts with "wireguard://" -> WIREGUARD
if uri starts with "hysteria2://" or "hy2://" -> HYSTERIA2
if uri starts with "hysteria://"  -> HYSTERIA
if uri starts with "tuic://"      -> TUIC
if uri starts with "http://" or "https://" -> HTTP
if uri is valid JSON              -> CUSTOM (full config)
```

---

## Utility Functions (Abstract)

### Base64 Encoding/Decoding

```
decode(base64_string):
    - Try standard Base64 decode
    - If fails, try URL-safe Base64 decode
    - Strip padding (=) if needed
    - Return UTF-8 string

encode(plain_string, remove_padding=false):
    - Encode to Base64
    - Optionally remove padding characters
    - Return encoded string
```

### URL Encoding/Decoding

```
decodeURIComponent(encoded_string):
    - Replace + with %2B
    - URL decode using UTF-8
    - Return decoded string

encodeURIComponent(plain_string):
    - URL encode
    - Replace + with %20 (space)
    - Return encoded string
```

### URL Validation

```
fixIllegalUrl(url_string):
    - Replace spaces with %20
    - Replace | with %7C
    - Return fixed URL

isValidUrl(string):
    - Check against URL pattern
    - Check against domain pattern
    - Return boolean

isIpAddress(string):
    - Check if valid IPv4
    - Check if valid IPv6
    - Handle CIDR notation
    - Return boolean
```

### IDN Host Extraction

```
getHostFromUri(uri):
    - Extract host from URI
    - Convert to IDN (Internationalized Domain Name) if needed
    - Return host string
```

---

## Regular Expressions

### IPv4 Pattern
```regex
^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$
```

### IPv6 Pattern
```regex
^((?:[0-9A-Fa-f]{1,4}))?((?::[0-9A-Fa-f]{1,4}))*::((?:[0-9A-Fa-f]{1,4}))?((?::[0-9A-Fa-f]{1,4}))*|((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4})){7}$
```

### Shadowsocks Legacy Pattern
```regex
^(.+?):(.*)@(.+?):(\d+?)/?$
```

---

## Supported Protocols Summary

| Protocol | Scheme(s) | Status |
|----------|-----------|--------|
| VMess | `vmess://` | Full (Classic + Standard) |
| VLESS | `vless://` | Full |
| Shadowsocks | `ss://` | Full (SIP002 + Legacy + Plugin) |
| Trojan | `trojan://` | Full |
| Hysteria2 | `hysteria2://`, `hy2://` | Full |
| WireGuard | `wireguard://` | Full (URI + Config) |
| SOCKS | `socks://` | Basic |
| HTTP | `http://`, `https://` | Basic |
| Hysteria | `hysteria://` | Partial |
| Tuic | `tuic://` | Not implemented |
| Custom | JSON | Full |

---

## Example URIs for Testing

### VMess (Classic Base64)
```
vmess://eyJ2IjoiMiIsInBzIjoiRXhhbXBsZSIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiYzEyOWQ0YjUtMTYyMS00MjM0LTlhZDctNjYyZDcxNThhYmNkIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii92bWVzcyIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIn0=
```

### VMess (Standard URI)
```
vmess://uuid@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fvmess#Example
```

### VLESS
```
vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=example.com&path=%2Fvless#Example
```

### Shadowsocks (SIP002)
```
ss://YWVzLTI1Ni1nY206bXlwYXNzd29yZA==@example.com:8388#Example
```

### Shadowsocks (Legacy)
```
ss://YWVzLTI1Ni1nY206bXlwYXNzd29yZEBleGFtcGxlLmNvbTo4Mzg4#Example
```

### Trojan
```
trojan://mypassword@example.com:443?security=tls&sni=example.com&type=tcp#Example
```

### Hysteria2
```
hysteria2://mypassword@example.com:443?security=tls&sni=example.com&obfs=salamander&obfs-password=pass123&mport=443,80#Example
```

### WireGuard
```
wireguard://uI8D3K4J5L6M7N8O9P0Q1R2S3T4U5V6W7X8Y9Z0A1B2C3D4E5F6G7H8I9J0K1L2M@example.com:51820?address=172.16.0.2%2F32&publickey=serverpublickey&presharedkey=psk&mtu=1420&reserved=0,0,0#Example
```

### SOCKS
```
socks://dXNlcjpwYXNz@192.168.1.1:1080#Example
```

---

## Implementation Notes

### Parsing Order for Shadowsocks
1. Try SIP002 format first (modern standard)
2. Fall back to Legacy format if SIP002 fails

### Parsing Order for VMess
1. Check for query parameters (`?` and `&`) - if present, use Standard URI format
2. Otherwise, decode Base64 and parse as Classic JSON format

### Default Values
- `security`: `none` if not specified (except Trojan which defaults to `tls`)
- `network`: `tcp` if not specified
- `headerType`: `none` if not specified
- `insecure`: `false` if not specified
- `mtu` (WireGuard): `1420`

### Special Handling
- IPv6 addresses in URIs should be enclosed in brackets: `[::1]:8080`
- Fragment (remarks) should be URL-decoded
- Query parameter values should be URL-decoded
- Base64 decoding should handle both standard and URL-safe variants

---

## Outbound Configuration Generation

After parsing a URI into a configuration object, the next step is typically to generate an outbound proxy configuration for a core (Xray, V2Ray, etc.). This involves:

1. Creating an outbound object with the appropriate protocol type
2. Populating connection settings (address, port, credentials)
3. Configuring transport/stream settings (network, path, host)
4. Configuring security settings (TLS, Reality, certificates)
5. Adding protocol-specific options (flow, encryption, etc.)

The exact structure of the outbound configuration depends on the target core's configuration schema.

---

*Document Created: 2026-03-16*
*Last Updated: 2026-03-16*
*Skill Version: 2.0 (Language-Agnostic)*
