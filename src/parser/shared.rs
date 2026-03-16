//! Shared types and utilities for parser modules.
//!
//! This module contains the common data structures used across all protocol parsers.
//!
//! # Architecture
//!
//! The parsing system is built around the [`ServerConfig`] enum, which represents
//! a unified configuration object for all supported proxy protocols. Each protocol
//! has its own variant with protocol-specific fields.
//!
//! ## Supported Protocols
//!
//! - Shadowsocks (`ss://`) — SIP002, Legacy, Plugin formats
//! - VLESS (`vless://`) — Standard URI format
//! - VMess (`vmess://`) — Classic (Base64 JSON) и Standard URI formats
//! - Trojan (`trojan://`) — Standard URI format
//! - Hysteria2 (`hysteria2://`, `hy2://`) — Standard URI format
//! - WireGuard (`wireguard://`) — URI format
//! - SOCKS (`socks://`) — Base64-encoded credentials
//! - HTTP (`http://`, `https://`) — Basic auth format

use anyhow::{Context, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use urlencoding::decode;

/// VPN server configuration parsed from URL.
///
/// Represents a parsed VPN server configuration ready for Xray outbound generation.
/// Each variant corresponds to a specific VPN protocol.
///
/// # Examples
///
/// ```rust
/// use proxy_harvest_rs::parser::{ServerConfig, NetworkSettings, TlsSettings};
///
/// let config = ServerConfig::Shadowsocks {
///     tag: "test-ss".to_string(),
///     address: "example.com".to_string(),
///     port: 8388,
///     method: "aes-256-gcm".to_string(),
///     password: "password".to_string(),
///     plugin: None,
///     plugin_opts: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol")]
pub enum ServerConfig {
    /// Shadowsocks server configuration.
    ///
    /// Supports SIP002, Legacy, and Plugin formats.
    #[serde(rename = "shadowsocks")]
    Shadowsocks {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// Encryption method (e.g., "aes-256-gcm", "chacha20-ietf-poly1305", "none").
        method: String,
        /// Password for authentication.
        password: String,
        /// Optional plugin configuration (e.g., "obfs-local").
        plugin: Option<String>,
        /// Optional plugin options.
        plugin_opts: Option<String>,
    },
    /// VLESS server configuration.
    ///
    /// Supports standard URI format with TLS, Reality, and various transports.
    #[serde(rename = "vless")]
    Vless {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// User UUID for authentication.
        id: String,
        /// Encryption type (e.g., "none", "auto").
        encryption: String,
        /// Traffic flow for XTLS (e.g., "xtls-rprx-vision", "xtls-rprx-vision-udp443").
        flow: String,
        /// Network transport type (e.g., "tcp", "ws", "grpc", "kcp", "xhttp").
        network: String,
        /// Security layer (e.g., "none", "tls", "reality").
        security: String,
        /// TLS/Reality settings if security is enabled.
        tls_settings: Option<Box<TlsSettings>>,
        /// Network-specific settings (WebSocket, gRPC, TCP, XHTTP).
        network_settings: Option<NetworkSettings>,
    },
    /// VMess server configuration.
    ///
    /// Supports both Classic (Base64-encoded JSON) and Standard URI formats.
    #[serde(rename = "vmess")]
    Vmess {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// User UUID for authentication.
        id: String,
        /// AlterID for VMess protocol compatibility.
        alter_id: u16,
        /// Security method (e.g., "auto", "aes-128-gcm", "none", "zero").
        security: String,
        /// Network transport type (e.g., "tcp", "ws", "grpc", "kcp", "http", "quic").
        network: String,
        /// TLS mode (empty string or "tls").
        tls: String,
        /// TLS settings if TLS is enabled.
        tls_settings: Option<Box<TlsSettings>>,
        /// Network-specific settings (WebSocket, gRPC, TCP).
        network_settings: Option<NetworkSettings>,
    },
    /// Trojan server configuration.
    ///
    /// Supports standard URI format with TLS/Reality and various transports.
    #[serde(rename = "trojan")]
    Trojan {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// Password for authentication.
        password: String,
        /// Network transport type (e.g., "tcp", "ws", "grpc").
        network: String,
        /// Security layer (e.g., "tls", "reality", "none").
        security: String,
        /// Server Name Indication for TLS.
        sni: Option<String>,
        /// TLS/Reality settings if security is enabled.
        tls_settings: Option<Box<TlsSettings>>,
        /// Network-specific settings (WebSocket, gRPC, TCP).
        network_settings: Option<NetworkSettings>,
    },
    /// Hysteria2 server configuration.
    ///
    /// Supports standard URI format with obfuscation and TLS settings.
    #[serde(rename = "hysteria2")]
    Hysteria2 {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// Password for authentication.
        password: String,
        /// Obfuscation type (e.g., "salamander").
        obfs: Option<String>,
        /// Obfuscation password.
        obfs_password: Option<String>,
        /// Server Name Indication for TLS.
        sni: Option<String>,
        /// Allow insecure TLS connections.
        insecure: bool,
        /// Certificate pinning hash (SHA256).
        pinned_sha256: Option<String>,
        /// Port hopping specification (e.g., "443,80,8000-9000").
        port_hopping: Option<String>,
        /// Port hopping interval in seconds.
        port_hopping_interval: Option<String>,
        /// Download bandwidth limit.
        bandwidth_down: Option<String>,
        /// Upload bandwidth limit.
        bandwidth_up: Option<String>,
    },
    /// WireGuard server configuration.
    ///
    /// Supports URI format with all WireGuard-specific parameters.
    #[serde(rename = "wireguard")]
    WireGuard {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// Private key (base64-encoded).
        secret_key: String,
        /// Server public key (base64-encoded).
        public_key: String,
        /// Optional preshared key (base64-encoded).
        pre_shared_key: Option<String>,
        /// Client IP address in CIDR notation (e.g., "172.16.0.2/32").
        local_address: String,
        /// Reserved bytes as comma-separated values (e.g., "0,0,0").
        reserved: Option<String>,
        /// Maximum Transmission Unit.
        mtu: u16,
    },
    /// SOCKS proxy server configuration.
    ///
    /// Supports base64-encoded credentials format.
    #[serde(rename = "socks")]
    Socks {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// Optional username for authentication.
        username: Option<String>,
        /// Optional password for authentication.
        password: Option<String>,
        /// SOCKS version ("4", "4a", "5").
        version: String,
    },
    /// HTTP/HTTPS proxy server configuration.
    ///
    /// Supports basic auth format.
    #[serde(rename = "http")]
    Http {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// Optional username for authentication.
        username: Option<String>,
        /// Optional password for authentication.
        password: Option<String>,
        /// TLS enabled (true for https://).
        tls: bool,
    },
}

/// TLS/Reality protocol settings.
///
/// Contains configuration for TLS or Reality security layers,
/// including server name, fingerprint, ALPN, and Reality-specific parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    /// Server name for SNI (Server Name Indication).
    pub server_name: String,
    /// Browser fingerprint to emulate (e.g., "chrome", "firefox").
    pub fingerprint: String,
    /// Application-Layer Protocol Negotiation list.
    pub alpn: Option<Vec<String>>,
    /// Allow insecure TLS connections (skip certificate verification).
    pub allow_insecure: bool,
    /// Reality public key (Reality protocol only).
    pub public_key: Option<String>,
    /// Reality short ID (Reality protocol only).
    pub short_id: Option<String>,
    /// Reality spiderX path (Reality protocol only).
    pub spider_x: Option<String>,
}

/// Network transport settings.
///
/// Contains protocol-specific settings for different network transports
/// such as WebSocket, gRPC, or raw TCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NetworkSettings {
    /// WebSocket transport settings.
    #[serde(rename = "ws")]
    WebSocket {
        /// WebSocket path for connection.
        path: String,
        /// Host header for WebSocket connection.
        host: String,
    },
    /// gRPC transport settings.
    #[serde(rename = "grpc")]
    Grpc {
        /// gRPC service name.
        service_name: String,
        /// gRPC authority header.
        authority: String,
    },
    /// TCP transport settings.
    #[serde(rename = "tcp")]
    Tcp {
        /// TCP header type (e.g., "none", "http").
        header_type: String,
    },
    /// XHTTP transport settings (experimental).
    #[serde(rename = "xhttp")]
    XHttp {
        /// XHTTP path for connection.
        path: String,
        /// Host header for XHTTP connection.
        host: String,
        /// XHTTP mode (auto, stream-up, etc.).
        mode: String,
        /// Extra JSON configuration.
        extra: Option<String>,
    },
}

impl ServerConfig {
    /// Returns the server tag/label.
    ///
    /// # Returns
    ///
    /// A string slice containing the server's tag used for identification.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use proxy_harvest_rs::parser::ServerConfig;
    ///
    /// let config = ServerConfig::Shadowsocks {
    ///     tag: "test-ss".to_string(),
    ///     address: "example.com".to_string(),
    ///     port: 8388,
    ///     method: "aes-256-gcm".to_string(),
    ///     password: "password".to_string(),
    ///     plugin: None,
    ///     plugin_opts: None,
    /// };
    /// assert_eq!(config.tag(), "test-ss");
    /// ```
    pub fn tag(&self) -> &str {
        match self {
            ServerConfig::Shadowsocks { tag, .. } => tag,
            ServerConfig::Vless { tag, .. } => tag,
            ServerConfig::Vmess { tag, .. } => tag,
            ServerConfig::Trojan { tag, .. } => tag,
            ServerConfig::Hysteria2 { tag, .. } => tag,
            ServerConfig::WireGuard { tag, .. } => tag,
            ServerConfig::Socks { tag, .. } => tag,
            ServerConfig::Http { tag, .. } => tag,
        }
    }

    /// Returns the server address.
    ///
    /// # Returns
    ///
    /// A string slice containing the server's hostname or IP address.
    pub fn address(&self) -> &str {
        match self {
            ServerConfig::Shadowsocks { address, .. } => address,
            ServerConfig::Vless { address, .. } => address,
            ServerConfig::Vmess { address, .. } => address,
            ServerConfig::Trojan { address, .. } => address,
            ServerConfig::Hysteria2 { address, .. } => address,
            ServerConfig::WireGuard { address, .. } => address,
            ServerConfig::Socks { address, .. } => address,
            ServerConfig::Http { address, .. } => address,
        }
    }

    /// Returns the server port.
    ///
    /// # Returns
    ///
    /// The server's port number.
    pub fn port(&self) -> u16 {
        match self {
            ServerConfig::Shadowsocks { port, .. } => *port,
            ServerConfig::Vless { port, .. } => *port,
            ServerConfig::Vmess { port, .. } => *port,
            ServerConfig::Trojan { port, .. } => *port,
            ServerConfig::Hysteria2 { port, .. } => *port,
            ServerConfig::WireGuard { port, .. } => *port,
            ServerConfig::Socks { port, .. } => *port,
            ServerConfig::Http { port, .. } => *port,
        }
    }

    /// Checks if this server is a WARP server.
    ///
    /// # Returns
    ///
    /// `true` if the server tag contains "warp" (case-insensitive), `false` otherwise.
    pub fn is_warp(&self) -> bool {
        self.tag().to_lowercase().contains("warp")
    }

    /// Checks if this server is a Cloudflare server.
    ///
    /// Detects Cloudflare servers by IP range (104.x.x.x) or hostname patterns.
    ///
    /// # Returns
    ///
    /// `true` if the server appears to be a Cloudflare server, `false` otherwise.
    pub fn is_cloudflare(&self) -> bool {
        let addr = self.address().to_lowercase();
        addr.starts_with("104.") || addr.contains("cloudflare") || addr.contains("cdn")
    }

    /// Generates a URI string from this configuration.
    ///
    /// # Returns
    ///
    /// Returns a URI string representing this server configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use proxy_harvest_rs::parser::ServerConfig;
    ///
    /// let config = ServerConfig::Shadowsocks {
    ///     tag: "test-ss".to_string(),
    ///     address: "example.com".to_string(),
    ///     port: 8388,
    ///     method: "aes-256-gcm".to_string(),
    ///     password: "password".to_string(),
    ///     plugin: None,
    ///     plugin_opts: None,
    /// };
    /// let uri = config.to_uri();
    /// assert!(uri.starts_with("ss://"));
    /// ```
    pub fn to_uri(&self) -> String {
        match self {
            ServerConfig::Shadowsocks {
                tag,
                address,
                port,
                method,
                password,
                plugin,
                plugin_opts,
            } => {
                // Format: ss://base64(method:password)@host:port#tag
                let credentials = format!("{}:{}", method, password);
                let encoded = BASE64_STANDARD.encode(credentials);
                let mut uri = format!("ss://{}@{}:{}", encoded, address, port);

                if let Some(p) = plugin {
                    uri.push_str("?plugin=");
                    uri.push_str(&urlencoding::encode(p));
                    if let Some(opts) = plugin_opts {
                        uri.push_str("%3B");
                        uri.push_str(&urlencoding::encode(opts));
                    }
                }

                if !tag.is_empty() {
                    uri.push('#');
                    uri.push_str(&urlencoding::encode(tag));
                }
                uri
            }
            ServerConfig::Vless {
                tag,
                address,
                port,
                id,
                encryption,
                flow,
                network,
                security,
                tls_settings,
                network_settings,
            } => {
                // Format: vless://uuid@host:port?params#tag
                let mut params = Vec::new();
                params.push(format!("encryption={}", encryption));

                if !flow.is_empty() {
                    params.push(format!("flow={}", flow));
                }

                params.push(format!("security={}", security));

                if let Some(tls) = tls_settings {
                    if !tls.server_name.is_empty() {
                        params.push(format!("sni={}", tls.server_name));
                    }
                    if !tls.fingerprint.is_empty() && tls.fingerprint != "chrome" {
                        params.push(format!("fp={}", tls.fingerprint));
                    }
                    if let Some(ref alpn) = tls.alpn {
                        params.push(format!("alpn={}", alpn.join(",")));
                    }
                    if security == "reality" {
                        if let Some(ref pk) = tls.public_key {
                            params.push(format!("pbk={}", pk));
                        }
                        if let Some(ref sid) = tls.short_id {
                            params.push(format!("sid={}", sid));
                        }
                        if let Some(ref spx) = tls.spider_x {
                            params.push(format!("spx={}", urlencoding::encode(spx)));
                        }
                    }
                }

                params.push(format!("type={}", network));

                if let Some(net) = network_settings {
                    match net {
                        NetworkSettings::WebSocket { path, host } => {
                            if !host.is_empty() {
                                params.push(format!("host={}", host));
                            }
                            params.push(format!("path={}", urlencoding::encode(path)));
                        }
                        NetworkSettings::Grpc {
                            service_name,
                            authority,
                        } => {
                            if !service_name.is_empty() {
                                params.push(format!("serviceName={}", service_name));
                            }
                            if !authority.is_empty() {
                                params.push(format!("authority={}", authority));
                            }
                        }
                        NetworkSettings::Tcp { header_type } => {
                            if header_type != "none" {
                                params.push(format!("headerType={}", header_type));
                            }
                        }
                        NetworkSettings::XHttp {
                            path,
                            host,
                            mode,
                            extra,
                        } => {
                            if !host.is_empty() {
                                params.push(format!("host={}", host));
                            }
                            params.push(format!("path={}", urlencoding::encode(path)));
                            if mode != "auto" {
                                params.push(format!("mode={}", mode));
                            }
                            if let Some(e) = extra {
                                params.push(format!("extra={}", urlencoding::encode(e)));
                            }
                        }
                    }
                }

                let query = params.join("&");
                let mut uri = format!("vless://{}@{}:{}?{}", id, address, port, query);

                if !tag.is_empty() {
                    uri.push('#');
                    uri.push_str(&urlencoding::encode(tag));
                }
                uri
            }
            ServerConfig::Vmess {
                tag,
                address,
                port,
                id,
                alter_id,
                security,
                network,
                tls,
                tls_settings,
                network_settings,
            } => {
                // Use Classic Base64 JSON format for compatibility
                let mut json_obj = serde_json::Map::new();
                json_obj.insert("v".to_string(), json!("2"));
                json_obj.insert("ps".to_string(), json!(tag));
                json_obj.insert("add".to_string(), json!(address));
                json_obj.insert("port".to_string(), json!(port.to_string()));
                json_obj.insert("id".to_string(), json!(id));
                json_obj.insert("aid".to_string(), json!(alter_id.to_string()));
                json_obj.insert("scy".to_string(), json!(security));
                json_obj.insert("net".to_string(), json!(network));

                if let Some(net) = network_settings {
                    match net {
                        NetworkSettings::WebSocket { path, host } => {
                            json_obj.insert("path".to_string(), json!(path));
                            json_obj.insert("host".to_string(), json!(host));
                        }
                        NetworkSettings::Grpc {
                            service_name,
                            authority,
                        } => {
                            json_obj.insert("path".to_string(), json!(service_name));
                            json_obj.insert("host".to_string(), json!(authority));
                        }
                        NetworkSettings::Tcp { header_type } => {
                            json_obj.insert("type".to_string(), json!(header_type));
                        }
                        _ => {}
                    }
                }

                if !tls.is_empty() {
                    json_obj.insert("tls".to_string(), json!(tls));
                    if let Some(tls_cfg) = tls_settings {
                        json_obj.insert("sni".to_string(), json!(&tls_cfg.server_name));
                        if let Some(ref alpn) = tls_cfg.alpn {
                            json_obj.insert("alpn".to_string(), json!(alpn.join(",")));
                        }
                    }
                }

                let json_str = serde_json::to_string(&json_obj).unwrap_or_default();
                let encoded = BASE64_STANDARD.encode(json_str);
                format!("vmess://{}", encoded)
            }
            ServerConfig::Trojan {
                tag,
                address,
                port,
                password,
                network,
                security,
                sni,
                tls_settings: _,
                network_settings,
            } => {
                // Format: trojan://password@host:port?params#tag
                let mut params = Vec::new();
                params.push(format!("security={}", security));

                if let Some(ref s) = sni {
                    params.push(format!("sni={}", s));
                }

                params.push(format!("type={}", network));

                if let Some(net) = network_settings {
                    match net {
                        NetworkSettings::WebSocket { path, host } => {
                            if !host.is_empty() {
                                params.push(format!("host={}", host));
                            }
                            params.push(format!("path={}", urlencoding::encode(path)));
                        }
                        NetworkSettings::Grpc {
                            service_name,
                            authority: _,
                        } => {
                            if !service_name.is_empty() {
                                params.push(format!("serviceName={}", service_name));
                            }
                        }
                        NetworkSettings::Tcp { header_type } => {
                            if header_type != "none" {
                                params.push(format!("headerType={}", header_type));
                            }
                        }
                        _ => {}
                    }
                }

                let query = params.join("&");
                let mut uri = format!("trojan://{}@{}:{}?{}", password, address, port, query);

                if !tag.is_empty() {
                    uri.push('#');
                    uri.push_str(&urlencoding::encode(tag));
                }
                uri
            }
            ServerConfig::Hysteria2 {
                tag,
                address,
                port,
                password,
                obfs,
                obfs_password,
                sni,
                insecure,
                pinned_sha256,
                port_hopping,
                port_hopping_interval: _,
                bandwidth_down,
                bandwidth_up,
            } => {
                // Format: hysteria2://password@host:port?params#tag
                let mut params = Vec::new();

                if let Some(ref o) = obfs {
                    params.push(format!("obfs={}", o));
                    if let Some(ref op) = obfs_password {
                        params.push(format!("obfs-password={}", op));
                    }
                }

                if let Some(ref s) = sni {
                    params.push(format!("sni={}", s));
                }

                if *insecure {
                    params.push("insecure=1".to_string());
                }

                if let Some(ref p) = pinned_sha256 {
                    params.push(format!("pinSHA256={}", p));
                }

                if let Some(ref ph) = port_hopping {
                    params.push(format!("mport={}", ph));
                }

                if let Some(ref bd) = bandwidth_down {
                    params.push(format!("bandwidthDown={}", bd));
                }

                if let Some(ref bu) = bandwidth_up {
                    params.push(format!("bandwidthUp={}", bu));
                }

                let query = if params.is_empty() {
                    String::new()
                } else {
                    format!("?{}", params.join("&"))
                };

                let mut uri = format!("hysteria2://{}@{}:{}{}", password, address, port, query);

                if !tag.is_empty() {
                    uri.push('#');
                    uri.push_str(&urlencoding::encode(tag));
                }
                uri
            }
            ServerConfig::WireGuard {
                tag,
                address,
                port,
                secret_key,
                public_key,
                pre_shared_key,
                local_address,
                reserved,
                mtu,
            } => {
                // Format: wireguard://privatekey@host:port?params#tag
                let mut params = Vec::new();
                params.push(format!("address={}", urlencoding::encode(local_address)));
                params.push(format!("publickey={}", public_key));

                if let Some(ref psk) = pre_shared_key {
                    params.push(format!("presharedkey={}", psk));
                }

                params.push(format!("mtu={}", mtu));

                if let Some(ref r) = reserved {
                    params.push(format!("reserved={}", r));
                }

                let query = params.join("&");
                let mut uri = format!("wireguard://{}@{}:{}?{}", secret_key, address, port, query);

                if !tag.is_empty() {
                    uri.push('#');
                    uri.push_str(&urlencoding::encode(tag));
                }
                uri
            }
            ServerConfig::Socks {
                tag,
                address,
                port,
                username,
                password,
                version: _,
            } => {
                // Format: socks://base64(username:password)@host:port#tag
                let mut uri = String::from("socks://");

                if let (Some(u), Some(p)) = (username, password) {
                    let credentials = format!("{}:{}", u, p);
                    let encoded = BASE64_STANDARD.encode(credentials);
                    uri.push_str(&encoded);
                    uri.push('@');
                }

                uri.push_str(&format!("{}:{}#", address, port));

                if !tag.is_empty() {
                    uri.push_str(&urlencoding::encode(tag));
                } else {
                    uri.pop(); // Remove trailing #
                }

                uri
            }
            ServerConfig::Http {
                tag,
                address,
                port,
                username,
                password,
                tls,
            } => {
                // Format: http[s]://[username:password@]host:port#tag
                let scheme = if *tls { "https" } else { "http" };
                let mut uri = format!("{}://", scheme);

                if let (Some(u), Some(p)) = (username, password) {
                    uri.push_str(&urlencoding::encode(u));
                    uri.push(':');
                    uri.push_str(&urlencoding::encode(p));
                    uri.push('@');
                }

                uri.push_str(&format!("{}:{}#", address, port));

                if !tag.is_empty() {
                    uri.push_str(&urlencoding::encode(tag));
                } else {
                    uri.pop(); // Remove trailing #
                }

                uri
            }
        }
    }
}

/// Parses query string parameters into a HashMap.
///
/// # Arguments
///
/// * `query` - The query string to parse (without leading `?`)
///
/// # Returns
///
/// Returns a HashMap of key-value pairs or an error if decoding fails.
pub fn parse_query(query: &str) -> Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_value = decode(value)?.to_string();
            params.insert(key.to_string(), decoded_value);
        }
    }
    Ok(params)
}

/// Parses TLS settings from query parameters.
///
/// # Arguments
///
/// * `params` - Parsed query parameters
/// * `security` - Security type ("tls" or "reality")
///
/// # Returns
///
/// Returns TlsSettings or an error if parsing fails.
pub fn parse_tls_settings(params: &HashMap<String, String>, security: &str) -> Result<TlsSettings> {
    let server_name = params.get("sni").map(|s| s.to_string()).unwrap_or_default();
    let fingerprint = params
        .get("fp")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "chrome".to_string());

    let alpn = params.get("alpn").map(|s| {
        s.split(',')
            .map(|a| a.trim().to_string())
            .collect::<Vec<String>>()
    });

    let allow_insecure = params
        .get("allowInsecure")
        .map(|s| s == "1" || s == "true")
        .unwrap_or(true);

    let public_key = if security == "reality" {
        params.get("pbk").map(|s| s.to_string())
    } else {
        None
    };

    let short_id = if security == "reality" {
        params.get("sid").map(|s| s.to_string())
    } else {
        None
    };

    let spider_x = if security == "reality" {
        Some(
            params
                .get("spx")
                .or_else(|| params.get("path"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| "/".to_string()),
        )
    } else {
        None
    };

    Ok(TlsSettings {
        server_name,
        fingerprint,
        alpn,
        allow_insecure,
        public_key,
        short_id,
        spider_x,
    })
}

/// Parses network settings from query parameters.
///
/// # Arguments
///
/// * `params` - Parsed query parameters
/// * `network` - Network type ("ws", "grpc", "tcp")
///
/// # Returns
///
/// Returns NetworkSettings or an error if parsing fails.
pub fn parse_network_settings(
    params: &HashMap<String, String>,
    network: &str,
) -> Result<Option<NetworkSettings>> {
    match network {
        "ws" => {
            let path = params
                .get("path")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "/".to_string());
            let host = params
                .get("host")
                .map(|s| s.to_string())
                .unwrap_or_default();
            Ok(Some(NetworkSettings::WebSocket { path, host }))
        }
        "grpc" => {
            let service_name = params
                .get("serviceName")
                .map(|s| s.to_string())
                .unwrap_or_default();
            let authority = params
                .get("authority")
                .map(|s| s.to_string())
                .unwrap_or_default();
            Ok(Some(NetworkSettings::Grpc {
                service_name,
                authority,
            }))
        }
        "tcp" => {
            let header_type = params
                .get("headerType")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "none".to_string());
            Ok(Some(NetworkSettings::Tcp { header_type }))
        }
        "xhttp" => {
            let path = params
                .get("path")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "/".to_string());
            let host = params
                .get("host")
                .or_else(|| params.get("sni"))
                .map(|s| s.to_string())
                .unwrap_or_default();
            let mode = params
                .get("mode")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "auto".to_string());
            let extra = params.get("extra").cloned();
            Ok(Some(NetworkSettings::XHttp {
                path,
                host,
                mode,
                extra,
            }))
        }
        _ => Ok(None),
    }
}

/// Sanitizes a server tag by removing special characters and emojis.
///
/// # Arguments
///
/// * `tag` - The original tag string
/// * `protocol` - The protocol name for fallback tag generation
/// * `idx` - The index for fallback tag generation
/// * `is_warp` - Whether this is a WARP server
/// * `address` - Server address for uniqueness (optional)
/// * `port` - Server port for uniqueness (optional)
/// * `id` - Server ID/UUID for uniqueness (optional, for VLESS/Trojan/VMess)
///
/// # Returns
///
/// Returns a sanitized tag string. If address and port are provided and the tag
/// would otherwise be a duplicate, appends a short hash for uniqueness.
pub fn sanitize_tag(
    tag: &str,
    protocol: &str,
    idx: usize,
    is_warp: bool,
    address: Option<&str>,
    port: Option<u16>,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Remove emojis and special characters, keep alphanumeric and common separators
    let cleaned: String = tag
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == ' ')
        .collect();

    let cleaned = cleaned.trim();

    let mut base_tag = if cleaned.is_empty() {
        format!("{}-{}", protocol, idx)
    } else {
        cleaned.replace(' ', "-").to_lowercase()
    };

    // If it's a WARP server and tag doesn't start with "warp", prepend it
    if is_warp && !base_tag.starts_with("warp") {
        base_tag = format!("warp-{}", base_tag);
    }

    // Add uniqueness suffix if address and port are provided
    // Include address:port in hash to ensure uniqueness for same IP:port with different UUIDs
    if let (Some(addr), Some(p)) = (address, port) {
        let mut hasher = DefaultHasher::new();
        // Include protocol, address, port, and index in hash
        // This ensures servers with same IP:port but different positions get different tags
        format!("{}:{}:{}:{}", protocol, addr, p, idx).hash(&mut hasher);
        let hash = hasher.finish();
        let short_hash = format!("{:x}", hash)[..4].to_string();
        base_tag = format!("{}-{}", base_tag, short_hash);
    }

    base_tag
}

/// Checks if a server should be classified as WARP.
///
/// # Arguments
///
/// * `tag` - The server tag
/// * `params` - Query parameters (for checking path/host)
///
/// # Returns
///
/// Returns `true` if the server appears to be a WARP server.
pub fn check_is_warp(tag: &str, params: &HashMap<String, String>) -> bool {
    // Check tag for warp keyword
    let tag_lower = tag.to_lowercase();
    if tag_lower.contains("warp") {
        return true;
    }

    // Check path parameter for warp or cloudflare keywords
    if let Some(path) = params.get("path") {
        let path_lower = path.to_lowercase();
        if path_lower.contains("warp") || path_lower.contains("cloudflare") {
            return true;
        }
    }

    // Check host parameter for warp keyword
    if let Some(host) = params.get("host") {
        let host_lower = host.to_lowercase();
        if host_lower.contains("warp") {
            return true;
        }
    }

    false
}

/// Helper function to safely decode URL-encoded tag.
///
/// # Arguments
///
/// * `encoded` - The encoded tag string
/// * `default_fn` - Function to generate default tag if decoding fails
///
/// # Returns
///
/// Returns the decoded tag or the default.
pub fn decode_tag<F>(encoded: &str, default_fn: F) -> String
where
    F: FnOnce() -> String,
{
    decode(encoded)
        .ok()
        .map(|s| s.to_string())
        .unwrap_or_else(default_fn)
}

/// Helper function to decode base64 with multiple variants.
///
/// # Arguments
///
/// * `encoded` - The base64-encoded string
///
/// # Returns
///
/// Returns the decoded bytes or an error if all variants fail.
pub fn decode_base64_flexible(encoded: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| BASE64_URL_SAFE.decode(encoded.as_bytes()))
        .or_else(|_| BASE64_STANDARD_NO_PAD.decode(encoded.as_bytes()))
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(encoded.as_bytes()))
        .context("Failed to decode base64")
}
