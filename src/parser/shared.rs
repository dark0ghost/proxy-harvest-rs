//! Shared types and utilities for parser modules.
//!
//! This module contains the common data structures used across all protocol parsers.

use anyhow::{Context, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use urlencoding::decode;

/// VPN server configuration parsed from URL.
///
/// Represents a parsed VPN server configuration ready for Xray outbound generation.
/// Each variant corresponds to a specific VPN protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol")]
pub enum ServerConfig {
    /// Shadowsocks server configuration.
    #[serde(rename = "shadowsocks")]
    Shadowsocks {
        /// Server tag/label for identification.
        tag: String,
        /// Server hostname or IP address.
        address: String,
        /// Server port number.
        port: u16,
        /// Encryption method (e.g., "aes-256-gcm", "chacha20-ietf-poly1305").
        method: String,
        /// Password for authentication.
        password: String,
    },
    /// VLESS server configuration.
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
        /// Traffic flow for XTLS (e.g., "xtls-rprx-vision").
        flow: String,
        /// Network transport type (e.g., "tcp", "ws", "grpc").
        network: String,
        /// Security layer (e.g., "none", "tls", "reality").
        security: String,
        /// TLS/Reality settings if security is enabled.
        tls_settings: Option<Box<TlsSettings>>,
        /// Network-specific settings (WebSocket, gRPC, TCP).
        network_settings: Option<NetworkSettings>,
    },
    /// VMess server configuration.
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
        /// Security method (e.g., "auto", "aes-128-gcm").
        security: String,
        /// Network transport type (e.g., "tcp", "ws", "grpc").
        network: String,
        /// TLS mode (empty string or "tls").
        tls: String,
        /// TLS settings if TLS is enabled.
        tls_settings: Option<Box<TlsSettings>>,
        /// Network-specific settings (WebSocket, gRPC, TCP).
        network_settings: Option<NetworkSettings>,
    },
    /// Trojan server configuration.
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
        /// Security layer (e.g., "tls", "reality").
        security: String,
        /// Server Name Indication for TLS.
        sni: Option<String>,
        /// TLS/Reality settings if security is enabled.
        tls_settings: Option<Box<TlsSettings>>,
        /// Network-specific settings (WebSocket, gRPC, TCP).
        network_settings: Option<NetworkSettings>,
    },
    /// Hysteria2 server configuration.
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
        /// Certificate pinning hash.
        pinned_sha256: Option<String>,
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
}

impl ServerConfig {
    /// Returns the server tag/label.
    ///
    /// # Returns
    ///
    /// A string slice containing the server's tag used for identification.
    pub fn tag(&self) -> &str {
        match self {
            ServerConfig::Shadowsocks { tag, .. } => tag,
            ServerConfig::Vless { tag, .. } => tag,
            ServerConfig::Vmess { tag, .. } => tag,
            ServerConfig::Trojan { tag, .. } => tag,
            ServerConfig::Hysteria2 { tag, .. } => tag,
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
        match self {
            ServerConfig::Vless { address, .. }
            | ServerConfig::Vmess { address, .. }
            | ServerConfig::Trojan { address, .. } => {
                let addr = address.to_lowercase();
                addr.starts_with("104.") || addr.contains("cloudflare") || addr.contains("cdn")
            }
            _ => false,
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
    let server_name = params
        .get("sni")
        .map(|s| s.to_string())
        .unwrap_or_default();
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
        Some(params.get("spx").or_else(|| params.get("path")).map(|s| s.to_string()).unwrap_or_else(|| "/".to_string()))
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
///
/// # Returns
///
/// Returns a sanitized tag string.
pub fn sanitize_tag(tag: &str, protocol: &str, idx: usize, is_warp: bool) -> String {
    // Remove emojis and special characters, keep alphanumeric and common separators
    let cleaned: String = tag
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == ' ')
        .collect();

    let cleaned = cleaned.trim();

    let base_tag = if cleaned.is_empty() {
        format!("{}-{}", protocol, idx)
    } else {
        cleaned.replace(' ', "-").to_lowercase()
    };

    // If it's a WARP server and tag doesn't start with "warp", prepend it
    if is_warp && !base_tag.starts_with("warp") {
        format!("warp-{}", base_tag)
    } else {
        base_tag
    }
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
    decode(encoded).ok().map(|s| s.to_string()).unwrap_or_else(default_fn)
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
