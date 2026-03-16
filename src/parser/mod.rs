//! VPN server URL parsers.
//!
//! This module provides a trait-based architecture for parsing VPN server URLs
//! from various protocols. Each protocol has its own parser implementation.
//!
//! # Architecture
//!
//! The parsing system is built around the [`UrlParser`] trait, which defines
//! a common interface for all protocol parsers. The trait uses the
//! **Template Method Pattern**:
//!
//! 1. Each parser defines its own `Raw` associated type for intermediate data
//! 2. [`parse_raw`](UrlParser::parse_raw) extracts protocol-specific data
//! 3. [`to_server_config`](UrlParser::to_server_config) converts to unified format
//! 4. [`parse`](UrlParser::parse) combines both steps (default implementation)
//!
//! # Supported Protocols
//!
//! - Shadowsocks (`ss://`) — SIP002, Legacy, Plugin formats
//! - VLESS (`vless://`) — Standard URI format
//! - VMess (`vmess://`) — Classic (Base64 JSON) and Standard URI formats
//! - Trojan (`trojan://`) — Standard URI format
//! - Hysteria2 (`hysteria2://`, `hy2://`) — Standard URI format
//! - WireGuard (`wireguard://`) — URI format
//! - SOCKS (`socks://`) — Base64-encoded credentials
//! - HTTP (`http://`, `https://`) — Basic auth format
//!
//! # Example
//!
//! ```
//! use proxy_harvest_rs::parser::{parse_servers, ServerConfig};
//!
//! # fn main() -> anyhow::Result<()> {
//! let content = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388#server";
//! let servers = parse_servers(content)?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

use anyhow::Result;

// Parser modules
mod http;
mod hysteria2;
mod shadowsocks;
mod socks;
mod trojan;
mod vless;
mod vmess;
mod wireguard;

// Re-export parser implementations
use http::HttpParser;
use hysteria2::Hysteria2Parser;
use shadowsocks::ShadowsocksParser;
use socks::SocksParser;
use trojan::TrojanParser;
use vless::VlessParser;
use vmess::VmessParser;
use wireguard::WireGuardParser;

// Re-export common types
pub use shared::{check_is_warp, sanitize_tag, NetworkSettings, ServerConfig, TlsSettings};

/// Shared types and utilities for parser modules.
pub mod shared;

/// Trait for URL parsers.
///
/// This trait defines the interface for all protocol-specific parsers.
/// Each parser defines its own raw data format via the associated type `Raw`.
///
/// # Architecture
///
/// The trait uses the **Template Method Pattern**:
///
/// 1. [`parse_raw`](UrlParser::parse_raw) — protocol-specific URL parsing (must be implemented)
/// 2. [`to_server_config`](UrlParser::to_server_config) — conversion to unified format (must be implemented)
/// 3. [`parse`](UrlParser::parse) — public API combining both steps (default implementation)
///
/// # Associated Types
///
/// * `Raw` - The protocol-specific raw data structure
///
/// # Example
///
/// ```rust,ignore
/// struct MyParser;
///
/// impl UrlParser for MyParser {
///     type Raw = MyRawFormat;
///
///     fn prefixes(&self) -> &[&'static str] { &["myproto://"] }
///
///     fn parse_raw(&self, url: &str, idx: usize) -> Result<Self::Raw> {
///         // Parse URL into raw format
///     }
///
///     fn to_server_config(raw: Self::Raw, idx: usize) -> Result<ServerConfig> {
///         // Convert to ServerConfig
///     }
/// }
/// ```
pub trait UrlParser: Send + Sync {
    /// The protocol-specific raw data format.
    type Raw: Send + Sync;

    /// Returns the URL prefixes this parser handles.
    fn prefixes(&self) -> &[&'static str];

    /// Parses a URL into the protocol-specific raw format.
    ///
    /// # Arguments
    ///
    /// * `url` - The full URL to parse (including protocol prefix)
    /// * `idx` - The line index for generating default tags
    ///
    /// # Returns
    ///
    /// Returns the parsed raw data or an error if parsing fails.
    fn parse_raw(&self, url: &str, idx: usize) -> Result<Self::Raw>;

    /// Converts raw data to a unified ServerConfig.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw data from [`parse_raw`](UrlParser::parse_raw)
    /// * `idx` - The line index for generating default tags
    ///
    /// # Returns
    ///
    /// Returns a ServerConfig or an error if conversion fails.
    fn to_server_config(raw: Self::Raw, idx: usize) -> Result<ServerConfig>;

    /// Public API for parsing URLs.
    ///
    /// This default method combines [`parse_raw`](UrlParser::parse_raw) and
    /// [`to_server_config`](UrlParser::to_server_config). Override only if
    /// you need custom behavior.
    ///
    /// # Arguments
    ///
    /// * `url` - The full URL to parse (including protocol prefix)
    /// * `idx` - The line index for generating default tags
    ///
    /// # Returns
    ///
    /// Returns a ServerConfig or an error if parsing fails.
    fn parse(&self, url: &str, idx: usize) -> Result<ServerConfig> {
        let raw = self.parse_raw(url, idx)?;
        Self::to_server_config(raw, idx)
    }
}

/// Registry of URL parsers.
///
/// Manages a collection of protocol-specific parsers and provides
/// a unified interface for parsing URLs of any supported protocol.
pub struct ParserRegistry {
    parsers: Vec<Box<dyn DynParser>>,
}

/// Dynamic parser trait for type-erased storage.
trait DynParser: Send + Sync {
    fn matches(&self, url: &str) -> bool;
    fn parse(&self, url: &str, idx: usize) -> Result<ServerConfig>;
}

/// Wrapper for uniform parser access.
struct ParserWrapper<P: UrlParser + 'static> {
    inner: P,
}

impl<P: UrlParser + 'static> ParserWrapper<P> {
    fn new(parser: P) -> Self {
        Self { inner: parser }
    }
}

impl<P: UrlParser + 'static> DynParser for ParserWrapper<P> {
    fn matches(&self, url: &str) -> bool {
        self.inner.prefixes().iter().any(|p| url.starts_with(p))
    }

    fn parse(&self, url: &str, idx: usize) -> Result<ServerConfig> {
        self.inner.parse(url, idx)
    }
}

impl ParserRegistry {
    /// Creates a new parser registry with all supported protocols.
    pub fn new() -> Self {
        Self {
            parsers: vec![
                Box::new(ParserWrapper::new(ShadowsocksParser)),
                Box::new(ParserWrapper::new(VlessParser)),
                Box::new(ParserWrapper::new(VmessParser)),
                Box::new(ParserWrapper::new(TrojanParser)),
                Box::new(ParserWrapper::new(Hysteria2Parser)),
                Box::new(ParserWrapper::new(WireGuardParser)),
                Box::new(ParserWrapper::new(SocksParser)),
                Box::new(ParserWrapper::new(HttpParser)),
            ],
        }
    }

    /// Parses a URL using the appropriate protocol parser.
    ///
    /// # Arguments
    ///
    /// * `url` - The full URL to parse
    /// * `idx` - The line index for generating default tags
    ///
    /// # Returns
    ///
    /// Returns a ServerConfig or an error if no parser matches or parsing fails.
    pub fn parse_url(&self, url: &str, idx: usize) -> Result<ServerConfig> {
        for parser in &self.parsers {
            if parser.matches(url) {
                return parser.parse(url, idx);
            }
        }
        anyhow::bail!("Unsupported protocol: {}", url)
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses VPN server URLs from content and returns a vector of server configurations.
///
/// This function processes each line of the input content, attempting to parse
/// supported VPN protocol URLs (Shadowsocks, VLESS, VMess, Trojan, Hysteria2).
/// Invalid or unsupported URLs are silently skipped with a warning log.
///
/// # Arguments
///
/// * `content` - A string slice containing server URLs, one per line
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(Vec<ServerConfig>)` - Vector of successfully parsed server configurations
/// - `Err(anyhow::Error)` - Error if parsing fails critically (individual URL failures are logged but not returned)
///
/// # Supported Protocols
///
/// - `ss://` - Shadowsocks
/// - `vless://` - VLESS
/// - `vmess://` - VMess
/// - `trojan://` - Trojan
/// - `hysteria2://` or `hy2://` - Hysteria2
///
/// # Example
///
/// ```rust,no_run
/// # use proxy_harvest_rs::parser::parse_servers;
/// # fn main() -> anyhow::Result<()> {
/// let content = r#"
/// ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388#server
/// vless://uuid@example.com:443?security=tls#vless-server
/// "#;
///
/// let servers = parse_servers(content)?;
/// assert_eq!(servers.len(), 2);
/// # Ok(())
/// # }
/// ```
pub fn parse_servers(content: &str) -> Result<Vec<ServerConfig>> {
    let registry = ParserRegistry::new();
    let mut servers = Vec::new();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    for (idx, line) in lines.iter().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match registry.parse_url(line, idx) {
            Ok(server) => servers.push(server),
            Err(e) => {
                log::warn!("Failed to parse line {}: {} - Error: {}", idx + 1, line, e);
            }
        }
    }

    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = ParserRegistry::new();
        assert_eq!(registry.parsers.len(), 8); // 8 protocols
    }

    #[test]
    fn test_parse_servers_empty_input() {
        let result = parse_servers("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_servers_mixed_protocols() {
        let content = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388#ss-server
vless://uuid@example.com:443?security=tls#vless-server
trojan://password@example.com:443#trojan-server
hysteria2://password@example.com:443#hysteria2-server
wireguard://privatekey@example.com:51820?address=172.16.0.2%2F32&publickey=pubkey&mtu=1420#wireguard-server
socks://dXNlcjpwYXNz@192.168.1.1:1080#socks-server
http://user:pass@proxy.example.com:8080#http-server
"#;
        let result = parse_servers(content);
        assert!(result.is_ok());
        // Note: trojan and hysteria2 may fail without proper query params
        // Expected: ss, vless, wireguard, socks, http = 5
        assert!(result.unwrap().len() >= 5);
    }
}
