//! Shadowsocks URL parser.
//!
//! Parses `ss://` URLs into Shadowsocks server configurations.

use anyhow::{Context, Result};
use regex::Regex;

use crate::parser::shared::{decode_base64_flexible, decode_tag, sanitize_tag, ServerConfig};
use crate::parser::UrlParser;

/// Raw Shadowsocks data parsed from URL.
pub struct ShadowsocksRaw {
    pub method: String,
    pub password: String,
    pub address: String,
    pub port: u16,
    pub tag: String,
}

/// Shadowsocks protocol parser.
pub struct ShadowsocksParser;

impl UrlParser for ShadowsocksParser {
    type Raw = ShadowsocksRaw;

    fn prefixes(&self) -> &[&'static str] {
        &["ss://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<ShadowsocksRaw> {
        // Format: ss://base64(method:password)@host:port[?params][#tag]
        let re = Regex::new(r"^ss://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$")?;
        let caps = re.captures(url).context("Invalid shadowsocks URL format")?;

        let encoded = caps.get(1).unwrap().as_str();
        let host = caps.get(2).unwrap().as_str().to_string();
        let port: u16 = caps.get(3).unwrap().as_str().parse()?;
        let tag = decode_tag(caps.get(5).map(|m| m.as_str()).unwrap_or(""), || {
            format!("ss-{}", idx)
        });

        // Decode base64 credentials
        let decoded = decode_base64_flexible(encoded)?;
        let decoded_str = String::from_utf8(decoded)?;

        // Parse method:password
        let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid shadowsocks credentials format");
        }

        Ok(ShadowsocksRaw {
            method: parts[0].to_string(),
            password: parts[1].to_string(),
            address: host,
            port,
            tag,
        })
    }

    fn to_server_config(raw: ShadowsocksRaw, idx: usize) -> Result<ServerConfig> {
        let clean_tag = sanitize_tag(
            &raw.tag,
            "ss",
            idx,
            false,
            Some(&raw.address),
            Some(raw.port),
        );

        Ok(ServerConfig::Shadowsocks {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            method: raw.method,
            password: raw.password,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shadowsocks_basic() {
        let parser = ShadowsocksParser;
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#test-server";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Shadowsocks {
                method,
                address,
                port,
                ..
            } => {
                assert_eq!(method, "chacha20-ietf-poly1305");
                assert_eq!(address, "62.133.60.43");
                assert_eq!(port, 36456);
            }
            _ => panic!("Expected Shadowsocks config"),
        }
    }

    #[test]
    fn test_parse_shadowsocks_with_emoji_tag() {
        let parser = ShadowsocksParser;
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#%F0%9F%87%A9%F0%9F%87%AA%20PORT";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert!(server.tag().to_lowercase().contains("port"));
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = ShadowsocksParser;
        assert!(parser.prefixes().contains(&"ss://"));
    }
}
