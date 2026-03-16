//! SOCKS URL parser.
//!
//! Parses `socks://` URLs into SOCKS server configurations.
//!
//! # Format
//!
//! ```text
//! socks://base64(username:password)@server:port#Remarks
//! ```
//!
//! If no credentials are provided, authentication is not required.

use anyhow::{Context, Result};

use crate::parser::shared::{decode_base64_flexible, decode_tag, sanitize_tag, ServerConfig};
use crate::parser::UrlParser;

/// Raw SOCKS data parsed from URL.
pub struct SocksRaw {
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub version: String,
    pub tag: String,
}

/// SOCKS protocol parser.
pub struct SocksParser;

impl UrlParser for SocksParser {
    type Raw = SocksRaw;

    fn prefixes(&self) -> &[&'static str] {
        &["socks://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<SocksRaw> {
        // Format: socks://base64(username:password)@host:port#tag
        // or: socks://host:port#tag (no auth)
        let url_clean = url
            .strip_prefix("socks://")
            .context("Invalid socks URL format")?;

        // Split by # to get tag
        let (url_part, tag) = if let Some(hash_pos) = url_clean.find('#') {
            let (url_p, tag_p) = url_clean.split_at(hash_pos);
            (url_p, decode_tag(&tag_p[1..], || format!("socks-{}", idx)))
        } else {
            (url_clean, format!("socks-{}", idx))
        };

        // Check if there are credentials
        let (username, password, host_port) = if let Some(at_pos) = url_part.find('@') {
            let (creds, hp) = url_part.split_at(at_pos);
            let hp = &hp[1..]; // skip @

            // Decode base64 credentials
            let decoded = decode_base64_flexible(creds)?;
            let decoded_str = String::from_utf8(decoded)?;

            // Parse username:password
            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if parts.len() == 2 {
                (
                    Some(parts[0].to_string()),
                    Some(parts[1].to_string()),
                    hp.to_string(),
                )
            } else {
                (None, None, hp.to_string())
            }
        } else {
            (None, None, url_part.to_string())
        };

        // Parse host:port
        let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
            let (h, p) = host_port.split_at(colon_pos);
            (h.to_string(), p[1..].parse()?)
        } else {
            anyhow::bail!("Missing port in socks URL");
        };

        // Detect SOCKS version from tag or default to 5
        let version = if tag.to_lowercase().contains("4") {
            "4".to_string()
        } else {
            "5".to_string() // Default to SOCKS5
        };

        Ok(SocksRaw {
            address: host,
            port,
            username,
            password,
            version,
            tag,
        })
    }

    fn to_server_config(raw: SocksRaw, idx: usize) -> Result<ServerConfig> {
        let clean_tag = sanitize_tag(
            &raw.tag,
            "socks",
            idx,
            false,
            Some(&raw.address),
            Some(raw.port),
        );

        Ok(ServerConfig::Socks {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            username: raw.username,
            password: raw.password,
            version: raw.version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks_with_auth() {
        let parser = SocksParser;
        // base64("user:pass") = dXNlcjpwYXNz
        let url = "socks://dXNlcjpwYXNz@192.168.1.1:1080#test-socks";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Socks {
                address,
                port,
                username,
                password,
                tag,
                ..
            } => {
                assert_eq!(address, "192.168.1.1");
                assert_eq!(port, 1080);
                assert_eq!(username, Some("user".to_string()));
                assert_eq!(password, Some("pass".to_string()));
                assert!(tag.contains("socks"));
            }
            _ => panic!("Expected SOCKS config"),
        }
    }

    #[test]
    fn test_parse_socks_no_auth() {
        let parser = SocksParser;
        let url = "socks://192.168.1.1:1080#test-socks";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Socks {
                address,
                port,
                username,
                password,
                ..
            } => {
                assert_eq!(address, "192.168.1.1");
                assert_eq!(port, 1080);
                assert_eq!(username, None);
                assert_eq!(password, None);
            }
            _ => panic!("Expected SOCKS config"),
        }
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = SocksParser;
        assert!(parser.prefixes().contains(&"socks://"));
    }
}
