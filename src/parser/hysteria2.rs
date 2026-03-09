//! Hysteria2 URL parser.
//!
//! Parses `hysteria2://` and `hy2://` URLs into Hysteria2 server configurations.

use anyhow::{Context, Result};
use std::collections::HashMap;

use crate::parser::shared::{decode_tag, parse_query, sanitize_tag, ServerConfig};
use crate::parser::UrlParser;

/// Raw Hysteria2 data parsed from URL.
pub struct Hysteria2Raw {
    pub password: String,
    pub address: String,
    pub port: u16,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub sni: Option<String>,
    pub insecure: bool,
    pub pinned_sha256: Option<String>,
    pub tag: String,
}

/// Hysteria2 protocol parser.
pub struct Hysteria2Parser;

impl UrlParser for Hysteria2Parser {
    type Raw = Hysteria2Raw;

    fn prefixes(&self) -> &[&'static str] {
        &["hysteria2://", "hy2://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<Hysteria2Raw> {
        // Format: hysteria2://[auth@]hostname[:port][/]?params#tag or hy2://...
        let url_clean = url
            .strip_prefix("hysteria2://")
            .or_else(|| url.strip_prefix("hy2://"))
            .context("Invalid hysteria2 URL format")?;

        // Split by # to get tag
        let (url_part, tag) = if let Some(hash_pos) = url_clean.find('#') {
            let (url_p, tag_p) = url_clean.split_at(hash_pos);
            (
                url_p,
                decode_tag(&tag_p[1..], || format!("hysteria2-{}", idx)),
            )
        } else {
            (url_clean, format!("hysteria2-{}", idx))
        };

        // Split by /? or ? to get params
        let (host_part, query) = if let Some(slash_q_pos) = url_part.find("/?") {
            let (host_p, query_p) = url_part.split_at(slash_q_pos);
            (host_p, &query_p[2..]) // skip /?
        } else if let Some(q_pos) = url_part.find('?') {
            let (host_p, query_p) = url_part.split_at(q_pos);
            (host_p, &query_p[1..]) // skip ?
        } else {
            // Remove trailing slash if present
            let host_p = url_part.trim_end_matches('/');
            (host_p, "")
        };

        // Parse auth@host:port
        // Use rfind to handle passwords that contain @ (like email addresses)
        let (password, host, port) = if let Some(at_pos) = host_part.rfind('@') {
            let (auth, host_port) = host_part.split_at(at_pos);
            let host_port = &host_port[1..]; // skip @

            let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
                let (h, p) = host_port.split_at(colon_pos);
                (h.to_string(), p[1..].parse()?)
            } else {
                (host_port.to_string(), 443)
            };

            (decode_tag(auth, String::new), host, port)
        } else {
            // No auth, parse host:port
            let (host, port) = if let Some(colon_pos) = host_part.rfind(':') {
                let (h, p) = host_part.split_at(colon_pos);
                (h.to_string(), p[1..].parse()?)
            } else {
                (host_part.to_string(), 443)
            };
            (String::new(), host, port)
        };

        let params = if !query.is_empty() {
            parse_query(query)?
        } else {
            HashMap::new()
        };

        let obfs = params.get("obfs").map(|s| s.to_string());
        let obfs_password = params.get("obfs-password").map(|s| s.to_string());
        let sni = params.get("sni").map(|s| s.to_string());
        let insecure = params
            .get("insecure")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        let pinned_sha256 = params.get("pinSHA256").map(|s| s.to_string());

        Ok(Hysteria2Raw {
            password,
            address: host,
            port,
            obfs,
            obfs_password,
            sni,
            insecure,
            pinned_sha256,
            tag,
        })
    }

    fn to_server_config(raw: Hysteria2Raw, idx: usize) -> Result<ServerConfig> {
        let clean_tag = sanitize_tag(&raw.tag, "hysteria2", idx, false);

        Ok(ServerConfig::Hysteria2 {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            password: raw.password,
            obfs: raw.obfs,
            obfs_password: raw.obfs_password,
            sni: raw.sni,
            insecure: raw.insecure,
            pinned_sha256: raw.pinned_sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hysteria2_basic() {
        let parser = Hysteria2Parser;
        let url = "hysteria2://password@example.com:443#test-hysteria2";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Hysteria2 {
                password,
                address,
                port,
                tag,
                ..
            } => {
                assert_eq!(password, "password");
                assert_eq!(address, "example.com");
                assert_eq!(port, 443);
                assert_eq!(tag, "test-hysteria2");
            }
            _ => panic!("Expected Hysteria2 config"),
        }
    }

    #[test]
    fn test_parse_hysteria2_with_params() {
        let parser = Hysteria2Parser;
        let url = "hysteria2://auth@example.com:443?obfs=salamander&obfs-password=secret&sni=example.com#test";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Hysteria2 {
                obfs,
                obfs_password,
                sni,
                ..
            } => {
                assert_eq!(obfs, Some("salamander".to_string()));
                assert_eq!(obfs_password, Some("secret".to_string()));
                assert_eq!(sni, Some("example.com".to_string()));
            }
            _ => panic!("Expected Hysteria2 config"),
        }
    }

    #[test]
    fn test_parse_hy2_alias() {
        let parser = Hysteria2Parser;
        let url = "hy2://password@example.com:8443#test";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Hysteria2 { port, .. } => {
                assert_eq!(port, 8443);
            }
            _ => panic!("Expected Hysteria2 config"),
        }
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = Hysteria2Parser;
        assert!(parser.prefixes().contains(&"hysteria2://"));
        assert!(parser.prefixes().contains(&"hy2://"));
    }
}
