//! HTTP/HTTPS URL parser.
//!
//! Parses `http://` and `https://` URLs into HTTP proxy server configurations.
//!
//! # Format
//!
//! ```text
//! http://username:password@server:port#Remarks
//! https://username:password@server:port#Remarks
//! ```

use anyhow::Result;

use crate::parser::shared::{decode_tag, sanitize_tag, ServerConfig};
use crate::parser::UrlParser;

/// Raw HTTP data parsed from URL.
pub struct HttpRaw {
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub tag: String,
}

/// HTTP protocol parser.
pub struct HttpParser;

impl UrlParser for HttpParser {
    type Raw = HttpRaw;

    fn prefixes(&self) -> &[&'static str] {
        &["http://", "https://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<HttpRaw> {
        // Format: http[s]://[username:password@]host:port#tag
        let (url_clean, tls) = if let Some(stripped) = url.strip_prefix("https://") {
            (stripped, true)
        } else if let Some(stripped) = url.strip_prefix("http://") {
            (stripped, false)
        } else {
            anyhow::bail!("Invalid http URL format");
        };

        // Split by # to get tag
        let (url_part, tag) = if let Some(hash_pos) = url_clean.find('#') {
            let (url_p, tag_p) = url_clean.split_at(hash_pos);
            (url_p, decode_tag(&tag_p[1..], || format!("http-{}", idx)))
        } else {
            (url_clean, format!("http-{}", idx))
        };

        // Check if there are credentials
        let (username, password, host_port) = if let Some(at_pos) = url_part.find('@') {
            let (creds, hp) = url_part.split_at(at_pos);
            let hp = &hp[1..]; // skip @

            // Parse username:password
            let parts: Vec<&str> = creds.splitn(2, ':').collect();
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
            anyhow::bail!("Missing port in http URL");
        };

        Ok(HttpRaw {
            address: host,
            port,
            username,
            password,
            tls,
            tag,
        })
    }

    fn to_server_config(raw: HttpRaw, idx: usize) -> Result<ServerConfig> {
        let clean_tag = sanitize_tag(
            &raw.tag,
            "http",
            idx,
            false,
            Some(&raw.address),
            Some(raw.port),
        );

        Ok(ServerConfig::Http {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            username: raw.username,
            password: raw.password,
            tls: raw.tls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_with_auth() {
        let parser = HttpParser;
        let url = "http://user:pass@192.168.1.1:8080#test-http";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Http {
                address,
                port,
                username,
                password,
                tls,
                tag,
                ..
            } => {
                assert_eq!(address, "192.168.1.1");
                assert_eq!(port, 8080);
                assert_eq!(username, Some("user".to_string()));
                assert_eq!(password, Some("pass".to_string()));
                assert!(!tls);
                assert!(tag.contains("http"));
            }
            _ => panic!("Expected HTTP config"),
        }
    }

    #[test]
    fn test_parse_https_with_auth() {
        let parser = HttpParser;
        let url = "https://user:pass@example.com:443#test-https";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Http {
                address, port, tls, ..
            } => {
                assert_eq!(address, "example.com");
                assert_eq!(port, 443);
                assert!(tls);
            }
            _ => panic!("Expected HTTP config"),
        }
    }

    #[test]
    fn test_parse_http_no_auth() {
        let parser = HttpParser;
        let url = "http://192.168.1.1:8080#test-http";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Http {
                address,
                port,
                username,
                password,
                ..
            } => {
                assert_eq!(address, "192.168.1.1");
                assert_eq!(port, 8080);
                assert_eq!(username, None);
                assert_eq!(password, None);
            }
            _ => panic!("Expected HTTP config"),
        }
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = HttpParser;
        assert!(parser.prefixes().contains(&"http://"));
        assert!(parser.prefixes().contains(&"https://"));
    }
}
