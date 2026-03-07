//! Trojan URL parser.
//!
//! Parses `trojan://` URLs into Trojan server configurations.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;

use crate::parser::shared::{
    decode_tag, parse_network_settings, parse_query, parse_tls_settings,
    sanitize_tag, NetworkSettings, ServerConfig, TlsSettings,
};
use crate::parser::UrlParser;

/// Raw Trojan data parsed from URL.
pub struct TrojanRaw {
    pub password: String,
    pub address: String,
    pub port: u16,
    pub network: String,
    pub security: String,
    pub sni: Option<String>,
    pub tls_settings: Option<TlsSettings>,
    pub network_settings: Option<NetworkSettings>,
    pub tag: String,
}

/// Trojan protocol parser.
pub struct TrojanParser;

impl UrlParser for TrojanParser {
    type Raw = TrojanRaw;

    fn prefixes(&self) -> &[&'static str] {
        &["trojan://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<TrojanRaw> {
        // Format: trojan://password@host:port[/]?params#tag
        let re = Regex::new(r"^trojan://([^@]+)@([^:]+):(\d+)/?\??([^#]*)(?:#(.*))?$")?;
        let caps = re.captures(url).context("Invalid trojan URL format")?;

        let password = decode_tag(
            caps.get(1).map(|m| m.as_str()).unwrap_or(""),
            || String::new(),
        );
        let host = caps.get(2).unwrap().as_str().to_string();
        let port: u16 = caps.get(3).unwrap().as_str().parse()?;
        let query = caps.get(4).map(|m| m.as_str()).unwrap_or("");
        let tag = decode_tag(
            caps.get(5).map(|m| m.as_str()).unwrap_or(""),
            || format!("trojan-{}", idx),
        );

        let params = if !query.is_empty() {
            parse_query(query)?
        } else {
            HashMap::new()
        };

        let network = params
            .get("type")
            .map(|s| s.as_str())
            .unwrap_or("tcp")
            .to_string();

        let security = params
            .get("security")
            .map(|s| s.as_str())
            .unwrap_or("tls")
            .to_string();

        let sni = params.get("sni").map(|s| s.to_string());

        // Parse TLS settings
        let tls_settings = if security == "tls" || security == "reality" {
            Some(parse_tls_settings(&params, &security)?)
        } else {
            None
        };

        // Parse network settings
        let network_settings = parse_network_settings(&params, &network)?;

        Ok(TrojanRaw {
            password,
            address: host,
            port,
            network,
            security,
            sni,
            tls_settings,
            network_settings,
            tag,
        })
    }

    fn to_server_config(raw: TrojanRaw, idx: usize) -> Result<ServerConfig> {
        let clean_tag = sanitize_tag(&raw.tag, "trojan", idx, false);

        Ok(ServerConfig::Trojan {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            password: raw.password,
            network: raw.network,
            security: raw.security,
            sni: raw.sni,
            tls_settings: raw.tls_settings.map(Box::new),
            network_settings: raw.network_settings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_trojan_basic() {
        let parser = TrojanParser;
        let url = "trojan://password123@example.com:443#test-trojan";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Trojan { password, address, port, tag, .. } => {
                assert_eq!(password, "password123");
                assert_eq!(address, "example.com");
                assert_eq!(port, 443);
                assert_eq!(tag, "test-trojan");
            }
            _ => panic!("Expected Trojan config"),
        }
    }

    #[test]
    fn test_parse_trojan_with_params() {
        let parser = TrojanParser;
        let url = "trojan://password@example.com:443/?type=ws&path=/trojan&security=tls#test";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Trojan { network, security, .. } => {
                assert_eq!(network, "ws");
                assert_eq!(security, "tls");
            }
            _ => panic!("Expected Trojan config"),
        }
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = TrojanParser;
        assert!(parser.prefixes().contains(&"trojan://"));
    }
}
