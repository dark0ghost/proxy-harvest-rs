//! VLESS URL parser.
//!
//! Parses `vless://` URLs into VLESS server configurations.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;

use crate::parser::shared::{
    check_is_warp, decode_tag, parse_network_settings, parse_query, parse_tls_settings,
    sanitize_tag, NetworkSettings, ServerConfig, TlsSettings,
};
use crate::parser::UrlParser;

/// Raw VLESS data parsed from URL.
pub struct VlessRaw {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub encryption: String,
    pub flow: String,
    pub network: String,
    pub security: String,
    pub tls_settings: Option<TlsSettings>,
    pub network_settings: Option<NetworkSettings>,
    pub tag: String,
}

/// VLESS protocol parser.
pub struct VlessParser;

impl UrlParser for VlessParser {
    type Raw = VlessRaw;

    fn prefixes(&self) -> &[&'static str] {
        &["vless://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<VlessRaw> {
        // Format: vless://uuid@host:port[/]?params#tag
        // Supports both IPv4 (host:port) and IPv6 ([ipv6]:port) formats
        let re =
            Regex::new(r"^vless://([^@]+)@(?:\[([^\]]+)\]|([^:]+)):(\d+)/?\?([^#]+)(?:#(.*))?$")?;
        let caps = re.captures(url).context("Invalid vless URL format")?;

        let id = caps.get(1).unwrap().as_str().to_string();
        // For IPv6, group 2 contains the address inside brackets
        // For IPv4/hostname, group 3 contains the address
        let host = caps
            .get(2)
            .map(|m| m.as_str().to_string())
            .or_else(|| caps.get(3).map(|m| m.as_str().to_string()))
            .context("Missing host in vless URL")?;
        let port: u16 = caps.get(4).unwrap().as_str().parse()?;
        let query = caps.get(5).unwrap().as_str();
        let tag = decode_tag(caps.get(6).map(|m| m.as_str()).unwrap_or(""), || {
            format!("vless-{}", idx)
        });

        // Parse query parameters
        let params = parse_query(query)?;

        let encryption = params
            .get("encryption")
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("none")
            .to_string();
        let flow = params
            .get("flow")
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let network = params
            .get("type")
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("tcp")
            .to_string();
        let security = params
            .get("security")
            .map(|s| s.as_str())
            .unwrap_or("none")
            .to_string();

        // Parse TLS/Reality settings
        let tls_settings = if security == "tls" || security == "reality" {
            Some(parse_tls_settings(&params, &security)?)
        } else {
            None
        };

        // Parse network settings
        let network_settings = parse_network_settings(&params, &network)?;

        Ok(VlessRaw {
            id,
            address: host,
            port,
            encryption,
            flow,
            network,
            security,
            tls_settings,
            network_settings,
            tag,
        })
    }

    fn to_server_config(raw: VlessRaw, idx: usize) -> Result<ServerConfig> {
        // Check if this is a WARP server
        let mut params = HashMap::new();
        if let Some(crate::parser::shared::NetworkSettings::WebSocket { path, host }) =
            &raw.network_settings
        {
            params.insert("path".to_string(), path.clone());
            params.insert("host".to_string(), host.clone());
        }
        let is_warp = check_is_warp(&raw.tag, &params);
        let clean_tag = sanitize_tag(
            &raw.tag,
            "vless",
            idx,
            is_warp,
            Some(&raw.address),
            Some(raw.port),
        );

        Ok(ServerConfig::Vless {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            id: raw.id,
            encryption: raw.encryption,
            flow: raw.flow,
            network: raw.network,
            security: raw.security,
            tls_settings: raw.tls_settings.map(Box::new),
            network_settings: raw.network_settings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless_with_slash_before_query() {
        let parser = VlessParser;
        let url = "vless://test-uuid@france-paris.hostinger.kcartik-vps.com:443/?type=ws&encryption=none&flow=&host=france-paris.hostinger.kcartik-vps.com&path=%2Fvless&security=tls&sni=france-paris.hostinger.kcartik-vps.com#France";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vless {
                id,
                address,
                port,
                network,
                security,
                ..
            } => {
                assert_eq!(id, "test-uuid");
                assert_eq!(address, "france-paris.hostinger.kcartik-vps.com");
                assert_eq!(port, 443);
                assert_eq!(network, "ws");
                assert_eq!(security, "tls");
            }
            _ => panic!("Expected Vless config"),
        }
    }

    #[test]
    fn test_parse_vless_reality() {
        let parser = VlessParser;
        let url = "vless://test-uuid@152.53.50.126:22955?security=reality&encryption=none&pbk=9Mt_Y8J_qDb1khlieWnhDSAq-kGtLHw6aOKgkAzOMms&fp=chrome&type=grpc&serviceName=grpc&sni=one-piece.com&sid=6ba85179e30d4fc2#Austria";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vless {
                security,
                tls_settings,
                ..
            } => {
                assert_eq!(security, "reality");
                assert!(tls_settings.is_some());
                let tls = tls_settings.unwrap();
                assert_eq!(
                    tls.public_key,
                    Some("9Mt_Y8J_qDb1khlieWnhDSAq-kGtLHw6aOKgkAzOMms".to_string())
                );
                assert_eq!(tls.short_id, Some("6ba85179e30d4fc2".to_string()));
            }
            _ => panic!("Expected Vless config"),
        }
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = VlessParser;
        assert!(parser.prefixes().contains(&"vless://"));
    }

    #[test]
    fn test_parse_vless_ipv6_mapped_ipv4() {
        let parser = VlessParser;
        let url = "vless://c060fdda-385d-aea1-3982-5a6c92876481@[::ffff:5585:f92b]:58387?security=none&encryption=none&host=arvancloud.ir&headerType=http&type=tcp";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vless {
                id, address, port, ..
            } => {
                assert_eq!(id, "c060fdda-385d-aea1-3982-5a6c92876481");
                assert_eq!(address, "::ffff:5585:f92b");
                assert_eq!(port, 58387);
            }
            _ => panic!("Expected Vless config"),
        }
    }

    #[test]
    fn test_parse_vless_ipv6_full() {
        let parser = VlessParser;
        let url = "vless://c060fdfd-1f7a-8986-1ea5-7d4bb5a04302@[::ffff:5eb8:071b]:49888?security=none&encryption=none&headerType=none&type=tcp";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vless {
                id, address, port, ..
            } => {
                assert_eq!(id, "c060fdfd-1f7a-8986-1ea5-7d4bb5a04302");
                assert_eq!(address, "::ffff:5eb8:071b");
                assert_eq!(port, 49888);
            }
            _ => panic!("Expected Vless config"),
        }
    }

    #[test]
    fn test_parse_vless_ipv6_with_tag() {
        let parser = VlessParser;
        let url = "vless://c060fdda-385d-aea1-3982-5a6c92876481@[::ffff:5585:f92b]:58387?security=none&encryption=none&host=arvancloud.ir&headerType=http&type=tcp#@Proxyiranip";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vless { tag, .. } => {
                // Tag is normalized by sanitize_tag (lowercase, special chars removed)
                assert!(tag.contains("proxyiranip"));
            }
            _ => panic!("Expected Vless config"),
        }
    }

    #[test]
    fn test_parse_vless_pure_ipv6() {
        let parser = VlessParser;
        let url = "vless://c3077f1d-3b94-4a83-aecb-f4e9beb4dc7e@[2001:19f0:7400:8c45:5400:04ff:feef:4ccb]:2083?security=none&encryption=none&host=speedtest.net&headerType=http&type=tcp";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vless {
                id, address, port, ..
            } => {
                assert_eq!(id, "c3077f1d-3b94-4a83-aecb-f4e9beb4dc7e");
                assert_eq!(address, "2001:19f0:7400:8c45:5400:04ff:feef:4ccb");
                assert_eq!(port, 2083);
            }
            _ => panic!("Expected Vless config"),
        }
    }

    #[test]
    fn test_parse_vless_reality_full() {
        let parser = VlessParser;
        let url = "vless://4fd2d5f6-d417-0bb8-9331-e20afde2fcd2@109.120.189.8:52006?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&fp=qq&sni=max.ru&pbk=4CH3o5zOMcFNMbnwXnkAg0FFepmsc0QzhahXkUzb1ik&sid=d8c6b58bcbb0c323#%5BVP1596%5D%E2%AD%90%20%F0%9F%87%AB%F0%9F%87%AE%20FIN%20%F0%9F%93%91%20%5BVK%5D";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vless {
                id,
                address,
                port,
                encryption,
                flow,
                network,
                security,
                tls_settings,
                tag,
                ..
            } => {
                assert_eq!(id, "4fd2d5f6-d417-0bb8-9331-e20afde2fcd2");
                assert_eq!(address, "109.120.189.8");
                assert_eq!(port, 52006);
                assert_eq!(encryption, "none");
                assert_eq!(flow, "xtls-rprx-vision");
                assert_eq!(network, "tcp");
                assert_eq!(security, "reality");

                assert!(tls_settings.is_some());
                let tls = tls_settings.unwrap();
                assert_eq!(tls.server_name, "max.ru");
                assert_eq!(tls.fingerprint, "qq");
                assert_eq!(
                    tls.public_key,
                    Some("4CH3o5zOMcFNMbnwXnkAg0FFepmsc0QzhahXkUzb1ik".to_string())
                );
                assert_eq!(tls.short_id, Some("d8c6b58bcbb0c323".to_string()));

                assert!(tag.contains("vp1596"));
                assert!(tag.contains("fin"));
            }
            _ => panic!("Expected Vless config"),
        }
    }
}
