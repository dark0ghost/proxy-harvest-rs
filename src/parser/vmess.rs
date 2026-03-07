//! VMess URL parser.
//!
//! Parses `vmess://` URLs (base64-encoded JSON) into VMess server configurations.

use anyhow::{Context, Result};

use crate::parser::shared::{
    decode_base64_flexible, sanitize_tag, NetworkSettings, ServerConfig, TlsSettings,
};
use crate::parser::UrlParser;

/// Raw VMess data parsed from URL.
pub struct VmessRaw {
    pub address: String,
    pub port: u16,
    pub id: String,
    pub alter_id: u16,
    pub security: String,
    pub network: String,
    pub tls: String,
    pub tls_settings: Option<TlsSettings>,
    pub network_settings: Option<NetworkSettings>,
    pub tag: String,
}

/// VMess protocol parser.
pub struct VmessParser;

impl UrlParser for VmessParser {
    type Raw = VmessRaw;

    fn prefixes(&self) -> &[&'static str] {
        &["vmess://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<VmessRaw> {
        // Format: vmess://base64(json)
        let encoded = url
            .strip_prefix("vmess://")
            .context("Invalid vmess URL format")?;

        let decoded = decode_base64_flexible(encoded)?;
        let json_str = String::from_utf8(decoded)?;

        let v: serde_json::Value = serde_json::from_str(&json_str)?;

        let address = v["add"]
            .as_str()
            .context("Missing 'add' field")?
            .to_string();

        let port: u16 = if let Some(p) = v["port"].as_u64() {
            p as u16
        } else if let Some(p) = v["port"].as_str() {
            p.parse()?
        } else {
            anyhow::bail!("Missing 'port' field")
        };

        let id = v["id"]
            .as_str()
            .context("Missing 'id' field")?
            .to_string();

        let alter_id: u16 = if let Some(a) = v["aid"].as_u64() {
            a as u16
        } else if let Some(a) = v["aid"].as_str() {
            a.parse().unwrap_or(0)
        } else {
            0
        };

        let security = v["scy"]
            .as_str()
            .or_else(|| v["type"].as_str())
            .unwrap_or("auto")
            .to_string();

        let network = v["net"]
            .as_str()
            .unwrap_or("tcp")
            .to_string();

        let tls = v["tls"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let tag = v["ps"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("vmess-{}", idx));

        // Parse TLS settings
        let tls_settings = if tls == "tls" {
            let server_name = v["sni"]
                .as_str()
                .or_else(|| v["host"].as_str())
                .unwrap_or("")
                .to_string();
            let alpn = v["alpn"]
                .as_str()
                .map(|s| s.split(',').map(|a| a.trim().to_string()).collect());

            Some(TlsSettings {
                server_name,
                fingerprint: "chrome".to_string(),
                alpn,
                allow_insecure: true,
                public_key: None,
                short_id: None,
                spider_x: None,
            })
        } else {
            None
        };

        // Parse network settings
        let network_settings = match network.as_str() {
            "ws" => {
                let path = v["path"]
                    .as_str()
                    .unwrap_or("/")
                    .to_string();
                let host = v["host"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                Some(NetworkSettings::WebSocket { path, host })
            }
            "grpc" => {
                let service_name = v["path"]
                    .as_str()
                    .or_else(|| v["serviceName"].as_str())
                    .unwrap_or("")
                    .to_string();
                Some(NetworkSettings::Grpc {
                    service_name,
                    authority: v["host"].as_str().unwrap_or("").to_string(),
                })
            }
            "tcp" => {
                let header_type = v["type"]
                    .as_str()
                    .unwrap_or("none")
                    .to_string();
                Some(NetworkSettings::Tcp { header_type })
            }
            _ => None,
        };

        Ok(VmessRaw {
            address,
            port,
            id,
            alter_id,
            security,
            network,
            tls,
            tls_settings,
            network_settings,
            tag,
        })
    }

    fn to_server_config(raw: VmessRaw, idx: usize) -> Result<ServerConfig> {
        let clean_tag = sanitize_tag(&raw.tag, "vmess", idx, false);

        Ok(ServerConfig::Vmess {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            id: raw.id,
            alter_id: raw.alter_id,
            security: raw.security,
            network: raw.network,
            tls: raw.tls,
            tls_settings: raw.tls_settings.map(Box::new),
            network_settings: raw.network_settings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    #[test]
    fn test_parse_vmess_basic() {
        // Create a valid vmess JSON and encode it
        let json = r#"{"add":"example.com","port":"443","id":"test-uuid","aid":"0","scy":"auto","net":"tcp","type":"none","tls":"tls","sni":"example.com","ps":"test-vmess"}"#;
        let encoded = BASE64_STANDARD.encode(json);
        let url = format!("vmess://{}", encoded);

        let parser = VmessParser;
        let result = parser.parse(&url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::Vmess { address, port, id, tag, .. } => {
                assert_eq!(address, "example.com");
                assert_eq!(port, 443);
                assert_eq!(id, "test-uuid");
                assert_eq!(tag, "test-vmess");
            }
            _ => panic!("Expected Vmess config"),
        }
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = VmessParser;
        assert!(parser.prefixes().contains(&"vmess://"));
    }
}
