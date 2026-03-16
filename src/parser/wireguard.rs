//! WireGuard URL parser.
//!
//! Parses `wireguard://` URLs into WireGuard server configurations.
//!
//! # Format
//!
//! ```text
//! wireguard://privatekey@server:port?address=172.16.0.2%2F32&publickey=serverpublickey&presharedkey=psk&mtu=1420&reserved=0,0,0#Remarks
//! ```

use anyhow::{Context, Result};
use std::collections::HashMap;

use crate::parser::shared::{decode_tag, parse_query, sanitize_tag, ServerConfig};
use crate::parser::UrlParser;

/// Raw WireGuard data parsed from URL.
pub struct WireGuardRaw {
    pub secret_key: String,
    pub address: String,
    pub port: u16,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub local_address: String,
    pub reserved: Option<String>,
    pub mtu: u16,
    pub tag: String,
}

/// WireGuard protocol parser.
pub struct WireGuardParser;

impl UrlParser for WireGuardParser {
    type Raw = WireGuardRaw;

    fn prefixes(&self) -> &[&'static str] {
        &["wireguard://"]
    }

    fn parse_raw(&self, url: &str, idx: usize) -> Result<WireGuardRaw> {
        // Format: wireguard://privatekey@host:port?params#tag
        let url_clean = url
            .strip_prefix("wireguard://")
            .context("Invalid wireguard URL format")?;

        // Split by # to get tag
        let (url_part, tag) = if let Some(hash_pos) = url_clean.find('#') {
            let (url_p, tag_p) = url_clean.split_at(hash_pos);
            (
                url_p,
                decode_tag(&tag_p[1..], || format!("wireguard-{}", idx)),
            )
        } else {
            (url_clean, format!("wireguard-{}", idx))
        };

        // Split by ? to get params
        let (host_part, query) = if let Some(q_pos) = url_part.find('?') {
            let (host_p, query_p) = url_part.split_at(q_pos);
            (host_p, &query_p[1..]) // skip ?
        } else {
            (url_part, "")
        };

        // Parse privatekey@host:port
        let (secret_key, host_port) = if let Some(at_pos) = host_part.find('@') {
            let (key, hp) = host_part.split_at(at_pos);
            (
                decode_tag(key, String::new),
                &hp[1..], // skip @
            )
        } else {
            anyhow::bail!("Missing private key in wireguard URL");
        };

        // Parse host:port
        let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
            let (h, p) = host_port.split_at(colon_pos);
            (h.to_string(), p[1..].parse()?)
        } else {
            (host_port.to_string(), 51820) // Default WireGuard port
        };

        // Parse query parameters
        let params = if !query.is_empty() {
            parse_query(query)?
        } else {
            HashMap::new()
        };

        // Extract required parameters
        let local_address = params
            .get("address")
            .map(|s| s.as_str())
            .unwrap_or("172.16.0.2/32")
            .to_string();

        let public_key = params
            .get("publickey")
            .map(|s| s.as_str())
            .context("Missing publickey in wireguard URL")?
            .to_string();

        let pre_shared_key = params.get("presharedkey").map(|s| s.to_string());

        let mtu: u16 = params
            .get("mtu")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1420);

        let reserved = params.get("reserved").map(|s| s.to_string());

        Ok(WireGuardRaw {
            secret_key,
            address: host,
            port,
            public_key,
            pre_shared_key,
            local_address,
            reserved,
            mtu,
            tag,
        })
    }

    fn to_server_config(raw: WireGuardRaw, idx: usize) -> Result<ServerConfig> {
        let clean_tag = sanitize_tag(
            &raw.tag,
            "wireguard",
            idx,
            false,
            Some(&raw.address),
            Some(raw.port),
        );

        Ok(ServerConfig::WireGuard {
            tag: clean_tag,
            address: raw.address,
            port: raw.port,
            secret_key: raw.secret_key,
            public_key: raw.public_key,
            pre_shared_key: raw.pre_shared_key,
            local_address: raw.local_address,
            reserved: raw.reserved,
            mtu: raw.mtu,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wireguard_basic() {
        let parser = WireGuardParser;
        let url = "wireguard://uI8D3K4J5L6M7N8O9P0Q1R2S3T4U5V6W7X8Y9Z0A1B2C3D4E5F6G7H8I9J0K1L2M@example.com:51820?address=172.16.0.2%2F32&publickey=serverpublickey&mtu=1420#Test-WireGuard";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::WireGuard {
                address,
                port,
                public_key,
                local_address,
                mtu,
                tag,
                ..
            } => {
                assert_eq!(address, "example.com");
                assert_eq!(port, 51820);
                assert_eq!(public_key, "serverpublickey");
                assert_eq!(local_address, "172.16.0.2/32");
                assert_eq!(mtu, 1420);
                assert!(tag.contains("wireguard"));
            }
            _ => panic!("Expected WireGuard config"),
        }
    }

    #[test]
    fn test_parse_wireguard_with_psk() {
        let parser = WireGuardParser;
        let url = "wireguard://privatekey@example.com:51820?address=10.0.0.2%2F32&publickey=pubkey&presharedkey=psk123&mtu=1400&reserved=0,0,0#Test";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::WireGuard {
                pre_shared_key,
                reserved,
                ..
            } => {
                assert_eq!(pre_shared_key, Some("psk123".to_string()));
                assert_eq!(reserved, Some("0,0,0".to_string()));
            }
            _ => panic!("Expected WireGuard config"),
        }
    }

    #[test]
    fn test_parse_wireguard_default_port() {
        let parser = WireGuardParser;
        let url =
            "wireguard://privatekey@example.com?address=10.0.0.2%2F32&publickey=pubkey&mtu=1420";
        let result = parser.parse(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        match server {
            ServerConfig::WireGuard { port, .. } => {
                assert_eq!(port, 51820); // Default port
            }
            _ => panic!("Expected WireGuard config"),
        }
    }

    #[test]
    fn test_parser_prefixes() {
        let parser = WireGuardParser;
        assert!(parser.prefixes().contains(&"wireguard://"));
    }
}
