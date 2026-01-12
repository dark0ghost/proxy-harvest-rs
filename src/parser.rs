use anyhow::{Context, Result};
use base64::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use urlencoding::decode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol")]
pub enum ServerConfig {
    #[serde(rename = "shadowsocks")]
    Shadowsocks {
        tag: String,
        address: String,
        port: u16,
        method: String,
        password: String,
    },
    #[serde(rename = "vless")]
    Vless {
        tag: String,
        address: String,
        port: u16,
        id: String,
        encryption: String,
        flow: String,
        network: String,
        security: String,
        // TLS/Reality settings
        tls_settings: Option<TlsSettings>,
        // Network settings (ws, grpc, tcp)
        network_settings: Option<NetworkSettings>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    pub server_name: String,
    pub fingerprint: String,
    pub alpn: Option<Vec<String>>,
    pub allow_insecure: bool,
    // Reality specific
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NetworkSettings {
    #[serde(rename = "ws")]
    WebSocket { path: String, host: String },
    #[serde(rename = "grpc")]
    Grpc {
        service_name: String,
        authority: String,
    },
    #[serde(rename = "tcp")]
    Tcp { header_type: String },
}

impl ServerConfig {
    pub fn tag(&self) -> &str {
        match self {
            ServerConfig::Shadowsocks { tag, .. } => tag,
            ServerConfig::Vless { tag, .. } => tag,
        }
    }

    pub fn is_warp(&self) -> bool {
        self.tag().to_lowercase().contains("warp")
    }

    pub fn is_cloudflare(&self) -> bool {
        match self {
            ServerConfig::Vless { address, .. } => {
                let addr = address.to_lowercase();
                addr.starts_with("104.") || addr.contains("cloudflare") || addr.contains("cdn")
            }
            _ => false,
        }
    }
}

pub fn parse_servers(content: &str) -> Result<Vec<ServerConfig>> {
    let mut servers = Vec::new();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    for (idx, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match parse_server_url(line, idx) {
            Ok(server) => servers.push(server),
            Err(e) => {
                log::warn!("Failed to parse line {}: {} - Error: {}", idx + 1, line, e);
            }
        }
    }

    Ok(servers)
}

fn parse_server_url(url: &str, idx: usize) -> Result<ServerConfig> {
    if url.starts_with("ss://") {
        parse_shadowsocks(url, idx)
    } else if url.starts_with("vless://") {
        parse_vless(url, idx)
    } else {
        anyhow::bail!("Unsupported protocol: {}", url)
    }
}

fn parse_shadowsocks(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: ss://base64(method:password)@host:port#tag
    let re = Regex::new(r"^ss://([^@]+)@([^:]+):(\d+)(?:#(.*))?$")?;
    let caps = re.captures(url).context("Invalid shadowsocks URL format")?;

    let encoded = caps.get(1).unwrap().as_str();
    let host = caps.get(2).unwrap().as_str().to_string();
    let port: u16 = caps.get(3).unwrap().as_str().parse()?;
    let tag = caps
        .get(4)
        .map(|m| decode(m.as_str()).unwrap().to_string())
        .unwrap_or_else(|| format!("ss-{}", idx));

    // Decode base64
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .context("Failed to decode base64")?;
    let decoded_str = String::from_utf8(decoded)?;

    // Parse method:password
    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid shadowsocks credentials format");
    }

    let method = parts[0].to_string();
    let password = parts[1].to_string();

    // Generate a clean tag
    let clean_tag = sanitize_tag(&tag, "ss", idx, false);

    Ok(ServerConfig::Shadowsocks {
        tag: clean_tag,
        address: host,
        port,
        method,
        password,
    })
}

fn parse_vless(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: vless://uuid@host:port?params#tag
    let re = Regex::new(r"^vless://([^@]+)@([^:]+):(\d+)\?([^#]+)(?:#(.*))?$")?;
    let caps = re.captures(url).context("Invalid vless URL format")?;

    let id = caps.get(1).unwrap().as_str().to_string();
    let host = caps.get(2).unwrap().as_str().to_string();
    let port: u16 = caps.get(3).unwrap().as_str().parse()?;
    let query = caps.get(4).unwrap().as_str();
    let tag = caps
        .get(5)
        .map(|m| decode(m.as_str()).unwrap().to_string())
        .unwrap_or_else(|| format!("vless-{}", idx));

    // Parse query parameters
    let params = parse_query(query)?;

    let encryption = params
        .get("encryption")
        .map(|s| s.as_str())
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

    // Check if this is a WARP server based on path or tag
    let is_warp = check_is_warp(&tag, &params);
    let clean_tag = sanitize_tag(&tag, "vless", idx, is_warp);

    Ok(ServerConfig::Vless {
        tag: clean_tag,
        address: host,
        port,
        id,
        encryption,
        flow,
        network,
        security,
        tls_settings,
        network_settings,
    })
}

fn parse_query(query: &str) -> Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_value = decode(value)?.to_string();
            params.insert(key.to_string(), decoded_value);
        }
    }
    Ok(params)
}

fn parse_tls_settings(params: &HashMap<String, String>, security: &str) -> Result<TlsSettings> {
    let server_name = params.get("sni").map(|s| s.to_string()).unwrap_or_default();
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
        params
            .get("spx")
            .or_else(|| params.get("path"))
            .map(|s| s.to_string())
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

fn parse_network_settings(
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

fn check_is_warp(tag: &str, params: &HashMap<String, String>) -> bool {
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

fn sanitize_tag(tag: &str, protocol: &str, idx: usize, is_warp: bool) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shadowsocks_basic() {
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#test-server";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Shadowsocks {
                tag,
                address,
                port,
                method,
                password,
            } => {
                assert_eq!(tag, "test-server");
                assert_eq!(address, "62.133.60.43");
                assert_eq!(port, 36456);
                assert_eq!(method, "chacha20-ietf-poly1305");
                assert_eq!(password, "TY29mbZbgplhc4vTT3xh3s");
            }
            _ => panic!("Expected Shadowsocks config"),
        }
    }

    #[test]
    fn test_parse_shadowsocks_with_emoji_tag() {
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#%F0%9F%87%A9%F0%9F%87%AA%20PORT";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.tag(), "port");
    }

    #[test]
    fn test_parse_vless_reality() {
        let url = "vless://test-uuid@example.com:443?encryption=none&security=reality&sni=download.cdn.yandex.net&fp=firefox&pbk=testkey&sid=a8f264ef&type=grpc&serviceName=grpc#test-vless";
        let result = parse_server_url(url, 5);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Vless {
                tag,
                address,
                port,
                id,
                security,
                network,
                tls_settings,
                ..
            } => {
                // Tag gets sanitized to lowercase
                assert_eq!(tag, "test-vless");
                assert_eq!(address, "example.com");
                assert_eq!(port, 443);
                assert_eq!(id, "test-uuid");
                assert_eq!(security, "reality");
                assert_eq!(network, "grpc");

                let tls = tls_settings.unwrap();
                assert_eq!(tls.server_name, "download.cdn.yandex.net");
                assert_eq!(tls.fingerprint, "firefox");
                assert_eq!(tls.public_key, Some("testkey".to_string()));
                assert_eq!(tls.short_id, Some("a8f264ef".to_string()));
            }
            _ => panic!("Expected VLESS config"),
        }
    }

    #[test]
    fn test_parse_vless_tls_websocket() {
        let url = "vless://test-uuid@example.com:443?encryption=none&security=tls&sni=example.com&fp=chrome&type=ws&path=/path&host=example.com#ws-test";
        let result = parse_server_url(url, 10);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Vless {
                network,
                security,
                network_settings,
                ..
            } => {
                assert_eq!(security, "tls");
                assert_eq!(network, "ws");

                match network_settings.unwrap() {
                    NetworkSettings::WebSocket { path, host } => {
                        assert_eq!(path, "/path");
                        assert_eq!(host, "example.com");
                    }
                    _ => panic!("Expected WebSocket settings"),
                }
            }
            _ => panic!("Expected VLESS config"),
        }
    }

    #[test]
    fn test_warp_detection_from_path() {
        let url = "vless://test-uuid@example.com:443?encryption=none&security=tls&type=ws&path=/warp-test&host=example.com#normal-tag";
        let result = parse_server_url(url, 20);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert!(server.tag().starts_with("warp-"));
        assert!(server.is_warp());
    }

    #[test]
    fn test_cloudflare_warp_detection() {
        let url = "vless://test-uuid@example.com:443?encryption=none&security=tls&type=ws&path=/cloudflare/warp&host=example.com#test";
        let result = parse_server_url(url, 25);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert!(server.tag().starts_with("warp-"));
    }

    #[test]
    fn test_warp_detection_from_tag() {
        let url = "vless://test-uuid@example.com:443?encryption=none&security=tls&type=ws&path=/test&host=example.com#warp-server";
        let result = parse_server_url(url, 30);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert!(server.is_warp());
        // Tag already has warp prefix, should not add another
        assert_eq!(server.tag(), "warp-server");
    }

    #[test]
    fn test_cloudflare_detection() {
        let url = "vless://test-uuid@104.18.82.55:443?encryption=none&security=tls&type=ws&path=/test&host=example.com#cf-test";
        let result = parse_server_url(url, 35);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert!(server.is_cloudflare());
    }

    #[test]
    fn test_parse_servers_multiple() {
        let content = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#server1
vless://test-uuid@example.com:443?encryption=none&security=tls&type=tcp#server2
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@1.2.3.4:1234#server3
"#;

        let result = parse_servers(content);
        assert!(result.is_ok());

        let servers = result.unwrap();
        assert_eq!(servers.len(), 3);

        // Check tags (they get sanitized to lowercase)
        assert!(servers[0].tag().contains("server1"));
        assert!(servers[1].tag().contains("server2"));
        assert!(servers[2].tag().contains("server3"));
    }

    #[test]
    fn test_parse_servers_with_errors() {
        let content = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#valid
invalid-url-here
vless://test-uuid@example.com:443?encryption=none#another-valid
"#;

        let result = parse_servers(content);
        assert!(result.is_ok());

        let servers = result.unwrap();
        assert_eq!(servers.len(), 2); // Only valid ones
    }

    #[test]
    fn test_sanitize_tag_removes_special_chars() {
        assert_eq!(sanitize_tag("test@#$%server", "ss", 0, false), "testserver");
        // Cyrillic characters are allowed by is_alphanumeric
        assert_eq!(sanitize_tag("тест сервер", "ss", 0, false), "тест-сервер");
        assert_eq!(
            sanitize_tag("Test Server 123", "ss", 0, false),
            "test-server-123"
        );
        assert_eq!(sanitize_tag("@#$%", "ss", 5, false), "ss-5"); // Only special chars, should fallback
    }

    #[test]
    fn test_sanitize_tag_warp_prefix() {
        assert_eq!(sanitize_tag("server", "vless", 0, true), "warp-server");
        assert_eq!(sanitize_tag("warp-server", "vless", 0, true), "warp-server");
    }

    #[test]
    fn test_check_is_warp() {
        let mut params = HashMap::new();

        // Test tag detection
        assert!(check_is_warp("warp-server", &params));
        assert!(check_is_warp("WARP-Server", &params));

        // Test path detection
        params.insert("path".to_string(), "/warp/test".to_string());
        assert!(check_is_warp("normal", &params));

        params.insert("path".to_string(), "/cloudflare/test".to_string());
        assert!(check_is_warp("normal", &params));

        // Test host detection
        params.clear();
        params.insert("host".to_string(), "warp.example.com".to_string());
        assert!(check_is_warp("normal", &params));

        // Test negative
        params.clear();
        params.insert("path".to_string(), "/normal/test".to_string());
        assert!(!check_is_warp("normal", &params));
    }

    #[test]
    fn test_empty_tag_fallback() {
        let url =
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456";
        let result = parse_server_url(url, 5);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.tag(), "ss-5");
    }
}
