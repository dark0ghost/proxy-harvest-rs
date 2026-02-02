use anyhow::{Result, Context};
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
        tls_settings: Option<Box<TlsSettings>>,
        // Network settings (ws, grpc, tcp)
        network_settings: Option<NetworkSettings>,
    },
    #[serde(rename = "vmess")]
    Vmess {
        tag: String,
        address: String,
        port: u16,
        id: String,
        alter_id: u16,
        security: String,
        network: String,
        tls: String,
        tls_settings: Option<Box<TlsSettings>>,
        network_settings: Option<NetworkSettings>,
    },
    #[serde(rename = "trojan")]
    Trojan {
        tag: String,
        address: String,
        port: u16,
        password: String,
        network: String,
        security: String,
        sni: Option<String>,
        tls_settings: Option<Box<TlsSettings>>,
        network_settings: Option<NetworkSettings>,
    },
    #[serde(rename = "hysteria2")]
    Hysteria2 {
        tag: String,
        address: String,
        port: u16,
        password: String,
        obfs: Option<String>,
        obfs_password: Option<String>,
        sni: Option<String>,
        insecure: bool,
        pinned_sha256: Option<String>,
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
            ServerConfig::Vmess { tag, .. } => tag,
            ServerConfig::Trojan { tag, .. } => tag,
            ServerConfig::Hysteria2 { tag, .. } => tag,
        }
    }

    pub fn is_warp(&self) -> bool {
        self.tag().to_lowercase().contains("warp")
    }

    pub fn is_cloudflare(&self) -> bool {
        match self {
            ServerConfig::Vless { address, .. }
            | ServerConfig::Vmess { address, .. }
            | ServerConfig::Trojan { address, .. } => {
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
    } else if url.starts_with("vmess://") {
        parse_vmess(url, idx)
    } else if url.starts_with("trojan://") {
        parse_trojan(url, idx)
    } else if url.starts_with("hysteria2://") || url.starts_with("hy2://") {
        parse_hysteria2(url, idx)
    } else {
        anyhow::bail!("Unsupported protocol: {}", url)
    }
}

fn parse_shadowsocks(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: ss://base64(method:password)@host:port[?params][#tag]
    // Some URLs have query parameters or just ? before #
    let re = Regex::new(r"^ss://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$")?;
    let caps = re
        .captures(url)
        .context("Invalid shadowsocks URL format")?;

    let encoded = caps.get(1).unwrap().as_str();
    let host = caps.get(2).unwrap().as_str().to_string();
    let port: u16 = caps.get(3).unwrap().as_str().parse()?;
    // caps.get(4) contains query params (ignored for shadowsocks)
    let tag = caps
        .get(5)
        .map(|m| decode(m.as_str()).unwrap().to_string())
        .unwrap_or_else(|| format!("ss-{}", idx));

    // Try to decode URL encoding first (handles %2B -> + etc), then fall back to raw if that fails
    let base64_str = decode(encoded)
        .map(|s| s.to_string())
        .unwrap_or_else(|_| encoded.to_string());

    // Decode base64 - try standard first, if it fails try URL-safe variant
    let decoded = BASE64_STANDARD
        .decode(base64_str.as_bytes())
        .or_else(|_| BASE64_URL_SAFE.decode(base64_str.as_bytes()))
        .or_else(|_| BASE64_STANDARD_NO_PAD.decode(base64_str.as_bytes()))
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(base64_str.as_bytes()))
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
    // Format: vless://uuid@host:port[/]?params#tag
    // Some URLs have /? instead of just ?
    let re = Regex::new(r"^vless://([^@]+)@([^:]+):(\d+)/?\?([^#]+)(?:#(.*))?$")?;
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
        Some(Box::new(parse_tls_settings(&params, &security)?))
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
    let server_name = params
        .get("sni")
        .map(|s| s.to_string())
        .unwrap_or_default();
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
        params.get("spx").or_else(|| params.get("path")).map(|s| s.to_string())
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

fn parse_vmess(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: vmess://base64(json)
    let encoded = url.strip_prefix("vmess://")
        .context("Invalid vmess URL format")?;

    let decoded = BASE64_STANDARD
        .decode(encoded)
        .context("Failed to decode vmess base64")?;
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

        Some(Box::new(TlsSettings {
            server_name,
            fingerprint: "chrome".to_string(),
            alpn,
            allow_insecure: true,
            public_key: None,
            short_id: None,
            spider_x: None,
        }))
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

    let clean_tag = sanitize_tag(&tag, "vmess", idx, false);

    Ok(ServerConfig::Vmess {
        tag: clean_tag,
        address,
        port,
        id,
        alter_id,
        security,
        network,
        tls,
        tls_settings,
        network_settings,
    })
}

fn parse_trojan(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: trojan://password@host:port[/]?params#tag
    // Some URLs have /? instead of just ?
    let re = Regex::new(r"^trojan://([^@]+)@([^:]+):(\d+)/?\??([^#]*)(?:#(.*))?$")?;
    let caps = re.captures(url).context("Invalid trojan URL format")?;

    let password = decode(caps.get(1).unwrap().as_str())?.to_string();
    let host = caps.get(2).unwrap().as_str().to_string();
    let port: u16 = caps.get(3).unwrap().as_str().parse()?;
    let query = caps.get(4).map(|m| m.as_str()).unwrap_or("");
    let tag = caps
        .get(5)
        .map(|m| decode(m.as_str()).unwrap().to_string())
        .unwrap_or_else(|| format!("trojan-{}", idx));

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
        Some(Box::new(parse_tls_settings(&params, &security)?))
    } else {
        None
    };

    // Parse network settings
    let network_settings = parse_network_settings(&params, &network)?;

    let clean_tag = sanitize_tag(&tag, "trojan", idx, false);

    Ok(ServerConfig::Trojan {
        tag: clean_tag,
        address: host,
        port,
        password,
        network,
        security,
        sni,
        tls_settings,
        network_settings,
    })
}

fn parse_hysteria2(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: hysteria2://[auth@]hostname[:port][/]?params#tag or hy2://...
    let url_clean = url
        .strip_prefix("hysteria2://")
        .or_else(|| url.strip_prefix("hy2://"))
        .context("Invalid hysteria2 URL format")?;

    // Split by # to get tag
    let (url_part, tag) = if let Some(hash_pos) = url_clean.find('#') {
        let (url_p, tag_p) = url_clean.split_at(hash_pos);
        (url_p, decode(&tag_p[1..])?.to_string())
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

        (decode(auth)?.to_string(), host, port)
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

    let clean_tag = sanitize_tag(&tag, "hysteria2", idx, false);

    Ok(ServerConfig::Hysteria2 {
        tag: clean_tag,
        address: host,
        port,
        password,
        obfs,
        obfs_password,
        sni,
        insecure,
        pinned_sha256,
    })
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
            ServerConfig::Shadowsocks { tag, address, port, method, password } => {
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
    fn test_parse_shadowsocks_with_question_mark() {
        // Some shadowsocks URLs have ? before #
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp5TUNydnZrMUxUa2JUZ0N6elM4MHZK@104.192.227.162:443?#%F0%9F%87%BA%F0%9F%87%B8%20US%20%7C%20%F0%9F%94%92%20SS%20%7C%20%40STR_BYPASS%20%5B19%5D";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Shadowsocks { tag, address, port, method, password } => {
                assert!(tag.contains("us") || tag.contains("ss") || tag.contains("str"));
                assert_eq!(address, "104.192.227.162");
                assert_eq!(port, 443);
                assert_eq!(method, "chacha20-ietf-poly1305");
                assert_eq!(password, "yMCrvvk1LTkbTgCzzS80vJ");
            }
            _ => panic!("Expected Shadowsocks config"),
        }
    }

    #[test]
    fn test_parse_shadowsocks_url_encoded() {
        // Base64 string is URL-encoded (+ becomes %2B, etc)
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpBUmd2R1p5d0ErZ2FjZ0dWMjZCdm11MDUrd1ptUlcvaitBZFUrWjhCdDQ0PQ@176.123.1.175:990?#Moldova";
        let result = parse_server_url(url, 0);

        if let Err(ref e) = result {
            println!("Parse error: {}", e);
        }
        assert!(result.is_ok(), "Failed to parse: {:?}", result);

        let server = result.unwrap();

        match server {
            ServerConfig::Shadowsocks { address, port, method, password, .. } => {
                assert_eq!(address, "176.123.1.175");
                assert_eq!(port, 990);
                assert_eq!(method, "chacha20-ietf-poly1305");
                println!("Password: {}", password);
            }
            _ => panic!("Expected Shadowsocks config"),
        }
    }

    #[test]
    fn test_parse_shadowsocks_with_query_params() {
        // Shadowsocks URL with query parameters (e.g., prefix)
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpvWklvQTY5UTh5aGNRVjhrYTNQYTNB@193.29.139.235:8080?prefix=%16%03%01%00%C2%A8%01%01#Netherlands";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Shadowsocks { address, port, method, password, .. } => {
                assert_eq!(address, "193.29.139.235");
                assert_eq!(port, 8080);
                assert_eq!(method, "chacha20-ietf-poly1305");
                assert_eq!(password, "oZIoA69Q8yhcQV8ka3Pa3A");
            }
            _ => panic!("Expected Shadowsocks config"),
        }
    }

    #[test]
    fn test_parse_vless_with_slash_before_query() {
        // Some VLESS URLs have /? instead of ?
        let url = "vless://test-uuid@france-paris.hostinger.kcartik-vps.com:443/?type=ws&encryption=none&flow=&host=france-paris.hostinger.kcartik-vps.com&path=%2Fvless&security=tls&sni=france-paris.hostinger.kcartik-vps.com#France";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Vless { address, port, network, security, .. } => {
                assert_eq!(address, "france-paris.hostinger.kcartik-vps.com");
                assert_eq!(port, 443);
                assert_eq!(network, "ws");
                assert_eq!(security, "tls");
            }
            _ => panic!("Expected VLESS config"),
        }
    }


    #[test]
    fn test_parse_vless_reality() {
        let url = "vless://test-uuid@example.com:443?encryption=none&security=reality&sni=download.cdn.yandex.net&fp=firefox&pbk=testkey&sid=a8f264ef&type=grpc&serviceName=grpc#test-vless";
        let result = parse_server_url(url, 5);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Vless { tag, address, port, id, security, network, tls_settings, .. } => {
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
            ServerConfig::Vless { network, security, network_settings, .. } => {
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
        assert_eq!(sanitize_tag("Test Server 123", "ss", 0, false), "test-server-123");
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
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456";
        let result = parse_server_url(url, 5);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.tag(), "ss-5");
    }

    #[test]
    fn test_parse_vless_empty_security_ws() {
        let url = "vless://test-uuid-123@151.101.3.8:80?path=%2F---%40MiTiVPN%2F---%40MiTiVPN%2F---%40MiTiVPN%2F---%40MiTiVPN%2F---%40MiTiVPN&security=&encryption=none&host=mitivpn.global.ssl.fastly.net&type=ws#%F0%9F%87%A9%F0%9F%87%AA%20Germany%2C%20Dreieich%20%5BBL%5D";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Vless {
                tag,
                address,
                port,
                id,
                encryption,
                security,
                network,
                network_settings,
                ..
            } => {
                assert_eq!(address, "151.101.3.8");
                assert_eq!(port, 80);
                assert_eq!(id, "test-uuid-123");
                assert_eq!(encryption, "none");
                assert_eq!(security, ""); // Empty security parameter should remain empty
                assert_eq!(network, "ws");

                match network_settings.unwrap() {
                    NetworkSettings::WebSocket { path, host } => {
                        assert_eq!(path, "/---@MiTiVPN/---@MiTiVPN/---@MiTiVPN/---@MiTiVPN/---@MiTiVPN");
                        assert_eq!(host, "mitivpn.global.ssl.fastly.net");
                    }
                    _ => panic!("Expected WebSocket settings"),
                }

                assert!(tag.contains("germany") || tag.contains("dreieich"));
            }
            _ => panic!("Expected VLESS config"),
        }
    }

    #[test]
    fn test_parse_vmess_basic() {
        // vmess://base64({"add":"example.com","aid":"0","host":"","id":"test-uuid-456","net":"tcp","path":"","port":"443","ps":"vmess-test","scy":"none","type":"none","v":"2"})
        let json_data = r#"{"add":"example.com","aid":"0","host":"","id":"test-uuid-456","net":"tcp","path":"","port":"443","ps":"vmess-test","scy":"none","type":"none","v":"2"}"#;
        let encoded = BASE64_STANDARD.encode(json_data);
        let url = format!("vmess://{}", encoded);

        let result = parse_server_url(&url, 0);
        assert!(result.is_ok());

        let server = result.unwrap();
        match server {
            ServerConfig::Vmess { tag, address, port, id, alter_id, security, network, tls, .. } => {
                assert_eq!(tag, "vmess-test");
                assert_eq!(address, "example.com");
                assert_eq!(port, 443);
                assert_eq!(id, "test-uuid-456");
                assert_eq!(alter_id, 0);
                assert_eq!(security, "none");
                assert_eq!(network, "tcp");
                assert_eq!(tls, "");
            }
            _ => panic!("Expected VMess config"),
        }
    }

    #[test]
    fn test_parse_vmess_with_websocket() {
        let json_data = r#"{"add":"ws.example.com","aid":"0","host":"ws.example.com","id":"test-uuid-789","net":"ws","path":"/vmess","port":"8443","ps":"vmess-ws","tls":"tls","type":"none","v":"2"}"#;
        let encoded = BASE64_STANDARD.encode(json_data);
        let url = format!("vmess://{}", encoded);

        let result = parse_server_url(&url, 0);
        assert!(result.is_ok());

        let server = result.unwrap();
        match server {
            ServerConfig::Vmess { network, tls, network_settings, .. } => {
                assert_eq!(network, "ws");
                assert_eq!(tls, "tls");

                match network_settings.unwrap() {
                    NetworkSettings::WebSocket { path, host } => {
                        assert_eq!(path, "/vmess");
                        assert_eq!(host, "ws.example.com");
                    }
                    _ => panic!("Expected WebSocket settings"),
                }
            }
            _ => panic!("Expected VMess config"),
        }
    }

    #[test]
    fn test_parse_trojan_basic() {
        let url = "trojan://mypassword@trojan.example.com:443#trojan-test";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Trojan { tag, address, port, password, network, security, .. } => {
                assert_eq!(tag, "trojan-test");
                assert_eq!(address, "trojan.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "mypassword");
                assert_eq!(network, "tcp");
                assert_eq!(security, "tls");
            }
            _ => panic!("Expected Trojan config"),
        }
    }

    #[test]
    fn test_parse_trojan_with_params() {
        let url = "trojan://password123@example.com:8443?type=ws&path=/trojan&host=cdn.example.com&sni=example.com#trojan-ws";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Trojan { network, sni, network_settings, .. } => {
                assert_eq!(network, "ws");
                assert_eq!(sni, Some("example.com".to_string()));

                match network_settings.unwrap() {
                    NetworkSettings::WebSocket { path, host } => {
                        assert_eq!(path, "/trojan");
                        assert_eq!(host, "cdn.example.com");
                    }
                    _ => panic!("Expected WebSocket settings"),
                }
            }
            _ => panic!("Expected Trojan config"),
        }
    }

    #[test]
    fn test_parse_trojan_with_slash_before_query() {
        // Some Trojan URLs have /? instead of ?
        let url = "trojan://xtA6WF92Itmhm9jfvXUH1MDVL@185.235.137.77:443/?type=ws&host=free-de-3.undef.network&path=%2Ff2fc2a1f&security=tls&sni=free-de-3.undef.network#Germany";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Trojan { address, port, password, network, security, .. } => {
                assert_eq!(address, "185.235.137.77");
                assert_eq!(port, 443);
                assert_eq!(password, "xtA6WF92Itmhm9jfvXUH1MDVL");
                assert_eq!(network, "ws");
                assert_eq!(security, "tls");
            }
            _ => panic!("Expected Trojan config"),
        }
    }

    #[test]
    fn test_parse_trojan_with_special_chars_in_password() {
        // Password contains dots and equals signs
        let url = "trojan://iCfh96DEJn3=QRbzF.Tdl@212.192.214.46:18069/?type=tcp&security=tls&sni=www.vk.com&allowInsecure=1#UK";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Trojan { password, address, port, .. } => {
                assert_eq!(password, "iCfh96DEJn3=QRbzF.Tdl");
                assert_eq!(address, "212.192.214.46");
                assert_eq!(port, 18069);
            }
            _ => panic!("Expected Trojan config"),
        }
    }


    #[test]
    fn test_parse_hysteria2_basic() {
        let url = "hysteria2://myauth@hy2.example.com:443#hy2-test";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Hysteria2 { tag, address, port, password, .. } => {
                assert_eq!(tag, "hy2-test");
                assert_eq!(address, "hy2.example.com");
                assert_eq!(port, 443);
                assert_eq!(password, "myauth");
            }
            _ => panic!("Expected Hysteria2 config"),
        }
    }

    #[test]
    fn test_parse_hysteria2_with_params() {
        let url = "hysteria2://auth123@example.com:8443?obfs=salamander&obfs-password=obfspass&sni=example.com&insecure=1#hy2-obfs";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Hysteria2 { obfs, obfs_password, sni, insecure, .. } => {
                assert_eq!(obfs, Some("salamander".to_string()));
                assert_eq!(obfs_password, Some("obfspass".to_string()));
                assert_eq!(sni, Some("example.com".to_string()));
                assert_eq!(insecure, true);
            }
            _ => panic!("Expected Hysteria2 config"),
        }
    }

    #[test]
    fn test_parse_hysteria2_with_slash_before_query() {
        // Some Hysteria2 URLs have /? instead of ?
        let url = "hysteria2://test-uuid@107.167.18.123:1743/?insecure=1&sni=3d2c11f1-t52o00-tdw2ye-2gok.la.shifen.uk#US-LA";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Hysteria2 { address, port, password, sni, insecure, .. } => {
                assert_eq!(address, "107.167.18.123");
                assert_eq!(port, 1743);
                assert_eq!(password, "test-uuid");
                assert_eq!(sni, Some("3d2c11f1-t52o00-tdw2ye-2gok.la.shifen.uk".to_string()));
                assert_eq!(insecure, true);
            }
            _ => panic!("Expected Hysteria2 config"),
        }
    }

    #[test]
    fn test_parse_hysteria2_with_email_password() {
        // Password can be an email address
        let url = "hysteria2://user@domain.com@107.167.18.123:1743/?sni=c37b0be5-t3kyo0-t3lvgh-2gok.la.shifen.uk#US";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();

        match server {
            ServerConfig::Hysteria2 { password, address, port, .. } => {
                assert_eq!(password, "user@domain.com");
                assert_eq!(address, "107.167.18.123");
                assert_eq!(port, 1743);
            }
            _ => panic!("Expected Hysteria2 config"),
        }
    }


    #[test]
    fn test_parse_hy2_alias() {
        let url = "hy2://password@example.com:443#hy2-alias";
        let result = parse_server_url(url, 0);

        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.tag(), "hy2-alias");
    }
}
