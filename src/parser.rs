use anyhow::{Context, Result};
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use base64::Engine;
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
        tls_settings: Box<Option<TlsSettings>>,
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
        // Network settings (ws, grpc, tcp)
        network_settings: Option<NetworkSettings>,
        // TLS settings
        tls_settings: Box<Option<TlsSettings>>,
        allow_insecure: bool,
    },
    #[serde(rename = "trojan")]
    Trojan {
        tag: String,
        address: String,
        port: u16,
        password: String,
        network: String,
        security: String,
        tls_settings: Box<Option<TlsSettings>>,
        network_settings: Option<NetworkSettings>,
        allow_insecure: bool,
    },
    #[serde(rename = "hysteria2")]
    Hysteria2 {
        tag: String,
        address: String,
        port: u16,
        password: String,
        server_name: String,
        allow_insecure: bool,
        obfs: Option<String>,
        obfs_password: Option<String>,
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

#[derive(Debug, Deserialize)]
struct VmessConfig {
    ps: String,
    add: String,
    port: String,
    id: String,
    aid: String,
    scy: String,
    net: String,
    #[serde(rename = "type")]
    type_field: Option<String>,
    #[serde(rename = "host")]
    host: Option<String>,
    path: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
    alpn: Option<String>,
    fp: Option<String>,
    insecure: Option<String>,
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
            ServerConfig::Vless { address, .. } | ServerConfig::Vmess { address, .. } | ServerConfig::Trojan { address, .. } | ServerConfig::Hysteria2 { address, .. } => {
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
    } else if url.starts_with("hysteria2://") {
        parse_hysteria2(url, idx)
    } else {
        anyhow::bail!("Unsupported protocol: {}", url)
    }
}

fn parse_shadowsocks(url: &str, idx: usize) -> Result<ServerConfig> {
    if !url.starts_with("ss://") {
        anyhow::bail!("Invalid shadowsocks URL format");
    }

    let url_part = url.trim_start_matches("ss://");

    // Find the first '@' that separates credentials from host:port
    let at_pos = url_part.find('@').context("Invalid shadowsocks URL format: missing @")?;
    let encoded_part = &url_part[..at_pos];
    let rest_part = &url_part[at_pos + 1..];

    // Split rest_part into host:port and optional query/tag
    let mut host_port_part = rest_part;
    let mut tag_part = "";

    if let Some(hash_pos) = rest_part.find('#') {
        tag_part = &rest_part[hash_pos + 1..];
        let before_hash = &rest_part[..hash_pos];
        if let Some(question_pos) = before_hash.find('?') {
            host_port_part = &before_hash[..question_pos];
        } else {
            host_port_part = before_hash;
        }
    } else if let Some(question_pos) = rest_part.find('?') {
        host_port_part = &rest_part[..question_pos];
    }

    // Parse host:port
    let parts: Vec<&str> = host_port_part.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid shadowsocks URL format: invalid host:port");
    }
    let host = parts[0].to_string();
    let port: u16 = parts[1].parse().context("Invalid port")?;

    // Get tag if exists
    let tag = if !tag_part.is_empty() {
        decode(tag_part).unwrap().to_string()
    } else {
        format!("ss-{}", idx)
    };

    // Decode base64
    let decoded = if encoded_part.contains('-') || encoded_part.contains('_') {
        BASE64_URL_SAFE_NO_PAD.decode(encoded_part)
    } else {
        // Handle padding for standard base64
        let padded = match encoded_part.len() % 4 {
            2 => format!("{}==", encoded_part),
            3 => format!("{}=", encoded_part),
            _ => encoded_part.to_string(),
        };
        BASE64_STANDARD.decode(padded)
    }.context("Failed to decode base64")?;

    let decoded_str = String::from_utf8(decoded)?;

    // Parse method:password
    let (method, password) = if decoded_str.contains(':') {
        let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid shadowsocks credentials format");
        }
        (parts[0].to_string(), parts[1].to_string())
    } else {
        anyhow::bail!("Invalid shadowsocks credentials format: missing colon");
    };

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
    let tls_settings = Box::new(if security == "tls" || security == "reality" {
        Some(parse_tls_settings(&params, &security)?)
    } else {
        None
    });

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

fn parse_vmess(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: vmess://base64(json)
    if !url.starts_with("vmess://") {
        anyhow::bail!("Invalid vmess URL format");
    }

    let base64_data = url.trim_start_matches("vmess://");
    if base64_data.is_empty() {
        anyhow::bail!("Empty vmess URL");
    }

    // Vmess may use URL-safe base64 or standard
    let decoded_data = if base64_data.contains('-') || base64_data.contains('_') {
        BASE64_URL_SAFE.decode(base64_data)
    } else {
        BASE64_STANDARD.decode(base64_data)
    }.context("Failed to decode vmess base64")?;

    let json_str = String::from_utf8(decoded_data)?;
    let config: VmessConfig = serde_json::from_str(&json_str)?;

    let tag = if !config.ps.is_empty() {
        decode(&config.ps).unwrap().to_string()
    } else {
        format!("vmess-{}", idx)
    };

    let port: u16 = config.port.parse().context("Invalid port in vmess config")?;
    let alter_id: u16 = config.aid.parse().context("Invalid alterId in vmess config")?;

    let network = config.net.to_lowercase();
    let security = config.scy.to_lowercase();

    // Parse network settings
    let network_settings = match network.as_str() {
        "ws" => {
            let path = config.path.unwrap_or_else(|| "/".to_string());
            let host = config.host.unwrap_or_default();
            Some(NetworkSettings::WebSocket { path, host })
        }
        "grpc" => {
            let service_name = config.path.unwrap_or_default();
            let authority = config.host.unwrap_or_default();
            Some(NetworkSettings::Grpc {
                service_name,
                authority,
            })
        }
        "tcp" => {
            let header_type = config.type_field.unwrap_or_else(|| "none".to_string());
            Some(NetworkSettings::Tcp { header_type })
        }
        _ => None,
    };

    // Parse TLS settings
    let is_tls = config.tls.as_ref().map(|s| s == "tls").unwrap_or(false);
    let allow_insecure = config.insecure.as_ref().map(|s| s == "1" || s == "true").unwrap_or(false);

    let tls_settings = Box::new(if is_tls {
        let server_name = config.sni.unwrap_or_default();
        let fingerprint = config.fp.unwrap_or_else(|| "chrome".to_string());
        let alpn = config.alpn.map(|a| {
            a.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        });

        Some(TlsSettings {
            server_name,
            fingerprint,
            alpn,
            allow_insecure,
            public_key: None, // Vmess не использует Reality
            short_id: None,
            spider_x: None,
        })
    } else {
        None
    });

    // Check if this is a WARP server
    let is_warp = check_is_warp(&tag, &HashMap::new()); // Vmess не имеет параметров в URL

    let clean_tag = sanitize_tag(&tag, "vmess", idx, is_warp);

    Ok(ServerConfig::Vmess {
        tag: clean_tag,
        address: config.add,
        port,
        id: config.id,
        alter_id,
        security,
        network,
        network_settings,
        tls_settings,
        allow_insecure,
    })
}

fn parse_trojan(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: trojan://password@host:port?params#tag
    let re = Regex::new(r"^trojan://([^@]+)@([^:]+):(\d+)\?([^#]+)(?:#(.*))?$")?;
    let caps = re.captures(url).context("Invalid trojan URL format")?;

    let password_encoded = caps.get(1).unwrap().as_str();
    let host = caps.get(2).unwrap().as_str().to_string();
    let port: u16 = caps.get(3).unwrap().as_str().parse()?;
    let query = caps.get(4).unwrap().as_str();
    let tag = caps
        .get(5)
        .map(|m| decode(m.as_str()).unwrap().to_string())
        .unwrap_or_else(|| format!("trojan-{}", idx));

    // URL-decode the password
    let password = decode(password_encoded)?.to_string();

    // Parse query parameters
    let params = parse_query(query)?;

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
    let allow_insecure = params
        .get("insecure")
        .or_else(|| params.get("allowInsecure"))
        .map(|s| s == "1" || s == "true")
        .unwrap_or(false);

    // Parse TLS settings
    let tls_settings = Box::new(if security == "tls" {
        let server_name = params.get("sni").map(|s| s.to_string()).unwrap_or_default();
        let fingerprint = params
            .get("fp")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "chrome".to_string());
        let alpn = params.get("alpn").map(|s| {
            s.split(',')
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .collect::<Vec<String>>()
        });

        Some(TlsSettings {
            server_name,
            fingerprint,
            alpn,
            allow_insecure,
            public_key: None,
            short_id: None,
            spider_x: None,
        })
    } else {
        None
    });

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
        tls_settings,
        network_settings,
        allow_insecure,
    })
}

fn parse_hysteria2(url: &str, idx: usize) -> Result<ServerConfig> {
    // Format: hysteria2://password@host:port?params#tag
    let re = Regex::new(r"^hysteria2://([^@]+)@([^:]+):(\d+)\?([^#]+)(?:#(.*))?$")?;
    let caps = match re.captures(url) {
        Some(caps) => caps,
        None => {
            // Try format without query parameters
            let re_simple = Regex::new(r"^hysteria2://([^@]+)@([^:]+):(\d+)(?:#(.*))?$")?;
            re_simple.captures(url).context("Invalid hysteria2 URL format")?
        }
    };

    let password_encoded = caps.get(1).unwrap().as_str();
    let host = caps.get(2).unwrap().as_str().to_string();
    let port: u16 = caps.get(3).unwrap().as_str().parse()?;
    let tag = if let Some(m) = caps.get(5) {
        decode(m.as_str()).unwrap().to_string()
    } else if let Some(m) = caps.get(4) {
        decode(m.as_str()).unwrap().to_string()
    } else {
        format!("hysteria2-{}", idx)
    };

    // URL-decode the password
    let password = decode(password_encoded)?.to_string();

    // Parse query parameters if they exist
    let mut server_name = "".to_string();
    let mut allow_insecure = false;
    let mut obfs = None;
    let mut obfs_password = None;

    if let Some(query) = caps.get(4) {
        let params = parse_query(query.as_str())?;
        server_name = params.get("sni").map(|s| s.to_string()).unwrap_or_default();
        allow_insecure = params
            .get("insecure")
            .or_else(|| params.get("allowInsecure"))
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        obfs = params.get("obfs").map(|s| s.to_string());
        obfs_password = params.get("obfs-password").map(|s| s.to_string());
    }

    let clean_tag = sanitize_tag(&tag, "hysteria2", idx, false);

    Ok(ServerConfig::Hysteria2 {
        tag: clean_tag,
        address: host,
        port,
        password,
        server_name,
        allow_insecure,
        obfs,
        obfs_password,
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
            .filter(|a| !a.is_empty())
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
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == ' ' || *c == '@' || *c == '|')
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