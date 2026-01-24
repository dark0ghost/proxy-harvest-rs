use anyhow::Result;
use log::{info, warn};
use rayon::prelude::*;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use crate::parser::ServerConfig;

/// Check if a proxy server is accessible by attempting a TCP connection
pub fn check_server_availability(server: &ServerConfig, timeout_secs: u64) -> bool {
    let (address, port) = match server {
        ServerConfig::Shadowsocks { address, port, .. } => (address, *port),
        ServerConfig::Vless { address, port, .. } => (address, *port),
    };

    let target = format!("{}:{}", address, port);
    let timeout = Duration::from_secs(timeout_secs);

    match target.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(_) => {
                        info!("✓ Server {} is available", server.tag());
                        true
                    }
                    Err(e) => {
                        warn!("✗ Server {} is unavailable: {}", server.tag(), e);
                        false
                    }
                }
            } else {
                warn!("✗ Server {} - no addresses resolved", server.tag());
                false
            }
        }
        Err(e) => {
            warn!("✗ Server {} - DNS resolution failed: {}", server.tag(), e);
            false
        }
    }
}

/// Filter servers by availability using parallel processing
pub fn filter_available_servers(
    servers: Vec<ServerConfig>,
    timeout_secs: u64,
) -> Result<Vec<ServerConfig>> {
    let total = servers.len();
    info!("Checking availability of {} servers (timeout: {}s) using parallel processing...", total, timeout_secs);

    let available: Vec<ServerConfig> = servers
        .into_par_iter()
        .filter(|server| check_server_availability(server, timeout_secs))
        .collect();

    let available_count = available.len();
    let unavailable_count = total - available_count;

    info!("Availability check complete:");
    info!("  ✓ Available: {}", available_count);
    info!("  ✗ Unavailable: {}", unavailable_count);

    if available.is_empty() {
        anyhow::bail!("No available servers found!");
    }

    Ok(available)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ServerConfig;

    #[test]
    fn test_check_server_availability_invalid() {
        let server = ServerConfig::Shadowsocks {
            tag: "test".to_string(),
            address: "192.0.2.1".to_string(),
            port: 9999,
            method: "aes-256-gcm".to_string(),
            password: "test".to_string(),
        };

        let result = check_server_availability(&server, 1);
        assert!(!result);
    }

    #[test]
    fn test_filter_available_servers_empty() {
        let servers = vec![];
        let result = filter_available_servers(servers, 1);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No available servers"));
    }
}
