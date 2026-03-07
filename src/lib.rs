//! # Proxy Harvest RS
//!
//! A powerful Rust library and CLI tool for generating Xray configuration files from VPN server URLs.
//!
//! ## Features
//!
//! - Parse multiple VPN protocol URLs (vless, vmess, trojan, ss, ssr)
//! - Generate Xray-compatible configuration files
//! - Check proxy server availability before inclusion
//! - Parallel processing for performance
//! - Flexible routing configuration
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use proxy_harvest_rs::parser::parse_servers;
//! use proxy_harvest_rs::config::{outbound, routing};
//!
//! # fn main() -> anyhow::Result<()> {
//! // Parse server URLs from content
//! let content = "vless://uuid@host:port?security=tls#tag";
//! let servers = parse_servers(content)?;
//!
//! // Generate Xray configurations
//! let outbounds = outbound::generate_outbounds(&servers)?;
//! let routing = routing::generate_routing(&servers)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## CLI Usage
//!
//! Single URL:
//! ```bash
//! proxy-harvest-rs --url https://example.com/servers --output ./configs
//! ```
//!
//! Multiple URLs:
//! ```bash
//! proxy-harvest-rs --url https://example.com/servers1 --url https://example.com/servers2 --output ./configs
//! ```
//!
//! With availability check:
//! ```bash
//! proxy-harvest-rs --url https://example.com/servers --output ./configs --check-availability
//! ```
//!
//! ## Modules
//!
//! - [`config`] - Configuration generation and management
//! - [`parser`] - VPN URL parsing utilities
//! - [`checker`] - Proxy availability checking

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

/// Configuration generation and management
pub mod config;
/// VPN URL parsing utilities
pub mod parser;
/// Proxy availability checking
pub mod checker;

use anyhow::Result;
use std::path::Path;

/// Fetches content from a URL using blocking HTTP request.
///
/// # Arguments
///
/// * `url` - The URL to fetch content from
///
/// # Returns
///
/// Returns the response body as a String, or an error if the request fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The HTTP request fails
/// - The response status is not successful (not 2xx)
/// - The response body cannot be decoded as UTF-8
///
/// # Example
///
/// ```rust,no_run
/// # use proxy_harvest_rs::fetch_url_content;
/// # fn main() -> anyhow::Result<()> {
/// let content = fetch_url_content("https://example.com/servers")?;
/// println!("Fetched {} bytes", content.len());
/// # Ok(())
/// # }
/// ```
pub fn fetch_url_content(url: &str) -> Result<String> {
    log::info!("Fetching content from URL: {}", url);
    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch URL: HTTP {}", response.status());
    }

    let content = response.text()?;
    Ok(content)
}

/// Processes VPN server URLs from multiple sources and generates Xray configuration files.
///
/// This is a high-level function that orchestrates the entire workflow:
/// 1. Fetches server lists from multiple URLs
/// 2. Parses server configurations from all sources
/// 3. Merges servers into a single list (duplicates removed by tag)
/// 4. Optionally checks server availability
/// 5. Generates Xray configuration files
///
/// # Arguments
///
/// * `urls` - Slice of URLs to fetch server lists from
/// * `output_dir` - Directory where configuration files will be written
/// * `check_availability` - Whether to check server availability
/// * `timeout` - Timeout in seconds for availability checks
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if any step fails.
///
/// # Errors
///
/// This function will return an error if:
/// - Any URL cannot be fetched
/// - The content cannot be parsed
/// - The output directory cannot be created
/// - Configuration files cannot be written
///
/// # Example
///
/// ```rust,no_run
/// # use proxy_harvest_rs::process_servers;
/// # use std::path::PathBuf;
/// # fn main() -> anyhow::Result<()> {
/// let urls = vec![
///     "https://example.com/servers1".to_string(),
///     "https://example.com/servers2".to_string(),
/// ];
/// process_servers(
///     &urls,
///     &PathBuf::from("./configs"),
///     true,
///     5
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn process_servers(
    urls: &[String],
    output_dir: &Path,
    check_availability: bool,
    timeout: u64,
) -> Result<()> {
    log::info!("Starting Xray config generator");
    log::info!("Fetching servers from {} URL(s)", urls.len());
    log::info!("Output directory: {}", output_dir.display());

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)?;

    // Collect all servers from all URLs
    let mut all_servers = Vec::new();

    for url in urls {
        log::info!("Fetching content from URL: {}", url);

        // Fetch the content from URL
        let content = fetch_url_content(url)?;
        log::info!("Fetched {} bytes of data from {}", content.len(), url);

        // Parse server URLs
        let servers = parser::parse_servers(&content)?;
        log::info!("Parsed {} servers from {}", servers.len(), url);

        all_servers.extend(servers);
    }

    log::info!("Total servers collected: {}", all_servers.len());

    // Remove duplicates by tag (keep first occurrence)
    let mut seen_tags = std::collections::HashSet::new();
    let mut unique_servers = Vec::new();
    for server in all_servers {
        let tag = server.tag().to_string();
        if seen_tags.insert(tag) {
            unique_servers.push(server);
        } else {
            log::debug!("Skipping duplicate server with tag: {}", server.tag());
        }
    }

    let mut servers = unique_servers;
    log::info!("Unique servers after deduplication: {}", servers.len());

    // Check availability if requested
    if check_availability {
        servers = checker::filter_available_servers(servers, timeout)?;
    }

    // Generate configurations
    let outbounds = config::outbound::generate_outbounds(&servers)?;
    let routing = config::routing::generate_routing(&servers)?;

    // Write configuration files
    let outbounds_path = output_dir.join("04_outbounds.json");
    let routing_path = output_dir.join("05_routing.json");

    config::write_config(&outbounds_path, &outbounds)?;
    config::write_config(&routing_path, &routing)?;

    log::info!("Successfully generated config files:");
    log::info!("  - {}", outbounds_path.display());
    log::info!("  - {}", routing_path.display());

    Ok(())
}