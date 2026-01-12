pub mod config;
pub mod parser;

use anyhow::Result;
use clap::Parser;
use log::info;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "xray-config-generator")]
#[command(about = "Generate Xray configuration files from VPN server URLs", long_about = None)]
struct Args {
    /// URL to fetch the server list from
    #[arg(short, long)]
    url: String,

    /// Output directory for generated config files
    #[arg(short, long, default_value = "./configs")]
    output: PathBuf,
}

#[allow(dead_code)]
fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    info!("Starting Xray config generator");
    info!("Fetching servers from: {}", args.url);
    info!("Output directory: {}", args.output.display());

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&args.output)?;

    // Fetch the content from URL
    let content = fetch_url_content(&args.url)?;
    info!("Fetched {} bytes of data", content.len());

    // Parse server URLs
    let servers = parser::parse_servers(&content)?;
    info!("Parsed {} servers", servers.len());

    // Generate configurations
    let outbounds = config::outbound::generate_outbounds(&servers)?;
    let routing = config::routing::generate_routing(&servers)?;

    // Write configuration files
    let outbounds_path = args.output.join("04_outbounds.json");
    let routing_path = args.output.join("05_routing.json");

    config::write_config(&outbounds_path, &outbounds)?;
    config::write_config(&routing_path, &routing)?;

    info!("Successfully generated config files:");
    info!("  - {}", outbounds_path.display());
    info!("  - {}", routing_path.display());

    Ok(())
}

fn fetch_url_content(url: &str) -> Result<String> {
    info!("Fetching content from URL...");
    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch URL: HTTP {}", response.status());
    }

    let content = response.text()?;
    Ok(content)
}
