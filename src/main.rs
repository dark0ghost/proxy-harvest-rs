use anyhow::Result;
use clap::Parser;
use proxy_harvest_rs::process_servers;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "proxy-harvest-rs")]
#[command(about = "Generate Xray configuration files from VPN server URLs", long_about = None)]
struct Args {
    /// URL to fetch the server list from
    #[arg(short, long)]
    url: String,

    /// Output directory for generated config files
    #[arg(short, long, default_value = "./configs")]
    output: PathBuf,

    /// Check proxy availability before including in config
    #[arg(short, long, default_value = "false")]
    check_availability: bool,

    /// Timeout in seconds for availability check (default: 5)
    #[arg(short = 't', long, default_value = "5")]
    timeout: u64,
}

#[allow(dead_code)]
fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    process_servers(&args.url, &args.output, args.check_availability, args.timeout)?;

    Ok(())
}
