/// Outbound server configuration generation
pub mod outbound;
/// Routing rules configuration generation
pub mod routing;

use anyhow::Result;
use serde_json::Value;
use std::path::Path;

/// Writes JSON configuration to a file
///
/// # Arguments
///
/// * `path` - Path where the configuration file will be written
/// * `config` - JSON configuration value to write
///
/// # Errors
///
/// Returns an error if JSON serialization or file writing fails
pub fn write_config(path: &Path, config: &Value) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(path, json)?;
    Ok(())
}
