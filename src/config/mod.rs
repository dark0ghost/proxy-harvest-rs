pub mod outbound;
pub mod routing;

use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub fn write_config(path: &Path, config: &Value) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(path, json)?;
    Ok(())
}
