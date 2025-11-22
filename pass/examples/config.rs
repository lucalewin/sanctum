use std::path::PathBuf;

use pass::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a default config path: ~/.local/share/pass/config.json
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let config_path = PathBuf::from(format!("{}/.local/share/pass/config.json", home));

    // Load existing config or create a sensible default and persist it.
    let cfg = Config::load_from_file(&config_path)?;

    println!("Configuration loaded from: {}", config_path.display());
    println!("Database path: {}", cfg.db_path);

    Ok(())
}
