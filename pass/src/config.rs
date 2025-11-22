use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{KeyInit, OsRng},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::Error;

/// Application configuration.
///
/// This struct is persisted as JSON. Use `Config::load_from_file` to read an
/// existing config or create a sensible default and persist it when the file
/// does not exist.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub email: String,
    /// 32-byte random salt for KDF (Argon2)
    pub salt: [u8; 32],
    /// Extra parameters (reserved for future use)
    pub params: Vec<String>,
    /// Path to the SQLite database file
    pub db_path: String,
}

impl Default for Config {
    fn default() -> Self {
        // Generate a random 32-byte salt using existing crate utilities.
        let key = ChaCha20Poly1305::generate_key(&mut OsRng).to_vec();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&key);

        let db_path = default_db_path();

        Config {
            email: String::new(),
            salt,
            params: Vec::new(),
            db_path,
        }
    }
}

fn default_db_path() -> String {
    // Prefer a per-user XDG-like path, fall back to ./pass.db if HOME isn't set.
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{}/.local/share/pass/pass.db", home)
}

impl Config {
    /// Load configuration from `path`. If the file does not exist, create a
    /// sensible default, persist it to `path`, and return it.
    ///
    /// Errors are returned as `crate::error::Error` to integrate with the
    /// application's error type.
    pub fn load_from_file(path: &Path) -> Result<Self, Error> {
        if path.exists() {
            let s = std::fs::read_to_string(path).map_err(Error::Io)?;
            let cfg: Config = serde_json::from_str(&s)
                .map_err(|e| Error::Other(format!("Failed to parse config: {}", e)))?;
            Ok(cfg)
        } else {
            let cfg = Config::default();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(Error::Io)?;
            }
            let s = serde_json::to_string_pretty(&cfg)
                .map_err(|e| Error::Other(format!("Failed to serialize config: {}", e)))?;
            std::fs::write(path, s).map_err(Error::Io)?;
            Ok(cfg)
        }
    }

    /// Persist the config to `path`.
    pub fn save_to_file(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        let s = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Other(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, s).map_err(Error::Io)?;
        Ok(())
    }
}
