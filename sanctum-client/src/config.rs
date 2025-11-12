use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub api_base_url: String,
    pub salt: Vec<u8>,
}
