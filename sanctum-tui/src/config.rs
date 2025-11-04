pub struct Config {
    pub api_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            api_url: "http://localhost:8080".to_string(),
        }
    }
}
