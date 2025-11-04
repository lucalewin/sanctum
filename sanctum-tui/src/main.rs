mod auth;
mod config;
mod vault;
mod ui {
    pub mod login;
}

use uuid::Uuid;

use crate::auth::{login, register};

const BASE_URL: &str = "http://localhost:3000/api/v1";

struct Vault {
    session_token: String,
}

impl Vault {
    pub fn login(username: &str, password: &str) -> Self {
        let home = std::env::home_dir().expect("Could not find home directory");
        let config_dir = home.join(".manager").join("vault");
        std::fs::create_dir_all(config_dir).expect("Failed to create ~/.manager/vault");

        let client = reqwest::blocking::Client::new();
        client
            .post(format!("{BASE_URL}/auth/login/start"))
            .json(&serde_json::json!({
                "username": username,
                "password": password
            }))
            .send()
            .unwrap();

        Vault {
            session_token: String::new(),
        }
    }

    pub fn sync(&mut self) {
        // Implementation for syncing data
    }
}

struct Record {
    id: Uuid,
    encrypted_record_key: String,
    encrypted_data_blob: String,
}

fn main() {
    // let mut vault = Vault::login("username", "password");
    // vault.sync();
    let email = "6@example.com";
    let password = "password";

    // register(email, password).unwrap();
    login(email, password).unwrap();
}
