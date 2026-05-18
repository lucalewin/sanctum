use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{PasswordHash, PasswordVerifier};
use dialoguer::{Password, theme::ColorfulTheme};

use crate::{
    remote::login,
    storage::{Metadata, db_connection, list_records},
    vault::list_vaults,
};

pub fn sync() {
    println!("sync");

    let conn = db_connection().expect("Failed to connect to vault database");
    let password_hash = Metadata::get_str(&conn, "password_hash")
        .expect("Failed to retrieve password hash from metadata")
        .unwrap();

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .report(false)
        .validate_with(|input: &String| -> Result<(), &str> {
            let hash = PasswordHash::new(&password_hash).unwrap();
            if argon2::Argon2::default()
                .verify_password(input.as_bytes(), &hash)
                .is_ok()
            {
                Ok(())
            } else {
                Err("Password is wrong")
            }
        })
        .interact()
        .unwrap();

    let email = Metadata::get_str(&conn, "email")
        .expect("Failed to retrieve email from metadata")
        .unwrap();

    let a = login(&email, &password).unwrap();

    let last_sync_timestamp: u32 = Metadata::get_str(&conn, "last_sync_timestamp")
        .unwrap()
        .unwrap()
        .parse()
        .unwrap();

    let client = ApiClient::new("http://localhost:3000".to_string(), a.access_token);

    let vaults = list_vaults(&conn).unwrap();

    for vault in vaults {
        dbg!(vault.updated_at, last_sync_timestamp);
        if vault.updated_at > last_sync_timestamp as i64 {
            client.update_vault(
                vault.id,
                &CreateVaultRequest {
                    encrypted_vault_key: base64::encode(vault.encrypted_vsk),
                    encrypted_name: base64::encode(vault.encrypted_name),
                },
            );
        }

        let items = list_records(&conn, &vault.id.to_string()).unwrap();

        for item in items {
            if item.3 > last_sync_timestamp {
                let record = CreateRecordRequest {
                    encrypted_data_blob: base64::encode(item.1),
                };
                let item_id = Uuid::parse_str(&item.0).unwrap();
                client.update_record(&vault.id, &item_id, &record).unwrap();
            }
        }
    }
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64;

    Metadata::set_str(&conn, "last_sync_timestamp", &current_timestamp.to_string()).unwrap();

    // GET https://sanctum.dev/api/v1/sync?since=2024-06-01T00:00:00Z
    // GET https://sanctum.dev/api/v1/me
}

use sanctum_shared::models::{CreateRecordRequest, CreateVaultRequest, Record, Vault};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::Error;

#[derive(Debug, Clone)]
pub struct ApiClient {
    base_url: String,
    access_token: String,
    client: reqwest::blocking::Client,
}

#[allow(unused)]
impl ApiClient {
    pub fn new(base_url: String, access_token: String) -> Self {
        Self {
            base_url,
            access_token,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn request_json<T: DeserializeOwned>(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> Result<T, Error> {
        let response = request
            .bearer_auth(&self.access_token)
            .send()
            .map_err(|e| Error::ApiError(e))?;

        let data = response
            .error_for_status()
            .map_err(|e| Error::ApiError(e))?
            .json()
            .map_err(|e| Error::ApiError(e))?;

        Ok(data)
    }

    fn request_empty(&self, request: reqwest::blocking::RequestBuilder) -> Result<(), Error> {
        request
            .bearer_auth(&self.access_token)
            .send()
            .map_err(|e| Error::ApiError(e))?
            .error_for_status()
            .map_err(|e| Error::ApiError(e))?;
        Ok(())
    }

    pub fn fetch_vaults(&self) -> Result<Vec<Vault>, Error> {
        let url = format!("{}/api/v1/vaults", &self.base_url);
        self.request_json(self.client.get(url))
    }

    pub fn fetch_vault(&self, id: &Uuid) -> Result<Vault, Error> {
        let url = format!("{}/api/v1/vaults/{}", &self.base_url, id);
        self.request_json(self.client.get(url))
    }

    pub fn create_vault(&self, vault: &CreateVaultRequest) -> Result<Vault, Error> {
        let url = format!("{}/api/v1/vaults", &self.base_url);
        self.request_json(self.client.post(url).json(vault))
    }

    pub fn update_vault(&self, vault_id: Uuid, vault: &CreateVaultRequest) -> Result<Vault, Error> {
        let url = format!("{}/api/v1/vaults/{}", &self.base_url, vault_id);
        self.request_json(self.client.put(url).json(vault))
    }

    pub fn delete_vault(&self, id: &Uuid) -> Result<(), Error> {
        let url = format!("{}/api/v1/vaults/{}", &self.base_url, id);
        self.request_empty(self.client.delete(url))
    }

    pub fn fetch_records(&self, vault_id: &Uuid) -> Result<Vec<Record>, Error> {
        let url = format!("{}/api/v1/vaults/{}/records", &self.base_url, vault_id);
        self.request_json(self.client.get(url))
    }

    pub fn fetch_record(&self, vault_id: &Uuid, record_id: &Uuid) -> Result<Record, Error> {
        let url = format!(
            "{}/api/v1/vaults/{}/records/{}",
            &self.base_url, vault_id, record_id
        );
        self.request_json(self.client.get(url))
    }

    pub fn create_record(
        &self,
        vault_id: &Uuid,
        record: &CreateRecordRequest,
    ) -> Result<Record, Error> {
        let url = format!("{}/api/v1/vaults/{}/records", &self.base_url, vault_id);
        self.request_json(self.client.post(url).json(record))
    }

    pub fn update_record(
        &self,
        vault_id: &Uuid,
        record_id: &Uuid,
        record: &CreateRecordRequest,
    ) -> Result<Record, Error> {
        let url = format!(
            "{}/api/v1/vaults/{}/records{}",
            &self.base_url, vault_id, record_id
        );
        self.request_json(self.client.put(url).json(record))
    }

    pub fn delete_record(&self, vault_id: &Uuid, record_id: &Uuid) -> Result<(), Error> {
        let url = format!(
            "{}/api/v1/vaults/{}/records/{}",
            &self.base_url, vault_id, record_id
        );
        self.request_empty(self.client.delete(url))
    }
}
