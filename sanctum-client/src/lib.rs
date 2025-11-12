use base64::{Engine, prelude::BASE64_STANDARD};
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use time::UtcDateTime;
use tokio::{sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    api::ApiClient,
    crypto::derive_key,
    models::{PlainRecord, PlainVault},
    store::{LocalStore, OutboxEntryKind, OutputEntryObject},
};

mod api;
mod auth;
mod crypto;
mod models;
mod store;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub api_base_url: String,
    pub salt: Vec<u8>,
}

pub struct LockedClient {
    config: Config,
}

impl LockedClient {
    pub fn from_config(config: Config) -> Result<Self, Error> {
        Ok(Self { config })
    }

    pub async fn login(mut self, email: &str, password: &str) -> Result<UnlockedClient, Error> {
        let resp = auth::login(email, password).await.unwrap();
        let salt = BASE64_STANDARD.decode(&resp.salt).unwrap();
        self.config.salt = salt;

        let master_key = derive_key(password, &self.config.salt)?;
        let api_client = ApiClient::new(self.config.api_base_url.clone(), resp.access_token);

        Ok(UnlockedClient {
            config: self.config,
            api_client: Some(api_client),
            master_key: SecretSlice::new(Box::new(master_key)),
            store: LocalStore::open("data.sled.db").unwrap(),
            last_sync: Mutex::new(None),
        })
    }

    pub async fn register(email: &str, password: &str) -> Result<(), Error> {
        auth::register(email, password).await.unwrap();
        Ok(())
    }

    pub fn unlock_offline(self, password: &str) -> Result<UnlockedClient, Error> {
        let master_key = derive_key(password, &self.config.salt)?;

        Ok(UnlockedClient {
            config: self.config,
            api_client: None,
            master_key: SecretSlice::new(Box::new(master_key)),
            store: LocalStore::open("data.sled.db").unwrap(),
            last_sync: Mutex::new(None),
        })
    }
}

pub struct UnlockedClient {
    config: Config,
    api_client: Option<ApiClient>,
    master_key: SecretSlice<u8>,
    store: LocalStore,
    last_sync: Mutex<Option<UtcDateTime>>,
}

impl UnlockedClient {
    pub fn lock(mut self) -> LockedClient {
        self.master_key.zeroize();

        LockedClient {
            config: self.config,
        }
    }

    // ------------------------------------------------------------------------------------

    pub fn list_vaults(&self) -> Vec<PlainVault> {
        unimplemented!()
    }

    pub fn create_vault(&self, name: &str) -> Result<PlainVault, Error> {
        unimplemented!()
    }

    pub fn update_vault(&self, vault_id: Uuid, name: &str) -> Result<PlainVault, Error> {
        unimplemented!()
    }

    pub fn delete_vault(&self, vault_id: Uuid) -> Result<(), Error> {
        unimplemented!()
    }

    // ------------------------------------------------------------------------------------

    pub fn list_records(&self, vault_id: Uuid) -> Vec<PlainRecord> {
        unimplemented!()
    }

    pub fn create_record(&self, vault_id: Uuid, data: &str) -> Result<PlainRecord, Error> {
        unimplemented!()
    }

    pub fn update_record(
        &self,
        vault_id: Uuid,
        record_id: Uuid,
        data: &str,
    ) -> Result<PlainRecord, Error> {
        unimplemented!()
    }

    pub fn delete_record(&self, vault_id: Uuid, record_id: Uuid) -> Result<(), Error> {
        unimplemented!()
    }

    // ------------------------------------------------------------------------------------

    pub async fn sync_once(&self) -> Result<(), Error> {
        let Some(api_client) = &self.api_client else {
            return Err(Error::SyncInOfflineMode);
        };

        let outbox = self.store.get_outbox().unwrap();
        for entry in outbox {
            match entry.kind {
                OutboxEntryKind::Create => {
                    match entry.object_kind {
                        OutputEntryObject::Vault => {
                            // Implementation details
                            unimplemented!()
                        }
                        OutputEntryObject::Record => {
                            // Implementation details
                            unimplemented!()
                        }
                    }
                }
                OutboxEntryKind::Update => {
                    // Implementation details
                    unimplemented!()
                }
                OutboxEntryKind::Delete => {
                    // Implementation details
                    unimplemented!()
                }
            }
        }

        unimplemented!()
    }

    pub fn start_background_sync(&self) -> Result<JoinHandle<()>, Error> {
        let Some(api_client) = &self.api_client else {
            return Err(Error::SyncInOfflineMode);
        };

        // Implementation details
        unimplemented!()
    }

    pub fn stop_background_sync(&self) -> Result<(), Error> {
        // Implementation details
        unimplemented!()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to derive key")]
    DeriveKey(argon2::Error),

    #[error("Sync is not allowed in offline mode")]
    SyncInOfflineMode,

    #[error("API error")]
    ApiError(#[from] reqwest::Error),
}
