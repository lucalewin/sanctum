use base64::{Engine, prelude::BASE64_STANDARD};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::OsRng};
use secrecy::{ExposeSecret, SecretSlice};
use std::sync::Arc;
use std::time::Duration;
use time::UtcDateTime;
use tokio::time::sleep;
use tokio::{sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{decrypt_vault, encrypt_vault};
use crate::outbox::{Action, EntityType, OutboxEntry};
use crate::{
    Config, Error,
    api::ApiClient,
    crypto::{decrypt_data, derive_key, encrypt_data},
    models::{EncryptedRecord, EncryptedVault, PlainRecord, PlainVault},
};

pub struct LockedClient {
    config: Config,
}

impl LockedClient {
    pub fn from_config(config: Config) -> Result<Self, Error> {
        Ok(Self { config })
    }

    pub async fn login(mut self, email: &str, password: &str) -> Result<UnlockedClient, Error> {
        let resp = crate::auth::login(email, password).await.unwrap();
        let salt = BASE64_STANDARD.decode(&resp.salt).unwrap();
        self.config.salt = salt;

        let master_key = derive_key(password, &self.config.salt)?;
        let api_client = ApiClient::new(self.config.api_base_url.clone(), resp.access_token);

        let db = sled::open("data.sled.db").unwrap();
        let data_tree = db.open_tree("data").unwrap();
        let outbox_tree = db.open_tree("outbox").unwrap();

        Ok(UnlockedClient {
            config: self.config,
            api_client: Some(Arc::new(api_client)),
            master_key: SecretSlice::new(Box::new(master_key)),
            // store: LocalStore::open("data.sled.db").unwrap(),
            db,
            data_tree,
            outbox_tree,
            last_sync: Mutex::new(None),
        })
    }

    pub async fn register(email: &str, password: &str) -> Result<(), Error> {
        crate::auth::register(email, password).await.unwrap();
        Ok(())
    }

    pub fn unlock_offline(self, password: &str) -> Result<UnlockedClient, Error> {
        let master_key = derive_key(password, &self.config.salt)?;

        let db = sled::open("data.sled.db").unwrap();
        let data_tree = db.open_tree("data").unwrap();
        let outbox_tree = db.open_tree("outbox").unwrap();

        Ok(UnlockedClient {
            config: self.config,
            api_client: None,
            master_key: SecretSlice::new(Box::new(master_key)),
            // store: LocalStore::open("data.sled.db").unwrap(),
            db,
            data_tree,
            outbox_tree,
            last_sync: Mutex::new(None),
        })
    }
}

pub struct UnlockedClient {
    config: Config,
    api_client: Option<Arc<ApiClient>>,
    master_key: SecretSlice<u8>,
    // store: LocalStore,
    db: sled::Db,
    data_tree: sled::Tree,
    outbox_tree: sled::Tree,
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
        self.data_tree
            .scan_prefix(b"vault:")
            .map(|e| {
                let (_, value) = e.unwrap();
                let encrypted = serde_json::from_slice(&value).unwrap();
                decrypt_vault(&encrypted, &self.master_key.expose_secret()).unwrap()
            })
            .collect::<Vec<_>>()
    }

    pub fn create_vault(&self, name: &str) -> Result<PlainVault, Error> {
        let vault_key = ChaCha20Poly1305::generate_key(&mut OsRng);

        let plain = PlainVault {
            id: Uuid::new_v4(),
            key: vault_key.to_vec().into(),
            name: name.into(),
            created_at: UtcDateTime::now(),
            updated_at: UtcDateTime::now(),
        };

        let encrypted = encrypt_vault(&plain, &self.master_key.expose_secret()).unwrap();
        let outbox_entry = OutboxEntry::new(
            Action::Create,
            EntityType::Vault,
            serde_json::to_value(&encrypted).unwrap(),
        );

        self.data_tree
            .insert(
                format!("vault:{}", encrypted.id),
                serde_json::to_vec(&encrypted).unwrap(),
            )
            .unwrap();
        self.outbox_tree
            .insert(
                format!("outbox:{}", outbox_entry.id),
                serde_json::to_vec(&outbox_entry).unwrap(),
            )
            .unwrap();

        self.db.flush().unwrap();

        Ok(plain)
    }

    pub fn update_vault(&self, vault_id: Uuid, name: &str) -> Result<PlainVault, Error> {
        // Try to fetch existing vault
        let key = format!("vault:{}", vault_id);
        if let Ok(Some(value)) = self.data_tree.get(&key) {
            let mut existing: EncryptedVault = serde_json::from_slice(&value).unwrap();
            // decrypt vault key
            let vault_key = decrypt_data(
                &BASE64_STANDARD
                    .decode(existing.encrypted_vault_key.clone())
                    .unwrap(),
                &self.master_key.expose_secret(),
            )
            .unwrap();

            // encrypt new name with vault key
            existing.encrypted_name =
                b64_encode(&encrypt_data(name.as_bytes(), &vault_key).unwrap());
            existing.updated_at = UtcDateTime::now();

            let outbox_entry = OutboxEntry::new(
                Action::Update,
                EntityType::Vault,
                serde_json::to_value(&existing).unwrap(),
            );

            self.data_tree
                .insert(key, serde_json::to_vec(&existing).unwrap())
                .unwrap();
            self.outbox_tree
                .insert(
                    format!("outbox:{}", outbox_entry.id),
                    serde_json::to_vec(&outbox_entry).unwrap(),
                )
                .unwrap();
            self.db.flush().unwrap();

            Ok(PlainVault {
                id: existing.id,
                key: vault_key.into(),
                name: name.into(),
                created_at: existing.created_at,
                updated_at: existing.updated_at,
            })
        } else {
            // Not found -> create a new vault with provided id
            self.create_vault(name) // FIXME: this does not use the provided uuid
        }
    }

    pub fn delete_vault(&self, vault_id: Uuid) -> Result<(), Error> {
        let vault = self
            .data_tree
            .remove(format!("vault:{}", vault_id))
            .unwrap()
            .unwrap();

        let vault: EncryptedVault = serde_json::from_slice(&vault).unwrap();

        let outbox_entry = OutboxEntry::new(
            Action::Delete,
            EntityType::Vault,
            serde_json::to_value(&vault).unwrap(),
        );

        self.outbox_tree
            .insert(
                format!("outbox:{}", outbox_entry.id),
                serde_json::to_vec(&outbox_entry).unwrap(),
            )
            .unwrap();

        self.db.flush().unwrap();
        Ok(())
    }

    // ------------------------------------------------------------------------------------

    pub fn list_records(&self, vault_id: Uuid) -> Vec<PlainRecord> {
        // fetch vault to obtain vault key
        let vault_key = match self.data_tree.get(format!("vault:{}", vault_id)).unwrap() {
            Some(v) => {
                let ev: EncryptedVault = serde_json::from_slice(&v).unwrap();
                decrypt_data(
                    &BASE64_STANDARD.decode(ev.encrypted_vault_key).unwrap(),
                    &self.master_key.expose_secret(),
                )
                .unwrap()
            }
            None => return vec![],
        };

        let prefix = format!("record:{}:", vault_id);
        self.data_tree
            .scan_prefix(prefix.as_bytes())
            .map(|e| {
                let (_, value) = e.unwrap();
                let r: EncryptedRecord = serde_json::from_slice(&value).unwrap();

                let record_key = decrypt_data(
                    &BASE64_STANDARD.decode(r.encrypted_record_key).unwrap(),
                    &vault_key,
                )
                .unwrap();

                let data = decrypt_data(
                    &BASE64_STANDARD.decode(r.encrypted_data_blob).unwrap(),
                    &record_key,
                )
                .unwrap();

                PlainRecord {
                    id: r.id,
                    vault_id: r.vault_id,
                    data: String::from_utf8(data).unwrap().into(),
                    key: record_key.into(),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                }
            })
            .collect::<Vec<_>>()
    }

    pub fn create_record(&self, vault_id: Uuid, data: &str) -> Result<PlainRecord, Error> {
        // fetch vault and vault key
        let vault_item = self
            .data_tree
            .get(format!("vault:{}", vault_id))
            .unwrap()
            .ok_or(Error::NotFound)?;

        let ev: EncryptedVault = serde_json::from_slice(&vault_item).unwrap();
        let vault_key = decrypt_data(
            &BASE64_STANDARD.decode(ev.encrypted_vault_key).unwrap(),
            &self.master_key.expose_secret(),
        )
        .unwrap();

        let record_key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let encrypted = EncryptedRecord {
            id: Uuid::new_v4(),
            vault_id,
            encrypted_record_key: b64_encode(&encrypt_data(&record_key, &vault_key).unwrap()),
            encrypted_data_blob: b64_encode(&encrypt_data(data.as_bytes(), &record_key).unwrap()),
            created_at: UtcDateTime::now(),
            updated_at: UtcDateTime::now(),
        };

        self.data_tree
            .insert(
                format!("record:{}:{}", vault_id, encrypted.id),
                serde_json::to_vec(&encrypted).unwrap(),
            )
            .unwrap();
        self.db.flush().unwrap();

        Ok(PlainRecord {
            id: encrypted.id,
            vault_id,
            data: data.into(),
            key: record_key.to_vec().into(),
            created_at: encrypted.created_at,
            updated_at: encrypted.updated_at,
        })
    }

    pub fn update_record(
        &self,
        vault_id: Uuid,
        record_id: Uuid,
        data: &str,
    ) -> Result<PlainRecord, Error> {
        // fetch vault key
        let vault_item = self
            .data_tree
            .get(format!("vault:{}", vault_id))
            .unwrap()
            .ok_or(Error::NotFound)?;
        let ev: EncryptedVault = serde_json::from_slice(&vault_item).unwrap();
        let vault_key = decrypt_data(
            &BASE64_STANDARD.decode(ev.encrypted_vault_key).unwrap(),
            &self.master_key.expose_secret(),
        )
        .unwrap();

        let key = format!("record:{}:{}", vault_id, record_id);
        let (record_key_bytes, created_at) = if let Ok(Some(value)) = self.data_tree.get(&key) {
            let existing: EncryptedRecord = serde_json::from_slice(&value).unwrap();
            let record_key = decrypt_data(
                &BASE64_STANDARD
                    .decode(existing.encrypted_record_key)
                    .unwrap(),
                &vault_key,
            )
            .unwrap();
            (record_key, existing.created_at)
        } else {
            // create new record key
            let rk = ChaCha20Poly1305::generate_key(&mut OsRng);
            (rk.to_vec(), UtcDateTime::now())
        };

        let encrypted = EncryptedRecord {
            id: record_id,
            vault_id,
            encrypted_record_key: b64_encode(&encrypt_data(&record_key_bytes, &vault_key).unwrap()),
            encrypted_data_blob: b64_encode(
                &encrypt_data(data.as_bytes(), &record_key_bytes).unwrap(),
            ),
            created_at,
            updated_at: UtcDateTime::now(),
        };

        self.data_tree
            .insert(key, serde_json::to_vec(&encrypted).unwrap())
            .unwrap();
        self.db.flush().unwrap();

        Ok(PlainRecord {
            id: encrypted.id,
            vault_id: encrypted.vault_id,
            data: data.into(),
            key: record_key_bytes.into(),
            created_at: encrypted.created_at,
            updated_at: encrypted.updated_at,
        })
    }

    pub fn delete_record(&self, vault_id: Uuid, record_id: Uuid) -> Result<(), Error> {
        self.data_tree
            .remove(format!("record:{}:{}", vault_id, record_id))
            .unwrap();
        self.db.flush().unwrap();
        Ok(())
    }

    // ------------------------------------------------------------------------------------

    pub async fn sync_once(&self) -> Result<(), Error> {
        let Some(api_client) = &self.api_client else {
            return Err(Error::SyncInOfflineMode);
        };

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

fn b64_encode(data: &[u8]) -> String {
    base64::encode(data)
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, Error> {
    base64::decode(encoded).map_err(|_| Error::InvalidBase64)
}
