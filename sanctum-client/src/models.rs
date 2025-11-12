use sanctum_shared::models::{Record, Vault};
use secrecy::{SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use time::UtcDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PlainVault {
    pub id: Uuid,

    pub name: SecretString,
    pub key: SecretSlice<u8>,

    pub created_at: UtcDateTime,
    pub updated_at: UtcDateTime,
}

#[derive(Debug, Clone)]
pub struct PlainRecord {
    pub id: Uuid,
    pub vault_id: Uuid,

    pub data: SecretString, // content as JSON string for now
    pub key: SecretSlice<u8>,

    pub created_at: UtcDateTime,
    pub updated_at: UtcDateTime,
}

// Encrypted representations that are persisted to sled in offline mode.
//
// These mirror the server-side shapes (they store base64-encoded
// ciphertexts for encrypted fields).
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVault {
    pub id: Uuid,
    pub encrypted_vault_key: String,
    pub encrypted_name: String,
    pub created_at: UtcDateTime,
    pub updated_at: UtcDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub encrypted_record_key: String,
    pub encrypted_data_blob: String,
    pub created_at: UtcDateTime,
    pub updated_at: UtcDateTime,
}

impl From<Vault> for EncryptedVault {
    fn from(value: Vault) -> Self {
        Self {
            id: value.id,
            encrypted_vault_key: value.encrypted_vault_key,
            encrypted_name: value.encrypted_name,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<Record> for EncryptedRecord {
    fn from(value: Record) -> Self {
        Self {
            id: value.id,
            vault_id: value.vault_id,
            encrypted_record_key: value.encrypted_record_key,
            encrypted_data_blob: value.encrypted_data_blob,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}
