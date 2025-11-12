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
