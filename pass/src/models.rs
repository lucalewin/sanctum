use secrecy::{SecretSlice, SecretString};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug)]
pub struct Vault {
    pub id: Uuid,
    pub name: String,
    pub(crate) encryption_key: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct PlainVault {
    pub id: Uuid,
    pub name: SecretString,
    pub(crate) encryption_key: SecretSlice<u8>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct Record {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub(crate) encryption_key: String,
    pub data: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct PlainRecord {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub(crate) encryption_key: SecretSlice<u8>,
    pub data: SecretString,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
