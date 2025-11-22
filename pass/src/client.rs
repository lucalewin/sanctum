use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::OsRng};
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretSlice};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::Config,
    crypto::{decrypt_record, decrypt_vault, derive_key, encrypt_record, encrypt_vault},
    db,
    models::{PlainRecord, PlainVault},
};

use crate::error::Error;

pub struct Client {
    config: Config,
    conn: Connection,
    master_key: SecretSlice<u8>,
}

impl Client {
    pub fn from_config(config: Config) -> Self {
        Client {
            conn: db::setup_database(&config.db_path),
            config,
            master_key: vec![].into(),
        }
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), Error> {
        self.master_key = SecretSlice::from(derive_key(password, &self.config.salt)?.to_vec());
        Ok(())
    }

    pub fn lock(&self) {
        // Implementation for locking the client
    }

    pub fn get_vaults(&self) -> Result<Vec<PlainVault>, Error> {
        let vaults = db::get_vaults(&self.conn)?;
        let decrypted = vaults
            .iter()
            .map(|v| decrypt_vault(self.master_key.expose_secret(), v))
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(decrypted)
    }

    pub fn create_vault(&self, name: &str) -> Result<PlainVault, Error> {
        let vault = PlainVault {
            id: Uuid::new_v4(),
            name: name.into(),
            encryption_key: ChaCha20Poly1305::generate_key(&mut OsRng).to_vec().into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let encrypted_vault = encrypt_vault(self.master_key.expose_secret(), &vault)?;
        db::create_vault(&self.conn, &encrypted_vault)?;
        Ok(vault)
    }

    pub fn delete_vault(&self, id: Uuid) -> Result<(), Error> {
        db::delete_vault(&self.conn, id)?;
        Ok(())
    }

    pub fn get_records(&self, vault_id: Uuid) -> Result<Vec<PlainRecord>, Error> {
        let vault = db::get_vault(&self.conn, vault_id)?;
        let decrypted_vault = decrypt_vault(self.master_key.expose_secret(), &vault)?;

        let records = db::get_records(&self.conn, vault_id)?;
        let decrypted = records
            .iter()
            .map(|r| decrypt_record(decrypted_vault.encryption_key.expose_secret(), r))
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(decrypted)
    }

    pub fn create_record(&self, vault_id: Uuid, data: &str) -> Result<PlainRecord, Error> {
        let vault = db::get_vault(&self.conn, vault_id)?;
        let decrypted_vault = decrypt_vault(self.master_key.expose_secret(), &vault)?;

        let record = PlainRecord {
            id: Uuid::new_v4(),
            vault_id,
            encryption_key: ChaCha20Poly1305::generate_key(&mut OsRng).to_vec().into(),
            data: data.into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let encrypted_record =
            encrypt_record(decrypted_vault.encryption_key.expose_secret(), &record)?;
        db::create_record(&self.conn, &encrypted_record)?;
        Ok(record)
    }

    pub fn delete_record(&self, id: Uuid) -> Result<(), Error> {
        db::delete_record(&self.conn, id)?;
        Ok(())
    }
}
