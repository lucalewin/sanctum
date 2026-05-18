use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{crypto::VaultKeys, error::Error};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Entry {
    Password {
        title: String,
        username: String,
        password: String,
        url: String,
    },
}

#[derive(Debug)]
pub struct Item {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub data: Entry,
    pub created_at: u32,
    pub updated_at: u32,
}

pub fn create_record(
    conn: &Connection,
    vault: String,
    item: Entry,
    keys: VaultKeys,
) -> Result<(), Box<dyn std::error::Error>> {
    let vault = crate::vault::list_vaults(conn)?
        .into_iter()
        .find(|v| {
            let name = v.decrypt_name(&keys).unwrap();
            name.to_lowercase() == vault.to_lowercase()
        })
        .unwrap();

    let vault_key = vault.decrypt_vsk(&keys)?;
    let encrypted_payload = {
        let item_json = serde_json::to_vec(&item)?;
        let (item_ciphertext, item_nonce) = crate::crypto::encrypt_payload(
            &vault_key.try_into().unwrap(),
            &item_json,
            &vault.id.to_string(),
        );
        let mut encrypted_payload = item_nonce.to_vec();
        encrypted_payload.extend_from_slice(&item_ciphertext);
        encrypted_payload
    };

    crate::storage::create_record(&conn, &vault.id.to_string(), &encrypted_payload)?;

    Ok(())
}

pub fn list_records(
    conn: &Connection,
    vault_name: &str,
    keys: &VaultKeys,
) -> Result<Vec<Item>, Error> {
    let vault_name = vault_name.to_lowercase();
    let vault = crate::vault::list_vaults(conn)?
        .into_iter()
        .find(|v| {
            let name = v.decrypt_name(&keys).unwrap();
            name.to_lowercase() == vault_name
        })
        .unwrap();

    let vault_key = vault.decrypt_vsk(&keys)?;

    let records = crate::storage::list_records(&conn, &vault.id.to_string())?
        .into_iter()
        .map(|record| {
            let (nonce_slice, ciphertext) = record.1.split_at(24);
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(nonce_slice);
            let payload_bytes = crate::crypto::decrypt_payload(
                &vault_key.as_slice().try_into().unwrap(),
                &ciphertext,
                &nonce,
                &vault.id.to_string(),
            )
            .unwrap();

            Item {
                id: Uuid::parse_str(&record.0).unwrap(),
                vault_id: vault.id.clone(),
                data: serde_json::from_slice(&payload_bytes).unwrap(),
                created_at: record.2,
                updated_at: record.3,
            }
        })
        .collect();

    Ok(records)
}

pub fn view_record(
    conn: &Connection,
    vault: String,
    name: String,
    keys: VaultKeys,
) -> Result<Item, Box<dyn std::error::Error>> {
    let records = list_records(conn, &vault, &keys)?;

    records
        .into_iter()
        .find(|record| match record.data {
            Entry::Password { ref title, .. } => title.to_lowercase() == name.to_lowercase(),
        })
        .ok_or_else(|| "Record not found".into())
}

#[allow(unused)]
pub fn delete_record(
    conn: &Connection,
    vault: String,
    name: String,
    keys: VaultKeys,
) -> Result<(), Box<dyn std::error::Error>> {
    // let records = list_records(conn, vault, keys)?;

    // let record = records
    //     .into_iter()
    //     .find(|record| match record {
    //         Item::Password { title, .. } => title.to_lowercase() == name.to_lowercase(),
    //     })
    //     .ok_or_else(|| "Record not found".to_string())?;

    // crate::storage::delete_record(conn, record., name)?;

    Ok(())
}
