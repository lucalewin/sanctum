use chacha20poly1305::{Key, XChaCha20Poly1305};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::crypto::VaultKeys;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Item {
    Password {
        title: String,
        username: String,
        password: String,
        url: String,
    },
}

pub fn create_record(
    conn: &Connection,
    vault: String,
    item: Item,
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
        let (item_ciphertext, item_nonce) =
            crate::crypto::encrypt_payload(&vault_key.try_into().unwrap(), &item_json, &vault.id);
        let mut encrypted_payload = item_nonce.to_vec();
        encrypted_payload.extend_from_slice(&item_ciphertext);
        encrypted_payload
    };

    crate::storage::create_record(&conn, &vault.id, &encrypted_payload)?;

    println!("Created a new record...");
    Ok(())
}

pub fn list_records(
    conn: &Connection,
    vault: String,
    keys: VaultKeys,
) -> Result<Vec<Item>, Box<dyn std::error::Error>> {
    println!("Listing all records...");
    let vault_name = vault.to_lowercase();
    let vault = crate::vault::list_vaults(conn)?
        .into_iter()
        .find(|v| {
            let name = v.decrypt_name(&keys).unwrap();
            name.to_lowercase() == vault_name
        })
        .unwrap();

    let vault_key = vault.decrypt_vsk(&keys)?;

    let records = crate::storage::list_records(&conn, &vault.id).unwrap();
    let records = records
        .into_iter()
        .map(|record| {
            let (nonce_slice, ciphertext) = record.split_at(24);
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(nonce_slice);
            let payload_bytes = crate::crypto::decrypt_payload(
                Key::from_slice(&vault_key),
                &ciphertext,
                &nonce,
                &vault.id,
            )
            .unwrap();
            serde_json::from_slice(&payload_bytes).unwrap()
        })
        .collect();
    Ok(records)
}

pub fn view_record(vault: String, name: String) -> Result<String, Box<dyn std::error::Error>> {
    println!("Viewing a record...");

    Ok("Record details".to_string())
}

pub fn delete_record() {
    println!("Deleting a record...");
}
