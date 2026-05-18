use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::OsRng};
use rusqlite::Connection;
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::{
    crypto::{VaultKeys, decrypt_payload, encrypt_payload},
    error::Error,
};

pub struct EncryptedVault {
    pub id: Uuid,
    pub encrypted_name: Vec<u8>,
    pub encrypted_vsk: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl EncryptedVault {
    pub fn decrypt_name(&self, keys: &VaultKeys) -> Result<String, Error> {
        let (nonce_slice, ciphertext) = self.encrypted_name.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_slice);
        let name_bytes = decrypt_payload(
            &keys.enc_key.expose_secret(),
            &ciphertext,
            &nonce,
            &self.id.to_string(),
        )
        .unwrap();
        Ok(String::from_utf8(name_bytes)?)
    }

    pub fn decrypt_vsk(&self, keys: &VaultKeys) -> Result<Vec<u8>, Error> {
        let (nonce_slice, ciphertext) = self.encrypted_vsk.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_slice);
        let vsk_bytes = decrypt_payload(
            keys.enc_key.expose_secret(),
            &ciphertext,
            &nonce,
            &self.id.to_string(),
        )
        .unwrap();
        Ok(vsk_bytes)
    }

    pub fn encrypt(
        id: Uuid,
        name: &str,
        vsk: &[u8],
        created_at: i64,
        updated_at: i64,
        keys: &VaultKeys,
    ) -> EncryptedVault {
        let id = id.to_string();
        let encrypted_name = {
            let (name_ciphertext, name_nonce) =
                encrypt_payload(&keys.enc_key.expose_secret(), name.as_bytes(), &id);
            let mut encrypted_name = name_nonce.to_vec();
            encrypted_name.extend_from_slice(&name_ciphertext);
            encrypted_name
        };

        let encrypted_vsk = {
            let (vsk_ciphertext, vsk_nonce) =
                encrypt_payload(&keys.enc_key.expose_secret(), vsk, &id);
            let mut encrypted_vsk = vsk_nonce.to_vec();
            encrypted_vsk.extend_from_slice(&vsk_ciphertext);
            encrypted_vsk
        };

        EncryptedVault {
            id: Uuid::parse_str(&id).unwrap(),
            encrypted_name,
            encrypted_vsk,
            created_at,
            updated_at,
        }
    }
}

/// Creates a new vault with encrypted name and vault symmetric key.
///
/// This function generates a new vault with the given name and stores it in the database.
/// It performs the following operations:
/// 1. Generates a unique vault ID
/// 2. Creates a blind index (HMAC) of the vault name using the MAC key
/// 3. Encrypts the vault name with the user's encryption key
/// 4. Generates and encrypts a new vault symmetric key (VSK)
/// 5. Stores all encrypted data in the database
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection
/// * `vault_name` - The name of the vault to create
/// * `keys` - The `VaultKeys` containing the encryption and MAC keys
pub fn create_vault(
    conn: &Connection,
    vault_name: &str,
    keys: &VaultKeys,
) -> Result<EncryptedVault, Error> {
    let id = Uuid::new_v4();
    let vault_key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let encrypted_vault = EncryptedVault::encrypt(id, vault_name, &vault_key, 0, 0, &keys);

    // Store the new vault in the database
    crate::storage::create_vault(
        &conn,
        &encrypted_vault.id.to_string(),
        &encrypted_vault.encrypted_name,
        &encrypted_vault.encrypted_vsk,
    )?;

    Ok(encrypted_vault)
}

/// Lists all vaults in the database and prints their decrypted names.
///
/// This function retrieves all vaults from the database, decrypts their names using the provided
/// encryption key, and prints each vault's ID and name to the standard output.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection
/// * `keys` - The `VaultKeys` containing the encryption and MAC keys
pub fn list_vaults(conn: &Connection) -> Result<Vec<EncryptedVault>, Error> {
    let vaults = crate::storage::list_vaults(&conn)?;

    let list = vaults
        .into_iter()
        .map(
            |(id, enc_name, enc_vsk, created_at, updated_at)| EncryptedVault {
                id: Uuid::parse_str(&id).unwrap(),
                encrypted_name: enc_name,
                encrypted_vsk: enc_vsk,
                created_at,
                updated_at,
            },
        )
        .collect();

    Ok(list)
}

/// Deletes a vault by its name.
///
/// This function deletes a vault from the database by looking it up using a blind index
/// of the vault name. It performs the following operations:
/// 1. Generates a blind index (HMAC) of the vault name using the MAC key
/// 2. Deletes the vault from the database using the blind index
/// 3. Prints a confirmation message
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection
/// * `vault_name` - The name of the vault to delete
/// * `keys` - The `VaultKeys` containing the encryption and MAC keys
///
/// # Returns
///
/// Returns `Ok(())` on successful deletion, or an error if the database operation fails
pub fn delete_vault(conn: &Connection, vault_name: &str, keys: VaultKeys) -> Result<(), Error> {
    let vault_to_delete = list_vaults(conn)?
        .into_iter()
        .find(|vault| {
            if let Ok(name) = vault.decrypt_name(&keys) {
                name == vault_name
            } else {
                false
            }
        })
        .ok_or_else(|| Error::VaultNotFound(vault_name.to_string()))?;

    crate::storage::delete_vault(&conn, &vault_to_delete.id.to_string())?;

    Ok(())
}
