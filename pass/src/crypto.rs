use argon2::Argon2;
use base64::{Engine, prelude::BASE64_STANDARD};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use secrecy::ExposeSecret;

use crate::models::{PlainRecord, PlainVault, Record, Vault};

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], crate::error::Error> {
    let mut master_key_bytes = [0u8; 32];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(&password.as_bytes(), &salt, &mut master_key_bytes)
        .map_err(|_| crate::error::Error::Other("Failed to derive key".into()))?;
    Ok(master_key_bytes)
}

pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, crate::error::Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| crate::error::Error::Other("Failed to create cipher".into()))?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| crate::error::Error::Other("Failed to encrypt data".into()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, crate::error::Error> {
    // Ensure we have at least a nonce (12 bytes) before slicing
    if data.len() < 12 {
        return Err(crate::error::Error::Other("Ciphertext too short".into()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| crate::error::Error::Other("Failed to create cipher".into()))?;
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| crate::error::Error::Other("Failed to decrypt data".into()))?;

    Ok(plaintext)
}

pub fn encrypt_vault(master_key: &[u8], vault: &PlainVault) -> Result<Vault, crate::error::Error> {
    let encrypted_key = encrypt_data(vault.encryption_key.expose_secret(), master_key)?;
    let encrypted_name = encrypt_data(
        vault.name.expose_secret().as_bytes(),
        &vault.encryption_key.expose_secret(),
    )?;

    let encoded_key = BASE64_STANDARD.encode(&encrypted_key);
    let encoded_name = BASE64_STANDARD.encode(&encrypted_name);

    Ok(Vault {
        id: vault.id,
        encryption_key: encoded_key,
        name: encoded_name,
        created_at: vault.created_at,
        updated_at: vault.updated_at,
    })
}

pub fn decrypt_vault(master_key: &[u8], vault: &Vault) -> Result<PlainVault, crate::error::Error> {
    let decoded_key = BASE64_STANDARD.decode(&vault.encryption_key)?;
    let decoded_name = BASE64_STANDARD.decode(&vault.name)?;

    let decrypted_key = decrypt_data(&decoded_key, master_key)?;
    let decrypted_name = decrypt_data(&decoded_name, &decrypted_key)?;

    Ok(PlainVault {
        id: vault.id,
        name: String::from_utf8(decrypted_name)?.into(),
        encryption_key: decrypted_key.into(),
        created_at: vault.created_at,
        updated_at: vault.updated_at,
    })
}

pub fn encrypt_record(
    vault_key: &[u8],
    record: &PlainRecord,
) -> Result<Record, crate::error::Error> {
    let encrypted_key = encrypt_data(record.encryption_key.expose_secret(), vault_key)?;
    let encrypted_data = encrypt_data(
        record.data.expose_secret().as_bytes(),
        record.encryption_key.expose_secret(),
    )?;

    let encoded_key = BASE64_STANDARD.encode(&encrypted_key);
    let encoded_data = BASE64_STANDARD.encode(&encrypted_data);

    Ok(Record {
        id: record.id,
        vault_id: record.vault_id,
        encryption_key: encoded_key,
        data: encoded_data,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

pub fn decrypt_record(
    vault_key: &[u8],
    record: &Record,
) -> Result<PlainRecord, crate::error::Error> {
    let decoded_key = BASE64_STANDARD.decode(&record.encryption_key)?;
    let decoded_data = BASE64_STANDARD.decode(&record.data)?;

    let decrypted_key = decrypt_data(&decoded_key, vault_key)?;
    let decrypted_data = decrypt_data(&decoded_data, &decrypted_key)?;

    Ok(PlainRecord {
        id: record.id,
        vault_id: record.vault_id,
        encryption_key: decrypted_key.into(),
        data: String::from_utf8(decrypted_data)?.into(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}
