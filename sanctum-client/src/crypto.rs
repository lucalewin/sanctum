use argon2::Argon2;
use base64::{Engine, prelude::BASE64_STANDARD};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use secrecy::ExposeSecret;

use crate::{
    Error,
    models::{EncryptedVault, PlainVault},
};

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], Error> {
    let mut master_key_bytes = [0u8; 32];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(&password.as_bytes(), &salt, &mut master_key_bytes)
        .map_err(Error::DeriveKey)?;
    Ok(master_key_bytes)
}

pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| Error::CryptoError)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::CryptoError)
}

pub fn encrypt_vault(plain: &PlainVault, master_key: &[u8]) -> Result<EncryptedVault, Error> {
    let encrypted_name = encrypt_data(plain.name.expose_secret().as_bytes(), &master_key).unwrap();
    let encrypted_vault_key = encrypt_data(plain.key.expose_secret(), &master_key).unwrap();

    Ok(EncryptedVault {
        id: plain.id,
        encrypted_name: b64_encode(&encrypted_name),
        encrypted_vault_key: b64_encode(&encrypted_vault_key),
        created_at: plain.created_at,
        updated_at: plain.updated_at,
    })
}

pub fn decrypt_vault(encrypted: &EncryptedVault, master_key: &[u8]) -> Result<PlainVault, Error> {
    let vault_key = decrypt_data(&b64_decode(&encrypted.encrypted_vault_key)?, master_key)?;
    let name = decrypt_data(&b64_decode(&encrypted.encrypted_name)?, &vault_key)?;
    let name = String::from_utf8(name).map_err(|_| Error::CryptoError)?;

    Ok(PlainVault {
        id: encrypted.id,
        name: name.into(),
        key: vault_key.into(),
        created_at: encrypted.created_at,
        updated_at: encrypted.updated_at,
    })
}

fn b64_encode(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, Error> {
    BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| Error::InvalidBase64)
}
