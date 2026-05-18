use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use secrecy::SecretBox;
use sha2::Sha256;

use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};

use crate::error::Error;

pub fn derive_master_key(password: &str, salt: &SaltString) -> Result<[u8; 32], Error> {
    // OWASP recommended baseline parameters for Argon2id
    let params = Params::new(
        65536,    // m_cost: 64 MB memory
        3,        // t_cost: 3 iterations
        4,        // p_cost: 4 degrees of parallelism
        Some(32), // Output length: 32 bytes (256 bits) for XChaCha20
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
        .expect("Failed to derive key");

    Ok(key)
}

// Helper to generate a new salt during registration
pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

pub struct VaultKeys {
    pub enc_key: SecretBox<[u8; 32]>,
    pub mac_key: SecretBox<[u8; 32]>,
}

pub fn derive_subkeys(root_key: &[u8; 32]) -> VaultKeys {
    let hk = Hkdf::<Sha256>::new(None, root_key);

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];

    // The strings "enc" and "mac" are Info strings.
    // They guarantee the two resulting keys are mathematically distinct.
    hk.expand(b"enc", &mut enc_key).expect("HKDF expand failed");
    hk.expand(b"mac", &mut mac_key).expect("HKDF expand failed");

    VaultKeys {
        enc_key: SecretBox::new(Box::new(enc_key)),
        mac_key: SecretBox::new(Box::new(mac_key)),
    }
}

pub fn encrypt_payload(
    key: &[u8; 32],
    plaintext_json: &[u8],
    vault_id: &str, // Used as Associated Data
) -> (Vec<u8>, [u8; 24]) {
    // Returns (Ciphertext, Nonce)
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);

    // Generate a random 192-bit (24-byte) nonce
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext_json,
        aad: vault_id.as_bytes(), // Binds the data to this specific vault
    };

    // The ciphertext returned here automatically includes the 16-byte Poly1305 MAC tag at the end.
    let ciphertext = cipher.encrypt(nonce, payload).expect("Encryption failed");

    (ciphertext, nonce_bytes)
}

pub fn decrypt_payload(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8; 24],
    vault_id: &str,
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let nonce = XNonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: vault_id.as_bytes(),
    };

    // This will fail if the ciphertext was altered, the key is wrong,
    // or the vault_id (AAD) doesn't match.
    cipher.decrypt(nonce, payload)
}
