use argon2::{PasswordHash, PasswordVerifier, password_hash::SaltString};
use dialoguer::{Password, theme::ColorfulTheme};
use rusqlite::Connection;

use crate::{
    crypto::VaultKeys,
    storage::{Metadata, db_connection},
};

// #![allow(unused)]
pub mod crypto;
pub mod error;
pub mod onboarding;
pub mod password;
pub mod record;
mod remote;
pub mod storage;
pub mod sync;
pub mod vault;

pub fn login() -> (Connection, VaultKeys) {
    let conn = db_connection().expect("Failed to connect to vault database");
    let password_hash = Metadata::get_str(&conn, "password_hash")
        .expect("Failed to retrieve password hash from metadata")
        .unwrap();

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .report(false)
        .validate_with(|input: &String| -> Result<(), &str> {
            let hash = PasswordHash::new(&password_hash).unwrap();
            if argon2::Argon2::default()
                .verify_password(input.as_bytes(), &hash)
                .is_ok()
            {
                Ok(())
            } else {
                Err("Password is wrong")
            }
        })
        .interact()
        .unwrap();

    let master_salt = Metadata::get_str(&conn, "salt")
        .expect("Failed to retrieve master salt from metadata")
        .unwrap();
    let root_key =
        crypto::derive_master_key(&password, &SaltString::from_b64(&master_salt).unwrap()).unwrap();
    let keys = crypto::derive_subkeys(&root_key);

    (conn, keys)
}
