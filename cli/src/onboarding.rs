use argon2::{PasswordHasher, password_hash::SaltString};
use chacha20poly1305::aead::OsRng;
use dialoguer::{Input, Password, Select, theme::ColorfulTheme};
use directories::ProjectDirs;

use crate::{
    crypto::{derive_master_key, derive_subkeys},
    remote::register,
    storage::{Metadata, init_schema, open_vault_db},
    vault::create_vault,
};

pub fn onboard() {
    let Some(project_dirs) = ProjectDirs::from("dev", "lucalewin", "sanctum") else {
        println!("Could not determine project directories.");
        return;
    };

    let config_dir = project_dirs.config_dir();
    if let Err(e) = std::fs::create_dir_all(config_dir) {
        println!("Failed to create config directory: {}", e);
        return;
    }

    let data_dir = project_dirs.data_dir();
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        println!("Failed to create data directory: {}", e);
        return;
    }

    let sqlite_path = data_dir.join("vault.db");
    let conn = match open_vault_db(&sqlite_path) {
        Ok(conn) => conn,
        Err(e) => {
            println!("Failed to initialize vault database: {}", e);
            return;
        }
    };

    match init_schema(&conn) {
        Ok(_) => (), //println!("Database schema initialized successfully."),
        Err(e) => {
            println!("Failed to initialize database schema: {}", e);
            return;
        }
    }

    let selections = &["Login to existing account", "Create new account"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an option")
        .report(false)
        .default(0)
        .items(&selections[..])
        .interact()
        .unwrap();

    match selection {
        0 => login_existing(),
        1 => create_account(conn),
        _ => unreachable!(),
    }

    println!("Onboarding complete.");
}

fn create_account(mut conn: rusqlite::Connection) {
    println!("Create new account");
    let email: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Email")
        .validate_with({
            move |input: &String| -> Result<(), &str> {
                if input.contains('@') {
                    Ok(())
                } else {
                    Err("This is not a mail address")
                }
            }
        })
        .interact_text()
        .unwrap();

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .with_confirmation("Repeat password", "Error: the passwords don't match.")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.chars().count() > 2 {
                Ok(())
            } else {
                Err("Password must be longer than 2")
            }
        })
        .interact()
        .unwrap();

    let password_salt = SaltString::generate(&mut OsRng);

    println!("Creating online account...");
    register(&email, &password, &password_salt).unwrap();
    println!("Online account created successfully.");

    let argon2 = argon2::Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &password_salt)
        .unwrap();

    let master_salt = SaltString::generate(&mut OsRng);
    let master_key = derive_master_key(&password, &master_salt).unwrap();
    let keys = derive_subkeys(&master_key);

    let tx = conn.transaction().unwrap();

    Metadata::set_str(&tx, "email", email.as_str()).unwrap();
    Metadata::set_str(&tx, "password_hash", password_hash.to_string().as_str()).unwrap();
    Metadata::set_str(&tx, "salt", master_salt.as_str()).unwrap();
    Metadata::set_str(&tx, "last_sync_timestamp", "0").unwrap();

    let default_vault_title = "Personal".to_lowercase();
    let enc_vault = create_vault(&tx, &default_vault_title, &keys).unwrap();

    Metadata::set_str(&tx, "default_vault_id", &enc_vault.id.to_string()).unwrap();

    tx.commit().unwrap();
}

fn login_existing() {
    println!("Login to existing account");
    // let mail: String = Input::with_theme(&ColorfulTheme::default())
    //     .with_prompt("Email")
    //     .validate_with({
    //         let mut force = None;
    //         move |input: &String| -> Result<(), &str> {
    //             if input.contains('@') || (force.as_ref() == Some(input)) {
    //                 Ok(())
    //             } else {
    //                 force = Some(input.clone());
    //                 Err("This is not a mail address; type the same value again to force use")
    //             }
    //         }
    //     })
    //     .interact_text()
    //     .unwrap();

    // let password = Password::with_theme(&ColorfulTheme::default())
    //     .with_prompt("Password")
    //     .interact()
    //     .unwrap();
}
