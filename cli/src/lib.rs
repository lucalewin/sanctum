pub mod crypto;
pub mod onboarding;
pub mod password;
pub mod record;
pub mod storage;
pub mod sync;
pub mod vault;

use argon2::password_hash::SaltString;
use clap::Args;
use directories::ProjectDirs;
use uuid::Uuid;

use crate::crypto::{VaultKeys, decrypt_payload, encrypt_payload, generate_blind_index};

#[derive(Args)]
pub struct PasswordOptions {
    #[arg(short, long, default_value = "20")]
    pub length: usize,
    #[arg(short, long)]
    pub numbers: bool,
    #[arg(short, long)]
    pub uppercase: bool,
    #[arg(short, long)]
    pub symbols: bool,
}

pub struct Client {
    keys: VaultKeys,
}

impl Client {
    pub fn login(password: &str) -> Self {
        println!("Logging in...");
        let root_key =
            crypto::derive_master_key(password, &SaltString::from_b64("ssdkusdsdfhg").unwrap());
        let keys = crypto::derive_subkeys(&root_key);
        Self { keys }
    }

    pub fn create_vault(&self, vault_name: &str) {
        let vault_id = Uuid::new_v4().to_string();

        let mut raw_vsk = [0u8; 32];
        rand::fill(&mut raw_vsk);

        let name_hmac = generate_blind_index(&self.keys.mac_key, vault_name);

        let (name_ciphertext, name_nonce) =
            encrypt_payload(&self.keys.enc_key, vault_name.as_bytes(), &vault_id);
        let mut encrypted_name = name_nonce.to_vec();
        encrypted_name.extend_from_slice(&name_ciphertext);

        let (vsk_ciphertext, vsk_nonce) = encrypt_payload(&self.keys.enc_key, &raw_vsk, &vault_id);
        let mut encrypted_vsk = vsk_nonce.to_vec();
        encrypted_vsk.extend_from_slice(&vsk_ciphertext);

        let conn = db_connection().expect("Failed to connect to vault database");
        crate::storage::create_vault(
            &conn,
            &vault_id,
            &name_hmac,
            &encrypted_name,
            &encrypted_vsk,
        )
        .unwrap();
        println!("Creating vault: {}", vault_name);
    }

    pub fn list_vaults(&self) {
        let conn = db_connection().expect("Failed to connect to vault database");
        crate::storage::list_vaults(&conn)
            .unwrap()
            .iter()
            .map(|(id, hmac, enc_name, enc_vsk)| {
                let (nonce_slice, ciphertext) = enc_name.split_at(24);
                let mut nonce = [0u8; 24];
                nonce.copy_from_slice(nonce_slice);
                let name = decrypt_payload(&self.keys.mac_key, &ciphertext, &nonce, id).unwrap();

                (id, String::from_utf8(name).unwrap())
            })
            .for_each(|(id, name_hmac)| println!("Vault ID: {}, Name: {}", id, name_hmac));
        println!("Listing vaults...");
    }

    pub fn delete_vault(&self, name: &str) {
        let name_hmac = generate_blind_index(&self.keys.mac_key, name);

        let conn = db_connection().expect("Failed to connect to vault database");
        crate::storage::delete_vault(&conn, &name_hmac).unwrap();

        println!("Deleting vault with name: {}", name);
    }
}

fn db_connection() -> Result<rusqlite::Connection, String> {
    let Some(project_dirs) = ProjectDirs::from("dev", "lucalewin", "sanctum") else {
        return Err("Could not determine project directories.".to_string());
    };

    let data_dir = project_dirs.data_dir();

    let conn = match crate::storage::open_vault_db(data_dir.join("vault.db")) {
        Ok(conn) => conn,
        Err(e) => {
            return Err(format!("Failed to open vault database: {}", e));
        }
    };

    Ok(conn)
}
