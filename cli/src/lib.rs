#![allow(unused)]
pub mod crypto;
pub mod onboarding;
pub mod password;
pub mod record;
pub mod storage;
// pub mod sync;
pub mod vault;

use directories::ProjectDirs;

pub fn db_connection() -> Result<rusqlite::Connection, String> {
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
