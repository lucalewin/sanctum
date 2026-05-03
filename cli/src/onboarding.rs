use directories::ProjectDirs;

use crate::storage::{init_schema, open_vault_db};

pub fn onboard() {
    println!("Onboarding process...");

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
        Ok(_) => println!("Database schema initialized successfully."),
        Err(e) => {
            println!("Failed to initialize database schema: {}", e);
            return;
        }
    }

    println!("Onboarding complete.");
}
