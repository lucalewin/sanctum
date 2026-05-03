use directories::ProjectDirs;
use uuid::Uuid;

pub fn list_vaults() {
    let Some(project_dirs) = ProjectDirs::from("dev", "lucalewin", "sanctum") else {
        println!("Could not determine project directories.");
        return;
    };

    let data_dir = project_dirs.data_dir();

    let conn = match crate::storage::open_vault_db(data_dir.join("vault.db")) {
        Ok(conn) => conn,
        Err(e) => {
            println!("Failed to open vault database: {}", e);
            return;
        }
    };

    let vaults = match crate::storage::list_vaults(&conn) {
        Ok(vaults) => vaults,
        Err(e) => {
            println!("Failed to list vaults: {}", e);
            return;
        }
    };
    // for (id, name_hmac) in vaults {
    //     println!("Vault ID: {}, Name HMAC: {}", id, name_hmac);
    // }
}

pub fn create_vault(name: &str) {
    let Some(project_dirs) = ProjectDirs::from("dev", "lucalewin", "sanctum") else {
        println!("Could not determine project directories.");
        return;
    };

    let data_dir = project_dirs.data_dir();

    let conn = match crate::storage::open_vault_db(data_dir.join("vault.db")) {
        Ok(conn) => conn,
        Err(e) => {
            println!("Failed to open vault database: {}", e);
            return;
        }
    };

    // ------- create data -------

    let vault_id = Uuid::new_v4().to_string();

    let mut raw_vsk = [0u8; 32];
    rand::fill(&mut raw_vsk);

    // let name_hmac = generate_blind_index(&master_keys.mac_key, name);

    // ------- store vault -------

    crate::storage::create_vault(&conn, &vault_id, "name_hmac", &[], &[]).unwrap();
    println!("create vault: {}", name);
}

pub fn delete_vault(id: &str) {
    let Some(project_dirs) = ProjectDirs::from("dev", "lucalewin", "sanctum") else {
        println!("Could not determine project directories.");
        return;
    };

    let data_dir = project_dirs.data_dir();

    let conn = match crate::storage::open_vault_db(data_dir.join("vault.db")) {
        Ok(conn) => conn,
        Err(e) => {
            println!("Failed to open vault database: {}", e);
            return;
        }
    };

    crate::storage::delete_vault(&conn, id).unwrap();
    println!("delete vault: {}", id);
}
