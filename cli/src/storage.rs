use rusqlite::{Connection, Result};
use std::path::Path;

pub fn open_vault_db<P: AsRef<Path>>(db_path: P) -> Result<Connection> {
    let conn = Connection::open(db_path)?;

    // ENFORCE FOREIGN KEYS: SQLite disables them by default for legacy reasons.
    conn.pragma_update(None, "foreign_keys", "ON")?;

    // SECURE DELETE: Overwrite deleted data with zeros. Crucial for a password manager
    // so deleted encrypted blobs cannot be recovered from unallocated disk space.
    conn.pragma_update(None, "secure_delete", "ON")?;

    // WAL MODE: Write-Ahead Logging. Improves read/write concurrency and performance.
    conn.pragma_update(None, "journal_mode", "WAL")?;

    Ok(conn)
}

pub fn init_schema(conn: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS vaults (
            id TEXT PRIMARY KEY, -- Storing UUID as TEXT
            name_hmac TEXT NOT NULL UNIQUE,
            encrypted_name BLOB NOT NULL,
            encrypted_vsk BLOB NOT NULL
        ) STRICT;

        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL,
            title_hmac TEXT NOT NULL,
            encrypted_payload BLOB NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
        ) STRICT;

        -- Index for fast blind index lookups
        CREATE INDEX IF NOT EXISTS idx_items_lookup ON items(vault_id, title_hmac);
        ",
    )?;
    Ok(())
}

pub fn create_vault(
    conn: &Connection,
    id: &str,
    name_hmac: &str,
    encrypted_name: &[u8],
    encrypted_vsk: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO vaults (id, name_hmac, encrypted_name, encrypted_vsk) VALUES (?1, ?2, ?3, ?4)",
        (id, name_hmac, encrypted_name, encrypted_vsk),
    )?;
    Ok(())
}

pub fn list_vaults(conn: &Connection) -> Result<Vec<(String, String, Vec<u8>, Vec<u8>)>> {
    let mut stmt =
        conn.prepare("SELECT id, name_hmac, encrypted_name, encrypted_vsk FROM vaults")?;
    let vault_iter = stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;

    let mut vaults = Vec::new();
    for vault in vault_iter {
        vaults.push(vault?);
    }
    Ok(vaults)
}

pub fn delete_vault(conn: &Connection, name_hmac: &str) -> Result<()> {
    conn.execute("DELETE FROM vaults WHERE name_hmac = ?1", [name_hmac])?;
    Ok(())
}
