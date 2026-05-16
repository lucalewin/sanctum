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
            encrypted_name BLOB NOT NULL,
            encrypted_vsk BLOB NOT NULL
        ) STRICT;

        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL,
            encrypted_payload BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        ) STRICT;
        ",
    )?;
    Ok(())
}

pub fn create_vault(
    conn: &Connection,
    id: &str,
    encrypted_name: &[u8],
    encrypted_vsk: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO vaults (id, encrypted_name, encrypted_vsk) VALUES (?1, ?2, ?3)",
        (id, encrypted_name, encrypted_vsk),
    )?;
    Ok(())
}

pub fn list_vaults(conn: &Connection) -> Result<Vec<(String, Vec<u8>, Vec<u8>)>> {
    let mut stmt = conn.prepare("SELECT id, encrypted_name, encrypted_vsk FROM vaults")?;
    let vault_iter = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

    let mut vaults = Vec::new();
    for vault in vault_iter {
        vaults.push(vault?);
    }
    Ok(vaults)
}

pub fn delete_vault(conn: &Connection, vault_id: &str) -> Result<()> {
    conn.execute("DELETE FROM vaults WHERE id = ?1", [vault_id])?;
    Ok(())
}

pub fn create_record(conn: &Connection, vault_id: &str, encrypted_payload: &[u8]) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    // let updated_at = chrono::Utc::now().timestamp();

    conn.execute(
        "INSERT INTO items (id, vault_id, encrypted_payload, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        (id, vault_id, encrypted_payload, 0, 0), // FIXME: updated_at should be current timestamp, but for testing we set it to 0. Use chrono crate to get current timestamp in production.
    )?;
    Ok(())
}

pub fn list_records(conn: &Connection, vault_id: &str) -> Result<Vec<Vec<u8>>> {
    let mut stmt = conn.prepare(
        "SELECT encrypted_payload FROM items WHERE vault_id = ?1 ORDER BY updated_at DESC",
    )?;
    let record_iter = stmt.query_map([vault_id], |row| Ok(row.get(0)?))?;

    let mut records = Vec::new();
    for record in record_iter {
        records.push(record?);
    }
    Ok(records)
}

pub fn delete_record(conn: &Connection, vault_id: &str, item_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM items WHERE vault_id = ?1 AND id = ?2",
        (vault_id, item_id),
    )?;
    Ok(())
}

pub fn get_record_by_title(
    conn: &Connection,
    vault_id: &str,
    title_hmac: &str,
) -> Result<Option<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT encrypted_payload, updated_at FROM items WHERE vault_id = ?1 AND title_hmac = ?2",
    )?;
    let mut rows = stmt.query((vault_id, title_hmac))?;

    if let Some(row) = rows.next()? {
        Ok(Some((row.get(0)?, row.get(1)?)))
    } else {
        Ok(None)
    }
}

pub struct Metadata;

impl Metadata {
    pub fn set(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )?;
        Ok(())
    }

    pub fn set_str(conn: &Connection, key: &str, value: &str) -> Result<()> {
        Metadata::set(conn, key, value.as_bytes())
    }

    pub fn get(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
        let mut stmt = conn.prepare("SELECT value FROM metadata WHERE key = ?1")?;
        let mut rows = stmt.query([key])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn get_str(conn: &Connection, key: &str) -> Result<Option<String>> {
        if let Some(value) = Metadata::get(conn, key)? {
            Ok(Some(String::from_utf8(value).unwrap()))
        } else {
            Ok(None)
        }
    }

    pub fn exists(conn: &Connection, key: &str) -> Result<bool> {
        let mut stmt = conn.prepare("SELECT 1 FROM metadata WHERE key = ?1 LIMIT 1")?;
        let mut rows = stmt.query([key])?;
        Ok(rows.next()?.is_some())
    }

    pub fn delete(conn: &Connection, key: &str) -> Result<()> {
        conn.execute("DELETE FROM metadata WHERE key = ?1", [key])?;
        Ok(())
    }
}
