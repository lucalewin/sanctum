use rusqlite::params;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::Error;
use crate::models::{Record, Vault};

pub fn setup_database(db_path: &str) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute_batch(
        "BEGIN;
        CREATE TABLE IF NOT EXISTS vaults (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        );

        CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            FOREIGN KEY (vault_id) REFERENCES vaults(id)
        );
        COMMIT;",
    )
    .unwrap();
    conn
}

pub fn get_vaults(conn: &rusqlite::Connection) -> Result<Vec<Vault>, Error> {
    let mut stmt =
        conn.prepare("SELECT id, name, encryption_key, created_at, updated_at FROM vaults")?;
    let vaults = stmt.query_map([], |row| {
        Ok(Vault {
            id: row.get(0)?,
            name: row.get(1)?,
            encryption_key: row.get(2)?,
            created_at: row.get(3)?,
            updated_at: row.get(4)?,
        })
    })?;

    let mut vaults_vec = Vec::new();
    for vault in vaults {
        vaults_vec.push(vault?);
    }
    Ok(vaults_vec)
}

pub fn get_vault(conn: &rusqlite::Connection, id: Uuid) -> Result<Vault, Error> {
    let mut stmt = conn.prepare(
        "SELECT id, name, encryption_key, created_at, updated_at FROM vaults WHERE id = ?1",
    )?;

    let vault = stmt.query_row([id], |row| {
        Ok(Vault {
            id: row.get(0)?,
            name: row.get(1)?,
            encryption_key: row.get(2)?,
            created_at: row.get(3)?,
            updated_at: row.get(4)?,
        })
    })?;

    Ok(vault)
}

pub fn create_vault(conn: &rusqlite::Connection, vault: &Vault) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO vaults (
            id,
            name,
            encryption_key,
            created_at,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vault.id,
            vault.name,
            vault.encryption_key,
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
        ],
    )
    .map(|_| ())?;

    Ok(())
}

pub fn delete_vault(conn: &rusqlite::Connection, id: Uuid) -> Result<(), Error> {
    conn.execute("DELETE FROM vaults WHERE id = ?1", [id])
        .map(|_| ())?;

    Ok(())
}

pub fn get_records(conn: &rusqlite::Connection, vault_id: Uuid) -> Result<Vec<Record>, Error> {
    // Explicit column list to avoid relying on implicit column ordering
    let mut stmt = conn.prepare(
        "SELECT id, vault_id, encryption_key, data, created_at, updated_at \
             FROM records WHERE vault_id = ?1",
    )?;
    let records = stmt.query_map([vault_id], |row| {
        Ok(Record {
            id: row.get(0)?,
            vault_id: row.get(1)?,
            encryption_key: row.get(2)?,
            data: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    })?;

    let mut result = Vec::new();
    for record in records {
        result.push(record?);
    }
    Ok(result)
}

pub fn create_record(conn: &rusqlite::Connection, record: &Record) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO records (
            id,
            vault_id,
            encryption_key,
            data,
            created_at,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            record.id,
            record.vault_id,
            record.encryption_key,
            record.data,
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
        ],
    )
    .map(|_| ())?;

    Ok(())
}

pub fn update_record(conn: &rusqlite::Connection, record: &Record) -> Result<(), Error> {
    conn.execute(
        "UPDATE records SET
            vault_id = ?2,
            encryption_key = ?3,
            data = ?4,
            updated_at = ?5
        WHERE id = ?1",
        params![
            record.id,
            record.vault_id,
            record.encryption_key,
            record.data,
            OffsetDateTime::now_utc(),
        ],
    )
    .map(|_| ())?;

    Ok(())
}

pub fn delete_record(conn: &rusqlite::Connection, record_id: Uuid) -> Result<(), Error> {
    conn.execute("DELETE FROM records WHERE id = ?1", [record_id.to_string()])
        .map(|_| ())?;

    Ok(())
}
