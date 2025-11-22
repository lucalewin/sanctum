use pass::{Client, Config};
use secrecy::ExposeSecret;
use std::error::Error;
use uuid::Uuid;

/// Helper to build a unique temporary DB path for each test.
fn unique_db_path() -> String {
    let tmp = std::env::temp_dir();
    let fname = format!("pass_test_{}.db", Uuid::new_v4());
    tmp.join(fname).to_string_lossy().to_string()
}

#[test]
fn create_vault_and_record_roundtrip() -> Result<(), Box<dyn Error>> {
    // unique temp file per test
    let db_path = unique_db_path();

    // Use default config but point DB to temp path
    let mut config = Config::default();
    config.db_path = db_path.clone();

    // Create client and unlock
    let mut client = Client::from_config(config);
    client.unlock("password")?;

    // Create a vault and verify
    let _vault = client.create_vault("My Vault")?;
    let vaults = client.get_vaults()?;
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].name.expose_secret(), "My Vault");

    // Create a record
    let _record = client.create_record(vaults[0].id, "secret-data")?;
    let records = client.get_records(vaults[0].id)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].data.expose_secret(), "secret-data");

    // Cleanup DB file (ignore errors)
    let _ = std::fs::remove_file(db_path);

    Ok(())
}

#[test]
fn wrong_password_fails_decryption() -> Result<(), Box<dyn Error>> {
    let db_path = unique_db_path();

    let mut config = Config::default();
    config.db_path = db_path.clone();

    // Create client A and add a vault
    let mut client_a = Client::from_config(config.clone());
    client_a.unlock("right-password")?;
    client_a.create_vault("Locked Vault")?;

    // Now create a new client B reading the same DB and unlock with wrong password
    let mut client_b = Client::from_config(config);
    client_b.unlock("wrong-password")?;

    // Attempt to get vaults should fail due to decryption error
    let res = client_b.get_vaults();
    assert!(res.is_err());

    // Cleanup
    let _ = std::fs::remove_file(db_path);

    Ok(())
}
