use pass::{Client, Config, Error};
use secrecy::ExposeSecret;
use std::path::PathBuf;

fn main() -> Result<(), Error> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let path = PathBuf::from(format!("{}/.local/share/pass/config.json", home));
    let config = Config::load_from_file(&path)?;
    let mut client = Client::from_config(config);
    client.unlock("password")?;

    // client.create_vault("My Vault")?;
    // client.create_vault("Another Vault")?;
    // client.create_vault("Third Vault")?;

    let vaults = client.get_vaults()?;

    for vault in &vaults {
        let records = client.get_records(vault.id)?;
        println!("Vault: {}", vault.name.expose_secret());
        println!("Records: {:#?}", records);
    }

    // client.create_record(vaults[0].id, "My Record Again")?;
    // client.create_record(vaults[1].id, "Record in different vault1")?;
    // client.create_record(vaults[2].id, "Record in different vault2")?;
    // client.create_record(vaults[0].id, "Record in different vault3")?;
    // client.create_record(vaults[1].id, "Record in different vault4")?;
    // client.create_record(vaults[2].id, "Record in different vault5")?;

    Ok(())
}
