use pass::{Client, Config, Error};
use secrecy::ExposeSecret;

fn main() -> Result<(), Error> {
    // check out examples/config.rs for more details
    let config = Config::default();
    let mut client = Client::from_config(config);
    client.unlock("password")?;

    // create three new vaults
    client.create_vault("My Vault")?;
    client.create_vault("Another Vault")?;
    client.create_vault("Third Vault")?;

    let vaults = client.get_vaults()?;

    // create some records in the newly created vaults
    client.create_record(vaults[0].id, "My Record Again")?;
    client.create_record(vaults[1].id, "Record in different vault1")?;
    client.create_record(vaults[2].id, "Record in different vault2")?;
    client.create_record(vaults[0].id, "Record in different vault3")?;
    client.create_record(vaults[1].id, "Record in different vault4")?;
    client.create_record(vaults[2].id, "Record in different vault5")?;

    // display the vaults and their records
    for vault in &vaults {
        let records = client.get_records(vault.id)?;
        println!("Vault: {}", vault.name.expose_secret());
        println!("Records: {:#?}", records);
    }

    Ok(())
}
