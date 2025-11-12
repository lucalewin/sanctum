use sanctum_client::{Config, LockedClient};

#[tokio::main]
async fn main() {
    let password = "password";
    let config = Config {
        api_base_url: "http://localhost:3000".to_string(),
        salt: vec![0; 32],
    };
    let client = LockedClient::from_config(config).unwrap();
    let client = client.unlock_offline(password).unwrap();

    // do all the desired operations here
    // such as creating a vault, updating a record, etc.

    let vault = client.create_vault("My Vault").unwrap();
    let record = client
        .create_record(vault.id, "{\"key\": \"value\"}")
        .unwrap();

    let updated_record = client
        .update_record(vault.id, record.id, "{\"key\": \"updated_value\"}")
        .unwrap();

    let vaults = client.list_vaults();
    let records = client.list_records(vault.id);

    client.delete_record(vault.id, record.id).unwrap();
    client.delete_vault(vault.id).unwrap();

    let _ = client.lock();
}
