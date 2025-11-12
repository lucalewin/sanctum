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

    let vault = client.create_vault("Personal").unwrap();
    let record = client
        .create_record(vault.id, "{\"key\": \"value\"}")
        .unwrap();

    let other_record = client
        .create_record(vault.id, "{\"key\": \"other_value\"}")
        .unwrap();

    dbg!(&record);
    dbg!(&other_record);

    dbg!(client.list_records(vault.id));

    client.delete_record(vault.id, record.id).unwrap();
    client.delete_record(vault.id, other_record.id).unwrap();
    client.delete_vault(vault.id).unwrap();

    dbg!(client.list_vaults());

    for vault in client.list_vaults() {
        for record in client.list_records(vault.id) {
            dbg!("deleting", &record.id);
            client.delete_record(vault.id, record.id).unwrap();
        }
        client.delete_vault(vault.id).unwrap();
    }

    let _ = client.lock();
}
