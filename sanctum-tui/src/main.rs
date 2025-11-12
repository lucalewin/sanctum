use sanctum_client::{Config, LockedClient};

#[tokio::main]
async fn main() {
    let email = "user@example.com";
    let password = "password";

    LockedClient::register(email, password).await.unwrap();

    let config = Config {
        api_base_url: "https://sanctum.lucalewin.dev".to_string(),
        salt: vec![0; 32],
    };
    let locked = LockedClient::from_config(config).unwrap();
    let client = locked.login(email, password).await.unwrap();

    let personal_vault = client.create_vault("Personal").unwrap();
    let _ = client
        .create_record(personal_vault.id, "record_data_here")
        .unwrap();

    client.sync_once().await.unwrap();
    client.lock();
}
