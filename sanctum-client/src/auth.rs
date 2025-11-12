use argon2::password_hash::rand_core::RngCore;
use base64::{Engine, prelude::BASE64_STANDARD};
use chacha20poly1305::aead::OsRng;
use sanctum_shared::models::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
    RegistrationFinishRequest, RegistrationStartRequest, RegistrationStartResponse,
};

#[allow(unused)]
pub async fn register(email: &str, password: &str) -> Result<(), String> {
    let client = reqwest::Client::new();

    let (state, message) = sanctum_shared::register::client_start(&password.as_bytes()).unwrap();

    let response = client
        .post("http://localhost:3000/api/v1/auth/register/start")
        .json(&RegistrationStartRequest {
            email: email.to_string(),
            client_start: BASE64_STANDARD.encode(message),
        })
        .send()
        .await
        .unwrap();

    if response.status() != 200 {
        dbg!(response);
        return Err("Registration start failed".to_string());
    }

    let response = response.json::<RegistrationStartResponse>().await.unwrap();

    let server_message = BASE64_STANDARD.decode(response.server_start).unwrap();
    let message =
        sanctum_shared::register::client_finish(&password.as_bytes(), &state, &server_message)
            .unwrap();

    let salt = {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    };

    let status = client
        .post("http://localhost:3000/api/v1/auth/register/finish")
        .json(&RegistrationFinishRequest {
            email: email.to_string(),
            salt: BASE64_STANDARD.encode(salt),
            client_finish: BASE64_STANDARD.encode(message),
        })
        .send()
        .await
        .unwrap()
        .status();

    dbg!(status);

    Ok(())
}

pub async fn login(email: &str, password: &str) -> Result<LoginFinishResponse, String> {
    let client = reqwest::Client::new();

    let (state, message) = sanctum_shared::login::client_start(password.as_bytes()).unwrap();

    let response = client
        .post("http://localhost:3000/api/v1/auth/login/start")
        .json(&LoginStartRequest {
            email: email.to_string(),
            client_start: BASE64_STANDARD.encode(message),
        })
        .send()
        .await
        .unwrap()
        .json::<LoginStartResponse>()
        .await
        .unwrap();

    let server_start = BASE64_STANDARD.decode(response.message).unwrap();

    let message_bytes =
        sanctum_shared::login::client_finish(&password.as_bytes(), &state, &server_start).unwrap();

    let response = client
        .post("http://localhost:3000/api/v1/auth/login/finish")
        .json(&LoginFinishRequest {
            email: email.to_string(),
            client_finish: BASE64_STANDARD.encode(message_bytes),
        })
        .send()
        .await
        .unwrap()
        .json::<LoginFinishResponse>()
        .await
        .unwrap();

    Ok(response)
}
