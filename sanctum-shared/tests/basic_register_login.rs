use base64::{Engine, prelude::BASE64_STANDARD};
use opaque_ke::ServerSetup;
use rand::rngs::OsRng;

use sanctum_shared::DefaultCipherSuite;

#[test]
fn both() {
    let email = "test@example.com";
    let password = "password";

    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

    // REGISTER

    let password_file = {
        // client
        let (client_state, message) =
            sanctum_shared::register::client_start(&password.as_bytes()).unwrap();
        // server
        let server_message =
            sanctum_shared::register::server_start(&setup, &email.as_bytes(), &message).unwrap();

        // client
        let client_message = sanctum_shared::register::client_finish(
            &password.as_bytes(),
            &client_state,
            &server_message,
        )
        .unwrap();
        // server
        sanctum_shared::register::server_finish(&client_message).unwrap()
    };

    let encoded = BASE64_STANDARD.encode(password_file);
    dbg!(&encoded);
    let password_file = BASE64_STANDARD.decode(encoded).unwrap();

    // let encoded = "WkUHatvnrLbmwkaaD+f8ySgQpyercgWyi54JB/De13j6TFs0dRyCcOm4kT425r4JrD4df8L6vZyt5d4Yt3W6bO50HMjp+gXBaO/6c3Fs4RCu3YmceZRVaFAAd+Jnh0iusB9f/OnOga0U4UIMPU/gVrsu9N9PcRFICQ1BgHl7ZxTZDZNa7fILAp9dQ6TKfqZvORu9UUeAWZMp6EiSfrxL9vWDBNZ5y9WVwrwcDearDV6PwuuOkXEKKexesoUCR+sQ";
    // let password_file = BASE64_STANDARD.decode(encoded).unwrap();

    // assert!(!password_file.is_empty());

    // // LOGIN

    // let email = "user@example.com";
    // let password = "password";

    // client
    let (client_state, client_message) =
        sanctum_shared::login::client_start(&password.as_bytes()).unwrap();
    // server
    let (server_state, server_message) = sanctum_shared::login::server_start(
        &setup,
        &email.as_bytes(),
        &password_file,
        &client_message,
    )
    .unwrap();

    // client
    let client_message =
        sanctum_shared::login::client_finish(&password.as_bytes(), &client_state, &server_message)
            .unwrap();
    // server
    sanctum_shared::login::server_finish(&client_message, &server_state).unwrap();
}
