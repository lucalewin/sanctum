pub mod login;
pub mod models;
pub mod register;
#[cfg(test)]
mod test;

use opaque_ke::{CipherSuite, argon2::Argon2};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

// #[derive(Serialize, Deserialize)]
// pub struct RegistrationStartRequest {
//     pub username: String,
//     pub registration_request_bytes: String,
// }

// #[derive(Serialize, Deserialize)]
// pub struct RegistrationFinishRequest {
//     pub username: String,
//     pub registration_request_bytes: String,
// }

// pub mod register {
//     use opaque_ke::ClientRegistration;
//     use rand::rngs::OsRng;

//     use crate::DefaultCipherSuite;

//     pub fn client_start(username: &str, password: &str) {
//         let mut client_rng = OsRng;
//         let client_registration_start_result =
//             ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
//                 .unwrap();
//         let registration_request_bytes = client_registration_start_result.message.serialize();
//     }
//     pub fn client_finish() {}

//     pub fn server_start() {}
//     pub fn server_finish() {}
// }

// pub mod login {
//     pub fn start() {}
//     pub fn finish() {}
// }
