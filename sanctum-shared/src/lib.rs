pub mod login;
pub mod models;
pub mod register;
#[cfg(test)]
mod test;

use opaque_ke::{CipherSuite, argon2::Argon2};

#[allow(dead_code)]
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}
