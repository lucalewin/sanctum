use argon2::Argon2;

use crate::Error;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], Error> {
    let mut master_key_bytes = [0u8; 32];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(&password.as_bytes(), &salt, &mut master_key_bytes)
        .map_err(Error::DeriveKey)?;
    Ok(master_key_bytes)
}
