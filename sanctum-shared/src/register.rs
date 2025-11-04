use bytes::Bytes;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, RegistrationRequest,
    RegistrationResponse, RegistrationUpload, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

use crate::DefaultCipherSuite;

pub fn server_start(
    setup: &ServerSetup<DefaultCipherSuite>,
    account: &[u8],
    client_start: &[u8],
) -> Result<Bytes, Box<dyn std::error::Error>> {
    match ServerRegistration::<DefaultCipherSuite>::start(
        setup,
        RegistrationRequest::deserialize(client_start).unwrap(),
        account,
    ) {
        Ok(start_result) => Ok(Bytes::copy_from_slice(
            &start_result.message.serialize()[..],
        )),
        Err(err) => Err(err.to_string().into()),
    }
}

pub fn server_finish(client_finish: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let registration_upload =
        RegistrationUpload::<DefaultCipherSuite>::deserialize(client_finish).unwrap();

    let password_file = ServerRegistration::finish(registration_upload);

    Ok(password_file.serialize().to_vec())
}

pub fn client_start(password: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    match ClientRegistration::<DefaultCipherSuite>::start(&mut OsRng, password) {
        Ok(start) => Ok((
            start.state.serialize().to_vec(),
            start.message.serialize().to_vec(),
        )),
        Err(err) => return Err(err.to_string().into()),
    }
}

pub fn client_finish(
    password: &[u8],
    client_state: &[u8],
    server_message: &[u8],
) -> Result<Bytes, Box<dyn std::error::Error>> {
    let client_state = match ClientRegistration::<DefaultCipherSuite>::deserialize(client_state) {
        Ok(s) => s,
        Err(err) => return Err(err.to_string().into()),
    };

    let mut rng = OsRng;

    match client_state.finish(
        &mut rng,
        password,
        RegistrationResponse::deserialize(server_message).unwrap(),
        ClientRegistrationFinishParameters::default(),
    ) {
        Ok(finish) => Ok(Bytes::copy_from_slice(&finish.message.serialize()[..])),
        Err(err) => Err(err.to_string().into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_start() {
        let password = b"password";
        let (state, message) = client_start(password).unwrap();

        assert!(!state.is_empty());
        assert!(!message.is_empty());
    }
}
