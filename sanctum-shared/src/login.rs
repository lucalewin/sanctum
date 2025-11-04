use std::error::Error;

use bytes::Bytes;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

use crate::DefaultCipherSuite;

pub fn server_start(
    setup: &ServerSetup<DefaultCipherSuite>,
    account: &[u8],
    password_file: &[u8],
    client_start: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let password_file =
        ServerRegistration::<DefaultCipherSuite>::deserialize(password_file).unwrap();

    let login_start_result = ServerLogin::start(
        &mut OsRng,
        setup,
        Some(password_file),
        CredentialRequest::deserialize(client_start).unwrap(),
        account,
        ServerLoginParameters::default(),
    )
    .unwrap();

    Ok((
        login_start_result.state.serialize().to_vec(),
        login_start_result.message.serialize().to_vec(),
        // Bytes::copy_from_slice(&login_start_result.message.serialize()[..]),
    ))
}

pub fn server_finish(client_finish: &[u8], server_start: &[u8]) -> Result<(), Box<dyn Error>> {
    let start_state = ServerLogin::<DefaultCipherSuite>::deserialize(server_start)?;

    let _ = start_state.finish(
        CredentialFinalization::deserialize(&client_finish).unwrap(),
        ServerLoginParameters::default(),
    )?;

    Ok(())
}

pub fn client_start(password: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let mut rng = OsRng;

    match ClientLogin::<DefaultCipherSuite>::start(&mut rng, password) {
        Ok(login) => Ok((
            login.state.serialize().to_vec(),
            login.message.serialize().to_vec(),
        )),
        Err(err) => return Err(err.to_string().into()),
    }
}

pub fn client_finish(
    password: &[u8],
    client_start: &[u8],
    server_start: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let client_state = ClientLogin::<DefaultCipherSuite>::deserialize(client_start)?;
    let credential_response = CredentialResponse::deserialize(server_start)?;

    let result = client_state.finish(
        &mut OsRng,
        password,
        credential_response,
        ClientLoginFinishParameters::default(),
    )?;

    Ok(result.message.serialize().to_vec())
}
