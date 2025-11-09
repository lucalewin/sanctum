use serde::{Deserialize, Serialize};
use time::UtcDateTime;
use uuid::Uuid;

// ------------------------------------------
//               Registration
// ------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    pub email: String,
    pub client_start: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationStartResponse {
    pub server_start: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    /// The email needs to be the same as the one
    /// used in the [`RegistrationStartRequest::email`].
    pub email: String,
    pub salt: String,
    pub client_finish: String,
}

// ------------------------------------------
//                  Login
// ------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct LoginStartRequest {
    pub email: String,
    pub client_start: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStartResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginFinishRequest {
    pub email: String,
    pub client_finish: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginFinishResponse {
    pub access_token: String,
    pub salt: String,
    // TODO: add refresh_token and other nice stuff
}

// ------------------------------------------
//                  Vault
// ------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_vault_key: String,
    pub encrypted_name: String,
    pub created_at: UtcDateTime,
}

#[derive(Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub encrypted_record_key: String,
    pub encrypted_data_blob: String,
    pub created_at: UtcDateTime,
    pub updated_at: UtcDateTime,
}

#[derive(Serialize, Deserialize)]
pub struct CreateVaultRequest {
    pub encrypted_vault_key: String,
    pub encrypted_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreateRecordRequest {
    pub encrypted_record_key: String,
    pub encrypted_data_blob: String,
}
