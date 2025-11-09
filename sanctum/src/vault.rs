#![allow(unused)]

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use sanctum_shared::models::{CreateRecordRequest, CreateVaultRequest, Record, Vault};
use uuid::Uuid;

use crate::{
    AppStateRef,
    middleware::{OwnedVault, Session},
    vault,
};

pub fn routes() -> Router<AppStateRef> {
    Router::new()
        .route("/vaults", get(list_vaults).post(create_vault))
        .route(
            "/vaults/{vault_id}",
            get(get_vault).put(update_vault).delete(delete_vault),
        )
        .route(
            "/vaults/{vault_id}/records",
            get(list_records).post(create_record),
        )
        .route(
            "/vaults/{vault_id}/records/{record_id}",
            get(get_record).put(update_record).delete(delete_record),
        )
}

async fn list_vaults(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
) -> Result<(StatusCode, Json<Vec<Vault>>), StatusCode> {
    let vaults = sqlx::query_as!(Vault, "SELECT * FROM vaults WHERE user_id = $1", user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, Json(vaults)))
}

async fn create_vault(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
    Json(payload): Json<CreateVaultRequest>,
) -> Result<(StatusCode, Json<Vault>), StatusCode> {
    let vault = sqlx::query_as!(
        Vault,
        "INSERT INTO vaults
            (user_id, encrypted_name, encrypted_vault_key)
        VALUES ($1, $2, $3) RETURNING *",
        user_id,
        payload.encrypted_name,
        payload.encrypted_vault_key
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(vault)))
}

async fn get_vault(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
    Path(vault_id): Path<Uuid>,
) -> Result<(StatusCode, Json<Vault>), StatusCode> {
    let vault = sqlx::query_as!(
        Vault,
        "SELECT * FROM vaults WHERE id = $1 AND user_id = $2",
        vault_id,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok((StatusCode::OK, Json(vault)))
}

async fn update_vault(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
) -> Result<StatusCode, StatusCode> {
    // todo!("should this really exists right now??")
    Ok(StatusCode::NOT_IMPLEMENTED)
}

async fn delete_vault(
    State(state): State<AppStateRef>,
    Path(vault_id): Path<Uuid>,
    Session(user_id): Session,
) -> Result<StatusCode, StatusCode> {
    sqlx::query!(
        "DELETE FROM vaults WHERE id = $1 AND user_id = $2",
        vault_id,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

// ----------------------------------------------------------------------------------------
//                                       Records
// ----------------------------------------------------------------------------------------

async fn list_records(
    State(state): State<AppStateRef>,
    OwnedVault(vault): OwnedVault,
) -> Result<(StatusCode, Json<Vec<Record>>), StatusCode> {
    let records = sqlx::query_as!(
        Record,
        "SELECT * FROM records WHERE vault_id = $1",
        vault.id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, Json(records)))
}

async fn create_record(
    State(state): State<AppStateRef>,
    OwnedVault(vault): OwnedVault,
    Json(payload): Json<CreateRecordRequest>,
) -> Result<(StatusCode, Json<Record>), StatusCode> {
    let record = sqlx::query_as!(
        Record,
        "INSERT INTO records (vault_id, encrypted_record_key, encrypted_data_blob) VALUES ($1, $2, $3) RETURNING *",
        vault.id,
        payload.encrypted_record_key,
        payload.encrypted_data_blob
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(record)))
}

async fn get_record(
    State(state): State<AppStateRef>,
    Path(record_id): Path<Uuid>,
    OwnedVault(vault): OwnedVault,
) -> Result<(StatusCode, Json<Record>), StatusCode> {
    let record = sqlx::query_as!(
        Record,
        "SELECT * FROM records WHERE vault_id = $1 AND id = $2",
        vault.id,
        record_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok((StatusCode::OK, Json(record)))
}

async fn update_record(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
) -> Result<StatusCode, StatusCode> {
    // todo!("should this really exists right now??")
    Ok(StatusCode::NOT_IMPLEMENTED)
}

async fn delete_record(
    State(state): State<AppStateRef>,
    Path(record_id): Path<Uuid>,
    OwnedVault(vault): OwnedVault,
) -> Result<StatusCode, StatusCode> {
    sqlx::query!(
        "DELETE FROM records WHERE vault_id = $1 AND id = $2",
        vault.id,
        record_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}
