#![allow(unused)]

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use sanctum_shared::models::{CreateRecordRequest, CreateVaultRequest, Record, Vault};
use serde::Deserialize;
use time::OffsetDateTime;
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
            get(get_vault)
                .put(create_or_update_vault)
                .delete(delete_vault),
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

#[derive(Debug, Deserialize)]
pub struct ListVaultsQuery {
    /// The timestamp to start listing vaults from in UNIX seconds.
    since: Option<i64>,
}

/// GET /vaults
/// List all vaults for the current user.
async fn list_vaults(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
    Query(params): Query<ListVaultsQuery>,
) -> Result<(StatusCode, Json<Vec<Vault>>), StatusCode> {
    let result = if let Some(timestamp) = params.since {
        let since =
            OffsetDateTime::from_unix_timestamp(timestamp).map_err(|_| StatusCode::BAD_REQUEST)?;

        // fetch all vaults for the current user
        // which were created or updated since the given timestamp
        sqlx::query_as!(
            Vault,
            r#"
            SELECT * FROM vaults
            WHERE user_id = $1
                AND updated_at > $2
            "#,
            user_id,
            since
        )
        .fetch_all(&state.db)
        .await
    } else {
        // fetch all vaults for the current user
        sqlx::query_as!(
            Vault,
            r#"
            SELECT * FROM vaults
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&state.db)
        .await
    };

    let vaults = result.map_err(|e| {
        tracing::error!("Failed to fetch vaults: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((StatusCode::OK, Json(vaults)))
}

/// POST /vaults
/// Create a new vault for the current user.
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

/// GET /vaults/{vault_id}
/// Retrieve a vault for the current user.
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

/// PUT /vaults/{vault_id}
///
/// Create or update a vault with ownership check
///
/// - returns 201 Created when created
/// - returns 200 OK when updated or idempotent
/// - returns 409 Conflict when id exists and belongs to another user
async fn create_or_update_vault(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
    Path(vault_id): Path<Uuid>,
    Json(payload): Json<CreateVaultRequest>,
) -> Result<(StatusCode, Json<Vault>), StatusCode> {
    // start a transaction
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // try to select the row FOR UPDATE if it exists
    let existing = sqlx::query_as!(
        Vault,
        "SELECT * FROM vaults WHERE id = $1 FOR UPDATE",
        vault_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(existing) = existing {
        // check if the user owns the vault
        if existing.user_id != user_id {
            tx.rollback()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            return Err(StatusCode::CONFLICT);
        }

        // check if the payload is idempotent
        if existing.encrypted_name == payload.encrypted_name
            && existing.encrypted_vault_key == payload.encrypted_vault_key
        {
            tx.commit()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            return Ok((StatusCode::OK, Json(existing)));
        }

        // update and return updated row
        let updated = sqlx::query_as!(
            Vault,
            "UPDATE vaults
            SET
                encrypted_name = $1,
                encrypted_vault_key = $2,
                updated_at = now()
            WHERE id = $3
            RETURNING *",
            payload.encrypted_name,
            payload.encrypted_vault_key,
            vault_id
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| {
            // TODO: ensure we rollback on error
            // (map_err returns StatusCode, but we still try to rollback)
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // not found -> insert with provided id
    let created = sqlx::query_as!(
        Vault,
        "INSERT INTO vaults
            (id, user_id, encrypted_name, encrypted_vault_key)
        VALUES ($1, $2, $3, $4)
        RETURNING *",
        vault_id,
        user_id,
        payload.encrypted_name,
        payload.encrypted_vault_key
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::CREATED, Json(created)))
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
