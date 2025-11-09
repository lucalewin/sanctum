#![allow(unused)]

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use jsonwebtoken::{EncodingKey, Header};
use redis::AsyncTypedCommands;
use sanctum_shared::models::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
    RegistrationFinishRequest, RegistrationStartRequest, RegistrationStartResponse,
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AppStateRef;
use crate::middleware::Claims;
use crate::util::normalize_email;

pub fn routes() -> Router<AppStateRef> {
    Router::new()
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/login/start", post(login_start))
        .route("/login/finish", post(login_finish))
}

pub async fn register_start(
    State(state): State<AppStateRef>,
    Json(payload): Json<RegistrationStartRequest>,
) -> Result<Json<RegistrationStartResponse>, StatusCode> {
    // check if the email is already registered
    let user = sqlx::query!("SELECT id FROM users WHERE email = $1", payload.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if user.is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // start the OPAQUE registration process
    let decoded_client_start = BASE64_STANDARD
        .decode(payload.client_start)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let server_start = sanctum_shared::register::server_start(
        &state.server_setup,
        normalize_email(&payload.email).as_bytes(),
        &decoded_client_start,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let encoded_server_start = BASE64_STANDARD.encode(server_start);

    // Return the OPAQUE server start response
    Ok(Json(RegistrationStartResponse {
        server_start: encoded_server_start,
    }))
}

pub async fn register_finish(
    State(state): State<AppStateRef>,
    Json(payload): Json<RegistrationFinishRequest>,
) -> Result<StatusCode, StatusCode> {
    let decoded_client_finish = BASE64_STANDARD.decode(payload.client_finish).unwrap();
    let password_file = sanctum_shared::register::server_finish(&decoded_client_finish).unwrap();
    let encoded_password_file = BASE64_STANDARD.encode(password_file);

    sqlx::query!(
        "INSERT INTO users (email, salt, password_file) VALUES ($1, $2, $3)",
        normalize_email(&payload.email),
        payload.salt,
        encoded_password_file
    )
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}

// ------------------------------------------------------------------------------------------------
//                                             Login
// ------------------------------------------------------------------------------------------------

pub async fn login_start(
    State(state): State<AppStateRef>,
    Json(payload): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, StatusCode> {
    let user = sqlx::query!(
        "SELECT id, email, password_file FROM users WHERE email = $1",
        payload.email
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    let password_file = BASE64_STANDARD
        .decode(user.password_file)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let client_start = BASE64_STANDARD
        .decode(payload.client_start)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (server_state, message) = sanctum_shared::login::server_start(
        &state.server_setup,
        //user.id.as_bytes(),
        user.email.as_bytes(),
        &password_file,
        &client_start,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    // save server state in cache
    let mut redis = state.redis.clone();
    let encoded_server_state = BASE64_STANDARD.encode(server_state);
    redis
        .set_ex(format!("login_state_{}", user.id), encoded_server_state, 60)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LoginStartResponse {
        message: BASE64_STANDARD.encode(message),
    }))
}

pub async fn login_finish(
    State(state): State<AppStateRef>,
    Json(payload): Json<LoginFinishRequest>,
) -> Result<Json<LoginFinishResponse>, StatusCode> {
    // get the user details from the database
    let user = sqlx::query!(
        "SELECT * FROM users WHERE email = $1",
        normalize_email(&payload.email)
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(user) = user else {
        return Err(StatusCode::NOT_FOUND);
    };

    // get login_state from cache
    let login_state = state
        .redis
        .clone()
        .get_del(format!("login_state_{}", user.id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // decode the payload data
    let client_finish = BASE64_STANDARD
        .decode(payload.client_finish)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let server_start = BASE64_STANDARD
        .decode(login_state)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // finish the OPAQUE login process
    let server_finish = sanctum_shared::login::server_finish(&client_finish, &server_start)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // generate a JWT
    let now = OffsetDateTime::now_utc();
    let expires = now + Duration::days(7);
    let claims = Claims {
        sub: user.id.to_string(),
        exp: expires.unix_timestamp() as u64,
        iat: now.unix_timestamp() as u64,
        iss: "https://sanctum.lucalewin.dev".into(),
        nbf: now.unix_timestamp() as u64,
        aud: "https://sanctum.lucalewin.dev".into(),
        jti: uuid::Uuid::new_v4().to_string(),
    };

    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&state.jwt_secret.as_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LoginFinishResponse {
        access_token: token,
        salt: user.salt,
    }))
}
