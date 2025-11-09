use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, Path},
    http::StatusCode,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use jsonwebtoken::{DecodingKey, Validation};
use sanctum_shared::models::Vault;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppStateRef;

pub const ISSUER: &str = "https://sanctum.lucalewin.dev";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub nbf: u64,
}

pub struct Session(pub Uuid);

impl FromRequestParts<AppStateRef> for Session {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppStateRef,
    ) -> Result<Self, Self::Rejection> {
        // Extract the Bearer Token
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // Define JWT validation rules
        let validation = {
            let mut validation = Validation::default();
            validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
            validation.set_issuer(&[ISSUER]);
            validation.set_audience(&[ISSUER]);
            validation
        };

        // Decode and validate the JWT token
        let claims = jsonwebtoken::decode::<Claims>(
            bearer.token(),
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // extract the user ID from the JWT claims
        let user_id = Uuid::parse_str(&claims.claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(Session(user_id))
    }
}

pub struct OwnedVault(pub Vault);

impl axum::extract::FromRequestParts<AppStateRef> for OwnedVault {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppStateRef,
    ) -> Result<Self, Self::Rejection> {
        // 1. Extract the vault_id from the URL path
        let Path(vault_id) = parts
            .extract::<Path<Uuid>>()
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // 2. Extract the user_id from the session
        let Session(user_id) = Session::from_request_parts(parts, state).await?;

        // 3. Perform the ownership check query
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

        Ok(OwnedVault(vault))
    }
}
