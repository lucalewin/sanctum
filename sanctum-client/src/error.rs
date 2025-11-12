#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to derive key")]
    DeriveKey(argon2::Error),

    #[error("Sync is not allowed in offline mode")]
    SyncInOfflineMode,

    #[error("API error")]
    ApiError(#[from] reqwest::Error),

    #[error("Not found")]
    NotFound,

    #[error("Crypto error")]
    CryptoError,

    #[error("Invalid base64 data")]
    InvalidBase64,
}
