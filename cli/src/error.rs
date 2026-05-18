#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage error: {0}")]
    StorageError(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Argon2Error(#[from] argon2::Error),
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("Vault not found: {0}")]
    VaultNotFound(String),
    #[error("Item not found: {0}")]
    ItemNotFound(String),
    #[error("String Conversion: {0}")]
    UTF8Error(#[from] std::string::FromUtf8Error),
    #[error("API error: {0}")]
    ApiError(#[from] reqwest::Error),
}
