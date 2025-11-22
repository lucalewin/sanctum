use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A generic wrapper for errors represented as strings.
    #[error("{0}")]
    Other(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Other(s.into())
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Other(format!("Argon2 error: {:?}", e))
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(e: chacha20poly1305::aead::Error) -> Self {
        Error::Other(format!("AEAD error: {:?}", e))
    }
}
