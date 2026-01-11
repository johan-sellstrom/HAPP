use thiserror::Error;

pub type HappResult<T> = Result<T, HappError>;

#[derive(Debug, Error)]
pub enum HappError {
    #[error("invalid data: {0}")]
    Invalid(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("expired: {0}")]
    Expired(String),
}
