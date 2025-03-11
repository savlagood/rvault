use crate::{
    http::jwt_tokens::TokenError, policies::PoliciesError, secrets::SecretError,
    storage::StorageError, topics::TopicError, utils::hkdf::HkdfError,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

#[derive(Serialize, Deserialize)]
struct ErrorMessage {
    message: String,
}

impl ErrorMessage {
    fn with_message(message: String) -> Self {
        Self { message }
    }
}

const INTERNAL_STORAGE_ERROR: &str = "Internal Storage Error";

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("Do not have enough permissions to perform this operation")]
    AccessDenied,

    #[error("Passed refresh_token is not related to passed access_token")]
    DifferentTokens,

    #[error("Do not have permissions to set global defaults fields")]
    CannotSetDefaultFields,

    #[error("Topic name can only contain Latin letters (both uppercase and lowercase), numbers, and underscores")]
    InvalidTopicName,

    #[error("Secret name can only contain Latin letters (both uppercase and lowercase), numbers, and underscores")]
    InvalidSecretName,

    #[error(transparent)]
    HkdfError(#[from] HkdfError),

    #[error(transparent)]
    Token(#[from] TokenError),

    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Topic(#[from] TopicError),

    #[error(transparent)]
    Secret(#[from] SecretError),

    #[error(transparent)]
    Policies(#[from] PoliciesError),
}

impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ResponseError::AccessDenied => (StatusCode::FORBIDDEN, self.to_string()),
            ResponseError::DifferentTokens => (StatusCode::BAD_REQUEST, self.to_string()),
            ResponseError::CannotSetDefaultFields => (StatusCode::BAD_REQUEST, self.to_string()),

            ResponseError::InvalidTopicName => (StatusCode::BAD_REQUEST, self.to_string()),
            ResponseError::InvalidSecretName => (StatusCode::BAD_REQUEST, self.to_string()),

            ResponseError::HkdfError(err) => {
                error!("Error during hkdf operation: {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Vault Error".to_string(),
                )
            }

            ResponseError::Token(err) => match err {
                TokenError::CreationFailed(jwt_err) => {
                    error!("Failed to create JWT token: {jwt_err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to create JWT token".to_string(),
                    )
                }
                TokenError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            },

            ResponseError::Storage(err) => match err {
                StorageError::StorageCorrupted(_) => {
                    error!("Storage data has been corrupted: {err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        String::from(INTERNAL_STORAGE_ERROR),
                    )
                }
                StorageError::InternalStorage(err) => {
                    error!("Internal storage error: {err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        String::from(INTERNAL_STORAGE_ERROR),
                    )
                }
                StorageError::InvalidStorageState {
                    current: _,
                    expected: _,
                } => (StatusCode::BAD_REQUEST, err.to_string()),
                StorageError::InvalidSharedKeys(err) => (StatusCode::BAD_REQUEST, err.to_string()),
            },

            ResponseError::Topic(err) => match err {
                TopicError::AlreadyExists => (StatusCode::CONFLICT, err.to_string()),
                TopicError::InvalidStorageEncryptionKey(err) => {
                    error!("Internal storage error: {err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Storage Error".to_string(),
                    )
                }
                TopicError::Storage(err) => {
                    error!("Internal storage error: {err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Storage Error".to_string(),
                    )
                }
                TopicError::Database(err) => {
                    error!("Error during database operation: {err:?}");
                    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                }
                TopicError::TopicCorrupted => {
                    error!("Topic data has been corrupted: {}", err.to_string());
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        String::from("Topic's data has been corrupted"),
                    )
                }
                TopicError::NotFound => (
                    StatusCode::NOT_FOUND,
                    "The topic with the requested name was not found".to_string(),
                ),
                TopicError::InvalidKey => (StatusCode::FORBIDDEN, err.to_string()),
            },

            ResponseError::Secret(err) => match err {
                SecretError::InvalidStorageKey(err) => {
                    error!("Internal storage error: {err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Storage Error".to_string(),
                    )
                }
                SecretError::InvalidTopicKey(_err) => {
                    (StatusCode::FORBIDDEN, "Invalid topic key".to_string())
                }
                SecretError::InvalidSecretKey(_err) => {
                    (StatusCode::FORBIDDEN, "Invalid secret key".to_string())
                }
                SecretError::InvalidKeys => (StatusCode::FORBIDDEN, err.to_string()),
                SecretError::SecretCorrupted => {
                    error!("Secret data has been corrupted: {}", err.to_string());
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        String::from("Secret's data has been corrupted"),
                    )
                }
                SecretError::AlreadyExists => (StatusCode::CONFLICT, err.to_string()),
                SecretError::NotFound => (StatusCode::NOT_FOUND, err.to_string()),
                SecretError::Database(err) => {
                    error!("Error during database operation: {err:?}");
                    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                }
            },

            ResponseError::Policies(err) => (StatusCode::FORBIDDEN, err.to_string()),
        };

        let body = Json(ErrorMessage::with_message(message));

        (status, body).into_response()
    }
}
