use crate::{
    http::jwt_tokens::TokenError, policies::PoliciesError, storage::StorageError,
    topics::TopicsError,
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

    #[error(transparent)]
    Token(#[from] TokenError),

    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Topics(#[from] TopicsError),

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
                StorageError::StorageCorrupted => {
                    error!("Storage data has been corrupted!");
                    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                }
                StorageError::InternalStorage(err) => {
                    error!("Internal storage error: {err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Storage Error".to_string(),
                    )
                }
                StorageError::InvalidStorageState {
                    current: _,
                    expected: _,
                } => (StatusCode::BAD_REQUEST, err.to_string()),
                StorageError::InvalidSharedKeys(err) => (StatusCode::BAD_REQUEST, err.to_string()),
            },

            ResponseError::Topics(err) => match err {
                // TopicsError::ChecksumMismatch => (
                //     StatusCode::FORBIDDEN,
                //     "Invalid topic encryption key".to_string(),
                // ),
                TopicsError::InvalidStorageEncryptionKey => {
                    error!("Internal storage error: {err:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Storage Error".to_string(),
                    )
                }
                TopicsError::InvalidTopicEncryptionKey => (StatusCode::FORBIDDEN, err.to_string()),
                TopicsError::TopicAlreadyExists => (StatusCode::CONFLICT, err.to_string()),
                TopicsError::TopicCorrupted => {
                    error!("Topic data has been corrupted: {}", err.to_string());
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        String::from("Topic's data has been corrupted"),
                    )
                }
                TopicsError::Database(err) => {
                    error!("Error during database operation : {err:?}");
                    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                }
            },

            ResponseError::Policies(err) => (StatusCode::FORBIDDEN, err.to_string()),
        };

        let body = Json(ErrorMessage::with_message(message));

        (status, body).into_response()
    }
}
