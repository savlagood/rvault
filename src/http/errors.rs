use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Enumeration of possible errors returned in responses.
#[derive(Debug)]
pub enum ResponseError {
    /// Error indicating an invalid token was provided.
    InvalidToken,
    /// Error indicating the provided root token is invalid.
    InvalidRootToken,
    /// Error during token creation.
    TokenCreation,
    /// Error indicating mismatched refresh and access tokens.
    DifferentTokens,
    /// Error indicating access is denied for the operation.
    AccessDenied,
    /// Error indicating insufficient permissions to set global default fields.
    CannotSetDefaultFields,
    /// Error indicating an invalid operation was attempted.
    InvalidOperation,
}

impl IntoResponse for ResponseError {
    /// Converts a `ResponseError` into an HTTP response with appropriate status and error message.
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ResponseError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            ResponseError::InvalidRootToken => (StatusCode::UNAUTHORIZED, "Invalid root token"),
            ResponseError::TokenCreation => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error")
            }
            ResponseError::DifferentTokens => (
                StatusCode::BAD_REQUEST,
                "Passed refresh_token is not related to passed access_token",
            ),
            ResponseError::AccessDenied => (StatusCode::FORBIDDEN, "Access denied"),
            ResponseError::CannotSetDefaultFields => (
                StatusCode::BAD_REQUEST,
                "Do not have permissions to set global defaults fields",
            ),
            ResponseError::InvalidOperation => (
                StatusCode::FORBIDDEN,
                "Do not have permissions to do this operation",
            ),
        };

        let body = Json(json!({
            "error": message,
        }));

        (status, body).into_response()
    }
}
