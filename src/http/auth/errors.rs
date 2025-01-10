use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    InvalidRootToken,
    TokenCreation,
    // DifferentTokens,
    AccessDenied,
    SetDefaultsFields,
    InvalidOperation,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::InvalidRootToken => (StatusCode::UNAUTHORIZED, "Invalid root token"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            // AuthError::DifferentTokens => (
            //     StatusCode::BAD_REQUEST,
            //     "Passed refresh_token is not related to passed access_token",
            // ),
            AuthError::AccessDenied => (StatusCode::FORBIDDEN, "Access denied"),
            AuthError::SetDefaultsFields => (
                StatusCode::BAD_REQUEST,
                "Do not have permissions to set global defaults fields",
            ),
            AuthError::InvalidOperation => (
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
