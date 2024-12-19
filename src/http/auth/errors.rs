use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub enum AuthError {
    InvalidToken,
    InvalidRootToken,
    WrongCredentials,
    TokenCreation,
    MissingCredentials,
    DifferentTokens,
    TokenExpired,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::InvalidRootToken => (StatusCode::FORBIDDEN, "Invalid root token"),
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::DifferentTokens => (
                StatusCode::BAD_REQUEST,
                "Passed refresh_token is not related to passed access_token",
            ),
            AuthError::TokenExpired => (StatusCode::FORBIDDEN, "Token has expired"),
        };

        let body = Json(json!({
            "error": message,
        }));

        (status, body).into_response()
    }
}
