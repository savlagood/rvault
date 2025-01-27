use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ResponseError {
    InvalidToken,
    InvalidRootToken,
    TokenCreation,
    DifferentTokens,
    AccessDenied,
    CannotSetDefaultFields,
    // InvalidOperation,
}

impl IntoResponse for ResponseError {
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
            // ResponseError::InvalidOperation => (
            //     StatusCode::FORBIDDEN,
            //     "Do not have permissions to do this operation",
            // ),
        };

        let body = Json(json!({
            "error": message,
        }));

        (status, body).into_response()
    }
}
