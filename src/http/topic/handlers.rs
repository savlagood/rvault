use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};

use super::utils::is_valid_name;
use crate::http::auth::{errors::AuthError, policy::Permission, tokens::AccessTokenClaims, utils};

pub fn router() -> Router {
    Router::new().nest(
        "/topic",
        Router::new().route("/:topic_name", post(create_topic)),
    )
}

async fn create_topic(
    Path(topic_name): Path<String>,
    claims: AccessTokenClaims,
) -> Result<Response, AuthError> {
    let policy = claims.policy;

    match utils::check_topic_access_rights(&policy, Permission::Create, &topic_name) {
        Ok(is_have_rights) => {
            if !is_have_rights {
                return Err(AuthError::InvalidOperation);
            }
        }
        Err(_) => return Err(AuthError::InvalidToken),
    }

    Ok((
        StatusCode::IM_A_TEAPOT,
        format!(
            "Topic {} validation status: {}, your type is {:?}",
            topic_name,
            is_valid_name(&topic_name),
            claims.token_type,
        ),
    )
        .into_response())
}
