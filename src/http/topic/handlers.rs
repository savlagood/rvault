use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};

use crate::{
    http::{auth::jwt_tokens::AccessTokenClaims, errors::ResponseError},
    policies::{check_topic_access_permissions, Permission},
};

mod utils {
    pub fn is_valid_name(input: &str) -> bool {
        input.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
}

pub fn router() -> Router {
    Router::new().nest(
        "/topic",
        Router::new().route("/:topic_name", post(create_topic)),
    )
}

async fn create_topic(
    Path(topic_name): Path<String>,
    claims: AccessTokenClaims,
) -> Result<Response, ResponseError> {
    let policies = claims.policy;

    if !check_topic_access_permissions(&policies, Permission::Create, &topic_name) {
        return Err(ResponseError::InvalidOperation);
    }

    Ok((
        StatusCode::IM_A_TEAPOT,
        format!(
            "Topic {} validation status: {}, your type is {:?}",
            topic_name,
            utils::is_valid_name(&topic_name),
            claims.token_type,
        ),
    )
        .into_response())
}
