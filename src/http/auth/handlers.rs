use axum::{
    routing::{get, post},
    Json, Router,
};

use crate::{
    config::CONFIG,
    http::auth::{
        errors::AuthError,
        models::{RootToken, TokenPair},
        policy::Policies,
        tokens::{AccessTokenClaims, TokenType},
        utils,
    },
};

pub fn router() -> Router {
    Router::new()
        .route("/admin/token", post(issue_admin_token))
        .route("/user/token", post(issue_user_token))
        // .route("/token/refresh", post())
        .route("/protected", get(protected))
}

async fn issue_admin_token(Json(payload): Json<RootToken>) -> Result<Json<TokenPair>, AuthError> {
    let root_token = CONFIG.root_token.as_str();
    if payload.root_token != root_token {
        return Err(AuthError::InvalidRootToken);
    }

    let policy = utils::get_admin_policy();
    let response_body = TokenPair::new(policy, TokenType::Admin)?;

    Ok(Json(response_body))
}

async fn issue_user_token(
    claims: AccessTokenClaims,
    Json(mut policies): Json<Policies>,
) -> Result<Json<TokenPair>, AuthError> {
    match claims.token_type {
        TokenType::Admin => {
            policies.add_defaults();

            match policies.is_default_empty() {
                Ok(is_empty) => {
                    if !is_empty {
                        return Err(AuthError::SetDefaultsFields);
                    }
                }
                Err(_) => return Err(AuthError::InvalidToken),
            };

            Ok(Json(TokenPair::new(policies, TokenType::User)?))
        }
        _ => Err(AuthError::AccessDenied),
    }
}

async fn protected(claims: AccessTokenClaims) -> Result<String, AuthError> {
    Ok(format!(
        "Welcome to the protected area! {:?}",
        claims.token_type
    ))
}
