use axum::{
    routing::{get, post},
    Json, Router,
};
use jsonwebtoken::{DecodingKey, Validation};

use crate::{
    config::CONFIG,
    http::auth::{
        errors::AuthError,
        models::{TokenPair, TokenRequest},
        policy::Policies,
        tokens::{AccessTokenClaims, TokenType},
        utils,
    },
};

use super::tokens::RefreshTokenClaims;

pub fn router() -> Router {
    Router::new()
        .route("/token/issue/admin", post(issue_admin_token))
        .route("/token/issue/user", post(issue_user_token))
        .route("/token/refresh", post(refresh_token))
        .route("/protected", get(protected))
}

async fn issue_admin_token(
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenPair>, AuthError> {
    let root_token = CONFIG.root_token.as_str();
    if payload.token != root_token {
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

async fn refresh_token(Json(token_pair): Json<TokenPair>) -> Result<Json<TokenPair>, AuthError> {
    let decoding_key = DecodingKey::from_secret(CONFIG.jwt_secret.as_bytes());

    // Refresh token
    let refresh_token_claims =
        utils::decode_token::<RefreshTokenClaims>(&token_pair.refresh_token, &decoding_key)?.claims;

    // Access token
    let mut validator = Validation::new(jsonwebtoken::Algorithm::HS256);
    validator.validate_exp = false;

    let access_token_claims = jsonwebtoken::decode::<AccessTokenClaims>(
        &token_pair.access_token,
        &decoding_key,
        &validator,
    )
    .map_err(|_| AuthError::InvalidToken)?
    .claims;

    // Check ids
    if refresh_token_claims.access_token_id != access_token_claims.id {
        return Err(AuthError::DifferentTokens);
    }

    // Generate new token pair
    let policy = utils::get_admin_policy();
    let response_body = TokenPair::new(policy, TokenType::Admin)?;

    Ok(Json(response_body))
}

async fn protected(claims: AccessTokenClaims) -> Result<String, AuthError> {
    Ok(format!(
        "Welcome to the protected area! {:?}",
        claims.token_type
    ))
}
