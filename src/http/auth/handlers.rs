use axum::{extract::State, routing::post, Json, Router};
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    http::{
        auth::{
            errors::AuthError,
            policy::Policies,
            tokens::{AccessTokenClaims, RefreshTokenClaims},
            utils,
        },
        server::AppContext,
    },
};

pub fn router() -> Router<AppContext> {
    Router::new().route("/admin/token", post(issue_admin_token))
}

#[derive(Serialize, Deserialize)]
struct RootToken {
    root_token: String,
}

#[derive(Serialize, Deserialize)]
struct AccessRefreshToken {
    access_token: String,
    refresh_token: String,
}

impl AccessRefreshToken {
    fn new(config: &Config, policy: Policies) -> Result<Self, AuthError> {
        let jwt_secret = config.jwt_secret.as_bytes();
        let encoding_key = EncodingKey::from_secret(jwt_secret);

        let access_token_claims = AccessTokenClaims::new(policy, config.access_token_exp);
        let access_token = utils::encode_token(&access_token_claims, &encoding_key)?;

        let refresh_token_claims =
            RefreshTokenClaims::new(access_token_claims.id, config.refresh_token_exp);
        let refresh_token = utils::encode_token(&refresh_token_claims, &encoding_key)?;

        Ok(Self {
            access_token,
            refresh_token,
        })
    }
}

async fn issue_admin_token(
    context: State<AppContext>,
    Json(payload): Json<RootToken>,
) -> Result<Json<AccessRefreshToken>, AuthError> {
    let root_token = context.config.root_token.as_str();
    if payload.root_token != root_token {
        return Err(AuthError::InvalidRootToken);
    }

    let policy = utils::get_admin_policy();
    let response_body = AccessRefreshToken::new(&context.config, policy)?;

    Ok(Json(response_body))
}
