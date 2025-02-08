use crate::{
    http::{
        errors::ResponseError,
        jwt_tokens::{
            decode_token_into_claims, decode_token_into_claims_without_exp_checking,
            AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenType,
        },
    },
    policies::Policies,
    state::AppState,
};
use axum::{extract::State, routing::post, Json, Router};
use jsonwebtoken::DecodingKey;

pub mod utils {
    use crate::policies::{self, Permission, Policies};

    const FULL_ACCESS: &[Permission] = &[
        Permission::Create,
        Permission::Read,
        Permission::Update,
        Permission::Delete,
    ];

    pub fn get_admin_policies() -> Policies {
        let mut policies = Policies::new();

        let default_topic = policies
            .get_topic_mut(policies::DEFAULT)
            .expect("Policies do not have default value after initialization");

        default_topic.set_permissions(FULL_ACCESS);
        default_topic.set_secret_permissions(policies::DEFAULT, FULL_ACCESS);

        policies
    }
}

mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct TokenRequest {
        pub token: String,
    }
}

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/token/issue/admin", post(issue_admin_token))
        .route("/token/issue/user", post(issue_user_token))
        .route("/token/refresh", post(refresh_token))
        .with_state(app_state)
}

async fn issue_admin_token(
    State(state): State<AppState>,
    Json(payload): Json<models::TokenRequest>,
) -> Result<Json<TokenPair>, ResponseError> {
    let config = state.get_config();
    let root_token = config.root_token.as_str();

    if payload.token != root_token {
        return Err(ResponseError::AccessDenied);
    }

    let policies = utils::get_admin_policies();
    let response_body = TokenPair::new(config, policies, TokenType::Admin)?;

    Ok(Json(response_body))
}

async fn issue_user_token(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
    Json(mut policies): Json<Policies>,
) -> Result<Json<TokenPair>, ResponseError> {
    if !matches!(claims.token_type, TokenType::Admin) {
        return Err(ResponseError::AccessDenied);
    }

    policies.initialize_defaults();

    let default_topic = policies.get_default_topic();
    let default_secret = default_topic.get_default_secret();

    if !default_topic.permissions.is_empty() || !default_secret.is_empty() {
        return Err(ResponseError::CannotSetDefaultFields);
    }

    let config = state.get_config();
    Ok(Json(TokenPair::new(config, policies, TokenType::User)?))
}

async fn refresh_token(
    State(state): State<AppState>,
    Json(token_pair): Json<TokenPair>,
) -> Result<Json<TokenPair>, ResponseError> {
    let config = state.get_config();
    let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

    let refresh_token_claims =
        decode_token_into_claims::<RefreshTokenClaims>(&token_pair.refresh_token, &decoding_key)?
            .claims;
    let access_token_claims = decode_token_into_claims_without_exp_checking::<AccessTokenClaims>(
        &token_pair.access_token,
        &decoding_key,
    )?
    .claims;

    // Check ids
    if refresh_token_claims.access_token_id != access_token_claims.id {
        return Err(ResponseError::DifferentTokens);
    }

    // Generate new token pair
    let policies = access_token_claims.policies;
    let token_type = access_token_claims.token_type;

    let response_body = TokenPair::new(config, policies, token_type)?;

    Ok(Json(response_body))
}
