use crate::{
    http::{
        auth::jwt_tokens::{
            utils::decode_token, AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenType,
        },
        errors::ResponseError,
    },
    policies::Policies,
    state::AppState,
};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use jsonwebtoken::{DecodingKey, Validation};

/// Utility functions for token-related operations
pub mod utils {
    use crate::policies::{self, Permission, Policies};

    const FULL_ACCESS: &[Permission] = &[
        Permission::Create,
        Permission::Read,
        Permission::Update,
        Permission::Delete,
    ];

    /// Creates an admin policy with full permissions.
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

/// Models for request payloads
mod models {
    use serde::{Deserialize, Serialize};

    /// Represents a request to issue a token.
    #[derive(Serialize, Deserialize)]
    pub struct TokenRequest {
        pub token: String,
    }
}

/// Defines the router for token management endpoints.
pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/token/issue/admin", post(issue_admin_token))
        .route("/token/issue/user", post(issue_user_token))
        .route("/token/refresh", post(refresh_token))
        .route("/protected", get(protected))
        .with_state(app_state)
}

/// Issues an admin token if the provided root token is valid.
async fn issue_admin_token(
    State(state): State<AppState>,
    Json(payload): Json<models::TokenRequest>,
) -> Result<Json<TokenPair>, ResponseError> {
    let config = state.get_config();
    let root_token = config.root_token.as_str();

    if payload.token != root_token {
        return Err(ResponseError::InvalidRootToken);
    }

    let policies = utils::get_admin_policies();
    let response_body = TokenPair::new(config, policies, TokenType::Admin)?;

    Ok(Json(response_body))
}

/// Issues a user token if the provided claims belong to an admin.
async fn issue_user_token(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
    Json(mut policies): Json<Policies>,
) -> Result<Json<TokenPair>, ResponseError> {
    if claims.token_type != TokenType::Admin {
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

/// Refreshes a token pair, ensuring the validity and consistency of the provided tokens.
async fn refresh_token(
    State(state): State<AppState>,
    Json(token_pair): Json<TokenPair>,
) -> Result<Json<TokenPair>, ResponseError> {
    let config = state.get_config();

    let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

    // Refresh token
    let refresh_token_claims =
        decode_token::<RefreshTokenClaims>(&token_pair.refresh_token, &decoding_key)?.claims;

    // Access token
    let mut validator = Validation::new(jsonwebtoken::Algorithm::HS256);
    validator.validate_exp = false;

    let access_token_claims = jsonwebtoken::decode::<AccessTokenClaims>(
        &token_pair.access_token,
        &decoding_key,
        &validator,
    )
    .map_err(|_| ResponseError::InvalidToken)?
    .claims;

    // Check ids
    if refresh_token_claims.access_token_id != access_token_claims.id {
        return Err(ResponseError::DifferentTokens);
    }

    // Generate new token pair
    let polies = utils::get_admin_policies();
    let response_body = TokenPair::new(config, polies, TokenType::Admin)?;

    Ok(Json(response_body))
}

async fn protected(claims: AccessTokenClaims) -> Result<String, ResponseError> {
    Ok(format!(
        "Welcome to the protected area! {:?}",
        claims.token_type
    ))
}
