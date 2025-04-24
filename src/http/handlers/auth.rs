use crate::{
    http::{
        errors::ResponseError,
        jwt_tokens::{
            decode_token_into_claims, decode_token_into_claims_without_exp_checking,
            AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenType,
        },
    },
    models::http::auth::TokenRequest,
    policies::Policies,
    state::AppState,
    utils::common::get_admin_policies,
};
use axum::{extract::State, routing::post, Json, Router};
use jsonwebtoken::DecodingKey;
use tracing::{debug, info, warn};

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/token/issue/admin", post(issue_admin_token))
        .route("/token/issue/user", post(issue_user_token))
        .route("/token/refresh", post(refresh_token))
        .with_state(app_state)
}

async fn issue_admin_token(
    State(state): State<AppState>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenPair>, ResponseError> {
    info!("Admin token issuance requested");

    let config = state.get_config();
    let root_token = config.root_token.as_str();

    if payload.token != root_token {
        warn!("Invalid root token provided in admin token request");
        return Err(ResponseError::AccessDenied);
    }

    let policies = get_admin_policies();

    match TokenPair::new(config, policies, TokenType::Admin) {
        Ok(token_pair) => {
            info!("Admin token pair successfully issued");
            Ok(Json(token_pair))
        }
        Err(err) => {
            warn!(error = ?err, "Failed to issue admin token pair");
            Err(err.into())
        }
    }
}

async fn issue_user_token(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
    Json(mut policies): Json<Policies>,
) -> Result<Json<TokenPair>, ResponseError> {
    info!("User token issuance requested");

    if !matches!(claims.token_type, TokenType::Admin) {
        warn!(
            issuer_type = ?claims.token_type,
            "Non-admin user attempted to issue user token"
        );
        return Err(ResponseError::AccessDenied);
    }

    policies.initialize_defaults();

    let default_topic = policies.get_default_topic();
    let default_secret = default_topic.get_default_secret();

    if !default_topic.permissions.is_empty() || !default_secret.is_empty() {
        warn!("Attempt to set default permissions in user token");
        return Err(ResponseError::CannotSetDefaultFields);
    }

    let config = state.get_config();
    match TokenPair::new(config, policies, TokenType::User) {
        Ok(token_pair) => {
            info!("User token pair successfully issued");
            Ok(Json(token_pair))
        }
        Err(err) => {
            warn!(error = ?err, "Failed to issue user token pair");
            Err(err.into())
        }
    }
}

async fn refresh_token(
    State(state): State<AppState>,
    Json(token_pair): Json<TokenPair>,
) -> Result<Json<TokenPair>, ResponseError> {
    info!("Token refresh requested");

    let config = state.get_config();
    let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

    let refresh_token_claims = match decode_token_into_claims::<RefreshTokenClaims>(
        &token_pair.refresh_token,
        &decoding_key,
    ) {
        Ok(claims) => {
            debug!("Refresh token successfully decoded");
            claims.claims
        }
        Err(err) => {
            warn!(error = ?err, "Failed to decode refresh token");
            return Err(err.into());
        }
    };
    let access_token_claims = match decode_token_into_claims_without_exp_checking::<AccessTokenClaims>(
        &token_pair.access_token,
        &decoding_key,
    ) {
        Ok(claims) => {
            debug!("Access token successfully decoded");
            claims.claims
        }
        Err(err) => {
            warn!(error = ?err, "Failed to decode access token");
            return Err(err.into());
        }
    };

    // Check ids
    if refresh_token_claims.access_token_id != access_token_claims.id {
        warn!(
            refresh_token_id = ?refresh_token_claims.access_token_id,
            access_token_id = ?access_token_claims.id,
            "Token IDs mismatch during refresh"
        );
        return Err(ResponseError::DifferentTokens);
    }

    // Generate new token pair
    let policies = access_token_claims.policies;
    let token_type = access_token_claims.token_type;

    match TokenPair::new(config, policies, token_type) {
        Ok(token_pair) => {
            info!("Token pair successfully refreshed");
            Ok(Json(token_pair))
        }
        Err(err) => {
            warn!(error = ?err, "Failed to generate new token pair during refresh");
            Err(err.into())
        }
    }
}
