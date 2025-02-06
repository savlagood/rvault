use crate::{
    crypto::shared_keys::{SharedKeys, SharedKeysSettings},
    http::{
        errors::ResponseError,
        jwt_tokens::{AccessTokenClaims, TokenType},
    },
    state::AppState,
};
use axum::{extract::State, routing::post, Json, Router};

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/init", post(init_storage_handler))
        .route("/unseal", post(unseal_storage_handler))
        .route("/seal", post(seal_storage_handler))
        .with_state(app_state)
}

async fn init_storage_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
    Json(shared_keys_settings): Json<SharedKeysSettings>,
) -> Result<Json<SharedKeys>, ResponseError> {
    is_admin(&claims.token_type)?;

    let mut storage = state.get_storage_write().await;
    let shared_keys = storage.initialize(shared_keys_settings).await?;

    Ok(Json(shared_keys))
}

async fn unseal_storage_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
    Json(shared_keys): Json<SharedKeys>,
) -> Result<(), ResponseError> {
    is_admin(&claims.token_type)?;

    let mut storage = state.get_storage_write().await;
    storage.unseal(shared_keys).await?;

    Ok(())
}

async fn seal_storage_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
) -> Result<(), ResponseError> {
    is_admin(&claims.token_type)?;

    let mut storage = state.get_storage_write().await;
    storage.seal().await?;

    Ok(())
}

fn is_admin(token_type: &TokenType) -> Result<(), ResponseError> {
    if !matches!(token_type, TokenType::Admin) {
        return Err(ResponseError::AccessDenied);
    }

    Ok(())
}
