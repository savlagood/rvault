use crate::{
    http::{errors::ResponseError, jwt_tokens::AccessTokenClaims},
    state::AppState,
    utils::{
        shared_keys::{SharedKeys, SharedKeysSettings},
        validators,
    },
};
use axum::{extract::State, routing::post, Json, Router};
use tracing::{error, info};

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
    info!(
        threshold = shared_keys_settings.threshold,
        total_keys = shared_keys_settings.total_keys,
        "Storage initialization requested"
    );

    validators::is_admin(&claims.token_type)?;

    let mut storage = state.get_storage_write().await;

    match storage.initialize(shared_keys_settings).await {
        Ok(shared_keys) => {
            info!("Storage initialized successfully");
            Ok(Json(shared_keys))
        }
        Err(err) => {
            error!(error = ?err, "Failed to initialize storage");
            Err(err.into())
        }
    }
}

async fn unseal_storage_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
    Json(shared_keys): Json<SharedKeys>,
) -> Result<(), ResponseError> {
    info!(
        shared_count = shared_keys.count(),
        "Storage unseal requested"
    );

    validators::is_admin(&claims.token_type)?;

    let mut storage = state.get_storage_write().await;
    match storage.unseal(shared_keys).await {
        Ok(()) => {
            info!("Storage unsealed successfully");
            Ok(())
        }
        Err(err) => {
            error!(error = ?err, "Failed to unseal storage");
            Err(err.into())
        }
    }
}

async fn seal_storage_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
) -> Result<(), ResponseError> {
    info!("Storage seal requested");

    validators::is_admin(&claims.token_type)?;

    let mut storage = state.get_storage_write().await;
    match storage.seal().await {
        Ok(()) => {
            info!("Storage sealed successfully");
            Ok(())
        }
        Err(err) => {
            error!(error = ?err, "Failed to seal storage");
            Err(err.into())
        }
    }
}
