use crate::{
    crypto,
    http::{errors::ResponseError, jwt_tokens::AccessTokenClaims},
    policies::Permission,
    state::AppState,
    storage::StorageState,
    topics::Topic,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use tracing::info;

mod models {
    use crate::crypto;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct TopicEncryptionKey {
        key: String,
    }

    impl TopicEncryptionKey {
        pub fn from_key_bytes(key: &[u8]) -> Self {
            let key = crypto::base64::encode(key);
            Self { key }
        }
    }
}

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/topics/:topic_name", post(create_new_topic_handler))
        .with_state(app_state)
}

async fn create_new_topic_handler(
    claims: AccessTokenClaims,
    Path(topic_name): Path<String>,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<models::TopicEncryptionKey>), ResponseError> {
    // checks
    let policies = claims.policies;
    policies.ensure_topic_access_permitted(topic_name.as_str(), Permission::Create)?;

    {
        let storage = state.get_storage_read().await;
        storage.ensure_state_is(StorageState::Unsealed)?;
    }

    ensure_topic_name_valid(topic_name.as_str())?;

    // action
    let hashed_topic_name = crypto::claculate_string_hash_base64(&topic_name);
    let topic_key = create_topic(hashed_topic_name, state).await?;

    info!("Topic '{}' successfully created", topic_name);
    Ok((StatusCode::CREATED, Json(topic_key)))
}

async fn create_topic(
    name: String,
    state: AppState,
) -> Result<models::TopicEncryptionKey, ResponseError> {
    let storage = state.get_storage_read().await;

    let storage_key = storage.get_encryption_key()?;
    let topic_key = crypto::generate_256_bit_key();

    let topic = Topic::new(name, storage_key, &topic_key)?;

    let db = state.get_db();
    db.create_topic(topic).await?;

    let topic_key = models::TopicEncryptionKey::from_key_bytes(&topic_key);
    Ok(topic_key)
}

fn ensure_topic_name_valid(topic_name: &str) -> Result<(), ResponseError> {
    if validate_topic_name(topic_name) {
        Ok(())
    } else {
        Err(ResponseError::InvalidTopicName)
    }
}

fn validate_topic_name(topic_name: &str) -> bool {
    topic_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
}
