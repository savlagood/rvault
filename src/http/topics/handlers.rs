use crate::{
    http::{errors::ResponseError, jwt_tokens::AccessTokenClaims, utils},
    policies::Permission,
    state::AppState,
    topics,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
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

    #[derive(Serialize, Deserialize)]
    pub struct TopicNames {
        topics: Vec<String>,
    }

    impl TopicNames {
        pub fn new(names: Vec<String>) -> Self {
            Self { topics: names }
        }
    }
}

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/topics", get(get_list_of_topics_handler))
        .route("/topics/:topic_name", post(create_topic_handler))
        .with_state(app_state)
}

async fn get_list_of_topics_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
) -> Result<Json<models::TopicNames>, ResponseError> {
    // checks
    utils::is_admin(&claims.token_type)?;
    utils::ensure_storage_is_unsealed(state.clone()).await?;

    // action
    let topic_names = topics::fetch_topic_names(state).await?;
    let topic_names = models::TopicNames::new(topic_names);

    Ok(Json(topic_names))
}

async fn create_topic_handler(
    claims: AccessTokenClaims,
    Path(topic_name): Path<String>,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<models::TopicEncryptionKey>), ResponseError> {
    // checks
    let policies = claims.policies;
    policies.ensure_topic_access_permitted(topic_name.as_str(), Permission::Create)?;

    utils::ensure_storage_is_unsealed(state.clone()).await?;
    utils::ensure_topic_name_valid(topic_name.as_str())?;

    // action
    let topic_key_bytes = topics::create_topic(topic_name.clone(), state).await?;
    let topic_key = models::TopicEncryptionKey::from_key_bytes(&topic_key_bytes);

    info!("Topic '{}' successfully created", topic_name);
    Ok((StatusCode::CREATED, Json(topic_key)))
}
