use crate::{
    crypto,
    http::{errors::ResponseError, jwt_tokens::AccessTokenClaims, utils},
    models::{
        http::topics::{TopicEncryptionKey, TopicNames, TopicSettings},
        Encryption, StorageAndTopicKeys,
    },
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
use std::collections::HashSet;
use tracing::info;

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(get_topic_names_handler))
        .route("/:topic_name", post(create_topic_handler))
        .with_state(app_state)
}

async fn get_topic_names_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
) -> Result<Json<TopicNames>, ResponseError> {
    // checks
    utils::is_admin(&claims.token_type)?;
    utils::ensure_storage_is_unsealed(state.clone()).await?;

    // actions
    let topic_names = get_topic_names(state).await?;

    let response_body = TopicNames { names: topic_names };
    Ok(Json(response_body))
}

async fn get_topic_names(state: AppState) -> Result<HashSet<String>, ResponseError> {
    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    let db = state.get_db();
    let topic_dao = topics::TopicDao::new(db);
    let topic_names = topic_dao.fetch_topic_names(storage_key).await?;

    Ok(topic_names)
}

async fn create_topic_handler(
    claims: AccessTokenClaims,
    Path(topic_name): Path<String>,
    State(state): State<AppState>,
    Json(topic_settings): Json<TopicSettings>,
) -> Result<(StatusCode, Json<TopicEncryptionKey>), ResponseError> {
    // checks
    let policies = claims.policies;
    policies.ensure_topic_access_permitted(topic_name.as_str(), Permission::Create)?;

    utils::ensure_storage_is_unsealed(state.clone()).await?;
    utils::ensure_topic_name_valid(topic_name.as_str())?;

    // actions
    let topic_key = generate_key_and_create_topic(topic_name, topic_settings, state).await?;

    let response_body = TopicEncryptionKey { value: topic_key };
    Ok((StatusCode::CREATED, Json(response_body)))
}

async fn generate_key_and_create_topic(
    name: String,
    settings: TopicSettings,
    state: AppState,
) -> Result<Option<String>, ResponseError> {
    let (primary_topic_key, topic_key_to_return) = match settings.encryption {
        Encryption::Provided(key) => (key.clone(), Some(key)),
        Encryption::Generate => {
            let key_bytes = crypto::generate_256_bit_key();
            let key = crypto::base64::encode(&key_bytes);

            (key.clone(), Some(key))
        }
        Encryption::None => {
            let config = state.get_config();
            let key = config.default_topic_key.clone();

            (key, None)
        }
    };
    let topic_key = crypto::hkdf::string_into_256_bit_key(primary_topic_key)?;

    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    let keyset = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };

    let db = state.get_db();
    let topic_dao = topics::TopicDao::new(db);

    let topic = topics::TopicDto::new(name, &keyset)?;
    let hashed_name = topic.hashed_name.clone();

    topic_dao.create(topic).await?;

    info!("Topic {hashed_name:?} successfully created");

    Ok(topic_key_to_return)
}
