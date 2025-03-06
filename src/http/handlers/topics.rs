use crate::{
    http::{errors::ResponseError, jwt_tokens::AccessTokenClaims},
    models::{
        http::topics::{TopicEncryptionKey, TopicNames, TopicSettings},
        Encryption, StorageAndTopicKeys,
    },
    policies::Permission,
    state::AppState,
    topics,
    utils::{common::generate_external_key, hkdf, validators},
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
    validators::is_admin(&claims.token_type)?;
    validators::ensure_storage_is_unsealed(state.clone()).await?;

    // actions
    let topic_names = get_topic_names(state).await?;

    let response_body = TopicNames { names: topic_names };
    Ok(Json(response_body))
}

async fn get_topic_names(state: AppState) -> Result<HashSet<String>, ResponseError> {
    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    let db = state.get_db_conn();
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

    validators::ensure_storage_is_unsealed(state.clone()).await?;
    validators::ensure_topic_name_valid(topic_name.as_str())?;

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
    // topic key
    let (external_key, topic_key) = get_external_and_internal_topic_keys(
        settings.encryption.clone(),
        &state.get_config().default_topic_key,
    )?;

    // storage key
    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    // keyset
    let keyset = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };

    // create DAO
    let db = state.get_db_conn();
    let topic_dao = topics::TopicDao::new(db);

    // create topic structure
    let topic = topics::TopicDto::new(name, &keyset)?;
    let hashed_name = topic.hashed_name.clone();

    // save topic to database
    topic_dao.create(topic).await?;

    info!("Topic {hashed_name:?} successfully created");

    let external_key = match settings.encryption {
        Encryption::None => None,
        _ => Some(external_key),
    };
    Ok(external_key)
}

fn get_external_and_internal_topic_keys(
    encryption_type: Encryption,
    default_key: &str,
) -> Result<(String, Vec<u8>), ResponseError> {
    let external_key = generate_external_key(encryption_type, default_key);
    let internal_key = hkdf::string_into_256_bit_key(external_key.clone())?;

    Ok((external_key, internal_key))
}
