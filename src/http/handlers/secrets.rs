use crate::{
    http::{
        errors::ResponseError,
        headers::{SecretKeyHeader, TopicKeyHeader},
        jwt_tokens::AccessTokenClaims,
    },
    models::{
        http::secrets::{
            SecretEncryptionKey, SecretNames, SecretSettings, SecretUpdateRequest, SecretValue,
        },
        Encryption, StorageAndTopicKeys, StorageTopicAndSecretKeys,
    },
    policies::Permission,
    secrets::{self, SecretDao, SecretError},
    state::AppState,
    topics::{self, TopicDao},
    utils::{common::generate_external_key, hkdf, validators},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use axum_extra::TypedHeader;
use std::collections::HashSet;
use tracing::info;

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(get_secret_names_handler))
        .route(
            "/:secret_name",
            post(create_secret_handler)
                .get(read_secret_handler)
                .put(update_secret_handler)
                .delete(delete_secret_handler),
        )
        .with_state(app_state)
}

async fn get_secret_names_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    Path(topic_name): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<SecretNames>, ResponseError> {
    // checks
    validators::is_admin(&claims.token_type)?;
    validators::ensure_storage_is_unsealed(state.clone()).await?;

    // actions
    let config = state.get_config();
    let primary_topic_key = topic_key_header
        .value
        .unwrap_or(config.default_topic_key.clone());

    let secret_names = get_secret_names(topic_name, primary_topic_key, state).await?;

    let response_body = SecretNames {
        names: secret_names,
    };
    Ok(Json(response_body))
}

async fn get_secret_names(
    topic_name: String,
    primary_topic_key: String,
    state: AppState,
) -> Result<HashSet<String>, ResponseError> {
    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    let topic_key = hkdf::string_into_256_bit_key(primary_topic_key)?;

    let keysey = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };

    let db = state.get_db_conn();
    let topic_dao = TopicDao::new(db.clone());

    let topic = topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&keysey)?;

    let secret_dao = secrets::SecretDao::new(db);
    let secret_names = secret_dao
        .fetch_secret_names(&topic.hashed_name, storage_key)
        .await?;

    Ok(secret_names)
}

async fn create_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(secret_settings): Json<SecretSettings>,
) -> Result<(StatusCode, Json<SecretEncryptionKey>), ResponseError> {
    // checks
    let policies = claims.policies;
    policies.ensure_topic_access_permitted(&topic_name, Permission::Update)?;
    policies.ensure_secret_access_permitted(&topic_name, &secret_name, Permission::Create)?;

    validators::ensure_storage_is_unsealed(state.clone()).await?;
    validators::ensure_secret_name_valid(&secret_name)?;

    // actions
    let primary_topic_key = topic_key_header
        .value
        .unwrap_or(state.get_config().default_topic_key.clone());

    let secret_key = create_secret(
        topic_name,
        secret_name,
        primary_topic_key,
        secret_settings,
        state,
    )
    .await?;

    let response_body = SecretEncryptionKey { value: secret_key };
    Ok((StatusCode::CREATED, Json(response_body)))
}

async fn create_secret(
    topic_name: String,
    secret_name: String,
    primary_topic_key: String,
    secret_settings: SecretSettings,
    state: AppState,
) -> Result<Option<String>, ResponseError> {
    // secret key
    let external_key = generate_external_key(
        secret_settings.encryption.clone(),
        &state.get_config().default_secret_key,
    );
    let secret_key = hkdf::string_into_256_bit_key(external_key.clone())?;

    // topic key
    let topic_key = hkdf::string_into_256_bit_key(primary_topic_key)?;

    // storage key
    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    // keyset: storage + topic
    let topic_keyset = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };

    // DAO objects
    let db = state.get_db_conn();
    let topic_dao = topics::TopicDao::new(db.clone());
    let secret_dao = secrets::SecretDao::new(db);

    // find topic by name
    let mut topic = topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&topic_keyset)?;

    // keyset: storage + topic + secret
    let secret_keyset = StorageTopicAndSecretKeys {
        storage_key,
        topic_key: &topic_key,
        secret_key: &secret_key,
    };

    // create secret structure and add to topic
    let secret = secrets::SecretDto::new(
        secret_name,
        secret_settings.value,
        topic.hashed_name.clone(),
        &secret_keyset,
    )?;
    if topic.is_contains_secret(&secret.hashed_name) {
        return Err(ResponseError::Secret(secrets::SecretError::AlreadyExists));
    }
    topic.add_hashed_secret_name(secret.hashed_name.clone(), &topic_keyset)?;

    // save topic with new secret to database
    let hashed_secret_name = secret.hashed_name.clone();
    let hashed_topic_name = topic.hashed_name.clone();

    secret_dao.create(secret).await?;
    topic_dao.update(topic).await?;

    info!("Secret {hashed_secret_name:?} in the topic {hashed_topic_name} successfully created");

    let external_key = match secret_settings.encryption {
        Encryption::None => None,
        _ => Some(external_key),
    };
    Ok(external_key)
}

async fn read_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<SecretValue>, ResponseError> {
    // checks
    let policies = claims.policies;
    policies.ensure_topic_access_permitted(&topic_name, Permission::Read)?;
    policies.ensure_secret_access_permitted(&topic_name, &secret_name, Permission::Read)?;

    validators::ensure_storage_is_unsealed(state.clone()).await?;

    // actions
    let external_topic_key = topic_key_header
        .value
        .unwrap_or(state.get_config().default_topic_key.clone());
    let external_secret_key = secret_key_header
        .value
        .unwrap_or(state.get_config().default_secret_key.clone());

    let secret_value = read_secret_value(
        topic_name,
        secret_name,
        external_topic_key,
        external_secret_key,
        state,
    )
    .await?;

    Ok(Json(secret_value))
}

async fn read_secret_value(
    topic_name: String,
    secret_name: String,
    external_topic_key: String,
    external_secret_key: String,
    state: AppState,
) -> Result<SecretValue, ResponseError> {
    let storage = state.get_storage_read().await;

    // keys
    let storage_key = storage.get_encryption_key()?;
    let topic_key = hkdf::string_into_256_bit_key(external_topic_key)?;
    let secret_key = hkdf::string_into_256_bit_key(external_secret_key)?;

    // DAO objects
    let db = state.get_db_conn();
    let topic_dao = TopicDao::new(db.clone());
    let secret_dao = SecretDao::new(db);

    // getting topic
    let topic_keyset = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };
    let topic = topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&topic_keyset)?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    // getting secret
    let secret_keyset = StorageTopicAndSecretKeys {
        storage_key,
        topic_key: &topic_key,
        secret_key: &secret_key,
    };
    let secret = secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&secret_keyset)?;

    Ok(SecretValue {
        value: secret.get_current_secret_value(&secret_keyset)?,
        version: secret.cursor,
    })
}

async fn update_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(update_request): Json<SecretUpdateRequest>,
) -> Result<StatusCode, ResponseError> {
    // checks
    let policies = claims.policies;
    policies.ensure_topic_access_permitted(&topic_name, Permission::Read)?;
    policies.ensure_secret_access_permitted(&topic_name, &secret_name, Permission::Update)?;

    validators::ensure_storage_is_unsealed(state.clone()).await?;

    // actions
    let external_topic_key = topic_key_header
        .value
        .unwrap_or(state.get_config().default_topic_key.clone());
    let external_secret_key = secret_key_header
        .value
        .unwrap_or(state.get_config().default_secret_key.clone());

    update_secret_value(
        topic_name,
        secret_name,
        update_request.value,
        external_topic_key,
        external_secret_key,
        state,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn update_secret_value(
    topic_name: String,
    secret_name: String,
    new_value: String,
    external_topic_key: String,
    external_secret_key: String,
    state: AppState,
) -> Result<(), ResponseError> {
    let storage = state.get_storage_read().await;

    // keys
    let storage_key = storage.get_encryption_key()?;
    let topic_key = hkdf::string_into_256_bit_key(external_topic_key)?;
    let secret_key = hkdf::string_into_256_bit_key(external_secret_key)?;

    // DAO objects
    let db = state.get_db_conn();
    let topic_dao = TopicDao::new(db.clone());
    let secret_dao = SecretDao::new(db);

    // getting topic
    let topic_keyset = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };
    let topic = topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&topic_keyset)?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    // getting secret
    let secret_keyset = StorageTopicAndSecretKeys {
        storage_key,
        topic_key: &topic_key,
        secret_key: &secret_key,
    };
    let mut secret = secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&secret_keyset)?;

    secret.update_secret_value(new_value, &secret_keyset)?;
    secret_dao.update(&secret).await?;

    Ok(())
}

async fn delete_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, ResponseError> {
    // checks
    let policies = claims.policies;
    policies.ensure_topic_access_permitted(&topic_name, Permission::Update)?;
    policies.ensure_secret_access_permitted(&topic_name, &secret_name, Permission::Delete)?;

    validators::ensure_storage_is_unsealed(state.clone()).await?;

    // actions
    let external_topic_key = topic_key_header
        .value
        .unwrap_or(state.get_config().default_topic_key.clone());
    let external_secret_key = secret_key_header
        .value
        .unwrap_or(state.get_config().default_secret_key.clone());

    delete_secret_value(
        topic_name,
        secret_name,
        external_topic_key,
        external_secret_key,
        state,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_secret_value(
    topic_name: String,
    secret_name: String,
    external_topic_key: String,
    external_secret_key: String,
    state: AppState,
) -> Result<(), ResponseError> {
    let storage = state.get_storage_read().await;

    // keys
    let storage_key = storage.get_encryption_key()?;
    let topic_key = hkdf::string_into_256_bit_key(external_topic_key)?;
    let secret_key = hkdf::string_into_256_bit_key(external_secret_key)?;

    // DAO objects
    let db = state.get_db_conn();
    let topic_dao = TopicDao::new(db.clone());
    let secret_dao = SecretDao::new(db);

    // getting topic
    let topic_keyset = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };
    let mut topic = topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&topic_keyset)?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    // getting secret
    let secret_keyset = StorageTopicAndSecretKeys {
        storage_key,
        topic_key: &topic_key,
        secret_key: &secret_key,
    };
    let secret = secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&secret_keyset)?;

    // performing delete operation
    let hashed_topic_name = topic.hashed_name.clone();
    let hashed_secret_name = secret.hashed_name.clone();

    secret_dao
        .delete(&hashed_topic_name, &hashed_secret_name)
        .await?;

    topic.remove_hashed_secret_name(secret.hashed_name, &topic_keyset)?;
    topic_dao.update(topic).await?;

    info!("Secret {hashed_secret_name} in the topic {hashed_topic_name} successfully deleted");

    Ok(())
}
