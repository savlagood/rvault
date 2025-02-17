use crate::{
    crypto,
    http::{errors::ResponseError, headers::TopicKeyHeader, jwt_tokens::AccessTokenClaims, utils},
    models::{
        http::secrets::{SecretEncryptionKey, SecretSettings},
        Encryption, StorageAndTopicKeys, StorageTopicAndSecretKeys,
    },
    policies::Permission,
    secrets,
    state::AppState,
    topics,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use axum_extra::TypedHeader;
use tracing::info;

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/:secret_name", post(create_secret_handler))
        .with_state(app_state)
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
    policies.ensure_secret_access_permitted(
        topic_name.as_str(),
        secret_name.as_str(),
        Permission::Create,
    )?;

    utils::ensure_storage_is_unsealed(state.clone()).await?;
    utils::ensure_secret_name_valid(&secret_name)?;

    // actions
    let config = state.get_config();
    let primary_topic_key = topic_key_header
        .value
        .unwrap_or(config.default_topic_key.clone());

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
    let (primary_secret_key, secret_key_to_return) = match secret_settings.encryption {
        Encryption::Provided(key) => (key.clone(), Some(key)),
        Encryption::Generate => {
            let key_bytes = crypto::generate_256_bit_key();
            let key = crypto::base64::encode(&key_bytes);

            (key.clone(), Some(key))
        }
        Encryption::None => {
            let config = state.get_config();
            let key = config.default_secret_key.clone();

            (key, None)
        }
    };
    let secret_key = crypto::hkdf::string_into_256_bit_key(primary_secret_key)?;

    let topic_key = crypto::hkdf::string_into_256_bit_key(primary_topic_key)?;

    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    let topic_keyset = StorageAndTopicKeys {
        storage_key,
        topic_key: &topic_key,
    };

    let db = state.get_db();
    let topic_dao = topics::TopicDao::new(db.clone());
    let secret_dao = secrets::SecretDao::new(db);

    let mut topic = topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&topic_keyset)?;

    let secret_keyset = StorageTopicAndSecretKeys {
        storage_key,
        topic_key: &topic_key,
        secret_key: &secret_key,
    };

    let secret = secrets::SecretDto::new(secret_name, secret_settings.value, &secret_keyset)?;
    if topic.is_contains_secret(&secret.hashed_name) {
        return Err(ResponseError::Secret(secrets::SecretError::AlreadyExists));
    }
    topic.add_hashed_secret_name(secret.hashed_name.clone(), &topic_keyset)?;

    let hashed_secret_name = secret.hashed_name.clone();
    let hashed_topic_name = topic.hashed_name.clone();

    secret_dao.create(secret).await?;
    topic_dao.update(topic).await?;

    info!("Secret {hashed_secret_name:?} in the topic {hashed_topic_name} successfully created");

    Ok(secret_key_to_return)
}
