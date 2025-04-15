use crate::{
    http::{
        errors::ResponseError,
        headers::{SecretKeyHeader, TopicKeyHeader},
        jwt_tokens::AccessTokenClaims,
    },
    models::{
        http::secrets::{
            SecretCurrentVersion, SecretEncryptionKey, SecretNames, SecretSettings,
            SecretUpdateRequest, SecretValue, SecretVersions,
        },
        StorageAndTopicKeys, StorageTopicAndSecretKeys,
    },
    policies::Permission,
    secrets::{SecretDao, SecretDto, SecretError},
    state::AppState,
    topics::TopicDao,
    utils::{common::generate_external_key, hkdf, validators},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use axum_extra::TypedHeader;

enum SecretOperation {
    Names,
    Versions,
    UpdateVersion,
    Create,
    Read,
    Update,
    Delete,
}

impl SecretOperation {
    fn get_required_permissions(self) -> (Permission, Option<Permission>) {
        match self {
            Self::Names => (Permission::Read, None),
            Self::Versions => (Permission::Read, Some(Permission::Read)),
            Self::UpdateVersion => (Permission::Read, Some(Permission::Update)),
            Self::Create => (Permission::Update, Some(Permission::Create)),
            Self::Read => (Permission::Read, Some(Permission::Read)),
            Self::Update => (Permission::Read, Some(Permission::Update)),
            Self::Delete => (Permission::Update, Some(Permission::Delete)),
        }
    }
}

struct SecretContext {
    storage_key: Vec<u8>,
    topic_key: Vec<u8>,
    secret_key: Vec<u8>,
    topic_dao: TopicDao,
    secret_dao: SecretDao,
}

impl SecretContext {
    async fn new(
        state: &AppState,
        external_topic_key: Option<String>,
        external_secret_key: Option<String>,
    ) -> Result<Self, ResponseError> {
        let storage = state.get_storage_read().await;
        let config = state.get_config();

        let storage_key = storage.get_encryption_key()?.to_vec();
        let topic_key = if let Some(key) = external_topic_key {
            hkdf::string_into_256_bit_key(key)?
        } else {
            hkdf::string_into_256_bit_key(config.default_topic_key.clone())?
        };
        let secret_key = if let Some(key) = external_secret_key {
            hkdf::string_into_256_bit_key(key)?
        } else {
            hkdf::string_into_256_bit_key(config.default_secret_key.clone())?
        };

        let db = state.get_db_conn();
        let topic_dao = TopicDao::new(db.clone());
        let secret_dao = SecretDao::new(db);

        Ok(Self {
            storage_key,
            topic_key,
            secret_key,
            topic_dao,
            secret_dao,
        })
    }

    fn topic_keyset(&self) -> StorageAndTopicKeys {
        StorageAndTopicKeys {
            storage_key: &self.storage_key,
            topic_key: &self.topic_key,
        }
    }

    fn secret_keyset(&self) -> StorageTopicAndSecretKeys {
        StorageTopicAndSecretKeys {
            storage_key: &self.storage_key,
            topic_key: &self.topic_key,
            secret_key: &self.secret_key,
        }
    }
}

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
        .route("/:secret_name/versions", get(get_secret_versions_handler))
        .route(
            "/:secret_name/versions/current",
            put(update_current_version_handler),
        )
        .with_state(app_state)
}

async fn validate_request(
    claims: &AccessTokenClaims,
    state: &AppState,
    topic_name: &str,
    secret_name: Option<&str>,
    operation: SecretOperation,
) -> Result<(), ResponseError> {
    validators::ensure_storage_is_unsealed(state.clone()).await?;

    let (topic_permission, secret_permission) = operation.get_required_permissions();

    let policies = &claims.policies;
    policies.ensure_topic_access_permitted(topic_name, topic_permission)?;

    if let (Some(name), Some(perm)) = (secret_name, secret_permission) {
        policies.ensure_secret_access_permitted(topic_name, name, perm)?;
    }

    if let Some(name) = secret_name {
        validators::ensure_secret_name_valid(name)?;
    }

    Ok(())
}

async fn get_secret_names_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    Path(topic_name): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<SecretNames>, ResponseError> {
    validate_request(&claims, &state, &topic_name, None, SecretOperation::Names).await?;

    let external_topic_key = topic_key_header.value;
    let external_secret_key = None;

    let context = SecretContext::new(&state, external_topic_key, external_secret_key).await?;
    let topic = context.topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&context.topic_keyset())?;

    let secret_names = context
        .secret_dao
        .fetch_secret_names(&topic.hashed_name, &context.storage_key)
        .await?;

    Ok(Json(SecretNames {
        names: secret_names,
    }))
}

async fn create_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(secret_settings): Json<SecretSettings>,
) -> Result<(StatusCode, Json<SecretEncryptionKey>), ResponseError> {
    validate_request(
        &claims,
        &state,
        &topic_name,
        Some(&secret_name),
        SecretOperation::Create,
    )
    .await?;

    let external_secret_key = generate_external_key(secret_settings.encryption.clone());

    let context =
        SecretContext::new(&state, topic_key_header.value, external_secret_key.clone()).await?;

    let mut topic = context.topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&context.topic_keyset())?;

    let secret = SecretDto::new(
        secret_name,
        secret_settings.value,
        topic.hashed_name.clone(),
        &context.secret_keyset(),
    )?;

    if topic.is_contains_secret(&secret.hashed_name) {
        return Err(ResponseError::Secret(SecretError::AlreadyExists));
    }

    topic.add_hashed_secret_name(secret.hashed_name.clone(), &context.topic_keyset())?;

    context.secret_dao.create(secret).await?;
    context.topic_dao.update(topic).await?;

    Ok((
        StatusCode::CREATED,
        Json(SecretEncryptionKey {
            value: external_secret_key,
        }),
    ))
}

async fn read_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<SecretValue>, ResponseError> {
    validate_request(
        &claims,
        &state,
        &topic_name,
        Some(&secret_name),
        SecretOperation::Read,
    )
    .await?;

    let context =
        SecretContext::new(&state, topic_key_header.value, secret_key_header.value).await?;

    let topic = context.topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&context.topic_keyset())?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    let secret = context
        .secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&context.secret_keyset())?;

    Ok(Json(SecretValue {
        value: secret.get_current_secret_value(&context.secret_keyset())?,
        version: secret.cursor,
    }))
}

async fn update_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(update_request): Json<SecretUpdateRequest>,
) -> Result<StatusCode, ResponseError> {
    validate_request(
        &claims,
        &state,
        &topic_name,
        Some(&secret_name),
        SecretOperation::Update,
    )
    .await?;

    let context =
        SecretContext::new(&state, topic_key_header.value, secret_key_header.value).await?;

    let topic = context.topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&context.topic_keyset())?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    let mut secret = context
        .secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&context.secret_keyset())?;

    secret.update_secret_value(update_request.value, &context.secret_keyset())?;
    context.secret_dao.update(&secret).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn delete_secret_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, ResponseError> {
    validate_request(
        &claims,
        &state,
        &topic_name,
        Some(&secret_name),
        SecretOperation::Delete,
    )
    .await?;

    let context =
        SecretContext::new(&state, topic_key_header.value, secret_key_header.value).await?;

    let mut topic = context.topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&context.topic_keyset())?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    let secret = context
        .secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&context.secret_keyset())?;

    context
        .secret_dao
        .delete(&topic.hashed_name, &secret.hashed_name)
        .await?;

    topic.remove_hashed_secret_name(secret.hashed_name, &context.topic_keyset())?;
    context.topic_dao.update(topic).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn get_secret_versions_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<SecretVersions>, ResponseError> {
    validate_request(
        &claims,
        &state,
        &topic_name,
        Some(&secret_name),
        SecretOperation::Versions,
    )
    .await?;

    let context =
        SecretContext::new(&state, topic_key_header.value, secret_key_header.value).await?;

    let topic = context.topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&context.topic_keyset())?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    let secret = context
        .secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&context.secret_keyset())?;

    let keyset = context.secret_keyset();

    let versions = secret
        .versions
        .into_iter()
        .enumerate()
        .map(|(i, value)| {
            SecretDto::decrypt_secret_value(value, &keyset).map(|decrypted_value| SecretValue {
                value: decrypted_value,
                version: i,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(SecretVersions {
        current: secret.cursor,
        versions,
    }))
}

async fn update_current_version_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    TypedHeader(secret_key_header): TypedHeader<SecretKeyHeader>,
    Path((topic_name, secret_name)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(current_version): Json<SecretCurrentVersion>,
) -> Result<StatusCode, ResponseError> {
    validate_request(
        &claims,
        &state,
        &topic_name,
        Some(&secret_name),
        SecretOperation::UpdateVersion,
    )
    .await?;

    let context =
        SecretContext::new(&state, topic_key_header.value, secret_key_header.value).await?;

    let topic = context.topic_dao.find_by_name(&topic_name).await?;
    topic.check_integrity(&context.topic_keyset())?;

    if !topic.contains_secret_name(&secret_name) {
        return Err(ResponseError::Secret(SecretError::NotFound));
    }

    let mut secret = context
        .secret_dao
        .find_by_name(&topic.hashed_name, &secret_name)
        .await?;
    secret.check_integrity(&context.secret_keyset())?;

    secret.update_current_version(current_version.version, &context.secret_keyset())?;
    context.secret_dao.update(&secret).await?;

    Ok(StatusCode::NO_CONTENT)
}
