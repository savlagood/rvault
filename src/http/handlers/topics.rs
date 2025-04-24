use crate::{
    http::{errors::ResponseError, headers::TopicKeyHeader, jwt_tokens::AccessTokenClaims},
    models::{
        http::topics::{TopicEncryptionKey, TopicNames, TopicSettings},
        StorageAndTopicKeys,
    },
    policies::Permission,
    secrets::SecretDao,
    state::AppState,
    topics::{self, TopicDao, TopicDto, TopicError},
    utils::{common::generate_external_key, hkdf, validators},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use axum_extra::TypedHeader;
use tracing::{error, info, warn};

enum TopicOperation {
    Create,
    Delete,
}

impl TopicOperation {
    fn get_required_permissions(self) -> Permission {
        match self {
            TopicOperation::Create => Permission::Create,
            TopicOperation::Delete => Permission::Delete,
        }
    }
}

struct TopicContext {
    storage_key: Vec<u8>,
    topic_key: Vec<u8>,
    topic_dao: TopicDao,
}

impl TopicContext {
    async fn new(
        state: &AppState,
        external_topic_key: Option<String>,
    ) -> Result<Self, ResponseError> {
        let storage = state.get_storage_read().await;
        let config = state.get_config();

        let storage_key = storage.get_encryption_key()?.to_vec();
        let topic_key = if let Some(key) = external_topic_key {
            hkdf::string_into_256_bit_key(key)?
        } else {
            hkdf::string_into_256_bit_key(config.default_topic_key.clone())?
        };

        let db = state.get_db_conn();
        let cache = state.get_cache();
        let topic_dao = TopicDao::new(db, cache);

        Ok(Self {
            storage_key,
            topic_key,
            topic_dao,
        })
    }

    fn topic_keyset(&self) -> StorageAndTopicKeys {
        StorageAndTopicKeys {
            storage_key: &self.storage_key,
            topic_key: &self.topic_key,
        }
    }
}

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(get_topic_names_handler))
        .route(
            "/:topic_name",
            post(create_topic_handler).delete(delete_topic_handler),
        )
        .with_state(app_state)
}

async fn validate_request(
    claims: &AccessTokenClaims,
    state: &AppState,
    topic_name: &str,
    operation: TopicOperation,
) -> Result<(), ResponseError> {
    validators::ensure_storage_is_unsealed(state.clone()).await?;

    let required_permission = operation.get_required_permissions();
    let policies = &claims.policies;

    policies.ensure_topic_access_permitted(topic_name, required_permission)?;
    validators::ensure_topic_name_valid(topic_name)?;

    Ok(())
}

async fn get_topic_names_handler(
    claims: AccessTokenClaims,
    State(state): State<AppState>,
) -> Result<Json<TopicNames>, ResponseError> {
    info!("Topic names list requested");

    // checks
    validators::is_admin(&claims.token_type)?;
    validators::ensure_storage_is_unsealed(state.clone()).await?;

    // actions
    let storage = state.get_storage_read().await;
    let storage_key = storage.get_encryption_key()?;

    let db = state.get_db_conn();
    let cache = state.get_cache();

    match topics::TopicDao::new(db, cache)
        .fetch_topic_names(storage_key)
        .await
    {
        Ok(topic_names) => {
            info!(
                count = topic_names.len(),
                "Topic names list fetched successfully"
            );
            Ok(Json(TopicNames { names: topic_names }))
        }
        Err(err) => {
            error!(error = ?err, "Failed to fetch topic names");
            Err(err.into())
        }
    }
}

async fn create_topic_handler(
    claims: AccessTokenClaims,
    Path(topic_name): Path<String>,
    State(state): State<AppState>,
    Json(topic_settings): Json<TopicSettings>,
) -> Result<(StatusCode, Json<TopicEncryptionKey>), ResponseError> {
    info!("Topic creation requested");

    validate_request(&claims, &state, &topic_name, TopicOperation::Create).await?;

    let external_topic_key = generate_external_key(topic_settings.encryption);
    let context = TopicContext::new(&state, external_topic_key.clone()).await?;

    match TopicDto::new(topic_name, &context.topic_keyset()) {
        Ok(topic) => {
            let hashed_topic_name = topic.hashed_name.clone();
            match context.topic_dao.create(topic).await {
                Ok(()) => {
                    info!(
                        hashed_topic_name = %hashed_topic_name,
                        "Topic created successfully"
                    );
                    Ok((
                        StatusCode::CREATED,
                        Json(TopicEncryptionKey {
                            value: external_topic_key,
                        }),
                    ))
                }
                Err(TopicError::AlreadyExists) => {
                    warn!(
                        hashed_topic_name = %hashed_topic_name,
                        "Attempted to create already existing topic"
                    );
                    Err(TopicError::AlreadyExists.into())
                }
                Err(err) => {
                    error!(
                        err = ?err,
                        hashed_topic_name = %hashed_topic_name,
                        "Failed to create topic"
                    );
                    Err(err.into())
                }
            }
        }
        Err(err) => {
            error!(error = ?err, "Failed to create topic DTO");
            Err(err.into())
        }
    }
}

async fn delete_topic_handler(
    claims: AccessTokenClaims,
    TypedHeader(topic_key_header): TypedHeader<TopicKeyHeader>,
    Path(topic_name): Path<String>,
    State(state): State<AppState>,
) -> Result<StatusCode, ResponseError> {
    info!("Topic deletion requested");

    validate_request(&claims, &state, &topic_name, TopicOperation::Delete).await?;

    let context = TopicContext::new(&state, topic_key_header.value).await?;

    match context.topic_dao.find_by_name(&topic_name).await {
        Ok(topic) => {
            topic.check_integrity(&context.topic_keyset())?;

            let db = state.get_db_conn();
            let cache = state.get_cache();
            let secret_dao = SecretDao::new(db, cache);

            for secret_hashed_name in &topic.secret_hashed_names {
                if let Err(err) = secret_dao
                    .delete(&topic.hashed_name, secret_hashed_name)
                    .await
                {
                    error!(
                        error = ?err,
                        hashed_topic_name = %topic.hashed_name,
                        secret_hashed_name = secret_hashed_name,
                        "Failed to delete topic's secret"
                    );
                }
            }

            info!(
                hashed_topic_name = %topic.hashed_name,
                "Topic's secrets deleted successfully"
            );

            match context.topic_dao.delete(&topic.hashed_name).await {
                Ok(()) => {
                    info!(
                        hashed_topic_name = %topic.hashed_name,
                        "Topic and its secrets deleted successfully"
                    );
                    Ok(StatusCode::NO_CONTENT)
                }
                Err(err) => {
                    error!(
                        error = ?err,
                        hashed_topic_name = %topic.hashed_name,
                        "Failed to delete topic"
                    );
                    Err(err.into())
                }
            }
        }
        Err(err) => {
            error!(
                error = ?err,
                "Failed to find topic for deletion"
            );
            Err(err.into())
        }
    }
}
