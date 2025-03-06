use crate::{
    http::{errors::ResponseError, jwt_tokens::TokenType},
    state::AppState,
    storage::StorageState,
};

pub fn is_admin(token_type: &TokenType) -> Result<(), ResponseError> {
    if !matches!(token_type, TokenType::Admin) {
        return Err(ResponseError::AccessDenied);
    }

    Ok(())
}

pub async fn ensure_storage_is_unsealed(state: AppState) -> Result<(), ResponseError> {
    let storage = state.get_storage_read().await;
    storage.ensure_state_is(StorageState::Unsealed)?;

    Ok(())
}

pub fn ensure_topic_name_valid(topic_name: &str) -> Result<(), ResponseError> {
    if validate_name(topic_name) {
        Ok(())
    } else {
        Err(ResponseError::InvalidTopicName)
    }
}

pub fn ensure_secret_name_valid(secret_name: &str) -> Result<(), ResponseError> {
    if validate_name(secret_name) {
        Ok(())
    } else {
        Err(ResponseError::InvalidSecretName)
    }
}

fn validate_name(name: &str) -> bool {
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
