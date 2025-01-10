use crate::http::auth::{
    errors::AuthError,
    policy::{Permission, Policies},
};
use anyhow::Result;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

const FULL_TOPIC_ACCESS: &[Permission] =
    &[Permission::Create, Permission::Read, Permission::Delete];
const FULL_SECRET_ACCESS: &[Permission] = &[
    Permission::Create,
    Permission::Read,
    Permission::Update,
    Permission::Delete,
];

pub fn calculate_expiration_time(duration: Duration) -> usize {
    (Utc::now() + duration).timestamp() as usize
}

pub fn encode_token<T: Serialize>(
    claims: &T,
    encoding_key: &EncodingKey,
) -> Result<String, AuthError> {
    jsonwebtoken::encode(&Header::default(), &claims, encoding_key)
        .map_err(|_| AuthError::TokenCreation)
}

pub fn decode_token<T: DeserializeOwned>(
    token_string: &str,
    decoding_key: &DecodingKey,
) -> Result<TokenData<T>, AuthError> {
    jsonwebtoken::decode(token_string, decoding_key, &Validation::default())
        .map_err(|_| AuthError::InvalidToken)
}

pub fn get_admin_policy() -> Policies {
    let mut policies = Policies::new();
    policies.set_default_permissions(FULL_TOPIC_ACCESS, FULL_SECRET_ACCESS);
    policies
}

pub fn check_topic_access_rights(
    policy: &Policies,
    required_permission: Permission,
    topic_name: &str,
) -> Result<bool> {
    let topic = policy.get_topic(topic_name)?;
    Ok(topic.permissions.contains(&required_permission))
}

// pub fn check_secret_access_rights(
//     policy: &Policies,
//     required_permission: Permission,
//     topic_name: &str,
//     secret_name: &str,
// ) -> Result<bool> {
//     check_secret_access_rights(policy, required_permission, topic_name, secret_name)
// }
