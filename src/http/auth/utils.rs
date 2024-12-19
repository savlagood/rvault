use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{de::DeserializeOwned, Serialize};

const FULL_TOPIC_ACCESS: &[Permission] =
    &[Permission::Create, Permission::Read, Permission::Delete];
const FULL_SECRET_ACCESS: &[Permission] = &[
    Permission::Create,
    Permission::Read,
    Permission::Update,
    Permission::Delete,
];

use crate::http::auth::{
    errors::AuthError,
    policy::{Permission, Policies},
};

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
