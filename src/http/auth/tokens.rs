use std::time::Duration;

use axum::{async_trait, extract::FromRequestParts, http::request::Parts, RequestPartsExt};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::CONFIG,
    http::{
        auth::{policy::Policies, utils},
        errors::ResponseError,
    },
};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    User,
    Admin,
    Service,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub id: Uuid,
    pub exp: usize,
    pub policy: Policies,
    #[serde(rename = "type")]
    pub token_type: TokenType,
}

impl AccessTokenClaims {
    pub fn new(policy: Policies, token_type: TokenType, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = utils::calculate_expiration_time(ttl);

        Self {
            id,
            exp,
            policy,
            token_type,
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AccessTokenClaims
where
    S: Send + Sync,
{
    type Rejection = ResponseError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| ResponseError::InvalidToken)?;

        let decoding_key = DecodingKey::from_secret(CONFIG.jwt_secret.as_bytes());
        let token_data = utils::decode_token::<AccessTokenClaims>(bearer.token(), &decoding_key)?;

        Ok(token_data.claims)
    }
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub id: Uuid,
    pub access_token_id: Uuid,
    pub exp: usize,
}

impl RefreshTokenClaims {
    pub fn new(access_token_id: Uuid, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = utils::calculate_expiration_time(ttl);

        Self {
            id,
            access_token_id,
            exp,
        }
    }
}
