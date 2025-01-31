use crate::{config::Config, policies::Policies};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Failed to create JWT token")]
    CreationFailed(#[from] jsonwebtoken::errors::Error),

    #[error("Invalid token")]
    InvalidToken,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    User,
    Admin,
}

pub fn calculate_expiration_time(ttl: Duration) -> usize {
    (Utc::now() + ttl).timestamp() as usize
}

pub fn encode_token_from_claims<T: Serialize>(
    claims: &T,
    encoding_key: &EncodingKey,
) -> Result<String, TokenError> {
    let token = jsonwebtoken::encode(&Header::default(), claims, encoding_key)?;
    Ok(token)
}

pub fn decode_token_into_claims<T: DeserializeOwned>(
    token_str: &str,
    decoding_key: &DecodingKey,
) -> Result<TokenData<T>, TokenError> {
    jsonwebtoken::decode(token_str, decoding_key, &Validation::default())
        .map_err(|_| TokenError::InvalidToken)
}

pub fn decode_token_into_claims_without_exp_checking<T: DeserializeOwned>(
    token_str: &str,
    decoding_key: &DecodingKey,
) -> Result<TokenData<T>, TokenError> {
    let mut validation = Validation::default();
    validation.validate_exp = false;

    jsonwebtoken::decode(token_str, decoding_key, &validation).map_err(|_| TokenError::InvalidToken)
}

#[derive(Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

impl TokenPair {
    pub fn new(
        config: &Config,
        policies: Policies,
        token_type: TokenType,
    ) -> Result<Self, TokenError> {
        let jwt_secret = config.jwt_secret.as_bytes();
        let encoding_key = EncodingKey::from_secret(jwt_secret);

        let access_token_claims =
            AccessTokenClaims::new(policies, token_type, config.access_token_exp);
        let access_token = encode_token_from_claims(&access_token_claims, &encoding_key)?;

        let refresh_token_claims =
            RefreshTokenClaims::new(access_token_claims.id, config.refresh_token_exp);
        let refresh_token = encode_token_from_claims(&refresh_token_claims, &encoding_key)?;

        Ok(Self {
            access_token,
            refresh_token,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub id: Uuid,
    pub exp: usize,
    pub policies: Policies,

    #[serde(rename = "type")]
    pub token_type: TokenType,
}

impl AccessTokenClaims {
    pub fn new(policies: Policies, token_type: TokenType, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = calculate_expiration_time(ttl);

        Self {
            id,
            exp,
            policies,
            token_type,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub id: Uuid,
    pub exp: usize,
    pub access_token_id: Uuid,
}

impl RefreshTokenClaims {
    pub fn new(access_token_id: Uuid, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = calculate_expiration_time(ttl);

        Self {
            id,
            exp,
            access_token_id,
        }
    }
}

mod http {
    use crate::{
        http::{
            errors::ResponseError,
            jwt_tokens::{decode_token_into_claims, AccessTokenClaims, TokenError},
        },
        state::AppState,
    };
    use axum::{async_trait, extract::FromRequestParts, http::request::Parts, RequestPartsExt};
    use axum_extra::{
        headers::{authorization::Bearer, Authorization},
        TypedHeader,
    };
    use jsonwebtoken::DecodingKey;

    #[async_trait]
    impl<S> FromRequestParts<S> for AccessTokenClaims
    where
        S: Send + Sync + AsRef<AppState>,
    {
        type Rejection = ResponseError;

        async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
            let TypedHeader(Authorization(bearer)) = parts
                .extract::<TypedHeader<Authorization<Bearer>>>()
                .await
                .map_err(|_| TokenError::InvalidToken)?;

            let config = state.as_ref().get_config();

            let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
            let token_data =
                decode_token_into_claims::<AccessTokenClaims>(bearer.token(), &decoding_key)
                    .map_err(|_| TokenError::InvalidToken)?;

            Ok(token_data.claims)
        }
    }
}
