use crate::{config::Config, http::errors::ResponseError, policies::Policies, state::AppState};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts, RequestPartsExt};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// Utility functions for working with JWT tokens.
pub mod utils {
    use std::time::Duration;

    use chrono::Utc;
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
    use serde::{de::DeserializeOwned, Serialize};

    use crate::http::errors::ResponseError;

    /// Calculates the expiration time based on the current UTC time and a given duration.
    pub fn calculate_expiration_time(duration: Duration) -> usize {
        (Utc::now() + duration).timestamp() as usize
    }

    /// Encodes the given claims into a JWT token.
    pub fn encode_token<T: Serialize>(
        claims: &T,
        encoding_key: &EncodingKey,
    ) -> Result<String, ResponseError> {
        jsonwebtoken::encode(&Header::default(), &claims, encoding_key)
            .map_err(|_| ResponseError::TokenCreation)
    }

    /// Decodes a JWT token string into the specified claims type.
    pub fn decode_token<T: DeserializeOwned>(
        token_string: &str,
        decoding_key: &DecodingKey,
    ) -> Result<TokenData<T>, ResponseError> {
        jsonwebtoken::decode(token_string, decoding_key, &Validation::default())
            .map_err(|_| ResponseError::InvalidToken)
    }
}

/// Enum representing the type of token.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    User,
    Admin,
    Service,
}

/// Represents a pair of access and refresh tokens.
#[derive(Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

impl TokenPair {
    /// Creates a new `TokenPair` with the specified policies and token type.
    pub fn new(
        config: &Config,
        policies: Policies,
        token_type: TokenType,
    ) -> Result<Self, ResponseError> {
        let jwt_secret = config.jwt_secret.as_bytes();
        let encoding_key = EncodingKey::from_secret(jwt_secret);

        let access_token_claims =
            AccessTokenClaims::new(policies, token_type, config.access_token_exp);
        let access_token = utils::encode_token(&access_token_claims, &encoding_key)?;

        let refresh_token_claims =
            RefreshTokenClaims::new(access_token_claims.id, config.refresh_token_exp);
        let refresh_token = utils::encode_token(&refresh_token_claims, &encoding_key)?;

        Ok(Self {
            access_token,
            refresh_token,
        })
    }
}

/// Claims for an access token.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub id: Uuid,
    pub exp: usize,
    pub policy: Policies,
    #[serde(rename = "type")]
    pub token_type: TokenType,
}

impl AccessTokenClaims {
    /// Creates new access token claims with the given policies, token type, and TTL.
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
    S: Send + Sync + AsRef<AppState>,
{
    type Rejection = ResponseError;

    /// Extracts `AccessTokenClaims` from the request's authorization header.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| ResponseError::InvalidToken)?;

        let config = state.as_ref().get_config();

        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
        let token_data = utils::decode_token::<AccessTokenClaims>(bearer.token(), &decoding_key)?;

        Ok(token_data.claims)
    }
}

/// Claims for a refresh token.
#[derive(Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub id: Uuid,
    pub access_token_id: Uuid,
    pub exp: usize,
}

impl RefreshTokenClaims {
    /// Creates new refresh token claims with the associated access token ID and TTL.
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
