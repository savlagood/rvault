use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};

use crate::{
    config::CONFIG,
    http::{
        auth::{
            policy::Policies,
            tokens::{AccessTokenClaims, RefreshTokenClaims, TokenType},
            utils,
        },
        errors::ResponseError,
    },
};

#[derive(Serialize, Deserialize)]
pub struct TokenRequest {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

impl TokenPair {
    pub fn new(policy: Policies, token_type: TokenType) -> Result<Self, ResponseError> {
        let jwt_secret = CONFIG.jwt_secret.as_bytes();
        let encoding_key = EncodingKey::from_secret(jwt_secret);

        let access_token_claims =
            AccessTokenClaims::new(policy, token_type, CONFIG.access_token_exp);
        let access_token = utils::encode_token(&access_token_claims, &encoding_key)?;

        let refresh_token_claims =
            RefreshTokenClaims::new(access_token_claims.id, CONFIG.refresh_token_exp);
        let refresh_token = utils::encode_token(&refresh_token_claims, &encoding_key)?;

        Ok(Self {
            access_token,
            refresh_token,
        })
    }
}
