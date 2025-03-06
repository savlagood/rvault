use crate::api_tests::{
    consts::ENV_AUTH_SECRET,
    models::policies::Policies,
    utils::{common::get_env_var, jwt::decode_token_into_claims},
};
use jsonwebtoken::{DecodingKey, Validation};
use reqwest::Response;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    User,
    Admin,
}

#[derive(Serialize)]
pub struct RootToken {
    token: String,
}

impl RootToken {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub fn into_value(self) -> serde_json::Value {
        serde_json::json!(self)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

impl TokenPair {
    pub async fn from_response(response: Response) -> Self {
        response
            .json::<Self>()
            .await
            .expect("Error during parsing token pair from response")
    }

    pub fn into_value(self) -> serde_json::Value {
        serde_json::json!(self)
    }
}

pub struct TokenPayload {
    pub policies: Policies,
    pub token_type: TokenType,
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
    pub fn from_str(token: &str) -> Self {
        let jwt_secret = get_env_var(ENV_AUTH_SECRET);

        let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
        let validation = Validation::default();

        decode_token_into_claims(token, &decoding_key, &validation)
    }

    pub fn from_str_without_exp_checking(token: &str) -> Self {
        let jwt_secret = get_env_var(ENV_AUTH_SECRET);
        let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());

        let mut validation = Validation::default();
        validation.validate_exp = false;

        decode_token_into_claims(token, &decoding_key, &validation)
    }
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub id: Uuid,
    pub exp: usize,
    pub access_token_id: Uuid,
}

impl RefreshTokenClaims {
    pub fn from_str(token: &str) -> Self {
        let jwt_secret = get_env_var(ENV_AUTH_SECRET);

        let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
        let validation = Validation::default();

        decode_token_into_claims(token, &decoding_key, &validation)
    }
}
