use crate::api_tests::{
    consts::{ADMIN_POLICIES, ENV_AUTH_SECRET},
    models::auth::{AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenType},
    utils::common::get_env_var,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

pub fn make_admin_token_pair_with_specified_expiration_time(
    access_token_exp: usize,
    refresh_token_exp: usize,
) -> TokenPair {
    let access_token_claims = AccessTokenClaims {
        id: Uuid::new_v4(),
        exp: access_token_exp,
        policies: ADMIN_POLICIES.clone(),
        token_type: TokenType::Admin,
    };

    let refresh_token_claims = RefreshTokenClaims {
        id: Uuid::new_v4(),
        exp: refresh_token_exp,
        access_token_id: access_token_claims.id,
    };

    let access_token = encode_token_from_claims(&access_token_claims);
    let refresh_token = encode_token_from_claims(&refresh_token_claims);

    TokenPair {
        access_token,
        refresh_token,
    }
}

pub fn decode_token_into_claims<T: DeserializeOwned>(
    token: &str,
    decoding_key: &DecodingKey,
    validation: &Validation,
) -> T {
    jsonwebtoken::decode(token, decoding_key, validation)
        .expect("Failed to decode token")
        .claims
}

pub fn encode_token_from_claims<T: Serialize>(claims: &T) -> String {
    let jwt_secret = get_env_var(ENV_AUTH_SECRET);
    let decoding_key = EncodingKey::from_secret(jwt_secret.as_ref());

    jsonwebtoken::encode(&jsonwebtoken::Header::default(), claims, &decoding_key)
        .expect("Failed to encode token")
}
