use crate::http::auth::{
    handlers::utils::get_admin_policies,
    jwt_tokens::{utils as jwt_utils, AccessTokenClaims, RefreshTokenClaims, TokenPair},
};
use crate::tests::server::CONFIG;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use reqwest::Response;
use serde::de::DeserializeOwned;

pub async fn extract_token_pair_from_response(response: Response) -> TokenPair {
    response
        .json::<TokenPair>()
        .await
        .expect("Error during parsing token pari")
}

pub fn extract_token_claims<T: DeserializeOwned>(token: &str) -> T {
    let decoding_key = DecodingKey::from_secret(CONFIG.jwt_secret.as_bytes());

    let mut validation = Validation::default();
    validation.validate_exp = false;
    let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
        .expect("Failed to decode token");

    token_data.claims
}

pub fn make_admin_token_pair_with_specified_access_refresh_exp(
    access_exp: usize,
    refresh_exp: usize,
) -> TokenPair {
    let encoding_key = EncodingKey::from_secret(CONFIG.jwt_secret.as_bytes());

    let mut access_token_claims = AccessTokenClaims::new(
        get_admin_policies(),
        crate::http::auth::jwt_tokens::TokenType::Admin,
        CONFIG.access_token_exp,
    );
    println!("Access token1234");
    access_token_claims.exp = access_exp;
    let access_token = jwt_utils::encode_token(&access_token_claims, &encoding_key)
        .expect("Error during encoding access token");

    println!("Access token123");

    let mut refresh_token_claims =
        RefreshTokenClaims::new(access_token_claims.id, CONFIG.refresh_token_exp);
    refresh_token_claims.exp = refresh_exp;
    let refresh_token = jwt_utils::encode_token(&refresh_token_claims, &encoding_key)
        .expect("Error during encoding refresh token");

    TokenPair {
        access_token,
        refresh_token,
    }
}
