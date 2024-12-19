use std::time::Duration;

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

// where AppContext is
// pub struct AppContext {
//     pub config: Arc<Config>,
// }
//
// where Config is
// pub struct Config {
//     // Variables from yaml config
//     pub storage_dir_path: String,
//     pub server_ip: String,
//     pub server_port: u16,
//     pub request_timeout: Duration,

//     // Variables from env config
//     pub root_token: String,
//     pub jwt_secret: String,
// }
use crate::config::Config;
use crate::http::server::AppContext;

pub fn router() -> Router<AppContext> {
    Router::new()
        .route("/protected", get(protected))
        .route("/login", post(authorize))
        .route("/refresh", post(refresh_tokens))
}

enum AuthError {
    InvalidToken,
    WrongCredentials,
    TokenCreation,
    MissingCredentials,
    DifferentTokens,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::DifferentTokens => (
                StatusCode::BAD_REQUEST,
                "Passed refresh_token is not related to passed access_token",
            ),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct TokenPayload {
    username: String,
}

impl TokenPayload {
    fn new(username: String) -> Self {
        Self { username }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    id: Uuid,
    exp: usize,
    data: TokenPayload,
}

impl Claims {
    fn new(token_data: TokenPayload, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = calculate_expiration_time(ttl);
        Self {
            id,
            exp,
            data: token_data,
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    AppContext: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppContext::from_ref(state);

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        let token_data: TokenData<Claims> = jsonwebtoken::decode(
            bearer.token(),
            &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[derive(Serialize, Deserialize)]
struct RefreshClaims {
    id: Uuid,
    access_token_id: Uuid,
    exp: usize,
}

impl RefreshClaims {
    fn new(access_token_id: Uuid, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = calculate_expiration_time(ttl);
        Self {
            id,
            access_token_id,
            exp,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AuthBody {
    access_token: String,
    refresh_token: String,
}

impl AuthBody {
    fn new(access_token: String, refresh_token: String) -> Self {
        Self {
            access_token,
            refresh_token,
        }
    }
}

#[derive(Deserialize)]
struct AuthPayload {
    client_id: String,
    client_secret: String,
}

mod jwt_utils {
    use super::*;

    use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
    use serde::{de::DeserializeOwned, Serialize};

    pub fn encode_token<T: Serialize>(
        claims: &T,
        encoding_key: &EncodingKey,
    ) -> Result<String, AuthError> {
        jsonwebtoken::encode(&Header::default(), &claims, encoding_key)
            .map_err(|_| AuthError::TokenCreation)
    }

    pub fn decode_token<T: DeserializeOwned>(
        token_string: String,
        decoding_key: &DecodingKey,
    ) -> Result<TokenData<T>, AuthError> {
        jsonwebtoken::decode::<T>(&token_string, decoding_key, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)
    }

    pub fn gen_token_pair(
        config: &Config,
        username: String,
    ) -> Result<(String, String), AuthError> {
        let jwt_secret = config.jwt_secret.as_bytes();
        let encoding_key = EncodingKey::from_secret(jwt_secret);

        let token_data = TokenPayload::new(username);

        // Access token
        let access_token_claims = Claims::new(token_data, config.access_token_exp);
        let access_token = jwt_utils::encode_token(&access_token_claims, &encoding_key)?;

        // Refresh token
        let refresh_token_claims =
            RefreshClaims::new(access_token_claims.id, config.refresh_token_exp);
        let refresh_token = jwt_utils::encode_token(&refresh_token_claims, &encoding_key)?;

        Ok((access_token, refresh_token))
    }
}

fn calculate_expiration_time(duration: Duration) -> usize {
    (Utc::now() + duration).timestamp() as usize
}

async fn authorize(
    context: State<AppContext>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    if &payload.client_id != "foo" || &payload.client_secret != "bar" {
        return Err(AuthError::WrongCredentials);
    }

    let (access_token, refresh_token) =
        jwt_utils::gen_token_pair(&context.config, "Vlad".to_string())?;

    Ok(Json(AuthBody::new(access_token, refresh_token)))
}

async fn refresh_tokens(
    context: State<AppContext>,
    Json(payload): Json<AuthBody>,
) -> Result<Json<AuthBody>, AuthError> {
    let jwt_secret = context.config.jwt_secret.as_bytes();
    let decoding_key = DecodingKey::from_secret(jwt_secret);

    let refresh_token_claims =
        jwt_utils::decode_token::<RefreshClaims>(payload.refresh_token, &decoding_key)?.claims;

    let access_token_claims =
        jwt_utils::decode_token::<Claims>(payload.access_token, &decoding_key)?.claims;

    if refresh_token_claims.access_token_id != access_token_claims.id {
        return Err(AuthError::DifferentTokens);
    }

    let (access_token, refresh_token) =
        jwt_utils::gen_token_pair(&context.config, access_token_claims.data.username)?;

    Ok(Json(AuthBody::new(access_token, refresh_token)))
}

async fn protected(claims: Claims) -> String {
    format!("Welcome to the protected area, my id is {}", claims.id)
}
