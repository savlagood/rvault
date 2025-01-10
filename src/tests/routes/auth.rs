use jsonwebtoken::DecodingKey;
use once_cell::sync::Lazy;
use reqwest;
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::CONFIG;
use crate::http::auth::models::TokenPair;
use crate::http::auth::policy::Policies;
use crate::http::auth::tokens::{AccessTokenClaims, RefreshTokenClaims, TokenType};
use crate::http::auth::utils;
use crate::tests::setup::use_app;

#[derive(Serialize, Deserialize)]
struct ErrorMessage {
    error: String,
}

#[cfg(test)]
use pretty_assertions::assert_eq;

static ADMIN_ACCESS_TOKEN: Lazy<String> = Lazy::new(|| {
    let admin_policies = utils::get_admin_policy();
    let access_token = TokenPair::new(admin_policies, TokenType::Admin)
        .expect("Error during creating admin token")
        .access_token;

    access_token
});

fn extract_token_claims<T: DeserializeOwned>(token: String) -> T {
    let decoding_key = DecodingKey::from_secret(CONFIG.jwt_secret.as_bytes());
    let token_data = utils::decode_token::<T>(&token, &decoding_key).expect("Invalid token");

    token_data.claims
}

async fn extract_token_pair_from_response(response: Response) -> TokenPair {
    response
        .json::<TokenPair>()
        .await
        .expect("Error during parsing token pair")
}

fn validate_token_pair(
    token_pair: TokenPair,
    expected_token_type: TokenType,
    expected_policies: Policies,
) {
    let access_token_string = token_pair.access_token;
    let refresh_token_string = token_pair.refresh_token;

    assert!(!access_token_string.is_empty(), "Access token is empty");
    assert!(!refresh_token_string.is_empty(), "Refresh token is empty");

    // Extract claims
    let access_token_claims = extract_token_claims::<AccessTokenClaims>(access_token_string);
    let refresh_token_claims = extract_token_claims::<RefreshTokenClaims>(refresh_token_string);

    // Check token type
    assert_eq!(access_token_claims.token_type, expected_token_type);

    // Check that refresh_token is associated with access_token
    assert_eq!(refresh_token_claims.access_token_id, access_token_claims.id);

    // Checl policies
    assert_eq!(access_token_claims.policy, expected_policies);
}

async fn validate_error_message_from_response(response: Response) {
    let response_body = response
        .json::<ErrorMessage>()
        .await
        .expect("Error during parsing error message");

    assert!(
        !response_body.error.is_empty(),
        "Response must contain error message"
    );
}

mod routes {
    use once_cell::sync::Lazy;
    use reqwest::Response;
    use serde_json::Value;

    static HOST: &str = "http://localhost:9200/api/auth";

    pub static ISSUE_ADMIN_TOKEN_PATH: Lazy<String> =
        Lazy::new(|| format!("{}/token/issue/admin", HOST));
    pub static ISSUE_USER_TOKEN_PATH: Lazy<String> =
        Lazy::new(|| format!("{}/token/issue/user", HOST));
    pub static REFRESH_TOKEN_PATH: Lazy<String> = Lazy::new(|| format!("{}/token/refresh", HOST));

    pub async fn make_request(url: &str, body: Value, auth_token: Option<&str>) -> Response {
        let client = reqwest::Client::new();
        let mut request_builder = client.post(url).json(&body);

        if let Some(auth_token) = auth_token {
            request_builder = request_builder.bearer_auth(auth_token);
        }

        request_builder.send().await.unwrap()
    }
}

#[cfg(test)]
mod issue_admin_token_tests {
    use super::*;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    #[test]
    fn ok() {
        let request_body = serde_json::json!(
            {
                "token": CONFIG.root_token.clone()
            }
        );

        use_app(async move {
            let response =
                routes::make_request(&routes::ISSUE_ADMIN_TOKEN_PATH, request_body, None).await;

            // Status code
            assert_eq!(response.status(), StatusCode::OK);

            // Body
            let token_pair = extract_token_pair_from_response(response).await;
            validate_token_pair(token_pair, TokenType::Admin, utils::get_admin_policy());
        });
    }

    #[test]
    fn unauthorized() {
        let request_body = serde_json::json!(
            {
                "token": "some_invalid_token"
            }
        );

        use_app(async move {
            let response =
                routes::make_request(&routes::ISSUE_ADMIN_TOKEN_PATH, request_body, None).await;

            // Status code
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // Error message
            validate_error_message_from_response(response).await;
        });
    }
}

#[cfg(test)]
mod issue_user_token_tests {
    use super::*;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    #[test]
    fn ok() {
        let request_body = serde_json::json!({
            "some_topic_name1": {
                "permissions": ["create", "read"],
                "secrets": {
                    "some_secret_name1": ["read", "update"],
                    "some_secret_name2": ["read", "update", "delete"],
                    "__default__": ["read"]
                }
            },
            "some_topic_name2": {
                "permissions": ["create", "read", "delete"],
                "secrets": {
                    "some_secret_name1": ["read", "update", "create", "delete"],
                    "some_secret_name2": ["read", "update", "create"]
                }
            }
        });

        let expected_policies_value = serde_json::json!({
            "some_topic_name2": {
                "permissions": ["read", "delete", "create"],
                "secrets": {
                    "some_secret_name1": ["delete", "update", "create", "read"],
                    "some_secret_name2": ["read", "create", "update"],
                    "__default__": []
                }
            },
            "some_topic_name1": {
                "permissions": ["create", "read"],
                "secrets": {
                    "__default__": ["read"],
                    "some_secret_name1": ["read", "update"],
                    "some_secret_name2": ["read", "update", "delete"]
                }
            },
            "__default__": {
                "permissions": [],
                "secrets": {
                    "__default__": []
                }
            }
        });
        let expected_policies: Policies = serde_json::from_value(expected_policies_value)
            .expect("Error during parsing policies from json value to struct");

        use_app(async move {
            let response = routes::make_request(
                routes::ISSUE_USER_TOKEN_PATH.as_str(),
                request_body,
                Some(ADMIN_ACCESS_TOKEN.as_str()),
            )
            .await;

            // Status code
            assert_eq!(response.status(), StatusCode::OK);

            // Body
            let token_pair = extract_token_pair_from_response(response).await;
            validate_token_pair(token_pair, TokenType::User, expected_policies);
        });
    }

    #[test]
    fn with_empty_body() {
        let request_body = serde_json::json!({});

        let expected_policies_value = serde_json::json!(
            {
                "__default__": {
                "permissions": [],
                    "secrets": {
                        "__default__": []
                    }
                }
            }
        );
        let expected_policies: Policies = serde_json::from_value(expected_policies_value)
            .expect("Error during parsing expected policies from string to struct");

        use_app(async move {
            let response = routes::make_request(
                routes::ISSUE_USER_TOKEN_PATH.as_str(),
                request_body,
                Some(ADMIN_ACCESS_TOKEN.as_str()),
            )
            .await;

            // Status code
            assert_eq!(response.status(), StatusCode::OK);

            // Body
            let token_pair = extract_token_pair_from_response(response).await;
            validate_token_pair(token_pair, TokenType::User, expected_policies);
        });
    }

    #[test]
    fn set_global_permission() {
        let request_body = serde_json::json!({
            "some_topic_name1": {
                "permissions": ["create", "read"],
                "secrets": {
                    "some_secret_name1": ["read", "update"],
                    "some_secret_name2": ["read", "update", "delete"],
                    "__default__": ["read"]
                }
            },
            "__default__": {
                "permissions": ["read"],
                "secrets": {
                    "__default__": ["create"]
                }
            }
        });

        use_app(async move {
            let response = routes::make_request(
                routes::ISSUE_USER_TOKEN_PATH.as_str(),
                request_body,
                Some(ADMIN_ACCESS_TOKEN.as_str()),
            )
            .await;

            // Status code
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // Error message
            validate_error_message_from_response(response).await;
        });
    }
}

#[cfg(test)]
mod refresh_token_tests {
    use jsonwebtoken::EncodingKey;
    use serde_json::Value;

    use super::*;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    fn make_token_pair(access_exp: usize, refresh_exp: usize) -> (String, String) {
        let encoding_key = EncodingKey::from_secret(CONFIG.jwt_secret.as_bytes());

        let mut access_token_claims = AccessTokenClaims::new(
            utils::get_admin_policy(),
            crate::http::auth::tokens::TokenType::Admin,
            CONFIG.access_token_exp,
        );
        access_token_claims.exp = access_exp;
        let access_token = utils::encode_token(&access_token_claims, &encoding_key)
            .expect("Error during encoding access token");

        let mut refresh_token_claims =
            RefreshTokenClaims::new(access_token_claims.id, CONFIG.refresh_token_exp);
        refresh_token_claims.exp = refresh_exp;
        let refresh_token = utils::encode_token(&refresh_token_claims, &encoding_key)
            .expect("Error during encoding refresh token");

        (access_token, refresh_token)
    }

    fn make_token_pair_into_request_body(access_exp: usize, refresh_exp: usize) -> Value {
        let (access_token, refresh_token) = make_token_pair(access_exp, refresh_exp);

        serde_json::json!(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        )
    }

    #[test]
    fn test_access_token_still_valid() {
        let request_body = make_token_pair_into_request_body(
            utils::calculate_expiration_time(CONFIG.access_token_exp),
            utils::calculate_expiration_time(CONFIG.refresh_token_exp),
        );

        use_app(async move {
            let response =
                routes::make_request(&routes::REFRESH_TOKEN_PATH, request_body, None).await;

            // Status code
            assert_eq!(response.status(), StatusCode::OK);

            // Body
            let token_pair = extract_token_pair_from_response(response).await;
            validate_token_pair(token_pair, TokenType::Admin, utils::get_admin_policy());
        });
    }

    #[test]
    fn test_access_token_expired() {
        let request_body = make_token_pair_into_request_body(
            0,
            utils::calculate_expiration_time(CONFIG.refresh_token_exp),
        );

        use_app(async move {
            let response =
                routes::make_request(&routes::REFRESH_TOKEN_PATH, request_body, None).await;

            // Status code
            assert_eq!(response.status(), StatusCode::OK);

            // Body
            let token_pair = extract_token_pair_from_response(response).await;
            validate_token_pair(token_pair, TokenType::Admin, utils::get_admin_policy());
        });
    }

    #[test]
    fn test_refresh_token_expired() {
        let request_body = make_token_pair_into_request_body(
            0, // There is no matter what expiration time set to access token
            0,
        );

        use_app(async move {
            let response =
                routes::make_request(&routes::REFRESH_TOKEN_PATH, request_body, None).await;

            // Status code
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // Body
            validate_error_message_from_response(response).await;
        });
    }

    #[test]
    fn test_access_token_not_linked_to_refresh_token() {
        let (_access_token, refresh_token) = make_token_pair(
            utils::calculate_expiration_time(CONFIG.access_token_exp),
            utils::calculate_expiration_time(CONFIG.refresh_token_exp),
        );

        let request_body = serde_json::json!(
            {
                "access_token": ADMIN_ACCESS_TOKEN.clone(),
                "refresh_token": refresh_token,
            }
        );

        use_app(async move {
            let response =
                routes::make_request(&routes::REFRESH_TOKEN_PATH, request_body, None).await;

            // Status code
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // Body
            validate_error_message_from_response(response).await;
        });
    }
}
