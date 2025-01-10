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

#[cfg(test)]
mod post_issue_admin_token_tests {
    use super::*;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    #[test]
    fn ok() {
        let request_body = serde_json::json!(
            {
                "root_token": CONFIG.root_token.clone()
            }
        );

        use_app(async move {
            let client = reqwest::Client::new();
            let response = client
                .post("http://localhost:9200/api/auth/admin/token")
                .json(&request_body)
                .send()
                .await
                .unwrap();

            // Status code
            assert_eq!(response.status(), StatusCode::OK);

            // Body
            let token_pair = extract_token_pair_from_response(response).await;
            validate_token_pair(token_pair, TokenType::Admin, utils::get_admin_policy());
        });
    }

    #[test]
    fn forbidden() {
        let request_body = serde_json::json!(
            {
                "root_token": "some_invalid_token"
            }
        );

        use_app(async move {
            let client = reqwest::Client::new();
            let response = client
                .post("http://localhost:9200/api/auth/admin/token")
                .json(&request_body)
                .send()
                .await
                .unwrap();

            // Status code
            assert_eq!(response.status(), StatusCode::FORBIDDEN);

            // Error message
            validate_error_message_from_response(response).await;
        });
    }
}

#[cfg(test)]
mod post_issue_user_token_tests {
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
            let client = reqwest::Client::new();
            let response = client
                .post("http://localhost:9200/api/auth/user/token")
                .bearer_auth(ADMIN_ACCESS_TOKEN.as_str())
                .json(&request_body)
                .send()
                .await
                .unwrap();

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
            let client = reqwest::Client::new();
            let response = client
                .post("http://localhost:9200/api/auth/user/token")
                .bearer_auth(ADMIN_ACCESS_TOKEN.as_str())
                .json(&request_body)
                .send()
                .await
                .unwrap();

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
            let client = reqwest::Client::new();
            let response = client
                .post("http://localhost:9200/api/auth/user/token")
                .bearer_auth(ADMIN_ACCESS_TOKEN.as_str())
                .json(&request_body)
                .send()
                .await
                .unwrap();

            // Status code
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // Error message
            validate_error_message_from_response(response).await;
        });
    }
}
