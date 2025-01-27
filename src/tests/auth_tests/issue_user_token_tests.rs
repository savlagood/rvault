use crate::policies::Policies;
use crate::tests::{
    assertions, routes,
    server::{use_app, ClientWithServer},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_everything_ok() {
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
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assertions::token_pair::assert_response_contains_valid_token_pair_with_excepted_policies(
            response,
            expected_policies,
        )
        .await;
    });
}

#[test]
fn test_without_authorization_token() {
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assertions::error_message::assert_response_contains_error_message(response).await;
    });
}

#[test]
fn with_empty_body() {
    let request_body = serde_json::json!({});

    let expected_policies_value = serde_json::json!({
        "__default__": {
        "permissions": [],
            "secrets": {
                "__default__": []
            }
        }
    });
    let expected_policies: Policies = serde_json::from_value(expected_policies_value)
        .expect("Error during parsing expected policies from string to struct");

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assertions::token_pair::assert_response_contains_valid_token_pair_with_excepted_policies(
            response,
            expected_policies,
        )
        .await;
    });
}

#[test]
fn test_impossibility_to_set_global_permissions() {
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
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assertions::error_message::assert_response_contains_error_message(response).await;
    });
}
