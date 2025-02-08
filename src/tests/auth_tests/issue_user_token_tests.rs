use crate::tests::{
    assertions::{
        error_message::assert_error_response,
        token_pair::assert_response_contains_valid_token_pair_with_expected_payload,
    },
    consts::SIMPLE_USER_POLICIES,
    models::{
        jwt_tokens::{TokenPayload, TokenType},
        policies::Policies,
    },
    routes,
    server::{use_app, ClientWithServer},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_issue_token() {
    let request_body = serde_json::json!(SIMPLE_USER_POLICIES.clone());

    let expected_policies = Policies::from_value(serde_json::json!({
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
    }));
    let expected_payload = TokenPayload {
        policies: expected_policies,
        token_type: TokenType::User,
    };

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_token_pair_with_expected_payload(response, expected_payload)
            .await;
    })
}

#[test]
fn test_unauthorized() {
    let request_body = serde_json::json!(SIMPLE_USER_POLICIES.clone());

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_without_policies() {
    let request_body = serde_json::json!({});

    let expected_policies = Policies::from_value(serde_json::json!({
        "__default__": {
            "permissions": [],
            "secrets": {
                "__default__": []
            }
        }
    }));
    let expected_payload = TokenPayload {
        policies: expected_policies,
        token_type: TokenType::User,
    };

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_token_pair_with_expected_payload(response, expected_payload)
            .await;
    });
}

#[test]
fn test_impossibility_to_set_global_permissions() {
    let request_body = serde_json::json!({
        "__default__": {
            "permissions": ["create", "read"],
            "secrets": {
                "__default__": ["read"]
            }
        }
    });

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(routes::ISSUE_USER_TOKEN_PATH, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}
