use crate::api_tests::{
    assertions::{
        auth::assert_response_contains_valid_token_pair_with_expected_payload,
        error_message::assert_error_response,
    },
    consts::{SIMPLE_USER_POLICIES, SIMPLE_USER_POLICIES_WITH_DEFAULTS},
    endpoints::ISSUE_USER_TOKEN,
    models::{
        auth::{TokenPayload, TokenType},
        policies::Policies,
    },
    runtime::use_app,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_issue_token() {
    // preparing
    let request_body = serde_json::json!(SIMPLE_USER_POLICIES.clone());
    let expected_payload = TokenPayload {
        policies: SIMPLE_USER_POLICIES_WITH_DEFAULTS.clone(),
        token_type: TokenType::User,
    };

    use_app(|client| async move {
        // processing
        let response = client
            .make_admin_request(ISSUE_USER_TOKEN.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_token_pair_with_expected_payload(response, expected_payload)
            .await;
    })
    .await;
}

#[tokio::test]
async fn test_unauthorized() {
    // preparing
    let request_body = serde_json::json!(SIMPLE_USER_POLICIES.clone());

    use_app(|client| async move {
        // processing
        let response = client
            .make_request(ISSUE_USER_TOKEN.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_without_policies() {
    // preparing
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

    use_app(|client| async move {
        // processing
        let response = client
            .make_admin_request(ISSUE_USER_TOKEN.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_token_pair_with_expected_payload(response, expected_payload)
            .await;
    })
    .await;
}

#[tokio::test]
async fn test_impossibility_to_set_global_permissions() {
    // preparing
    let request_body = serde_json::json!({
        "__default__": {
            "permissions": ["create", "read"],
            "secrets": {
                "__default__": ["read"]
            }
        }
    });

    use_app(|client| async move {
        // processing
        let response = client
            .make_admin_request(ISSUE_USER_TOKEN.clone(), &request_body)
            .await;

        // checking
        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    })
    .await;
}
