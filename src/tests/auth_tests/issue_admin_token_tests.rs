use crate::tests::{
    assertions, routes,
    server::{use_app, ClientWithServer, CONFIG},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_everything_ok() {
    let request_body = serde_json::json!({
        "token": CONFIG.root_token.clone()
    });

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::ISSUE_ADMIN_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assertions::token_pair::assert_response_contains_valid_admin_token_pair(response).await;
    });
}

#[test]
fn test_unauthorized() {
    let request_body = serde_json::json!({
        "token": "some_invalid_token",
    });

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::ISSUE_ADMIN_TOKEN_PATH, request_body)
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assertions::error_message::assert_error_response(response, expected_status_code).await;
    });
}
