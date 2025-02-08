use crate::tests::{
    assertions::{
        error_message::assert_error_response,
        token_pair::assert_response_contains_valid_admin_token_pair,
    },
    consts::ENV_ROOT_TOKEN,
    routes,
    server::{use_app, ClientWithServer},
    utils::get_env_var,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_issue_token() {
    let request_body = root_token_as_request_body();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::ISSUE_ADMIN_TOKEN_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_admin_token_pair(response).await;
    });
}

fn root_token_as_request_body() -> serde_json::Value {
    let root_token = get_env_var(ENV_ROOT_TOKEN);
    let request_body = token_into_request_body(&root_token);

    request_body
}

#[test]
fn test_invalid_root_token() {
    let request_body = token_into_request_body("some_invalid_token");

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::ISSUE_ADMIN_TOKEN_PATH, request_body)
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_empty_root_token() {
    let request_body = token_into_request_body("");

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::ISSUE_ADMIN_TOKEN_PATH, request_body)
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

fn token_into_request_body(token: &str) -> serde_json::Value {
    serde_json::json!({"token": token})
}
