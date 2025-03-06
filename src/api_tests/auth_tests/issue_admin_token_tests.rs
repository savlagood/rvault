use crate::api_tests::{
    assertions::{
        auth::assert_response_contains_valid_admin_token_pair, error_message::assert_error_response,
    },
    client::ClientWithServer,
    endpoints::ISSUE_ADMIN_TOKEN,
    models::auth::RootToken,
    runtime::use_app,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

fn get_root_token_as_request_body(client: &ClientWithServer) -> serde_json::Value {
    let root_token = client.config.root_token.clone();
    RootToken::new(root_token).into_value()
}

#[tokio::test]
async fn test_issue_token() {
    use_app(|client| async move {
        // preparing
        let request_body = get_root_token_as_request_body(&client);

        // processing
        let response = client
            .make_request(ISSUE_ADMIN_TOKEN.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_admin_token_pair(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_invalid_root_token() {
    // preparing
    let root_token = RootToken::new(String::from("some_invalid_token"));
    let request_body = root_token.into_value();

    use_app(|client| async move {
        // processing
        let response = client
            .make_request(ISSUE_ADMIN_TOKEN.clone(), &request_body)
            .await;

        // checking
        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    })
    .await;
}

#[tokio::test]
async fn test_empty_root_token() {
    // preparing
    let root_token = RootToken::new(String::from(""));
    let request_body = root_token.into_value();

    use_app(|client| async move {
        // processing
        let response = client
            .make_request(ISSUE_ADMIN_TOKEN.clone(), &request_body)
            .await;

        // checking
        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    })
    .await;
}
