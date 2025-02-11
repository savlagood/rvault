use crate::tests::{
    assertions::{
        error_message::assert_error_response,
        token_pair::assert_response_contains_valid_refreshed_token_pair,
    },
    consts::{SIMPLE_USER_POLICIES, TEST_ACCESS_TOKEN_TTL, TEST_REFRESH_TOKEN_TTL},
    models::jwt_tokens::TokenPair,
    routes,
    server::{use_app, ClientWithServer},
    utils,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_refresh_admin_token_pair() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let original_admin_token_pair = client.fetch_admin_token_pair().await;

        let request_body = serde_json::json!(original_admin_token_pair);
        let response = client
            .make_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_admin_token_pair)
            .await;
    });
}

#[test]
fn test_refresh_user_token_pair() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let original_admin_token_pair = client
            .fetch_user_token_pair(SIMPLE_USER_POLICIES.clone())
            .await;

        let request_body = serde_json::json!(original_admin_token_pair);
        let response = client
            .make_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_admin_token_pair)
            .await;
    });
}

#[test]
fn test_access_and_refresh_tokens_still_valid() {
    let access_token_exp = utils::calculate_expiration_time(TEST_ACCESS_TOKEN_TTL);
    let refresh_token_exp = utils::calculate_expiration_time(TEST_REFRESH_TOKEN_TTL);

    let original_token_pair = utils::jwt::make_admin_token_pair_with_specified_expiration_time(
        access_token_exp,
        refresh_token_exp,
    );
    let request_body = serde_json::json!(original_token_pair);

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_token_pair).await;
    });
}

#[test]
fn test_empty_tokens() {
    let token_pair = TokenPair {
        access_token: "".to_string(),
        refresh_token: "".to_string(),
    };
    let request_body = serde_json::json!(token_pair);

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_invalid_tokens() {
    let token_pair = TokenPair {
        access_token: "some_invalid_access_token".to_string(),
        refresh_token: "some_invalid_refresh_token".to_string(),
    };
    let request_body = serde_json::json!(token_pair);

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_access_token_expired() {
    let access_token_exp = 0;
    let refresh_token_exp = utils::calculate_expiration_time(TEST_REFRESH_TOKEN_TTL);

    let original_token_pair = utils::jwt::make_admin_token_pair_with_specified_expiration_time(
        access_token_exp,
        refresh_token_exp,
    );
    let request_body = serde_json::json!(original_token_pair);

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_token_pair).await;
    });
}

#[test]
fn test_refresh_token_expired() {
    let access_token_exp = utils::calculate_expiration_time(TEST_ACCESS_TOKEN_TTL);
    let refresh_token_exp = 0;

    let token_pair = utils::jwt::make_admin_token_pair_with_specified_expiration_time(
        access_token_exp,
        refresh_token_exp,
    );
    let request_body = serde_json::json!(token_pair);

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_both_tokens_expired() {
    let access_token_exp = 0;
    let refresh_token_exp = 0;

    let token_pair = utils::jwt::make_admin_token_pair_with_specified_expiration_time(
        access_token_exp,
        refresh_token_exp,
    );
    let request_body = serde_json::json!(token_pair);

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_access_token_not_linked_to_refresh_token() {
    use_app(async move {
        let client = ClientWithServer::new().await;

        let first_token_pair = client.fetch_admin_token_pair().await;
        let second_token_pair = client.fetch_admin_token_pair().await;

        let combined_token_pair = TokenPair {
            access_token: first_token_pair.access_token,
            refresh_token: second_token_pair.refresh_token,
        };
        let request_body = serde_json::json!(combined_token_pair);

        let response = client
            .make_admin_request(&routes::REFRESH_TOKEN_PAIR_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}
