use crate::api_tests::{
    assertions::{
        auth::assert_response_contains_valid_refreshed_token_pair,
        error_message::assert_error_response,
    },
    consts::SIMPLE_USER_POLICIES,
    endpoints::REFRESH_TOKEN_PAIR,
    models::auth::TokenPair,
    runtime::use_app,
    utils::{
        common::calculate_expiration_time,
        jwt::make_admin_token_pair_with_specified_expiration_time,
    },
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_refresh_admin_token_pair() {
    use_app(|client| async move {
        // preparing
        let original_admin_token_pair = client.fetch_admin_token_pair().await;
        let request_body = serde_json::json!(original_admin_token_pair);

        // processing
        let response = client
            .make_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_admin_token_pair)
            .await;
    })
    .await;
}

#[tokio::test]
async fn test_refresh_user_token_pair() {
    use_app(|client| async move {
        // preparing
        let original_admin_token_pair = client
            .fetch_user_token_pair(SIMPLE_USER_POLICIES.clone())
            .await;
        let request_body = original_admin_token_pair.clone().into_value();

        // processing
        let response = client
            .make_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_admin_token_pair)
            .await;
    })
    .await;
}

#[tokio::test]
async fn test_empty_tokens() {
    // preparing
    let token_pair = TokenPair {
        access_token: String::new(),
        refresh_token: String::new(),
    };
    let request_body = serde_json::json!(token_pair);

    use_app(|client| async move {
        // processing
        let response = client
            .make_admin_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_invalid_tokens() {
    // preparing
    let token_pair = TokenPair {
        access_token: String::from("some_invalid_access_token"),
        refresh_token: String::from("some_invalid_refresh_token"),
    };
    let request_body = token_pair.clone().into_value();

    use_app(|client| async move {
        // preparing
        let response = client
            .make_admin_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_access_and_refresh_tokens_still_valid() {
    use_app(|client| async move {
        // preparing
        let access_token_exp = calculate_expiration_time(client.config.access_token_ttl);
        let refresh_token_exp = calculate_expiration_time(client.config.refresh_token_ttl);

        let original_token_pair = make_admin_token_pair_with_specified_expiration_time(
            access_token_exp,
            refresh_token_exp,
        );
        let request_body = original_token_pair.clone().into_value();

        // processing
        let response = client
            .make_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_token_pair).await;
    })
    .await;
}

#[tokio::test]
async fn test_access_token_expired() {
    use_app(|client| async move {
        // preparing
        let access_token_exp = 0;
        let refresh_token_exp = calculate_expiration_time(client.config.refresh_token_ttl);

        let original_token_pair = make_admin_token_pair_with_specified_expiration_time(
            access_token_exp,
            refresh_token_exp,
        );
        let request_body = original_token_pair.clone().into_value();

        // processing
        let response = client
            .make_admin_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_refreshed_token_pair(response, original_token_pair).await;
    })
    .await;
}

#[tokio::test]
async fn test_refresh_token_expired() {
    use_app(|client| async move {
        // preparing
        let access_token_exp = calculate_expiration_time(client.config.access_token_ttl);
        let refresh_token_exp = 0;

        let original_token_pair = make_admin_token_pair_with_specified_expiration_time(
            access_token_exp,
            refresh_token_exp,
        );
        let request_body = original_token_pair.clone().into_value();

        // processing
        let response = client
            .make_admin_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_both_tokens_expired() {
    use_app(|client| async move {
        // preparing
        let access_token_exp = 0;
        let refresh_token_exp = 0;

        let original_token_pair = make_admin_token_pair_with_specified_expiration_time(
            access_token_exp,
            refresh_token_exp,
        );
        let request_body = original_token_pair.clone().into_value();

        // processing
        let response = client
            .make_admin_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_access_token_not_linked_to_refresh_token() {
    use_app(|client| async move {
        // preparing
        let first_token_pair = client.fetch_admin_token_pair().await;
        let second_token_pair = client.fetch_admin_token_pair().await;

        let combined_token_pair = TokenPair {
            access_token: first_token_pair.access_token,
            refresh_token: second_token_pair.refresh_token,
        };
        let request_body = combined_token_pair.clone().into_value();

        // processing
        let response = client
            .make_admin_request(REFRESH_TOKEN_PAIR.clone(), &request_body)
            .await;

        // checking
        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    })
    .await;
}
