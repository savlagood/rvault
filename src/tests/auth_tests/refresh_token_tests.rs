use crate::http::jwt_tokens::{self, TokenPair};
use crate::tests::{
    assertions, jwt_utils, routes,
    server::{use_app, ClientWithServer, CONFIG},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_access_and_refresh_tokens_still_valid() {
    let token_pair = jwt_utils::make_admin_token_pair_with_specified_access_refresh_exp(
        jwt_tokens::calculate_expiration_time(CONFIG.access_token_exp),
        jwt_tokens::calculate_expiration_time(CONFIG.refresh_token_exp),
    );
    let request_body = serde_json::to_value(&token_pair).expect("Failed to serialize token pair");

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::REFRESH_TOKEN_PAIR_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assertions::token_pair::assert_response_contains_valid_refreshed_token_pair(
            response, token_pair,
        )
        .await;
    });
}

#[test]
fn test_access_token_expired() {
    let token_pair = jwt_utils::make_admin_token_pair_with_specified_access_refresh_exp(
        0,
        jwt_tokens::calculate_expiration_time(CONFIG.refresh_token_exp),
    );
    let request_body = serde_json::to_value(&token_pair).expect("Failed to serialize token pair");

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::REFRESH_TOKEN_PAIR_PATH, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assertions::token_pair::assert_response_contains_valid_refreshed_token_pair(
            response, token_pair,
        )
        .await;
    });
}

#[test]
fn test_refresh_token_expired() {
    let token_pair = jwt_utils::make_admin_token_pair_with_specified_access_refresh_exp(0, 0);
    let request_body = serde_json::to_value(&token_pair).expect("Failed to serialize token pair");

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(routes::REFRESH_TOKEN_PAIR_PATH, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assertions::error_message::assert_error_response(response, expected_status_code).await;
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

        let request_body =
            serde_json::to_value(&combined_token_pair).expect("Failed to seralize token pair");

        let response = client
            .make_request(routes::REFRESH_TOKEN_PAIR_PATH, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assertions::error_message::assert_error_response(response, expected_status_code).await;
    });
}
