use crate::tests::{
    assertions::error_message::assert_error_response,
    consts::{SIMPLE_USER_POLICIES, THRESHOLD},
    models::shared_keys::SharedKeys,
    routes,
    server::{use_app, ClientWithServer},
    storage,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_pass_all_shared_keys() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let shared_keys = storage::init_and_get_shared_keys(&client).await;

        let request_body = serde_json::json!(shared_keys);
        let response = client
            .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    });
}

#[test]
fn test_unauthorized() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let shared_keys = storage::init_and_get_shared_keys(&client).await;

        let request_body = serde_json::json!(shared_keys);
        let response = client
            .make_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_unseal_with_user_token() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let shared_keys = storage::init_and_get_shared_keys(&client).await;

        let request_body = serde_json::json!(shared_keys);
        let response = client
            .make_user_request(
                &routes::UNSEAL_STORAGE_ENDPOINT,
                SIMPLE_USER_POLICIES.clone(),
                request_body,
            )
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_unseal_storage_when_storage_state_is_uninitialized() {
    use_app(async {
        let client = ClientWithServer::new().await;

        let shared_keys = SharedKeys::new_empty();
        let request_body = serde_json::json!(shared_keys);

        let response: reqwest::Response = client
            .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_unseal_storage_when_storage_state_is_unsealed() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let shared_keys = storage::init_and_get_shared_keys(&client).await;

        // 1st unseal
        storage::unseal(&client, &shared_keys).await;

        // 2nd unseal with check response
        let request_body = serde_json::json!(shared_keys);
        let response = client
            .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_pass_empty_shared_keys_array() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let _shared_keys = storage::init_and_get_shared_keys(&client).await;

        let shared_keys = SharedKeys::new_empty();
        let request_body = serde_json::json!(shared_keys);

        let response = client
            .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_pass_minimum_necessary_number_of_shared_keys() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let shared_keys = storage::init_and_get_shared_keys(&client).await;

        let truncated_shared_keys = shared_keys.trim_shares(THRESHOLD as usize);
        let request_body = serde_json::json!(truncated_shared_keys);

        let response = client
            .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    });
}

#[test]
fn test_pass_smaller_number_of_shared_keys_than_required() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let shared_keys = storage::init_and_get_shared_keys(&client).await;

        let threshold = THRESHOLD - 1;
        let truncated_shared_keys = shared_keys.trim_shares(threshold as usize);
        let request_body = serde_json::json!(truncated_shared_keys);

        let response = client
            .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_pass_larger_number_of_shared_keys_than_required() {
    use_app(async {
        let client = ClientWithServer::new().await;
        let shared_keys = storage::init_and_get_shared_keys(&client).await;

        let threshold = THRESHOLD + 1;
        let truncated_shared_keys = shared_keys.trim_shares(threshold as usize);
        let request_body = serde_json::json!(truncated_shared_keys);

        let response = client
            .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    });
}
