use crate::api_tests::{
    assertions::error_message::assert_error_response,
    consts::{SIMPLE_USER_POLICIES, THRESHOLD},
    endpoints::UNSEAL_STORAGE,
    models::shared_keys::SharedKeys,
    runtime::use_app,
    utils::storage,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_unseal_ok() {
    use_app(|client| async move {
        // preparing
        let shared_keys = storage::init(&client).await;
        let request_body = shared_keys.into_value();

        // processing
        let response = client
            .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await
}

#[tokio::test]
async fn test_unauthorized() {
    use_app(|client| async move {
        // preparing
        let shared_keys = storage::init(&client).await;
        let request_body = shared_keys.into_value();

        // processing
        let response = client
            .make_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_unseal_as_user() {
    use_app(|client| async move {
        // preparing
        let shared_keys = storage::init(&client).await;
        let request_body = shared_keys.into_value();

        // processing
        let response = client
            .make_user_request(
                UNSEAL_STORAGE.clone(),
                SIMPLE_USER_POLICIES.clone(),
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_unseal_when_storage_uninitialized() {
    use_app(|client| async move {
        // preparing
        let shared_keys = SharedKeys::new();
        let request_body = shared_keys.into_value();

        // processing
        let response: reqwest::Response = client
            .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_unseal_when_storage_unsealed() {
    use_app(|client| async move {
        // preparing
        let shared_keys = storage::init(&client).await;

        // 1st unseal
        storage::unseal(&client, shared_keys.clone()).await;

        let request_body = shared_keys.into_value();

        // processing
        // 2nd unseal
        let response: reqwest::Response = client
            .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_unseal_with_empty_shared_keys_array() {
    use_app(|client| async move {
        // preparing
        let _shared_keys = storage::init(&client).await;

        let shared_keys = SharedKeys::new();
        let request_body = shared_keys.into_value();

        // processing
        let response = client
            .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_unseal_with_minimum_necessary_number_of_shared_keys() {
    use_app(|client| async move {
        // preparing
        let shared_keys = storage::init(&client).await;

        let truncated_shared_keys = shared_keys.trim_shares(THRESHOLD as usize);
        let request_body = truncated_shared_keys.into_value();

        // processing
        let response = client
            .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn test_unseal_with_smaller_number_of_shared_keys_than_required() {
    use_app(|client| async move {
        // preparing
        let shared_keys = storage::init(&client).await;

        let threshold = THRESHOLD - 1;
        let truncated_shared_keys = shared_keys.trim_shares(threshold as usize);
        let request_body = truncated_shared_keys.into_value();

        // processing
        let response = client
            .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_unseal_with_larger_number_of_shared_keys_than_required() {
    use_app(|client| async move {
        // preparing
        let shared_keys = storage::init(&client).await;

        let threshold = THRESHOLD + 1;
        let truncated_shared_keys = shared_keys.trim_shares(threshold as usize);
        let request_body = truncated_shared_keys.into_value();

        // processing
        let response = client
            .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await;
}
