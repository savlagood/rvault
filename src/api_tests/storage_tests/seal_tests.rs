use crate::api_tests::{
    assertions::error_message::assert_error_response, consts::SIMPLE_USER_POLICIES,
    endpoints::SEAL_STORAGE, runtime::use_app, utils::storage,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_seal_ok() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(SEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn test_unauthorized() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_request(SEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_seal_as_user() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_user_request(
                SEAL_STORAGE.clone(),
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
async fn test_seal_when_storage_uninitialized() {
    use_app(|client| async move {
        // preparing
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(SEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_seal_when_storage_sealed() {
    use_app(|client| async move {
        // preparing
        let _shared_keys = storage::init(&client).await;
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(SEAL_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
