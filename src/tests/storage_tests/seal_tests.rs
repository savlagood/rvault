use crate::tests::{
    assertions::error_message::assert_error_response,
    consts::SIMPLE_USER_POLICIES,
    routes,
    server::{use_app, ClientWithServer},
    storage,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_seal_ok() {
    use_app(async {
        let client = ClientWithServer::new().await;

        storage_to_unsealed_state(&client).await;

        let request_body = serde_json::json!({});
        let response = client
            .make_admin_request(&routes::SEAL_STORAGE_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    });
}

#[test]
fn test_unauthorized() {
    use_app(async {
        let client = ClientWithServer::new().await;

        storage_to_unsealed_state(&client).await;

        let request_body = serde_json::json!({});
        let response = client
            .make_request(&routes::SEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_seal_with_user_token() {
    use_app(async {
        let client = ClientWithServer::new().await;

        storage_to_unsealed_state(&client).await;

        let request_body = serde_json::json!({});
        let response = client
            .make_user_request(
                &routes::SEAL_STORAGE_ENDPOINT,
                SIMPLE_USER_POLICIES.clone(),
                request_body,
            )
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_seal_storage_when_storage_state_is_uninitialized() {
    use_app(async {
        let client = ClientWithServer::new().await;

        let request_body = serde_json::json!({});
        let response = client
            .make_admin_request(&routes::SEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_seal_storage_when_storage_state_is_sealed() {
    use_app(async {
        let client = ClientWithServer::new().await;

        let _shared_keys = storage::init_and_get_shared_keys(&client).await;

        let request_body = serde_json::json!({});
        let response = client
            .make_admin_request(&routes::SEAL_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

async fn storage_to_unsealed_state(client: &ClientWithServer) {
    let shared_keys = storage::init_and_get_shared_keys(client).await;
    storage::unseal(client, &shared_keys).await;
}
