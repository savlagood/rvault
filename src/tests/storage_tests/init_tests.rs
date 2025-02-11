use crate::tests::{
    assertions::error_message::assert_error_response,
    consts::SIMPLE_USER_POLICIES,
    models::shared_keys::{SharedKeys, SharedKeysSettings},
    routes,
    server::{use_app, ClientWithServer},
    storage,
};
use reqwest::{Response, StatusCode};

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn test_init_ok() {
    let shared_keys_settings = SharedKeysSettings::new_with_defaults();
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_shared_keys(response).await;
    });
}

async fn assert_response_contains_valid_shared_keys(response: Response) {
    let shared_keys = response
        .json::<SharedKeys>()
        .await
        .expect("Error during parsing shared keys from response");

    assert!(!shared_keys.shares.is_empty());
}

#[test]
fn test_unauthorized() {
    let shared_keys_settings = SharedKeysSettings::new_with_defaults();
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::UNAUTHORIZED;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_init_with_user_token() {
    let shared_keys_settings = SharedKeysSettings::new_with_defaults();
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_user_request(
                &routes::INIT_STORAGE_ENDPOINT,
                SIMPLE_USER_POLICIES.clone(),
                request_body,
            )
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_init_storage_when_storage_state_is_sealed() {
    let shared_keys_settings = SharedKeysSettings::new_with_defaults();
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        storage::from_uninitialized_to_sealed(&client).await;

        let response = client
            .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_init_storage_when_storage_state_is_unsealed() {
    let shared_keys_settings = SharedKeysSettings::new_with_defaults();
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        storage::from_uninitialized_to_unsealed(&client).await;

        let response = client
            .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_threshold_and_total_keys_equals() {
    let shared_keys_settings = SharedKeysSettings {
        threshold: 42,
        total_keys: 42,
    };
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_threshold_greater_than_total_keys() {
    let shared_keys_settings = SharedKeysSettings {
        threshold: 92,
        total_keys: 42,
    };
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_one_threshold() {
    let shared_keys_settings = SharedKeysSettings {
        threshold: 1,
        total_keys: 42,
    };
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_zero_threshold() {
    let shared_keys_settings = SharedKeysSettings {
        threshold: 0,
        total_keys: 42,
    };
    let request_body = shared_keys_settings.into_json_value();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}
