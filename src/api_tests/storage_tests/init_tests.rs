use crate::api_tests::{
    assertions::{
        error_message::assert_error_response, storage::assert_response_contains_valid_shared_keys,
    },
    consts::{SIMPLE_USER_POLICIES, THRESHOLD, TOTAL_KEYS},
    endpoints::INIT_STORAGE,
    models::shared_keys::SharedKeysSettings,
    runtime::use_app,
    utils::storage,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_init_ok() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings {
            threshold: THRESHOLD,
            total_keys: TOTAL_KEYS,
        };
        let request_body = shared_keys_settings.into_value();

        // processing
        let response = client
            .make_admin_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_valid_shared_keys(response, TOTAL_KEYS as usize).await;
    })
    .await;
}

#[tokio::test]
async fn test_unauthorized() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings::default();
        let request_body = shared_keys_settings.into_value();

        // processing
        let response = client
            .make_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_init_with_user_token() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings::default();
        let request_body = shared_keys_settings.into_value();

        // processing
        let response = client
            .make_user_request(
                INIT_STORAGE.clone(),
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
async fn test_init_when_storage_sealed() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings::default();
        let request_body = shared_keys_settings.into_value();

        storage::from_uninitialized_to_sealed(&client).await;

        // processing
        let response = client
            .make_admin_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_init_when_storage_unsealed() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings::default();
        let request_body = shared_keys_settings.into_value();

        storage::from_uninitialized_to_unsealed(&client).await;

        // processing
        let response = client
            .make_admin_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_threshold_and_total_keys_equals() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings {
            threshold: 42,
            total_keys: 42,
        };
        let request_body = shared_keys_settings.into_value();

        // processing
        let response = client
            .make_admin_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_threshold_greater_than_total_keys() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings {
            threshold: 92,
            total_keys: 42,
        };
        let request_body = shared_keys_settings.into_value();

        // processing
        let response = client
            .make_admin_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_one_threshold() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings {
            threshold: 1,
            total_keys: 42,
        };
        let request_body = shared_keys_settings.into_value();

        // processing
        let response = client
            .make_admin_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_zero_threshold() {
    use_app(|client| async move {
        // preparing
        let shared_keys_settings = SharedKeysSettings {
            threshold: 0,
            total_keys: 42,
        };
        let request_body = shared_keys_settings.into_value();

        // processing
        let response = client
            .make_admin_request(INIT_STORAGE.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
