use crate::api_tests::{
    assertions::{
        error_message::assert_error_response, secrets::assert_response_contains_secret_value,
    },
    consts::{SECRET_NAME, SECRET_VALUE, TOPIC_NAME},
    endpoints::read_secret,
    models::{common::Headers, policies::Permission, secrets::SecretValue},
    runtime::use_app,
    utils::{common::build_policies, storage},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_read_as_admin() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;
        let secret_key = client
            .create_secret_in_encrypted_topic(
                TOPIC_NAME,
                SECRET_NAME,
                String::from(SECRET_VALUE),
                &topic_key,
            )
            .await;

        let request_body = serde_json::json!({});

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // processing
        let response = client
            .make_admin_request_with_headers(
                read_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        let expected_value = SecretValue {
            value: String::from(SECRET_VALUE),
            version: 0,
        };
        assert_response_contains_secret_value(response, &expected_value).await;
    })
    .await;
}

#[tokio::test]
async fn test_read_as_user() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;
        let secret_key = client
            .create_secret_in_encrypted_topic(
                TOPIC_NAME,
                SECRET_NAME,
                String::from(SECRET_VALUE),
                &topic_key,
            )
            .await;

        let request_body = serde_json::json!({});

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Read],
            SECRET_NAME,
            vec![Permission::Read],
        );

        // processing
        let response = client
            .make_user_request_with_headers(
                read_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        let expected_value = SecretValue {
            value: String::from(SECRET_VALUE),
            version: 0,
        };
        assert_response_contains_secret_value(response, &expected_value).await;
    })
    .await;
}

#[tokio::test]
async fn test_read_as_user_without_permissions() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;
        let secret_key = client
            .create_secret_in_encrypted_topic(
                TOPIC_NAME,
                SECRET_NAME,
                String::from(SECRET_VALUE),
                &topic_key,
            )
            .await;

        let request_body = serde_json::json!({});

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        let policies = build_policies(TOPIC_NAME, vec![Permission::Read], SECRET_NAME, vec![]);

        // processing
        let response = client
            .make_user_request_with_headers(
                read_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_topic_and_secret_encryption_none() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        client.create_topic_encryption_none(TOPIC_NAME).await;
        client
            .create_secret_encryption_none(TOPIC_NAME, SECRET_NAME, String::from(SECRET_VALUE))
            .await;

        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(read_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        let expected_value = SecretValue {
            value: String::from(SECRET_VALUE),
            version: 0,
        };
        assert_response_contains_secret_value(response, &expected_value).await;
    })
    .await;
}

#[tokio::test]
async fn test_only_topic_encryption_invalid_topic_key() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;
        client
            .create_secret_encryption_none_in_encrypted_topic(
                TOPIC_NAME,
                SECRET_NAME,
                String::from(SECRET_VALUE),
                &topic_key,
            )
            .await;

        let request_body = serde_json::json!({});

        let mut headers = Headers::new();
        headers.add_topic_key_header("some_invalid_topic key :)");

        // processing
        let response = client
            .make_admin_request_with_headers(
                read_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_invalid_secret_key() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;
        let _secret_key = client
            .create_secret_in_encrypted_topic(
                TOPIC_NAME,
                SECRET_NAME,
                String::from(SECRET_VALUE),
                &topic_key,
            )
            .await;

        let request_body = serde_json::json!({});

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header("some invalid secret key :)");

        // processing
        let response = client
            .make_admin_request_with_headers(
                read_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_storage_is_sealed() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_sealed(&client).await;
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(read_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_storage_is_uninitialized() {
    use_app(|client| async move {
        // preparing
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(read_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
