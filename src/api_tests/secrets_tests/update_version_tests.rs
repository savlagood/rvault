use crate::api_tests::{
    assertions::error_message::assert_error_response,
    client::ClientWithServer,
    consts::{SECRET_NAME, SECRET_VALUE, TOPIC_NAME},
    endpoints::{read_secret, update_secret, update_secret_version},
    models::{common::Headers, policies::Permission, secrets::SecretValue},
    runtime::use_app,
    utils::{common::build_policies, storage},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

async fn assert_version_updated(
    client: &ClientWithServer,
    headers: Headers,
    expected_version: usize,
    expected_value: &str,
) {
    let response = client
        .make_admin_request_with_headers(
            read_secret(TOPIC_NAME, SECRET_NAME),
            &serde_json::json!({}),
            headers,
        )
        .await;

    let secret = SecretValue::from_response(response).await;

    assert_eq!(secret.version, expected_version);
    assert_eq!(secret.value, expected_value);
}

#[tokio::test]
async fn test_update_version_as_admin() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;
        let secret_key = client
            .create_secret_in_encrypted_topic(
                TOPIC_NAME,
                SECRET_NAME,
                String::from("Version 0"),
                &topic_key,
            )
            .await;

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // Create multiple versions
        let versions = vec!["Version 1", "Version 2", "Version 3"];

        for version in versions.iter() {
            let request_body = serde_json::json!({
                "value": version
            });

            client
                .make_admin_request_with_headers(
                    update_secret(TOPIC_NAME, SECRET_NAME),
                    &request_body,
                    headers.clone(),
                )
                .await;
        }

        let expected_version = 1;

        // processing - switch to first version
        let request_body = serde_json::json!({ "version": expected_version});
        let response = client
            .make_admin_request_with_headers(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers.clone(),
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_version_updated(
            &client,
            headers,
            expected_version,
            &versions[expected_version - 1],
        )
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_update_version_as_user() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;
        let secret_key = client
            .create_secret_in_encrypted_topic(
                TOPIC_NAME,
                SECRET_NAME,
                String::from("Initial value"),
                &topic_key,
            )
            .await;

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Read, Permission::Update],
            SECRET_NAME,
            vec![Permission::Read, Permission::Update],
        );

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // Add another version
        client
            .make_admin_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
                &serde_json::json!({"value": "Updated value"}),
                headers.clone(),
            )
            .await;

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_user_request_with_headers(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    })
    .await;
}

#[tokio::test]
async fn test_update_version_unauthorized() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        client.create_topic_encryption_none(TOPIC_NAME).await;
        client
            .create_secret_encryption_none(TOPIC_NAME, SECRET_NAME, String::from(SECRET_VALUE))
            .await;

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_request(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_update_version_without_permissions() {
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

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Read],
            SECRET_NAME,
            vec![Permission::Read],
        );

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_user_request_with_headers(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
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
async fn test_update_version_nonexistent_version() {
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

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // processing
        let request_body = serde_json::json!({ "version": 99 });
        let response = client
            .make_admin_request_with_headers(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_update_version_nonexistent_secret() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_admin_request(
                update_secret_version(TOPIC_NAME, "nonexistent_secret"),
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_update_version_nonexistent_topic() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_admin_request(
                update_secret_version("nonexistent_topic", SECRET_NAME),
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_update_version_invalid_topic_key() {
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

        let mut headers = Headers::new();
        headers.add_topic_key_header("invalid_topic_key");
        headers.add_secret_key_header(&secret_key);

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_admin_request_with_headers(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
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
async fn test_update_version_invalid_secret_key() {
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

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header("invalid_secret_key");

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_admin_request_with_headers(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
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
async fn test_update_version_storage_sealed() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_sealed(&client).await;

        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_admin_request(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_update_version_storage_uninitialized() {
    use_app(|client| async move {
        // processing
        let request_body = serde_json::json!({ "version": 0 });
        let response = client
            .make_admin_request(
                update_secret_version(TOPIC_NAME, SECRET_NAME),
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
