use crate::api_tests::{
    assertions::error_message::assert_error_response,
    consts::{SECRET_NAME, SECRET_VALUE, TOPIC_NAME},
    endpoints::{secret_versions, update_secret},
    models::{common::Headers, policies::Permission, secrets::SecretVersions},
    runtime::use_app,
    utils::{common::build_policies, storage},
};
use reqwest::{Response, StatusCode};

#[cfg(test)]
use pretty_assertions::assert_eq;

async fn assert_response_contains_versions(response: Response, expected_versions: Vec<&str>) {
    let versions_response = SecretVersions::from_response(response).await;

    for version in versions_response.versions {
        assert_eq!(version.value, expected_versions[version.version]);
    }
}

#[tokio::test]
async fn test_get_versions_as_admin() {
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

        // Create multiple versions by updating
        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        let versions = vec![SECRET_VALUE, "Second version", "Third version"];
        for version in versions.iter().skip(1) {
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

        // processing
        let response = client
            .make_admin_request_with_headers(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                &serde_json::json!({}),
                headers,
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_versions(response, versions).await;
    })
    .await;
}

#[tokio::test]
async fn test_get_versions_as_user() {
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
        let response = client
            .make_user_request_with_headers(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                policies,
                &serde_json::json!({}),
                headers,
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        assert_response_contains_versions(response, vec![SECRET_VALUE]).await;
    })
    .await;
}

#[tokio::test]
async fn test_get_versions_unauthorized() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;
        client
            .create_secret_encryption_none(TOPIC_NAME, SECRET_NAME, String::from(SECRET_VALUE))
            .await;

        // processing
        let response = client
            .make_request(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                &serde_json::json!({}),
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_get_versions_without_read_permission() {
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
            vec![Permission::Update],
            SECRET_NAME,
            vec![Permission::Update],
        );

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // processing
        let response = client
            .make_user_request_with_headers(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                policies,
                &serde_json::json!({}),
                headers,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_get_versions_nonexistent_topic() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        // processing
        let response = client
            .make_admin_request(
                secret_versions("nonexistent_topic", SECRET_NAME),
                &serde_json::json!({}),
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_get_versions_nonexistent_secret() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        // processing
        let response = client
            .make_admin_request(
                secret_versions(TOPIC_NAME, "nonexistent_secret"),
                &serde_json::json!({}),
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_get_versions_invalid_topic_key() {
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
        let response = client
            .make_admin_request_with_headers(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                &serde_json::json!({}),
                headers,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_get_versions_invalid_secret_key() {
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
        let response = client
            .make_admin_request_with_headers(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                &serde_json::json!({}),
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

        // processing
        let response = client
            .make_admin_request(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                &serde_json::json!({}),
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_storage_is_uninitialized() {
    use_app(|client| async move {
        // processing
        let response = client
            .make_admin_request(
                secret_versions(TOPIC_NAME, SECRET_NAME),
                &serde_json::json!({}),
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
