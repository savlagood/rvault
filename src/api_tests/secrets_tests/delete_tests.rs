use crate::api_tests::{
    assertions::error_message::assert_error_response,
    client::ClientWithServer,
    consts::{SECRET_NAME, SECRET_VALUE, TOPIC_NAME},
    endpoints::{delete_secret, secrets_list},
    models::{common::Headers, policies::Permission, secrets::SecretNames},
    runtime::use_app,
    utils::{common::build_policies, storage},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

async fn assert_secret_deleted(client: &ClientWithServer, topic_name: &str, headers: Headers) {
    let request_body = serde_json::json!({});
    let response = client
        .make_admin_request_with_headers(secrets_list(topic_name), &request_body, headers)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let names = SecretNames::from_response(response).await.names;
    assert!(names.is_empty());
}

#[tokio::test]
async fn test_delete_as_admin() {
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
                delete_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers.clone(),
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_secret_deleted(&client, TOPIC_NAME, headers).await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_as_user() {
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
            vec![Permission::Delete],
        );

        let request_body = serde_json::json!({});

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // processing
        let response = client
            .make_user_request_with_headers(
                delete_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
                headers.clone(),
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_secret_deleted(&client, TOPIC_NAME, headers).await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_as_user_without_permission() {
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
            vec![Permission::Read],
        );

        let request_body = serde_json::json!({});

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // processing
        let response = client
            .make_user_request_with_headers(
                delete_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
                headers.clone(),
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_unauthorized() {
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
            .make_request(delete_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_with_invalid_topic_key() {
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
        headers.add_topic_key_header("invalid_topic_key");
        headers.add_secret_key_header(&secret_key);

        // processing
        let response = client
            .make_admin_request_with_headers(
                delete_secret(TOPIC_NAME, SECRET_NAME),
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
async fn test_delete_with_invalid_secret_key() {
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
        headers.add_secret_key_header("invalid_secret_key");

        // processing
        let response = client
            .make_admin_request_with_headers(
                delete_secret(TOPIC_NAME, SECRET_NAME),
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
async fn test_delete_in_nonexistent_topic() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        // Topic not created
        let nonexistent_topic = "nonexistent_topic";
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(delete_secret(nonexistent_topic, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_nonexistent_secret() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let nonexistent_secret = "nonexistent_secret";
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(delete_secret(TOPIC_NAME, nonexistent_secret), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
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
            .make_admin_request(delete_secret(TOPIC_NAME, SECRET_NAME), &request_body)
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
            .make_admin_request(delete_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
