use crate::api_tests::{
    assertions::error_message::assert_error_response,
    client::ClientWithServer,
    consts::{SECRET_VALUE, TOPIC_NAME},
    endpoints::{delete_topic, secrets_list},
    models::{common::Headers, policies::Permission},
    runtime::use_app,
    utils::{common::build_policies_for_topic_access, storage},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

async fn create_topic_with_secrets(client: &ClientWithServer) -> String {
    // Create topic with some secrets
    let topic_key = client.create_topic(TOPIC_NAME).await;

    // Add a few secrets to the topic
    for secret_name in ["secret1", "secret2"] {
        client
            .create_secret_in_encrypted_topic(
                TOPIC_NAME,
                secret_name,
                String::from(SECRET_VALUE),
                &topic_key,
            )
            .await;
    }

    topic_key
}

async fn assert_topic_does_not_exists(client: &ClientWithServer, headers: Headers) {
    // Verify topic and its secrets are deleted
    let secret_list_response = client
        .make_admin_request_with_headers(secrets_list(TOPIC_NAME), &serde_json::json!({}), headers)
        .await;

    assert_error_response(secret_list_response, StatusCode::NOT_FOUND).await;
}

#[tokio::test]
async fn test_delete_topic_as_admin() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let topic_key = create_topic_with_secrets(&client).await;

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);

        // processing
        let response = client
            .make_admin_request_with_headers(
                delete_topic(TOPIC_NAME),
                &serde_json::json!({}),
                headers.clone(),
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_topic_does_not_exists(&client, headers).await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_topic_as_user_with_permission() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let topic_key = create_topic_with_secrets(&client).await;

        let permissions = vec![Permission::Delete];
        let policies = build_policies_for_topic_access(TOPIC_NAME, permissions);

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);

        // processing
        let response = client
            .make_user_request_with_headers(
                delete_topic(TOPIC_NAME),
                policies,
                &serde_json::json!({}),
                headers.clone(),
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_topic_does_not_exists(&client, headers).await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_topic_as_user_without_permission() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let topic_key = client.create_topic(TOPIC_NAME).await;

        let permissions = vec![Permission::Read, Permission::Create];
        let policies = build_policies_for_topic_access(TOPIC_NAME, permissions);

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);

        // processing
        let response = client
            .make_user_request_with_headers(
                delete_topic(TOPIC_NAME),
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
async fn test_delete_topic_with_invalid_topic_key() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let _topic_key = client.create_topic(TOPIC_NAME).await;

        let mut headers = Headers::new();
        headers.add_topic_key_header("invalid_topic_key");

        // processing
        let response = client
            .make_admin_request_with_headers(
                delete_topic(TOPIC_NAME),
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
async fn test_delete_nonexistent_topic() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        // processing
        let response = client
            .make_admin_request(delete_topic("nonexistent_topic"), &serde_json::json!({}))
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_topic_unauthorized() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        // processing
        let response = client
            .make_request(delete_topic(TOPIC_NAME), &serde_json::json!({}))
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
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
            .make_admin_request(delete_topic(TOPIC_NAME), &serde_json::json!({}))
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
            .make_admin_request(delete_topic(TOPIC_NAME), &serde_json::json!({}))
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
