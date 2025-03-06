use crate::api_tests::{
    assertions::{assert_same_elements, error_message::assert_error_response},
    consts::{SECRET_VALUE, SIMPLE_USER_POLICIES, TOPIC_NAME},
    endpoints::secrets_list,
    models::{common::Headers, secrets::SecretNames},
    runtime::use_app,
    utils::storage,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_empty_list() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(secrets_list(TOPIC_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);

        let names = SecretNames::from_response(response).await.names;
        assert_same_elements(&names, &vec![]);
    })
    .await;
}

#[tokio::test]
async fn test_many_secrets_topic_encryption_none() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let request_body = serde_json::json!({});

        let secret_names = vec![
            String::from("secret1"),
            String::from("secret2"),
            String::from("secret3"),
        ];

        for secret_name in &secret_names {
            let _key = client
                .create_secret(TOPIC_NAME, secret_name, String::from(SECRET_VALUE))
                .await;
        }

        // processing
        let response = client
            .make_admin_request(secrets_list(TOPIC_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);

        let names = SecretNames::from_response(response).await.names;
        assert_same_elements(&names, &secret_names);
    })
    .await;
}

#[tokio::test]
async fn test_many_secrets_topic_encryption_generate() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let topic_key = client.create_topic(TOPIC_NAME).await;

        let request_body = serde_json::json!({});

        let secret_names = vec![
            String::from("secret1"),
            String::from("secret2"),
            String::from("secret3"),
        ];

        for secret_name in &secret_names {
            let _key = client
                .create_secret_in_encrypted_topic(
                    TOPIC_NAME,
                    secret_name,
                    String::from(SECRET_VALUE),
                    &topic_key,
                )
                .await;
        }

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);

        // processing
        let response = client
            .make_admin_request_with_headers(secrets_list(TOPIC_NAME), &request_body, headers)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);

        let names = SecretNames::from_response(response).await.names;
        assert_same_elements(&names, &secret_names);
    })
    .await;
}

#[tokio::test]
async fn test_empty_list_with_user_token() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_user_request(
                secrets_list(TOPIC_NAME),
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
async fn test_when_storage_is_sealed() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        client.create_topic_encryption_none(TOPIC_NAME).await;
        let request_body = serde_json::json!({});

        storage::seal(&client).await;

        // processing
        let response = client
            .make_admin_request(secrets_list(TOPIC_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
