use crate::api_tests::{
    assertions::error_message::assert_error_response,
    consts::{SECRET_NAME, SECRET_VALUE, TOPIC_NAME},
    endpoints::update_secret,
    models::{
        common::Headers,
        policies::Permission,
        secrets::{SecretUpdateRequest, SecretValue},
    },
    runtime::use_app,
    utils::{common::build_policies, storage},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

const NEW_SECRET_VALUE: &str = "Updated secret VALUE 123 $@#";

#[tokio::test]
async fn test_update_as_admin() {
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

        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        // processing
        let response = client
            .make_admin_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers.clone(),
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        let updated_secret_value = client.fetch_secret(TOPIC_NAME, SECRET_NAME, headers).await;
        assert_eq!(
            updated_secret_value,
            SecretValue {
                value: String::from(NEW_SECRET_VALUE),
                version: 1
            }
        );
    })
    .await;
}

#[tokio::test]
async fn test_update_as_user() {
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

        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Read],
            SECRET_NAME,
            vec![Permission::Update],
        );

        // processing
        let response = client
            .make_user_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
                headers.clone(),
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);
        let updated_secret_value = client.fetch_secret(TOPIC_NAME, SECRET_NAME, headers).await;
        assert_eq!(
            updated_secret_value,
            SecretValue {
                value: String::from(NEW_SECRET_VALUE),
                version: 1
            }
        );
    })
    .await;
}

#[tokio::test]
async fn test_update_as_user_without_update_permission() {
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

        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header(&secret_key);

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Read],
            SECRET_NAME,
            vec![Permission::Create],
        );

        // processing
        let response = client
            .make_user_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
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
async fn test_update_with_invalid_topic_key() {
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

        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        let mut headers = Headers::new();
        headers.add_topic_key_header("invalid_topic_key");
        headers.add_secret_key_header(&secret_key);

        // processing
        let response = client
            .make_admin_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
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
async fn test_update_with_invalid_secret_key() {
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

        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);
        headers.add_secret_key_header("invalid_secret_key");

        // processing
        let response = client
            .make_admin_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
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
async fn test_update_nonexistent_secret() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_key = client.create_topic(TOPIC_NAME).await;

        // We don't create the secret here

        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);

        // processing
        let response = client
            .make_admin_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_update_in_nonexistent_topic() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        // Topic not created

        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        // processing
        let response = client
            .make_admin_request(update_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_multiple_updates_with_version_tracking() {
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

        // processing first update
        let first_new_secret_value = "Value 1";
        let request_body = SecretUpdateRequest::new(first_new_secret_value).into_value();

        let response = client
            .make_admin_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers.clone(),
            )
            .await;

        // checking first update
        assert_eq!(response.status(), StatusCode::OK);
        let updated_secret_value = client
            .fetch_secret(TOPIC_NAME, SECRET_NAME, headers.clone())
            .await;
        assert_eq!(
            updated_secret_value,
            SecretValue {
                value: String::from(first_new_secret_value),
                version: 1
            }
        );

        // processing second update
        let second_new_secret_value = "Value 2";
        let request_body = SecretUpdateRequest::new(second_new_secret_value).into_value();

        let response = client
            .make_admin_request_with_headers(
                update_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers.clone(),
            )
            .await;

        // checking second update
        assert_eq!(response.status(), StatusCode::OK);
        let updated_secret_value = client.fetch_secret(TOPIC_NAME, SECRET_NAME, headers).await;
        assert_eq!(
            updated_secret_value,
            SecretValue {
                value: String::from(second_new_secret_value),
                version: 2
            }
        );
    })
    .await;
}

#[tokio::test]
async fn test_storage_is_sealed() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_sealed(&client).await;
        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        // processing
        let response = client
            .make_admin_request(update_secret(TOPIC_NAME, SECRET_NAME), &request_body)
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
        let request_body = SecretUpdateRequest::new(NEW_SECRET_VALUE).into_value();

        // processing
        let response = client
            .make_admin_request(update_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
