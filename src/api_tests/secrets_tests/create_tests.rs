use crate::api_tests::{
    assertions::{
        assert_empty_response, error_message::assert_error_response,
        secrets::assert_response_contains_valid_secret_key,
    },
    consts::{SECRET_KEY, SECRET_NAME, SECRET_VALUE, TOPIC_KEY, TOPIC_NAME},
    endpoints::create_secret,
    models::{
        common::{EncryptionMode, Headers},
        policies::Permission,
        secrets::{SecretCreateRequest, SecretEncryptionKey},
    },
    runtime::use_app,
    utils::{common::build_policies, storage},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_topic_encryption_none() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        let response = client
            .make_admin_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_topic_encryption_generate() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();
        let topic_key = client.create_topic(TOPIC_NAME).await;

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);

        // processing
        let response = client
            .make_admin_request_with_headers(
                create_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_topic_encryption_provided() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();
        let _topic_key = client
            .create_topic_with_key(TOPIC_NAME, String::from(TOPIC_KEY))
            .await;

        let mut headers = Headers::new();
        headers.add_topic_key_header(TOPIC_KEY);

        // processing
        let response = client
            .make_admin_request_with_headers(
                create_secret(TOPIC_NAME, SECRET_NAME),
                &request_body,
                headers,
            )
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_secret_encryption_generate() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let request_body =
            SecretCreateRequest::new(EncryptionMode::Generate, String::from(SECRET_VALUE))
                .into_value();
        client.create_topic_encryption_none(TOPIC_NAME).await;

        // processing
        let response = client
            .make_admin_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_valid_secret_key(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_secret_encryption_provided() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let mut request =
            SecretCreateRequest::new(EncryptionMode::Provided, String::from(SECRET_VALUE));
        request.set_key(String::from(SECRET_KEY));
        let request_body = request.into_value();

        // processing
        let response = client
            .make_admin_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);

        let received_secret_key = SecretEncryptionKey::from_response_to_string(response).await;
        assert_eq!(received_secret_key, SECRET_KEY);
    })
    .await;
}

#[tokio::test]
async fn test_as_user() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Update],
            SECRET_NAME,
            vec![Permission::Create],
        );
        let request_body =
            SecretCreateRequest::new(EncryptionMode::Generate, String::from(SECRET_VALUE))
                .into_value();

        // processing
        let response = client
            .make_user_request(
                create_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
            )
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_valid_secret_key(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_already_exists() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        // 1st creation
        client
            .create_secret_encryption_none(TOPIC_NAME, SECRET_NAME, String::from(SECRET_VALUE))
            .await;

        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        // 2nd creation
        let response = client
            .make_admin_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::CONFLICT).await;
    })
    .await;
}

#[tokio::test]
async fn test_attempt_to_create_existing_secret_without_permission_to_do() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        // 1st creation
        client
            .create_secret_encryption_none(TOPIC_NAME, SECRET_NAME, String::from(SECRET_VALUE))
            .await;

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Update],
            SECRET_NAME,
            vec![Permission::Read],
        );
        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        // 2nd creation
        let response = client
            .make_user_request(
                create_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_has_permission_to_create_secret_but_not_to_modify_topic() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Read, Permission::Create, Permission::Delete],
            SECRET_NAME,
            vec![Permission::Create],
        );
        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        let response = client
            .make_user_request(
                create_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_not_enough_permissions_to_create_secret() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let policies = build_policies(
            TOPIC_NAME,
            vec![Permission::Update],
            SECRET_NAME,
            vec![Permission::Read, Permission::Update, Permission::Delete],
        );
        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        let response = client
            .make_user_request(
                create_secret(TOPIC_NAME, SECRET_NAME),
                policies,
                &request_body,
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

        let request_body =
            SecretCreateRequest::new(EncryptionMode::Generate, String::from(SECRET_VALUE))
                .into_value();

        // processing
        let response = client
            .make_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::UNAUTHORIZED).await;
    })
    .await;
}

#[tokio::test]
async fn test_create_secret_in_unexistent_topic() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        // without creating topic
        // client.create_topic_encryption_none(TOPIC_NAME).await;

        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        let response = client
            .make_admin_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::NOT_FOUND).await;
    })
    .await;
}

#[tokio::test]
async fn test_create_two_secrets_with_same_name_in_different_topics() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let first_topic_name = "some_topic_1";
        let second_topic_name = "some_topic_2";

        client.create_topic_encryption_none(first_topic_name).await;
        client.create_topic_encryption_none(second_topic_name).await;

        let request_body =
            SecretCreateRequest::new(EncryptionMode::Generate, String::from(SECRET_VALUE))
                .into_value();

        // processing
        let first_response = client
            .make_admin_request(create_secret(first_topic_name, SECRET_NAME), &request_body)
            .await;

        let second_response = client
            .make_admin_request(create_secret(second_topic_name, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_eq!(first_response.status(), StatusCode::CREATED);
        assert_response_contains_valid_secret_key(first_response).await;

        assert_eq!(second_response.status(), StatusCode::CREATED);
        assert_response_contains_valid_secret_key(second_response).await;
    })
    .await;
}

#[tokio::test]
async fn test_name_contains_invalid_characters() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        client.create_topic_encryption_none(TOPIC_NAME).await;

        let invalid_secret_name = "invalid_ $secret + name!";

        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        let response = client
            .make_admin_request(
                create_secret(TOPIC_NAME, invalid_secret_name),
                &request_body,
            )
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_storage_is_sealed() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_sealed(&client).await;
        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        let response = client
            .make_admin_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
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
        let request_body =
            SecretCreateRequest::new(EncryptionMode::None, String::from(SECRET_VALUE)).into_value();

        // processing
        let response = client
            .make_admin_request(create_secret(TOPIC_NAME, SECRET_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
