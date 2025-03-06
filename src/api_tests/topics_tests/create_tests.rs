use crate::api_tests::{
    assertions::{
        assert_empty_response, error_message::assert_error_response,
        topics::assert_response_contains_valid_topic_key,
    },
    consts::{TOPIC_KEY, TOPIC_NAME},
    endpoints::create_topic,
    models::{
        common::EncryptionMode,
        policies::Permission,
        topics::{TopicCreateRequest, TopicEncryptionKey},
    },
    runtime::use_app,
    utils::{common::build_policies_for_topic_access, storage},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_create_as_admin() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        // processing
        let response = client
            .make_admin_request(create_topic(TOPIC_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_valid_topic_key(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_create_as_user_with_permissions() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_permissions = vec![Permission::Create];
        let policies = build_policies_for_topic_access(TOPIC_NAME, topic_permissions);

        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        // processing
        let response = client
            .make_user_request(create_topic(TOPIC_NAME), policies, &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_valid_topic_key(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_create_as_user_without_permissions() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_permissions = vec![Permission::Read, Permission::Update, Permission::Delete];
        let policies = build_policies_for_topic_access(TOPIC_NAME, topic_permissions);

        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        // processing
        let response = client
            .make_user_request(create_topic(TOPIC_NAME), policies, &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_name_contains_invalid_characters() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let topic_name = "invalid_ $topic + name!";
        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        // processing
        let response = client
            .make_admin_request(create_topic(topic_name), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}

#[tokio::test]
async fn test_already_exists() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        // 1st creation
        let _key = client.create_topic(TOPIC_NAME).await;

        // processing
        // 2nd creation
        let response = client
            .make_admin_request(create_topic(TOPIC_NAME), &request_body)
            .await;

        // checling
        assert_error_response(response, StatusCode::CONFLICT).await;
    })
    .await;
}

#[tokio::test]
async fn test_attempt_to_create_existing_topic_without_permission_to_do() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        let permissions = vec![Permission::Read, Permission::Update, Permission::Delete];
        let policies = build_policies_for_topic_access(TOPIC_NAME, permissions);

        // 1st creation as admin
        let _key = client.create_topic(TOPIC_NAME).await;

        // processing
        // 2nd creation as user without permission
        let response = client
            .make_user_request(create_topic(TOPIC_NAME), policies, &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
    .await;
}

#[tokio::test]
async fn test_create_with_provided_mode() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        // let topic_key = String::from("Some topic password 42");

        let mut topic_encryption = TopicCreateRequest::new(EncryptionMode::Provided);
        topic_encryption.set_key(String::from(TOPIC_KEY));

        let request_body = topic_encryption.into_value();

        // processing
        let response = client
            .make_admin_request(create_topic(TOPIC_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);

        let received_topic_key = TopicEncryptionKey::from_response_to_string(response).await;
        assert_eq!(received_topic_key, String::from(TOPIC_KEY));
    })
    .await;
}

#[tokio::test]
async fn test_create_with_none_mode() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;
        let request_body = TopicCreateRequest::new(EncryptionMode::None).into_value();

        // processing
        let response = client
            .make_admin_request(create_topic(TOPIC_NAME), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    })
    .await;
}

#[tokio::test]
async fn test_storage_is_sealed() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_sealed(&client).await;
        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        // processing
        let response = client
            .make_admin_request(create_topic(TOPIC_NAME), &request_body)
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
        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();

        // processing
        let response = client
            .make_admin_request(create_topic(TOPIC_NAME), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
