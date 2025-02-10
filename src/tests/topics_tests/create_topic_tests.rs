use crate::tests::{
    assertions::{
        error_message::assert_error_response, topics::assert_response_contains_valid_topic_key,
    },
    models::policies::Permission,
    routes,
    server::{use_app, ClientWithServer},
    storage, utils,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

const VALID_TOPIC_NAME: &str = "Some_validTopicName_123";

#[test]
fn test_create_new_topic_as_admin() {
    let topic_name = VALID_TOPIC_NAME;

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        let response = client
            .make_admin_request(&routes::build_create_topic_path(topic_name), request_body)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_valid_topic_key(response).await;
    })
}

#[test]
fn test_create_new_topic_as_user() {
    let topic_name = VALID_TOPIC_NAME;

    let permissions = vec![Permission::Create];
    let policies = utils::build_policies_for_topic_access(topic_name, permissions);

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        let user_token_pair = client.fetch_user_token_pair(policies).await;
        let access_token = user_token_pair.access_token;

        let response = client
            .make_authorized_request(
                &routes::build_create_topic_path(topic_name),
                request_body,
                &access_token,
            )
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_valid_topic_key(response).await;
    })
}

#[test]
fn test_topic_name_contains_invalid_characters() {
    let topic_name = "invalid_ $topic + name!";

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        let response = client
            .make_admin_request(&routes::build_create_topic_path(topic_name), request_body)
            .await;

        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
}

#[test]
fn test_not_enough_permissions_to_create_topic() {
    let topic_name = VALID_TOPIC_NAME;

    // try to create topic with read permission
    let permissions = vec![Permission::Read];
    let policies = utils::build_policies_for_topic_access(topic_name, permissions);

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        let user_token_pair = client.fetch_user_token_pair(policies).await;
        let access_token = user_token_pair.access_token;

        let response = client
            .make_authorized_request(
                &routes::build_create_topic_path(topic_name),
                request_body,
                &access_token,
            )
            .await;

        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
}

#[test]
fn test_topic_already_exists() {
    let topic_name = VALID_TOPIC_NAME;

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        // 1st creation
        let response = client
            .make_admin_request(
                &routes::build_create_topic_path(topic_name),
                request_body.clone(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        // 2nd creation
        let response = client
            .make_admin_request(&routes::build_create_topic_path(topic_name), request_body)
            .await;

        assert_error_response(response, StatusCode::CONFLICT).await;
    })
}

#[test]
fn test_attempt_to_create_existing_topic_without_permission_to_do() {
    let topic_name = VALID_TOPIC_NAME;

    let permissions = vec![Permission::Read];
    let policies = utils::build_policies_for_topic_access(topic_name, permissions);

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        // 1st creation as admin
        let response = client
            .make_admin_request(
                &routes::build_create_topic_path(topic_name),
                request_body.clone(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        // 2nd creation as user without permission
        let user_token_pair = client.fetch_user_token_pair(policies).await;
        let access_token = user_token_pair.access_token;

        let response = client
            .make_authorized_request(
                &routes::build_create_topic_path(topic_name),
                request_body,
                &access_token,
            )
            .await;

        assert_error_response(response, StatusCode::FORBIDDEN).await;
    })
}

#[test]
fn test_create_topic_when_storage_is_sealed() {
    let topic_name = VALID_TOPIC_NAME;

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_sealed(&client).await;

        let response = client
            .make_admin_request(&routes::build_create_topic_path(topic_name), request_body)
            .await;

        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
}

#[test]
fn test_create_topic_when_storage_is_uninitialized() {
    let topic_name = VALID_TOPIC_NAME;

    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::build_create_topic_path(topic_name), request_body)
            .await;

        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
}
