use crate::tests::{
    assertions::{
        assert_empty_response,
        error_message::assert_error_response,
        secrets::{
            assert_response_contains_expected_secret_key, assert_response_contains_valid_secret_key,
        },
    },
    models::{policies::Permission, Headers},
    routes,
    server::{use_app, ClientWithServer},
    storage, utils,
};
use once_cell::sync::Lazy;
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

const VALID_TOPIC_NAME: &str = "Some_validTopicName_123";
const VALID_SECRET_NAME: &str = "Some_validSECRETname_123";

const SECRET_VALUE: &str = "some password 12321 !@#$%^&*()_";

static SIMPLE_REQUEST_BODY: Lazy<serde_json::Value> = Lazy::new(|| {
    serde_json::json!({
        "value": SECRET_VALUE,
        "encryption": {
            "mode": "none"
        }
    })
});

#[test]
fn test_as_admin() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    });
}

#[test]
fn test_as_user() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let topic_permissions = vec![Permission::Update];
    let secret_permissions = vec![Permission::Create];
    let policies = utils::build_policies_for_topic_and_secret_access(
        topic_name,
        topic_permissions,
        secret_name,
        secret_permissions,
    );

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let user_token_pair = client.fetch_user_token_pair(policies).await;
        let access_token = user_token_pair.access_token;

        let response = client
            .make_authorized_request(&endpoint, request_body, &access_token)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    });
}

#[test]
fn test_have_permission_to_create_secret_but_not_to_modify_topic() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let topic_permissions = vec![Permission::Create, Permission::Read];
    let secret_permissions = vec![Permission::Create];
    let policies = utils::build_policies_for_topic_and_secret_access(
        topic_name,
        topic_permissions,
        secret_name,
        secret_permissions,
    );

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let user_token_pair = client.fetch_user_token_pair(policies).await;
        let access_token = user_token_pair.access_token;

        let response = client
            .make_authorized_request(&endpoint, request_body, &access_token)
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_with_topic_key_header() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        let topic_key = client.create_topic_as_admin_and_get_key(topic_name).await;

        let mut headers = Headers::new();
        headers.add_topic_key_header(&topic_key);

        let response = client
            .make_admin_request_with_headers(&endpoint, request_body, headers)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    });
}

#[test]
fn test_without_topic_key_header() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        let _topic_key = client.create_topic_as_admin_and_get_key(topic_name).await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_not_enough_permissions() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let topic_permissions = vec![Permission::Update];
    let secret_permissions = vec![Permission::Read];
    let policies = utils::build_policies_for_topic_and_secret_access(
        topic_name,
        topic_permissions,
        secret_name,
        secret_permissions,
    );

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let user_token_pair = client.fetch_user_token_pair(policies).await;
        let access_token = user_token_pair.access_token;

        let response = client
            .make_authorized_request(&endpoint, request_body, &access_token)
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_attempt_to_create_existing_secret_without_permission_to_do() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let topic_permissions = vec![Permission::Update];
    let secret_permissions = vec![Permission::Read];
    let policies = utils::build_policies_for_topic_and_secret_access(
        topic_name,
        topic_permissions,
        secret_name,
        secret_permissions,
    );

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let user_token_pair = client.fetch_user_token_pair(policies).await;
        let access_token = user_token_pair.access_token;

        // 1st create secret as admin
        let response = client
            .make_admin_request(&endpoint, request_body.clone())
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        // 2nd create as user without permissions
        let response = client
            .make_authorized_request(&endpoint, request_body, &access_token)
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_name_contains_invalid_characters() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = "invalid_ $secret + name!";

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_already_exists() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        // 1st creation
        let response = client
            .make_admin_request(&endpoint, request_body.clone())
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        // 2nd creation
        let response = client.make_admin_request(&endpoint, request_body).await;

        let expected_status_code = StatusCode::CONFLICT;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_create_secret_in_unexistent_topic() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        // 1st creation
        let response = client
            .make_admin_request(&endpoint, request_body.clone())
            .await;

        let expected_status_code = StatusCode::NOT_FOUND;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_create_two_secrets_with_same_name_in_different_topics() {
    let first_topic_name = "some_topic_1";
    let second_topic_name = "some_topic_2";
    let secret_name = VALID_SECRET_NAME;

    let first_endpoint = routes::build_create_secret_path(first_topic_name, secret_name);
    let second_endpoint = routes::build_create_secret_path(second_topic_name, secret_name);

    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        // create both topics
        client
            .create_topic_as_admin_encryption_none(first_topic_name)
            .await;
        client
            .create_topic_as_admin_encryption_none(second_topic_name)
            .await;

        // create secret in first topic
        let response = client
            .make_admin_request(&first_endpoint, request_body.clone())
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;

        // create secret in second topic
        let response = client
            .make_admin_request(&second_endpoint, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_empty_response(response).await;
    });
}

#[test]
fn test_encrypted_with_provided_mode() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);

    let expected_key = "some secret key 123 #$$%";
    let request_body = serde_json::json!({
        "value": SECRET_VALUE,
        "encryption": {
            "mode": "provided",
            "key": expected_key
        }
    });

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_expected_secret_key(response, expected_key).await;
    });
}

#[test]
fn test_encrypted_with_generate_mode() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = serde_json::json!({
        "value": SECRET_VALUE,
        "encryption": {
            "mode": "generate"
        }
    });

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;
        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_response_contains_valid_secret_key(response).await;
    });
}

#[test]
fn test_when_storage_is_sealed() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_sealed(&client).await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn test_when_storage_is_uninitialized() {
    let topic_name = VALID_TOPIC_NAME;
    let secret_name = VALID_SECRET_NAME;

    let endpoint = routes::build_create_secret_path(topic_name, secret_name);
    let request_body = SIMPLE_REQUEST_BODY.clone();

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}
