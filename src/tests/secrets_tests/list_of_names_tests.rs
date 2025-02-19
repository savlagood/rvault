use crate::tests::{
    assertions::{assert_same_elements, error_message::assert_error_response},
    consts::SIMPLE_USER_POLICIES,
    models::secrets::SecretNames,
    routes,
    server::{use_app, ClientWithServer},
    storage,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

const TOPIC_NAME: &str = "some_topic_name1";

#[test]
fn empty_list_test() {
    let topic_name = TOPIC_NAME;

    let endpoint = routes::build_list_of_secrets_path(topic_name);
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let response = client.make_admin_request(&endpoint, request_body).await;
        assert_eq!(response.status(), StatusCode::OK);

        let secrets = SecretNames::from_response(response).await;
        assert_eq!(secrets.names.len(), 0);
    });
}

#[test]
fn many_secrets_test() {
    let topic_name = TOPIC_NAME;
    let secret_value = "Hello, world!";
    let expected_secret_names = vec![
        String::from("secret1"),
        String::from("some_another_secret_name"),
        String::from("123SECRET_NAME"),
    ];

    let endpoint = routes::build_list_of_secrets_path(topic_name);
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        for secret_name in &expected_secret_names {
            client
                .create_secret_as_admin_encryption_none(topic_name, secret_name, secret_value)
                .await;
        }

        let response = client.make_admin_request(&endpoint, request_body).await;

        assert_eq!(response.status(), StatusCode::OK);

        let secrets = SecretNames::from_response(response).await;
        assert_same_elements(&secrets.names, &expected_secret_names);
    });
}

#[test]
fn empty_list_with_user_token() {
    let topic_name = TOPIC_NAME;

    let endpoint = routes::build_list_of_secrets_path(topic_name);
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        let response = client
            .make_user_request(&endpoint, SIMPLE_USER_POLICIES.clone(), request_body)
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

// there is no point in doing a check when the storage is not initialized,
// because in this state it is impossible to create a topic,
// and there is already a test for this.
// fn storage_is_uninitialized_test() {}

#[test]
fn storage_is_sealed_test() {
    let topic_name = TOPIC_NAME;

    let endpoint = routes::build_list_of_secrets_path(topic_name);
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        client
            .create_topic_as_admin_encryption_none(topic_name)
            .await;

        storage::seal(&client).await;

        let response = client.make_admin_request(&endpoint, request_body).await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}
