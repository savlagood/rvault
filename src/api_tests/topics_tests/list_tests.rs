use crate::api_tests::{
    assertions::{assert_same_elements, error_message::assert_error_response},
    consts::SIMPLE_USER_POLICIES,
    endpoints::TOPICS_LIST,
    models::topics::TopicNames,
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
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(TOPICS_LIST.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);

        let names = TopicNames::from_response(response).await.names;
        assert_same_elements(&names, &vec![]);
    })
    .await;
}

#[tokio::test]
async fn test_many_topics() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let request_body = serde_json::json!({});
        let topic_names = vec![
            String::from("topic1"),
            String::from("some_another_topic_name"),
            String::from("TOPIC_NAME"),
        ];

        for topic_name in &topic_names {
            let _key = client.create_topic(topic_name).await;
        }

        // processing
        let response = client
            .make_admin_request(TOPICS_LIST.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::OK);

        let received_names = TopicNames::from_response(response).await.names;
        assert_same_elements(&received_names, &topic_names);
    })
    .await;
}

#[tokio::test]
async fn test_unauthorized() {
    use_app(|client| async move {
        // preparing
        storage::from_uninitialized_to_unsealed(&client).await;

        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_request(TOPICS_LIST.clone(), &request_body)
            .await;

        // checking
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn test_empty_list_of_topics_with_user_token() {
    use_app(|client| async move {
        storage::from_uninitialized_to_unsealed(&client).await;

        let request_body = serde_json::json!({});

        let response = client
            .make_user_request(
                TOPICS_LIST.clone(),
                SIMPLE_USER_POLICIES.clone(),
                &request_body,
            )
            .await;

        assert_error_response(response, StatusCode::FORBIDDEN).await;
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
            .make_admin_request(TOPICS_LIST.clone(), &request_body)
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
        let request_body = serde_json::json!({});

        // processing
        let response = client
            .make_admin_request(TOPICS_LIST.clone(), &request_body)
            .await;

        // checking
        assert_error_response(response, StatusCode::BAD_REQUEST).await;
    })
    .await;
}
