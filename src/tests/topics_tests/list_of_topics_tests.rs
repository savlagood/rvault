use crate::tests::{
    assertions::error_message::assert_error_response,
    consts::SIMPLE_USER_POLICIES,
    models::topics::TopicsNames,
    routes,
    server::{use_app, ClientWithServer},
    storage,
};
use reqwest::StatusCode;
use std::{collections::HashMap, fmt::Debug, hash::Hash};

#[cfg(test)]
use pretty_assertions::assert_eq;

#[test]
fn empty_list_test() {
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        let response = client
            .make_admin_request(&routes::TOPICS_LIST_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let topics = TopicsNames::from_response(response).await;
        assert_eq!(topics.names.len(), 0);
    });
}

#[test]
fn many_topics_test() {
    let request_body = serde_json::json!({});
    let expected_topic_names = vec![
        String::from("topic1"),
        String::from("some_another_topic_name"),
        String::from("TOPIC_NAME"),
    ];

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        for topic_name in &expected_topic_names {
            let response = client
                .make_admin_request(
                    &routes::build_create_topic_path(topic_name.as_str()),
                    request_body.clone(),
                )
                .await;

            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let response = client
            .make_admin_request(&routes::TOPICS_LIST_ENDPOINT, request_body)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let topics = TopicsNames::from_response(response).await;
        assert_same_elements(&topics.names, &expected_topic_names);
    });
}

#[test]
fn empty_list_of_topics_with_user_token_test() {
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_unsealed(&client).await;

        let response = client
            .make_user_request(
                &routes::TOPICS_LIST_ENDPOINT,
                SIMPLE_USER_POLICIES.clone(),
                request_body,
            )
            .await;

        let expected_status_code = StatusCode::FORBIDDEN;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn storage_is_uninitialized_test() {
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;

        let response = client
            .make_admin_request(&routes::TOPICS_LIST_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

#[test]
fn storage_is_sealed_test() {
    let request_body = serde_json::json!({});

    use_app(async move {
        let client = ClientWithServer::new().await;
        storage::from_uninitialized_to_sealed(&client).await;

        let response = client
            .make_admin_request(&routes::TOPICS_LIST_ENDPOINT, request_body)
            .await;

        let expected_status_code = StatusCode::BAD_REQUEST;
        assert_error_response(response, expected_status_code).await;
    });
}

fn assert_same_elements<T>(vec1: &[T], vec2: &[T])
where
    T: Eq + Hash + Debug,
{
    let count_vec1 = count_elements(vec1);
    let count_vec2 = count_elements(vec2);

    assert_eq!(count_vec1, count_vec2);
}

fn count_elements<T>(vector: &[T]) -> HashMap<&T, usize>
where
    T: Eq + Hash,
{
    let mut counts = HashMap::with_capacity(vector.len());
    for item in vector {
        *counts.entry(item).or_insert(0) += 1;
    }

    counts
}
