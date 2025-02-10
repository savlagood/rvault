use crate::tests::models::topics::TopicEncryptionKey;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use reqwest::Response;

#[cfg(test)]
use pretty_assertions::assert_eq;

pub async fn assert_response_contains_valid_topic_key(response: Response) {
    let topic_key = TopicEncryptionKey::from_response(response).await;
    let decoded_key = STANDARD_NO_PAD
        .decode(topic_key.key)
        .expect("Failed to decode topic key from response");

    assert_eq!(decoded_key.len(), 32);
}
