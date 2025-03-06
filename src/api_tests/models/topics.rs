use crate::api_tests::models::common::{Encryption, EncryptionMode};
use reqwest::Response;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct TopicCreateRequest {
    encryption: Encryption,
}

impl TopicCreateRequest {
    pub fn new(mode: EncryptionMode) -> Self {
        let encryption = Encryption::new(mode);
        Self { encryption }
    }

    pub fn set_key(&mut self, key: String) {
        self.encryption.set_key(key);
    }

    pub fn into_value(self) -> serde_json::Value {
        serde_json::json!(self)
    }
}

#[derive(Deserialize)]
pub struct TopicEncryptionKey {
    topic_key: String,
}

impl TopicEncryptionKey {
    pub async fn from_response_to_string(response: Response) -> String {
        response
            .json::<Self>()
            .await
            .expect("Error during parsing topic key from response")
            .topic_key
    }
}

#[derive(Deserialize)]
pub struct TopicNames {
    pub names: Vec<String>,
}

impl TopicNames {
    pub async fn from_response(response: Response) -> Self {
        response
            .json::<Self>()
            .await
            .expect("Error during parsing topic names from response")
    }
}
