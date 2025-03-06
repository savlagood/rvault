use crate::api_tests::consts::TOPIC_KEY_HEADER;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMode {
    Generate,
    Provided,
    None,
}

#[derive(Serialize)]
pub struct Encryption {
    mode: EncryptionMode,

    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

impl Encryption {
    pub fn new(mode: EncryptionMode) -> Self {
        Self { mode, key: None }
    }

    pub fn set_key(&mut self, key: String) {
        self.key = Some(key);
    }
}

pub struct Headers {
    pub headers: HeaderMap,
}

impl Headers {
    pub fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
        }
    }

    pub fn add_topic_key_header(&mut self, topic_key: &str) {
        let value = HeaderValue::from_str(topic_key)
            .expect("Failed to convert into header value topic key");
        self.headers.insert(TOPIC_KEY_HEADER, value);
    }
}
