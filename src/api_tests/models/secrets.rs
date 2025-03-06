use crate::api_tests::models::common::{Encryption, EncryptionMode};
use reqwest::Response;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SecretCreateRequest {
    encryption: Encryption,
    value: String,
}

impl SecretCreateRequest {
    pub fn new(mode: EncryptionMode, value: String) -> Self {
        let encryption = Encryption::new(mode);
        Self { encryption, value }
    }

    pub fn set_key(&mut self, key: String) {
        self.encryption.set_key(key);
    }

    pub fn into_value(self) -> serde_json::Value {
        serde_json::json!(self)
    }
}

#[derive(Deserialize)]
pub struct SecretEncryptionKey {
    secret_key: String,
}

impl SecretEncryptionKey {
    pub async fn from_response_to_string(response: Response) -> String {
        response
            .json::<Self>()
            .await
            .expect("Error during parsing secret key from response")
            .secret_key
    }
}

#[derive(Deserialize)]
pub struct SecretNames {
    pub names: Vec<String>,
}

impl SecretNames {
    pub async fn from_response(response: Response) -> Self {
        response
            .json::<Self>()
            .await
            .expect("Error during parsing secret names from response")
    }
}
