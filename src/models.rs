use serde::Deserialize;

#[derive(Deserialize, Clone)]
#[serde(tag = "mode", content = "key")]
pub enum Encryption {
    #[serde(rename = "none")]
    None,

    #[serde(rename = "generate")]
    Generate,

    #[serde(rename = "provided")]
    Provided(String),
}

pub struct StorageAndTopicKeys<'a> {
    pub storage_key: &'a [u8],
    pub topic_key: &'a [u8],
}
pub struct StorageTopicAndSecretKeys<'a> {
    pub storage_key: &'a [u8],
    pub topic_key: &'a [u8],
    pub secret_key: &'a [u8],
}

pub mod http {
    pub mod topics {
        use crate::models::Encryption;
        use serde::{Deserialize, Serialize};
        use std::collections::HashSet;

        #[derive(Deserialize)]
        pub struct TopicSettings {
            pub encryption: Encryption,
        }

        #[derive(Serialize)]
        pub struct TopicEncryptionKey {
            #[serde(rename = "topic_key")]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub value: Option<String>,
        }

        #[derive(Serialize)]
        pub struct TopicNames {
            pub names: HashSet<String>,
        }
    }

    pub mod secrets {
        use crate::models::Encryption;
        use serde::{Deserialize, Serialize};
        use std::collections::HashSet;

        #[derive(Deserialize)]
        pub struct SecretSettings {
            pub value: String,
            pub encryption: Encryption,
        }

        #[derive(Serialize)]
        pub struct SecretEncryptionKey {
            #[serde(rename = "secret_key")]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub value: Option<String>,
        }

        #[derive(Serialize)]
        pub struct SecretNames {
            pub names: HashSet<String>,
        }

        #[derive(Serialize)]
        pub struct SecretValue {
            pub value: String,
            pub version: usize,
        }
    }

    pub mod auth {
        use serde::Deserialize;

        #[derive(Deserialize)]
        pub struct TokenRequest {
            pub token: String,
        }
    }
}
