use crate::tests::consts::HEADER_WITH_TOPIC_KEY;
use reqwest::header::{HeaderMap, HeaderValue};

pub struct Headers {
    pub headers: HeaderMap,
}

impl Headers {
    pub fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
        }
    }

    pub fn add_topic_key_header(&mut self, key: &str) {
        let value =
            HeaderValue::from_str(key).expect("Failed to convert into header value topic key");
        self.headers.insert(HEADER_WITH_TOPIC_KEY, value);
    }

    // pub fn add_secret_key_header(&mut self, key: &str) {
    //     let value =
    //         HeaderValue::from_str(key).expect("Failed to convert into header value secret key");
    //     self.headers.insert(HEADER_WITH_SECRET_KEY, value);
    // }
}

pub mod jwt_tokens {
    use crate::tests::{consts::ENV_JWT_SECRET, models::policies::Policies, utils};
    use jsonwebtoken::{DecodingKey, Validation};
    use reqwest::Response;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(rename_all = "lowercase")]
    pub enum TokenType {
        User,
        Admin,
    }

    #[derive(Serialize, Deserialize)]
    pub struct TokenPair {
        pub access_token: String,
        pub refresh_token: String,
    }

    impl TokenPair {
        pub async fn from_response(response: Response) -> Self {
            response
                .json::<Self>()
                .await
                .expect("Error during parsing token pair from response")
        }
    }

    pub struct TokenPayload {
        pub policies: Policies,
        pub token_type: TokenType,
    }

    #[derive(Serialize, Deserialize)]
    pub struct AccessTokenClaims {
        pub id: Uuid,
        pub exp: usize,
        pub policies: Policies,

        #[serde(rename = "type")]
        pub token_type: TokenType,
    }

    impl AccessTokenClaims {
        pub fn from_str(token: &str) -> Self {
            let jwt_secret = utils::get_env_var(ENV_JWT_SECRET);

            let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
            let validation = Validation::default();

            utils::jwt::decode_token_into_claims(token, &decoding_key, &validation)
        }

        pub fn from_str_without_exp_checking(token: &str) -> Self {
            let jwt_secret = utils::get_env_var(ENV_JWT_SECRET);
            let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());

            let mut validation = Validation::default();
            validation.validate_exp = false;

            utils::jwt::decode_token_into_claims(token, &decoding_key, &validation)
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct RefreshTokenClaims {
        pub id: Uuid,
        pub exp: usize,
        pub access_token_id: Uuid,
    }

    impl RefreshTokenClaims {
        pub fn from_str(token: &str) -> Self {
            let jwt_secret = utils::get_env_var(ENV_JWT_SECRET);

            let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
            let validation = Validation::default();

            utils::jwt::decode_token_into_claims(token, &decoding_key, &validation)
        }
    }
}

pub mod policies {
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};

    #[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum Permission {
        Create,
        Read,
        Update,
        Delete,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct Policies(HashMap<String, Topic>);

    impl Policies {
        pub fn from_value(value: serde_json::Value) -> Self {
            serde_json::from_value(value)
                .expect("Error during parsing policies from json value to struct")
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct Topic {
        pub permissions: HashSet<Permission>,
        pub secrets: HashMap<String, HashSet<Permission>>,
    }
}

pub mod shared_keys {
    use crate::tests::consts::{THRESHOLD, TOTAL_KEYS};
    use rand::{seq::SliceRandom, thread_rng};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct SharedKeysSettings {
        pub threshold: u8,
        pub total_keys: u8,
    }

    impl SharedKeysSettings {
        pub fn new_with_defaults() -> Self {
            Self {
                threshold: THRESHOLD,
                total_keys: TOTAL_KEYS,
            }
        }

        pub fn into_json_value(self) -> serde_json::Value {
            serde_json::json!(self)
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct SharedKeys {
        pub shares: Vec<String>,
    }

    impl SharedKeys {
        pub fn new_empty() -> Self {
            Self { shares: Vec::new() }
        }

        pub fn trim_shares(self, n: usize) -> Self {
            let mut rng = thread_rng();
            let mut selected_shares = self.shares;

            selected_shares.shuffle(&mut rng);
            selected_shares.truncate(n);

            Self {
                shares: selected_shares,
            }
        }
    }
}

pub mod topics {
    use reqwest::Response;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct TopicEncryptionKey {
        #[serde(rename = "topic_key")]
        pub value: String,
    }

    impl TopicEncryptionKey {
        pub async fn from_response(response: Response) -> Self {
            response
                .json::<Self>()
                .await
                .expect("Error during parsing token pair from response")
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct TopicsNames {
        pub names: Vec<String>,
    }

    impl TopicsNames {
        pub async fn from_response(response: Response) -> Self {
            response
                .json::<Self>()
                .await
                .expect("Error during parsing topics names from response")
        }
    }
}

pub mod secrets {
    use reqwest::Response;
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct SecretEncryptionKey {
        #[serde(rename = "secret_key")]
        pub value: String,
    }

    impl SecretEncryptionKey {
        pub async fn from_response(response: Response) -> Self {
            response
                .json::<Self>()
                .await
                .expect("Error during parsing token pair from response")
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
}
