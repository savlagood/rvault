use crate::tests::models::policies::{Permission, Policies};
use chrono::Utc;
use std::time::Duration;

pub fn get_env_var(key: &str) -> String {
    let value = std::env::var(key).expect(&format!("Environment vaiable {:?} is required", key));

    let result = value
        .parse()
        .expect(&format!("Failed to parse environment variable {key}"));

    result
}

pub fn get_admin_policies() -> Policies {
    Policies::from_value(serde_json::json!({
        "__default__": {
            "permissions": ["create", "read", "update", "delete"],
            "secrets": {
                "__default__": ["create", "read", "update", "delete"]
            }
        }
    }))
}

pub fn build_policies_for_topic_access(topic_name: &str, permissions: Vec<Permission>) -> Policies {
    let permissions = serde_json::json!(permissions);
    let policies = Policies::from_value(serde_json::json!({
        topic_name: {
            "permissions": permissions,
            "secrets": {}
        }
    }));

    policies
}

pub fn calculate_expiration_time(ttl: Duration) -> usize {
    (Utc::now() + ttl).timestamp() as usize
}

pub mod database {
    use crate::tests::{consts, utils};
    use mongodb::{Client, Database};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    pub async fn clear_test_data_from_db() {
        let connection_string = utils::get_env_var(consts::ENV_DB_CONNECTION_STRING);
        let db = MongoDB::setup_with_connection_str(connection_string.as_str()).await;

        db.drop_all_collections().await;
    }

    struct MongoDB {
        db: Arc<Mutex<Database>>,
    }

    impl MongoDB {
        async fn setup_with_connection_str(connection_str: &str) -> Self {
            let client = Client::with_uri_str(connection_str)
                .await
                .expect("Failed to connect to MongoDB and create client");
            let db = client.database(consts::DB_NAME);

            Self {
                db: Arc::new(Mutex::new(db)),
            }
        }

        async fn drop_all_collections(&self) {
            let db = self.db.lock().await;

            let collection_names = db
                .list_collection_names()
                .await
                .expect("Failed to list collection names");
            for name in collection_names {
                db.collection::<mongodb::bson::Document>(&name)
                    .drop()
                    .await
                    .expect(&format!("Failed to drop collection: {name}"));
            }
        }
    }
}

pub mod jwt {
    use crate::tests::{
        consts,
        models::jwt_tokens::{AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenType},
        utils,
    };
    use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use uuid::Uuid;

    pub fn make_admin_token_pair_with_specified_expiration_time(
        access_token_exp: usize,
        refresh_token_exp: usize,
    ) -> TokenPair {
        let access_token_claims = AccessTokenClaims {
            id: Uuid::new_v4(),
            exp: access_token_exp,
            policies: crate::tests::utils::get_admin_policies(),
            token_type: TokenType::Admin,
        };

        let refresh_token_claims = RefreshTokenClaims {
            id: Uuid::new_v4(),
            exp: refresh_token_exp,
            access_token_id: access_token_claims.id,
        };

        let access_token = encode_token_from_claims(&access_token_claims);
        let refresh_token = encode_token_from_claims(&refresh_token_claims);

        TokenPair {
            access_token,
            refresh_token,
        }
    }

    pub fn decode_token_into_claims<T: DeserializeOwned>(
        token: &str,
        decoding_key: &DecodingKey,
        validation: &Validation,
    ) -> T {
        jsonwebtoken::decode(token, decoding_key, validation)
            .expect("Failed to decode token")
            .claims
    }

    pub fn encode_token_from_claims<T: Serialize>(claims: &T) -> String {
        let jwt_secret = utils::get_env_var(consts::ENV_JWT_SECRET);
        let decoding_key = EncodingKey::from_secret(jwt_secret.as_ref());

        jsonwebtoken::encode(&jsonwebtoken::Header::default(), claims, &decoding_key)
            .expect("Failed to encode token")
    }
}
