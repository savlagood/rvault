use crate::tests::models::policies::Policies;
use once_cell::sync::Lazy;
use std::time::Duration;

// headers
pub const HEADER_WITH_TOPIC_KEY: &str = "x-rvault-topic-key";
// pub const HEADER_WITH_SECRET_KEY: &str = "x-rvault-secret-key";

// test constants for database
pub const DB_NAME: &str = "test_rvault";

// shared keys settings
pub const THRESHOLD: u8 = 3;
pub const TOTAL_KEYS: u8 = 5;

// variables from environment
pub const ENV_ROOT_TOKEN: &str = "RVAULT_ROOT_TOKEN";
pub const ENV_JWT_SECRET: &str = "RVAULT_AUTH_SECRET";
pub const ENV_DB_CONNECTION_STRING: &str = "RVAULT_DB_CONNECTION_STRING";

// test constants for jwt tokens
pub const TEST_ACCESS_TOKEN_TTL: Duration = Duration::from_secs(60 * 60 * 24);
pub const TEST_REFRESH_TOKEN_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 7);

pub static SIMPLE_USER_POLICIES: Lazy<Policies> = Lazy::new(|| {
    let policies_as_value = serde_json::json!({
        "some_topic_name1": {
            "permissions": ["create", "read"],
            "secrets": {
                "some_secret_name1": ["read", "update"],
                "some_secret_name2": ["read", "update", "delete"],
                "__default__": ["read"]
            }
        },
        "some_topic_name2": {
            "permissions": ["create", "read", "delete"],
            "secrets": {
                "some_secret_name1": ["read", "update", "create", "delete"],
                "some_secret_name2": ["read", "update", "create"]
            }
        }
    });
    Policies::from_value(policies_as_value)
});
