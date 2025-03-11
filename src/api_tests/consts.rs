use crate::api_tests::models::policies::Policies;
use once_cell::sync::Lazy;

// env
pub const ENV_ROOT_TOKEN: &str = "RVAULT_ROOT_TOKEN";
pub const ENV_AUTH_SECRET: &str = "RVAULT_AUTH_SECRET";

// shared keys
pub const THRESHOLD: u8 = 3;
pub const TOTAL_KEYS: u8 = 5;

// topics
pub const TOPIC_KEY_LENGTH: usize = 32;
pub const TOPIC_NAME: &str = "Some_validTopicName_123";
pub const TOPIC_KEY: &str = "Some topic password 42";

// secrets
pub const SECRET_KEY_LENGTH: usize = 32;
pub const SECRET_NAME: &str = "Some_validSecretName_123";
pub const SECRET_VALUE: &str = "some password 12321 !@#$%^&*()_";
pub const SECRET_KEY: &str = "Some secret password 42";

// headers
pub const TOPIC_KEY_HEADER: &str = "x-rvault-topic-key";
pub const SECRET_KEY_HEADER: &str = "x-rvault-secret-key";

// policies
pub static ADMIN_POLICIES: Lazy<Policies> = Lazy::new(|| {
    Policies::from_value(serde_json::json!({
        "__default__": {
            "permissions": ["create", "read", "update", "delete"],
            "secrets": {
                "__default__": ["create", "read", "update", "delete"]
            }
        }
    }))
});

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

pub static SIMPLE_USER_POLICIES_WITH_DEFAULTS: Lazy<Policies> = Lazy::new(|| {
    let policies_as_value = serde_json::json!({
        "some_topic_name2": {
            "permissions": ["read", "delete", "create"],
            "secrets": {
                "some_secret_name1": ["delete", "update", "create", "read"],
                "some_secret_name2": ["read", "create", "update"],
                "__default__": []
            }
        },
        "some_topic_name1": {
            "permissions": ["create", "read"],
            "secrets": {
                "__default__": ["read"],
                "some_secret_name1": ["read", "update"],
                "some_secret_name2": ["read", "update", "delete"]
            }
        },
        "__default__": {
            "permissions": [],
            "secrets": {
                "__default__": []
            }
        }
    });
    Policies::from_value(policies_as_value)
});
