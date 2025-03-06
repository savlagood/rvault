use crate::api_tests::models::policies::{Permission, Policies};
use chrono::Utc;
use std::time::Duration;

pub fn get_env_var(key: &str) -> String {
    std::env::var(key).expect(&format!("Failed to get env variable {}", key))
}

pub fn calculate_expiration_time(ttl: Duration) -> usize {
    (Utc::now() + ttl).timestamp() as usize
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

pub fn build_policies(
    topic_name: &str,
    topic_permissions: Vec<Permission>,
    secret_name: &str,
    secret_permissions: Vec<Permission>,
) -> Policies {
    let topic_permissions = serde_json::json!(topic_permissions);
    let secret_permissions = serde_json::json!(secret_permissions);

    let policies = Policies::from_value(serde_json::json!({
        topic_name: {
            "permissions": topic_permissions,
            "secrets": {
                secret_name: secret_permissions
            }
        }
    }));

    policies
}
