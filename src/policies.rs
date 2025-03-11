use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

pub const DEFAULT: &str = "__default__";

#[derive(Debug, Error)]
pub enum PoliciesError {
    #[error("Do not have enough permissions to perform this operation")]
    TopicAccessDenied,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Create,
    Read,
    Update,
    Delete,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Policies(HashMap<String, Topic>);

impl Policies {
    pub fn new() -> Self {
        let mut policies = Self(HashMap::new());

        policies.initialize_defaults();
        policies
    }

    pub fn get_topic_or_default(&self, name: &str) -> &Topic {
        self.get_topic(name).unwrap_or(self.get_default_topic())
    }

    pub fn get_topic(&self, name: &str) -> Option<&Topic> {
        self.0.get(name)
    }

    pub fn get_topic_mut(&mut self, name: &str) -> Option<&mut Topic> {
        self.0.get_mut(name)
    }

    pub fn get_default_topic(&self) -> &Topic {
        self.0
            .get(DEFAULT)
            .expect("Default topic must always exists")
    }

    pub fn initialize_defaults(&mut self) {
        for topic in self.0.values_mut() {
            topic.initialize_defaults();
        }

        self.0.entry(DEFAULT.to_string()).or_insert_with(Topic::new);
    }

    pub fn ensure_topic_access_permitted(
        &self,
        topic_name: &str,
        required_permission: Permission,
    ) -> Result<(), PoliciesError> {
        let topic = self.get_topic_or_default(topic_name);

        if topic.permissions.contains(&required_permission) {
            Ok(())
        } else {
            Err(PoliciesError::TopicAccessDenied)
        }
    }

    pub fn ensure_secret_access_permitted(
        &self,
        topic_name: &str,
        secret_name: &str,
        required_permission: Permission,
    ) -> Result<(), PoliciesError> {
        let topic = self.get_topic_or_default(topic_name);

        topic.ensure_secret_access_permitted(secret_name, required_permission)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Topic {
    pub permissions: HashSet<Permission>,
    pub secrets: HashMap<String, HashSet<Permission>>,
}

impl Topic {
    pub fn new() -> Self {
        let mut topic = Self {
            permissions: HashSet::new(),
            secrets: HashMap::new(),
        };

        topic.initialize_defaults();
        topic
    }

    fn ensure_secret_access_permitted(
        &self,
        secret_name: &str,
        required_permission: Permission,
    ) -> Result<(), PoliciesError> {
        let secret = self.get_secret_or_default(secret_name);

        if secret.contains(&required_permission) {
            Ok(())
        } else {
            Err(PoliciesError::TopicAccessDenied)
        }
    }

    fn get_secret_or_default(&self, secret_name: &str) -> &HashSet<Permission> {
        self.secrets
            .get(secret_name)
            .unwrap_or(self.get_default_secret())
    }

    pub fn get_default_secret(&self) -> &HashSet<Permission> {
        self.secrets
            .get(DEFAULT)
            .expect("Default secret must always exists")
    }

    fn initialize_defaults(&mut self) {
        self.secrets.entry(DEFAULT.to_string()).or_default();
    }

    pub fn set_permissions(&mut self, permissions: &[Permission]) {
        self.permissions = permissions.iter().cloned().collect();
    }

    pub fn set_secret_permissions(&mut self, name: &str, permissions: &[Permission]) {
        self.secrets
            .entry(name.to_string())
            .and_modify(|permissions_set| {
                permissions_set.clear();
                permissions_set.extend(permissions);
            })
            .or_insert_with(|| permissions.iter().cloned().collect());
    }
}
