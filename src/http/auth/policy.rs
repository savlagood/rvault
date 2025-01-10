use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const DEFAULT: &str = "__default__";

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Create,
    Read,
    Update,
    Delete,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Policies(pub HashMap<String, Topic>);

impl Policies {
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(DEFAULT.to_string(), Topic::new());

        Self(policies)
    }

    pub fn get_topic(&self, topic_name: &str) -> Result<&Topic> {
        match self.0.get(topic_name) {
            Some(topic) => Ok(topic),
            None => self.get_default(),
        }
    }

    /// Adds default values to access policies
    pub fn add_defaults(&mut self) {
        for (_topic_name, topic) in self.0.iter_mut() {
            topic.add_defaults();
        }

        self.0.entry(DEFAULT.to_string()).or_insert_with(Topic::new);
    }

    pub fn is_default_empty(&self) -> Result<bool> {
        let default_topic = self.get_default()?;
        default_topic.is_empty()
    }

    fn get_default(&self) -> Result<&Topic> {
        self.0.get(DEFAULT).context("Failed to take default topic")
    }

    pub fn set_default_permissions(
        &mut self,
        topics_permissions: &[Permission],
        secrets_permissions: &[Permission],
    ) {
        let default_topic = self.0.entry(DEFAULT.to_string()).or_insert_with(Topic::new);

        default_topic.set_permissions(topics_permissions);
        default_topic.set_secret_permissions(DEFAULT, secrets_permissions);
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Topic {
    pub permissions: HashSet<Permission>,
    pub secrets: HashMap<String, HashSet<Permission>>,
}

impl Topic {
    fn new() -> Self {
        let mut topic = Self {
            permissions: HashSet::new(),
            secrets: HashMap::new(),
        };
        topic.add_defaults();

        topic
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(self.is_topic_permissions_empty() && self.is_default_secrets_permissions_empty()?)
    }

    fn is_topic_permissions_empty(&self) -> bool {
        self.permissions.is_empty()
    }

    fn is_default_secrets_permissions_empty(&self) -> Result<bool> {
        let default_secret = self
            .secrets
            .get(DEFAULT)
            .context("Failed to take default secret")?;
        Ok(default_secret.is_empty())
    }

    fn add_defaults(&mut self) {
        self.secrets.entry(DEFAULT.to_string()).or_default();
    }

    pub fn add_permissions(&mut self, topics_permissions: &[Permission]) {
        self.permissions.extend(topics_permissions.iter().cloned());
    }

    pub fn set_permissions(&mut self, topics_permissions: &[Permission]) {
        self.permissions.clear();
        self.add_permissions(topics_permissions);
    }

    pub fn set_secret_permissions(
        &mut self,
        secret_name: &str,
        secrets_permissions: &[Permission],
    ) {
        self.secrets
            .entry(secret_name.to_string())
            .and_modify(|permissions| {
                permissions.clear();
                permissions.extend(secrets_permissions.iter().cloned());
            })
            .or_insert_with(|| secrets_permissions.iter().cloned().collect());
    }
}
