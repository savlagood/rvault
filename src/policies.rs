use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const DEFAULT: &str = "__default__";

/// Enum representing possible permissions for topics and secrets.
#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Create,
    Read,
    Update,
    Delete,
}

/// Checks whether a policy grants the required permission for a given topic.
///
/// # Arguments
/// * `policies` - Reference to the `Policies` containing the access rules.
/// * `required_permission` - The permission to check for.
/// * `topic_name` - The name of the topic to check access for.
///
/// # Returns
/// `true` if the required permission is granted for the topic, otherwise `false`.
pub fn check_topic_access_permissions(
    policies: &Policies,
    required_permission: Permission,
    topic_name: &str,
) -> bool {
    let topic = policies.get_topic_or_default(topic_name);
    topic.permissions.contains(&required_permission)
}

/// Struct representing a collection of policies for topics and secrets.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Policies(HashMap<String, Topic>);

impl Policies {
    /// Creates a new `Policies` instance with a default topic initialized.
    pub fn new() -> Self {
        let mut policies = Self(HashMap::new());

        policies.initialize_defaults();
        policies
    }

    /// Retrieves a reference to a topic by name.
    ///
    /// # Arguments
    /// * `name` - The name of the topic to retrieve.
    ///
    /// # Returns
    /// An `Option` containing a reference to the topic, or `None` if it does not exist.
    pub fn get_topic(&self, name: &str) -> Option<&Topic> {
        self.0.get(name)
    }

    /// Retrieves a mutable reference to a topic by name.
    ///
    /// # Arguments
    /// * `name` - The name of the topic to retrieve.
    ///
    /// # Returns
    /// An `Option` containing a mutable reference to the topic, or `None` if it does not exist.
    pub fn get_topic_mut(&mut self, name: &str) -> Option<&mut Topic> {
        self.0.get_mut(name)
    }

    /// Retrieves a reference to a topic by name, or the default topic if it does not exist.
    ///
    /// # Arguments
    /// * `name` - The name of the topic to retrieve.
    ///
    /// # Returns
    /// A reference to the requested topic or the default topic.
    pub fn get_topic_or_default(&self, name: &str) -> &Topic {
        self.get_topic(name).unwrap_or(self.get_default_topic())
    }

    /// Retrieves a reference to the default topic.
    ///
    /// # Returns
    /// A reference to the default topic.
    pub fn get_default_topic(&self) -> &Topic {
        self.0
            .get(DEFAULT)
            .expect("Default topic must always exists")
    }

    /// Initializes default entries in the policies.
    ///
    /// Ensures that every topic and the global default topic have a default entry.
    pub fn initialize_defaults(&mut self) {
        for topic in self.0.values_mut() {
            topic.initialize_defaults();
        }

        self.0.entry(DEFAULT.to_string()).or_insert_with(Topic::new);
    }
}

/// Struct representing permissions for a topic and its associated secrets.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Topic {
    /// Permissions for the topic itself.
    pub permissions: HashSet<Permission>,
    /// Permissions for individual secrets within the topic.
    pub secrets: HashMap<String, HashSet<Permission>>,
}

impl Topic {
    /// Creates a new `Topic` instance with default values initialized.
    pub fn new() -> Self {
        let mut topic = Self {
            permissions: HashSet::new(),
            secrets: HashMap::new(),
        };

        topic.initialize_defaults();
        topic
    }

    /// Retrieves the default permissions for secrets in the topic.
    ///
    /// # Returns
    /// A reference to the permissions of the default secret.
    pub fn get_default_secret(&self) -> &HashSet<Permission> {
        self.secrets
            .get(DEFAULT)
            .expect("Default secret must always exists")
    }

    /// Initializes default entry to the secrets map if missing.
    fn initialize_defaults(&mut self) {
        self.secrets.entry(DEFAULT.to_string()).or_default();
    }

    /// Adds new permissions to the topic without removing existing ones.
    ///
    /// # Arguments
    /// * `permissions` - Permissions to add to the topic.
    pub fn _add_permissions(&mut self, permissions: &[Permission]) {
        self.permissions.extend(permissions);
    }

    /// Replaces the topic's permissions with the provided list.
    ///
    /// # Arguments
    /// * `permissions` - Permissions to set for the topic.
    pub fn set_permissions(&mut self, permissions: &[Permission]) {
        self.permissions = permissions.iter().cloned().collect();
    }

    /// Sets permissions for a specific secret within the topic.
    ///
    /// # Arguments
    /// * `name` - The name of the secret.
    /// * `permissions` - Permissions to set for the secret.
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
