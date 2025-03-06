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

    pub fn into_value(self) -> serde_json::Value {
        serde_json::json!(self)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Topic {
    pub permissions: HashSet<Permission>,
    pub secrets: HashMap<String, HashSet<Permission>>,
}
