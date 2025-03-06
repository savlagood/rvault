use crate::api_tests::consts::{THRESHOLD, TOTAL_KEYS};
use rand::{seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SharedKeysSettings {
    pub threshold: u8,
    pub total_keys: u8,
}

impl SharedKeysSettings {
    pub fn default() -> Self {
        Self {
            threshold: THRESHOLD,
            total_keys: TOTAL_KEYS,
        }
    }

    pub fn into_value(self) -> serde_json::Value {
        serde_json::json!(self)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SharedKeys {
    pub shares: Vec<String>,
}

impl SharedKeys {
    pub fn new() -> Self {
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

    pub fn into_value(self) -> serde_json::Value {
        serde_json::json!(self)
    }
}
