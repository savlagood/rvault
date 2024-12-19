use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::http::auth::policy::Policies;

fn calculate_expiration_time(duration: Duration) -> usize {
    (Utc::now() + duration).timestamp() as usize
}

#[derive(Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub id: Uuid,
    pub exp: usize,
    pub policy: Policies,
}

impl AccessTokenClaims {
    pub fn new(policy: Policies, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = calculate_expiration_time(ttl);

        Self { id, exp, policy }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    id: Uuid,
    access_token_id: Uuid,
    exp: usize,
}

impl RefreshTokenClaims {
    pub fn new(access_token_id: Uuid, ttl: Duration) -> Self {
        let id = Uuid::new_v4();
        let exp = calculate_expiration_time(ttl);

        Self {
            id,
            access_token_id,
            exp,
        }
    }
}
