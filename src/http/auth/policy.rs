use std::collections::{HashMap, HashSet};

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

use super::{errors::AuthError, tokens::AccessTokenClaims};
use crate::http::server::AppContext;

const DEFAULT: &str = "__default__";

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Create,
    Read,
    Update,
    Delete,
}

#[derive(Serialize, Deserialize)]
pub struct Policies(HashMap<String, Topic>);

impl Policies {
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(DEFAULT.to_string(), Topic::new());

        Self(policies)
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

#[async_trait]
impl<S> FromRequestParts<S> for Policies
where
    AppContext: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppContext::from_ref(state);

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        let token_data: TokenData<AccessTokenClaims> = jsonwebtoken::decode(
            bearer.token(),
            &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims.policy)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Topic {
    permissions: HashSet<Permission>,
    secrets: HashMap<String, HashSet<Permission>>,
}

impl Topic {
    fn new() -> Self {
        let mut secrets = HashMap::new();
        secrets.insert(DEFAULT.to_string(), HashSet::new());

        Self {
            permissions: HashSet::new(),
            secrets,
        }
    }

    pub fn add_permissions(&mut self, topics_permissions: &[Permission]) {
        self.permissions.extend(topics_permissions.iter().cloned());
    }

    pub fn set_permissions(&mut self, topics_permissions: &[Permission]) {
        self.permissions.clear();
        self.add_permissions(topics_permissions);
    }

    // pub fn add_secret_permissions(
    //     &mut self,
    //     secret_name: &str,
    //     secrets_permissions: &[Permission],
    // ) {
    //     self.secrets
    //         .entry(secret_name.to_string())
    //         .or_insert_with(HashSet::new)
    //         .extend(secrets_permissions.iter().cloned());
    // }

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
