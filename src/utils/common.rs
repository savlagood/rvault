use crate::{
    models::Encryption,
    policies::{self, Permission, Policies},
    utils::{
        aes::{Aes256Cipher, AesError},
        base64,
    },
};
use anyhow::{Context, Result};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha512};
use std::{env::VarError, str::FromStr};

const FULL_ACCESS: &[Permission] = &[
    Permission::Create,
    Permission::Read,
    Permission::Update,
    Permission::Delete,
];

pub fn get_env_var_required<T: FromStr>(key: &str) -> Result<T> {
    get_env_var(key)?.context(format!("env variable {} is required", key))
}

pub fn get_env_var<T: FromStr>(key: &str) -> Result<Option<T>> {
    let value = match std::env::var(key) {
        Ok(value) => Ok(value),
        Err(err) => match err {
            VarError::NotPresent => return Ok(None),
            _ => Err(err),
        },
    }
    .context("Failed to read variable from environment")?;

    let result = value
        .parse::<T>()
        .map_err(|_| anyhow::anyhow!("Failed to parse env variable with key {}", key))?;

    Ok(Some(result))
}

pub fn generate_256_bit_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn hash_string_base64(data: &str) -> String {
    let hash = Sha512::digest(data.as_bytes());
    base64::encode(&hash)
}

pub fn encrypt_string_base64(data: &str, key: &[u8]) -> Result<String, AesError> {
    let cipher = Aes256Cipher::new(key)?;
    let encrypted_data_bytes = cipher.encrypt(data.as_bytes())?;
    let encrypted_data = base64::encode(&encrypted_data_bytes);

    Ok(encrypted_data)
}

pub fn get_admin_policies() -> Policies {
    let mut policies = Policies::new();

    let default_topic = policies
        .get_topic_mut(policies::DEFAULT)
        .expect("Policies do not have default value after initialization");

    default_topic.set_permissions(FULL_ACCESS);
    default_topic.set_secret_permissions(policies::DEFAULT, FULL_ACCESS);

    policies
}

pub fn generate_external_key(encryption_type: Encryption, default_key: &str) -> String {
    match encryption_type {
        Encryption::Provided(key) => key,
        Encryption::Generate => {
            let key_bytes = generate_256_bit_key();
            base64::encode(&key_bytes)
        }
        Encryption::None => default_key.to_string(),
    }
}
