use crate::{
    database::{DatabaseError, DbConn},
    models::StorageTopicAndSecretKeys,
    utils::aes::{Aes256Cipher, AesError},
    utils::{
        base64,
        common::{encrypt_string_base64, hash_string_base64},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Invalid storage encryption key. AesError: {0}")]
    InvalidStorageKey(String),

    #[error("Invalid topic encryption key. AesError: {0}")]
    InvalidTopicKey(String),

    #[error("Invalid secret encryption key. AesError: {0}")]
    InvalidSecretKey(String),

    #[error("Secret with such name already exists")]
    AlreadyExists,

    #[error("Secret's data has been corrupted")]
    SecretCorrupted,

    #[error("Database error")]
    Database(#[from] DatabaseError),
}

fn decrypt_value(cipher: &Aes256Cipher, encrypted_value: String) -> Result<String, SecretError> {
    let encrypted_value_bytes =
        base64::decode(encrypted_value).map_err(|_| SecretError::SecretCorrupted)?;
    let decrypted_value_bytes = cipher
        .decrypt(&encrypted_value_bytes)
        .map_err(|_| SecretError::SecretCorrupted)?;

    let value =
        std::str::from_utf8(&decrypted_value_bytes).map_err(|_| SecretError::SecretCorrupted)?;

    Ok(String::from(value))
}
pub struct SecretDao {
    db: Arc<DbConn>,
}

impl SecretDao {
    pub fn new(db: Arc<DbConn>) -> Self {
        Self { db }
    }

    pub async fn create(&self, secret: SecretDto) -> Result<(), SecretError> {
        self.db
            .create_secret(secret)
            .await
            .map_err(|err| match err {
                DatabaseError::AlreadyExists => SecretError::AlreadyExists,
                _ => SecretError::Database(err),
            })
    }

    pub async fn fetch_secret_names(
        &self,
        hashed_topic_name: &str,
        storage_key: &[u8],
    ) -> Result<HashSet<String>, SecretError> {
        let cipher = Aes256Cipher::new(storage_key)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        let encrypted_secret_names = self
            .db
            .fetch_topic_encrypted_secret_names(hashed_topic_name)
            .await?;

        let mut secret_names = HashSet::with_capacity(encrypted_secret_names.len());
        for encrypted_name in encrypted_secret_names {
            let secret_name = decrypt_value(&cipher, encrypted_name)?;
            secret_names.insert(secret_name);
        }

        Ok(secret_names)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretDto {
    pub hashed_name: String,
    pub encrypted_name: String,
    pub hashed_topic_name: String,
    pub versions: Vec<String>,
    pub cursor: usize,
    pub checksum: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<usize>,
}

impl SecretDto {
    pub fn new(
        name: String,
        value: String,
        hashed_topic_name: String,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<Self, SecretError> {
        let hashed_name = hash_string_base64(&name);
        let encrypted_name = encrypt_string_base64(&name, keyset.storage_key)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        let encrypted_value = Self::encrypt_secret_value(value, keyset)?;

        let mut secret_dto = Self {
            hashed_name,
            encrypted_name,
            hashed_topic_name,
            versions: vec![encrypted_value],
            cursor: 0,
            checksum: "".to_string(),
            exp: None,
        };
        secret_dto
            .update_checksum(keyset)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        Ok(secret_dto)
    }

    fn encrypt_secret_value(
        value: String,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<String, SecretError> {
        let encrypted_with_topic_key = encrypt_string_base64(&value, keyset.topic_key)
            .map_err(|err| SecretError::InvalidTopicKey(err.to_string()))?;
        let encrypted_with_secret_key =
            encrypt_string_base64(&encrypted_with_topic_key, keyset.secret_key)
                .map_err(|err| SecretError::InvalidSecretKey(err.to_string()))?;

        Ok(encrypted_with_secret_key)
    }

    fn update_checksum(&mut self, keyset: &StorageTopicAndSecretKeys) -> Result<(), AesError> {
        self.checksum = self.calculate_checksum(keyset)?;
        Ok(())
    }

    fn calculate_checksum(&self, keyset: &StorageTopicAndSecretKeys) -> Result<String, AesError> {
        let mut hasher = Sha512::new();

        // Using storage and topic keys as salt
        hasher.update(keyset.storage_key);
        hasher.update(keyset.topic_key);
        hasher.update(keyset.secret_key);

        hasher.update(&self.hashed_name);
        hasher.update(&self.encrypted_name);

        for version in self.versions.iter() {
            hasher.update(version);
        }

        hasher.update(self.cursor.to_le_bytes());

        if let Some(exp) = self.exp {
            hasher.update(exp.to_le_bytes());
        }

        let checksum_bytes = hasher.finalize().to_vec();
        let encoded_base64_checksum = base64::encode(&checksum_bytes);

        Ok(encoded_base64_checksum)
    }
}
