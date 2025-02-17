use crate::{
    crypto::{self, aes::AesError},
    database::{DatabaseError, MongoDb},
    models::StorageTopicAndSecretKeys,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::sync::Arc;
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

    #[error("Database error")]
    Database(#[from] DatabaseError),
}

pub struct SecretDao {
    db: Arc<MongoDb>,
}

impl SecretDao {
    pub fn new(db: Arc<MongoDb>) -> Self {
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
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretDto {
    pub hashed_name: String,
    pub encrypted_name: String,
    pub versions: Vec<String>,
    pub cursor: usize,
    pub checksum: String,
    pub encrypted: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<usize>,
}

impl SecretDto {
    pub fn new(
        name: String,
        value: String,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<Self, SecretError> {
        let hashed_name = crypto::hash_string_base64(&name);
        let encrypted_name = crypto::encrypt_string_base64(&name, keyset.storage_key)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        let encrypted_value = Self::encrypt_secret_value(value, keyset)?;

        let mut secret_dto = Self {
            hashed_name,
            encrypted_name,
            versions: vec![encrypted_value],
            cursor: 0,
            checksum: "".to_string(),
            encrypted: false,
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
        let encrypted_with_topic_key = crypto::encrypt_string_base64(&value, keyset.topic_key)
            .map_err(|err| SecretError::InvalidTopicKey(err.to_string()))?;
        let encrypted_with_secret_key =
            crypto::encrypt_string_base64(&encrypted_with_topic_key, keyset.secret_key)
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
        hasher.update([self.encrypted as u8]);

        if let Some(exp) = self.exp {
            hasher.update(exp.to_le_bytes());
        }

        let checksum_bytes = hasher.finalize().to_vec();
        let encoded_base64_checksum = crypto::base64::encode(&checksum_bytes);

        Ok(encoded_base64_checksum)
    }
}
