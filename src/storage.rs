use crate::{
    database::DbConn,
    utils::aes::Aes256Cipher,
    utils::{
        common::generate_256_bit_key,
        shared_keys::{SharedKeys, SharedKeysError, SharedKeysSettings},
    },
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Storage data has been corrupted: {0}")]
    StorageCorrupted(String),

    #[error("Invalid storage state: expected {expected:?}, but current {current:?}")]
    InvalidStorageState {
        current: StorageState,
        expected: StorageState,
    },

    #[error("Invalid shared keys")]
    InvalidSharedKeys(String),

    #[error("Internal storage error")]
    InternalStorage(#[from] anyhow::Error),
}

impl From<SharedKeysError> for StorageError {
    fn from(err: SharedKeysError) -> Self {
        StorageError::InvalidSharedKeys(err.to_string())
    }
}

#[derive(Debug, PartialEq)]
pub enum StorageState {
    Uninitialized,
    Sealed,
    Unsealed,
}

#[derive(Serialize, Deserialize)]
pub struct StorageDto {
    pub encrypted_encryption_key: Option<Vec<u8>>,
    pub shared_keys_settings: Option<SharedKeysSettings>,
}

impl StorageDto {
    fn setup_uninitialized() -> Self {
        Self {
            encrypted_encryption_key: None,
            shared_keys_settings: None,
        }
    }

    pub fn determine_state(&self) -> Result<StorageState, StorageError> {
        if self.encrypted_encryption_key.is_none() && self.shared_keys_settings.is_none() {
            return Ok(StorageState::Uninitialized);
        }

        if self.encrypted_encryption_key.is_some() && self.shared_keys_settings.is_some() {
            return Ok(StorageState::Sealed);
        }

        Err(StorageError::StorageCorrupted(String::from(
            "Storage from DTO cannot be unsealed",
        )))
    }
}

pub struct Storage {
    db: Arc<DbConn>,
    shared_keys_settings: Option<SharedKeysSettings>,
    encryption_key: Option<Vec<u8>>,
    encrypted_encryption_key: Option<Vec<u8>>,
}

impl Storage {
    pub async fn setup(db: Arc<DbConn>) -> Result<Self, StorageError> {
        let storage_dto = db
            .read_storage()
            .await
            .context("Failed to read storage data from database")?
            .unwrap_or_else(StorageDto::setup_uninitialized);

        Self::setup_storage_from_dto(db, storage_dto)
    }

    fn setup_storage_from_dto(
        db: Arc<DbConn>,
        storage_dto: StorageDto,
    ) -> Result<Self, StorageError> {
        let storage = match storage_dto.determine_state()? {
            StorageState::Sealed => Self::setup_sealed_storage(db, storage_dto)?,
            StorageState::Uninitialized => Self::setup_uninitialized_storage(db)?,
            _ => {
                return Err(StorageError::StorageCorrupted(String::from(
                    "Storage from DTO cannot be unsealed",
                )))
            }
        };

        Ok(storage)
    }

    fn setup_sealed_storage(
        db: Arc<DbConn>,
        storage_dto: StorageDto,
    ) -> Result<Self, StorageError> {
        let storage = Self {
            db,
            shared_keys_settings: Some(storage_dto.shared_keys_settings.ok_or(
                StorageError::StorageCorrupted(String::from(
                    "Shared keys settings required for sealed storage setup",
                )),
            )?),
            encryption_key: None,
            encrypted_encryption_key: Some(storage_dto.encrypted_encryption_key.ok_or(
                StorageError::StorageCorrupted(String::from(
                    "Encrypted encryption key required for sealed storage setup",
                )),
            )?),
        };

        Ok(storage)
    }

    fn setup_uninitialized_storage(db: Arc<DbConn>) -> Result<Self, StorageError> {
        let storage = Self {
            db,
            shared_keys_settings: None,
            encryption_key: None,
            encrypted_encryption_key: None,
        };

        Ok(storage)
    }

    pub fn get_encryption_key(&self) -> Result<&Vec<u8>, StorageError> {
        self.ensure_state_is(StorageState::Unsealed)?;

        self.encryption_key
            .as_ref()
            .ok_or(StorageError::StorageCorrupted(String::from(
                "Fielt encryption_key required in current state",
            )))
    }

    pub async fn initialize(
        &mut self,
        shared_keys_settings: SharedKeysSettings,
    ) -> Result<SharedKeys, StorageError> {
        self.ensure_state_is(StorageState::Uninitialized)?;
        shared_keys_settings.assert_valid()?;

        let root_key = generate_256_bit_key();
        let cipher = Aes256Cipher::new(&root_key).context("Failed to create cipher")?;

        let encryption_key = generate_256_bit_key();
        let encrypted_encryption_key = cipher
            .encrypt(&encryption_key)
            .context("Failed to encrypt encryption_key")?;

        let shared_keys = SharedKeys::from_key(root_key, &shared_keys_settings)
            .context("Failed to create shared keys from root key")?;

        self.shared_keys_settings = Some(shared_keys_settings);
        self.encrypted_encryption_key = Some(encrypted_encryption_key);

        self.save_db().await?;
        Ok(shared_keys)
    }

    pub async fn unseal(&mut self, shared_keys: SharedKeys) -> Result<(), StorageError> {
        self.ensure_state_is(StorageState::Sealed)?;

        let shared_keys_settings =
            self.shared_keys_settings
                .as_ref()
                .ok_or(StorageError::StorageCorrupted(String::from(
                    "Field shared_keys_settings required in current state",
                )))?;
        let root_key = shared_keys.into_key(shared_keys_settings.threshold)?;

        let cipher = Aes256Cipher::new(&root_key).context("Failed to create cipher")?;

        let encrypted_encryption_key =
            self.encrypted_encryption_key
                .as_ref()
                .ok_or(StorageError::StorageCorrupted(String::from(
                    "Field encrypted_encryption_key required in current state",
                )))?;
        let encryption_key = cipher
            .decrypt(encrypted_encryption_key)
            .map_err(|_| StorageError::InvalidSharedKeys("Invalid shared keys".to_string()))?;

        self.encryption_key = Some(encryption_key);

        Ok(())
    }

    pub async fn seal(&mut self) -> Result<(), StorageError> {
        self.ensure_state_is(StorageState::Unsealed)?;

        self.encryption_key = None;
        Ok(())
    }

    pub fn ensure_state_is(&self, expected: StorageState) -> Result<(), StorageError> {
        let current = self.determine_state()?;
        if current != expected {
            return Err(StorageError::InvalidStorageState { current, expected });
        }

        Ok(())
    }

    fn determine_state(&self) -> Result<StorageState, StorageError> {
        if self.shared_keys_settings.is_none()
            && self.encryption_key.is_none()
            && self.encrypted_encryption_key.is_none()
        {
            return Ok(StorageState::Uninitialized);
        }

        if self.shared_keys_settings.is_some()
            && self.encryption_key.is_none()
            && self.encrypted_encryption_key.is_some()
        {
            return Ok(StorageState::Sealed);
        }

        if self.shared_keys_settings.is_some()
            && self.encryption_key.is_some()
            && self.encrypted_encryption_key.is_some()
        {
            return Ok(StorageState::Unsealed);
        }

        Err(StorageError::StorageCorrupted(String::from(
            "Storage state cannot be determined",
        )))
    }

    async fn save_db(&self) -> Result<(), StorageError> {
        let storage_dto = StorageDto {
            encrypted_encryption_key: self.encrypted_encryption_key.clone(),
            shared_keys_settings: self.shared_keys_settings.clone(),
        };

        self.db
            .save_storage(&storage_dto)
            .await
            .context("Failed to save to database")?;

        Ok(())
    }
}
