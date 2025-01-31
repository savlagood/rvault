use crate::{config::Config, database::MongoDb, storage::Storage};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone)]
pub struct AppState(Arc<StateData>);

impl AppState {
    pub async fn setup() -> Result<Self> {
        let config = Config::setup().context("Failed to setup configuration")?;

        let db = MongoDb::setup_with_connection_str(&config.db_connection_string).await?;
        let storage = Storage::setup(db)
            .await
            .expect("Failed to initialize storage");

        let state_data = Arc::new(StateData {
            config: Arc::new(config),
            storage: Arc::new(RwLock::new(storage)),
        });

        Ok(Self(state_data))
    }

    pub fn get_config(&self) -> &Config {
        &self.0.config
    }

    pub async fn _get_storage_read(&self) -> RwLockReadGuard<'_, Storage> {
        self.0.storage.read().await
    }

    pub async fn get_storage_write(&self) -> RwLockWriteGuard<'_, Storage> {
        self.0.storage.write().await
    }
}

impl AsRef<AppState> for AppState {
    fn as_ref(&self) -> &AppState {
        self
    }
}

struct StateData {
    config: Arc<Config>,
    storage: Arc<RwLock<Storage>>,
}
