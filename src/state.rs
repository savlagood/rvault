use crate::{cache::RedisCache, config::Config, database::DbConn, storage::Storage};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(test))]
use crate::database::builder::build_db_connection;
#[cfg(test)]
use crate::database::builder::build_test_db_connection;

#[derive(Clone)]
pub struct AppState(Arc<StateData>);

impl AppState {
    pub async fn setup() -> Result<Self> {
        let config = Config::setup().context("Failed to setup configuration")?;

        #[cfg(not(test))]
        let connection = build_db_connection(&config)
            .await
            .context("Failed to setup db connection")?;
        #[cfg(test)]
        let connection = build_test_db_connection(&config)
            .await
            .context("Failed to setup db connection")?;

        let db_conn = Arc::new(connection);

        let cache = RedisCache::new(&config.redis_uri, config.cache_ttl)
            .await
            .context("Failed to create connection with redis")?;

        let storage = Storage::setup(db_conn.clone())
            .await
            .expect("Failed to initialize storage");

        let state_data = Arc::new(StateData {
            config: Arc::new(config),
            db_conn,
            storage: Arc::new(RwLock::new(storage)),
            cache: Arc::new(cache),
        });

        Ok(Self(state_data))
    }

    pub fn get_config(&self) -> &Config {
        &self.0.config
    }

    pub fn get_db_conn(&self) -> Arc<DbConn> {
        self.0.db_conn.clone()
    }

    pub fn get_cache(&self) -> Arc<RedisCache> {
        self.0.cache.clone()
    }

    pub async fn get_storage_read(&self) -> RwLockReadGuard<'_, Storage> {
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
    db_conn: Arc<DbConn>,
    storage: Arc<RwLock<Storage>>,
    cache: Arc<RedisCache>,
}
