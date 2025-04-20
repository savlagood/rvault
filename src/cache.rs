use redis::{aio::MultiplexedConnection, AsyncCommands, Client, RedisError};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Redis error: {0}")]
    RedisError(#[from] RedisError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct RedisCache {
    connection: Arc<Mutex<MultiplexedConnection>>,
    ttl: Duration,
    cache_key_prefix: String,
}

impl RedisCache {
    pub async fn new(uri: &str, ttl: Duration) -> Result<Self, CacheError> {
        let client = Client::open(uri)?;
        let connection = Arc::new(Mutex::new(client.get_multiplexed_async_connection().await?));
        let cache_key_prefix = Self::get_cache_key_prefix();

        Ok(Self {
            connection,
            ttl,
            cache_key_prefix,
        })
    }

    fn get_cache_key_prefix() -> String {
        #[cfg(test)]
        {
            format!("test:{}:rvault:", uuid::Uuid::new_v4())
        }
        #[cfg(not(test))]
        {
            "rvault:".to_string()
        }
    }

    #[cfg(test)]
    pub async fn clear_test_cache(&self) -> Result<(), CacheError> {
        let mut conn = self.connection.lock().await;

        let pattern = format!("{}*", &self.cache_key_prefix);
        let keys: Vec<String> = conn.keys(pattern).await?;

        if !keys.is_empty() {
            let _: () = conn.del(&keys).await?;
        }

        Ok(())
    }

    pub async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError> {
        let key = self.make_redis_key(key);

        let mut conn = self.connection.lock().await;
        let value: Option<String> = conn.get(key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<(), CacheError> {
        let key = self.make_redis_key(key);

        let mut conn = self.connection.lock().await;
        let value = serde_json::to_string(value)?;
        let _: () = conn.set_ex(key, value, self.ttl.as_secs()).await?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let key = self.make_redis_key(key);

        let mut conn = self.connection.lock().await;
        let _: () = conn.del(key).await?;
        Ok(())
    }

    fn make_redis_key(&self, key: &str) -> String {
        format!("{}{}", &self.cache_key_prefix, key)
    }
}
