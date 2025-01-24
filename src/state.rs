use crate::config::Config;
use anyhow::{Context, Result};
use std::sync::Arc;

pub type SharedState = Arc<AppState>;

#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
}

impl AppState {
    pub fn new() -> Result<SharedState> {
        let config = Config::setup().context("Failed to setup configuration")?;
        let config = Arc::new(config);

        let app_state = Self { config };
        let app_state = Arc::new(app_state);

        Ok(app_state)
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }
}
