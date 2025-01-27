use crate::config::Config;
use anyhow::{Context, Result};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState(Arc<StateData>);

impl AppState {
    pub fn setup() -> Result<Self> {
        let config = Arc::new(Config::setup().context("Failed to setup configuration")?);

        let state_data = Arc::new(StateData { config });

        Ok(Self(state_data))
    }

    pub fn get_config(&self) -> &Config {
        &self.0.config
    }
}

impl AsRef<AppState> for AppState {
    fn as_ref(&self) -> &AppState {
        self
    }
}

struct StateData {
    config: Arc<Config>,
}
