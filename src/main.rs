mod cache;
mod config;
mod database;
mod http;
mod logging;
mod metrics;
mod models;
mod policies;
mod secrets;
mod state;
mod storage;
mod topics;
mod utils;

use anyhow::Context;

#[cfg(test)]
mod api_tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::from_filename(".env").context("Failed to load values from .env file")?;
    logging::init()?;
    metrics::register_metrics();

    let app_state = state::AppState::setup()
        .await
        .context("Failed to setup AppState")?;

    http::server::serve(app_state).await
}
