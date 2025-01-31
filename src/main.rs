mod config;
mod crypto;
mod database;
mod http;
mod policies;
mod state;
mod storage;

use anyhow::Context;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let app_state = state::AppState::setup()
        .await
        .context("Failed to setup AppState")?;

    http::server::serve(app_state).await
}
