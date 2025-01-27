mod config;
mod http;
mod policies;
mod state;

use anyhow::Context;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let app_state = state::AppState::setup().context("Failed to setup AppState")?;
    http::server::serve(app_state).await
}
