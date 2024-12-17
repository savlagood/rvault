use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::{debug, info};

mod auth;
mod config;
mod router;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = config::Config::setup()?;
    debug!("Root token: {:?}", config.root_token);

    let app = router::create_route().await;
    let listener =
        TcpListener::bind(format!("{}:{}", config.server_ip, config.server_port)).await?;

    info!("Listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .await
        .context("Failed to start server")
}
