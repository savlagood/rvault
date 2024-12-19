mod config;
mod http;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = config::Config::setup()?;

    http::server::serve(config).await
}
