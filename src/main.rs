mod config;
mod http;
mod policies;
mod state;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    http::server::serve().await
}
