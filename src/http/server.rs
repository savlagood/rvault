use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use axum::{http::header::AUTHORIZATION, Router};
use tokio::net::TcpListener;
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer,
    sensitive_headers::SetSensitiveHeadersLayer, timeout::TimeoutLayer, trace,
};
use tracing::info;

use super::{storage, topic};
use crate::{config::CONFIG, http::auth};

/// Starts the HTTP server and begins serving requests.
///
/// # Errors
/// Returns an error if the server fails to bind to the specified address or encounters issues during execution.
pub async fn serve() -> Result<()> {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, CONFIG.server_port));

    let app = create_router();
    let listener = TcpListener::bind(addr).await?;

    info!("Listening on {} 🚀", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Failed to run HTTP server")
}

/// Creates the main application router, setting up API routes and middleware layers.
///
/// # Returns
/// A configured [`Router`] instance containing all routes and middleware layers.
pub fn create_router() -> Router {
    Router::new()
        .nest(
            "/api",
            Router::new()
                .nest("/auth", auth::handlers::router())
                .nest("/storage", storage::handlers::router())
                .nest("/topic", topic::handlers::router()),
        )
        .layer((
            SetSensitiveHeadersLayer::new([AUTHORIZATION]),
            CompressionLayer::new(),
            trace::TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().include_headers(true))
                .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO))
                .on_failure(()),
            TimeoutLayer::new(CONFIG.request_timeout),
            CatchPanicLayer::new(),
        ))
}

/// Waits for a shutdown signal (Ctrl+C or terminate signal) to gracefully terminate the server.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
