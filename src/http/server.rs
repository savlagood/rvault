use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use axum::{http::header::AUTHORIZATION, Router};
use tokio::net::TcpListener;
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer,
    sensitive_headers::SetSensitiveHeadersLayer, timeout::TimeoutLayer, trace,
};
use tracing::info;

use crate::{config::Config, http::auth};

use super::test_handlers;

#[derive(Clone)]
pub struct AppContext {
    pub config: Arc<Config>,
}

impl AppContext {
    fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

pub async fn serve(config: Config) -> Result<()> {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.server_port));

    let app_context = AppContext::new(config);

    let app = create_router(app_context); //
    let listener = TcpListener::bind(addr).await?;

    info!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Failed to run HTTP server")
}

fn create_router(app_context: AppContext) -> Router {
    Router::new()
        .nest(
            "/api",
            Router::new()
                .nest("/auth", auth::handlers::router())
                .nest("/test", test_handlers::router()),
        )
        .layer((
            SetSensitiveHeadersLayer::new([AUTHORIZATION]),
            CompressionLayer::new(),
            trace::TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().include_headers(true))
                .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO))
                .on_failure(()),
            TimeoutLayer::new(app_context.config.request_timeout),
            CatchPanicLayer::new(),
        ))
        .with_state(app_context)
}

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
