use crate::{
    http::{
        handlers,
        headers::{X_RVAULT_SECRET_KEY, X_RVAULT_TOPIC_KEY},
        middleware::metrics_middleware,
        tracing::RvaultMakeSpan,
    },
    state::AppState,
};
use anyhow::{Context, Result};
use axum::{
    http::{header::AUTHORIZATION, StatusCode},
    middleware,
    routing::get,
    Router,
};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::TcpListener;
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer,
    sensitive_headers::SetSensitiveHeadersLayer, timeout::TimeoutLayer, trace,
};
use tracing::info;

pub async fn serve(app_state: AppState) -> Result<()> {
    let config = app_state.get_config();

    let app = create_router(app_state.clone());

    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.server_port));
    let listener = TcpListener::bind(addr).await?;

    info!("Listening on {} 🚀", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Failed to run HTTP server")
}

pub fn create_router(app_state: AppState) -> Router {
    let config = app_state.get_config();

    Router::new()
        .route("/metrics", get(metrics_handler))
        .nest(
            "/api",
            Router::new()
                .nest("/auth", handlers::auth::create_router(app_state.clone()))
                .nest(
                    "/storage",
                    handlers::storage::create_router(app_state.clone()),
                )
                .nest(
                    "/topics",
                    handlers::topics::create_router(app_state.clone()),
                )
                .nest(
                    "/topics/:topic_name/secrets",
                    handlers::secrets::create_router(app_state.clone()),
                ),
        )
        .route_layer(middleware::from_fn(metrics_middleware))
        .layer((
            SetSensitiveHeadersLayer::new([
                AUTHORIZATION,
                X_RVAULT_TOPIC_KEY.clone(),
                X_RVAULT_SECRET_KEY.clone(),
            ]),
            CompressionLayer::new(),
            trace::TraceLayer::new_for_http()
                .make_span_with(RvaultMakeSpan)
                .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO))
                .on_failure(()),
            TimeoutLayer::new(config.request_timeout),
            CatchPanicLayer::new(),
        ))
}

async fn metrics_handler() -> (StatusCode, String) {
    let metrics = crate::metrics::gather_metrics();
    (StatusCode::OK, metrics)
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
