use axum::Router;
use tower_http::trace;

use crate::auth;

pub async fn create_route() -> Router {
    // Router::new().merge(router::create_route())
    Router::new()
        .merge(Router::new().nest("/auth", Router::new().merge(auth::router::create_route())))
        .layer(
            trace::TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().include_headers(true))
                .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
}
