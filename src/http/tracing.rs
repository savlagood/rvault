use axum::http::Request;
use tower_http::trace::MakeSpan;
use tracing::{Level, Span};
use uuid::Uuid;

#[derive(Clone)]
pub struct RvaultMakeSpan;

impl<B> MakeSpan<B> for RvaultMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let span_id = Uuid::new_v4();

        tracing::span!(
            Level::INFO,
            "request",
            span_id = %span_id,
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            headers = ?request.headers(),
        )
    }
}
