use lazy_static::lazy_static;
use prometheus::{
    exponential_buckets, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::{boxed::Box, time::Duration};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    /// Request duration histogram with percentiles
    pub static ref HTTP_REQUEST_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
        ).buckets(exponential_buckets(0.001, 2.0, 12).expect("Failed to create exponential buckets")),
        &["method", "path"]
    )
    .expect("Failed to register HTTP request duration histogram");

    /// Total requests counter
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "http_requests_total",
            "Total number of HTTP requests",
        ),
        &["method", "path", "status"]
    ).expect("Failed to register HTTP requests total counter");
}

pub fn register_metrics() {
    REGISTRY
        .register(Box::new(HTTP_REQUEST_DURATION.clone()))
        .expect("Failed to register HTTP request duration histogram");

    REGISTRY
        .register(Box::new(HTTP_REQUESTS_TOTAL.clone()))
        .expect("Failed to register HTTP requests total counter");
}

pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();

    encoder
        .encode_to_string(&metric_families)
        .unwrap_or_else(|err| {
            tracing::error!(
                error = ?err,
                "Failed to encode metrics"
            );
            String::from("Failed to encode metrics")
        })
}

#[derive(Clone)]
pub struct EndpointMetrics<'a> {
    method: &'a str,
    path: &'a str,
}

impl<'a> EndpointMetrics<'a> {
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Self { method, path }
    }

    pub fn observe_duration(&self, duration: Duration) {
        HTTP_REQUEST_DURATION
            .with_label_values(&[self.method, self.path])
            .observe(duration.as_secs_f64());
    }

    pub fn increment_requests(&self, status: u16) {
        HTTP_REQUESTS_TOTAL
            .with_label_values(&[self.method, self.path, &status.to_string()])
            .inc();
    }
}
