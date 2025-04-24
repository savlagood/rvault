use anyhow::{Context, Result};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{self, time::OffsetTime},
    prelude::*,
    Registry,
};

const ENV_LOG_LEVEL: &str = "RVAULT_LOG_LEVEL";

pub fn init() -> Result<()> {
    let timer = OffsetTime::local_rfc_3339().context("Failed to setup tracing timer")?;

    let log_level = std::env::var(ENV_LOG_LEVEL).unwrap_or_else(|_| {
        let level = if cfg!(debug_assertions) {
            String::from("debug")
        } else {
            String::from("info")
        };

        eprintln!("Logging level not specified, defaulting to {}", level);
        level
    });

    let filter_layer = EnvFilter::try_new(log_level).context("Failed to parse log level")?;

    let fmt_layer = fmt::layer()
        .with_timer(timer)
        .with_file(true)
        .with_line_number(true);

    Registry::default()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    tracing::debug!("Logging initialized");

    Ok(())
}
