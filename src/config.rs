use std::{fs, io::Write, path::Path, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// Static configuration instance initialized during runtime setup.
pub static CONFIG: Lazy<Config> =
    Lazy::new(|| Config::setup().expect("Failed to setup configuration"));

const CONFIG_FILEPATH: &str = "./rvault_data/storage.yaml";
const ENV_ROOT_TOKEN: &str = "RVAULT_ROOT_TOKEN";
const ENV_AUTH_SECRET: &str = "RVAULT_AUTH_SECRET";

/// Ensures the existence of a directory, creating it if necessary.
///
/// # Arguments
/// * `path` - The path of the directory to check or create.
fn check_directory_existence(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).context(format!("Failed to create directory {:?}", path,))?;
    }

    Ok(())
}

/// Retrieves and parses an environment variable.
///
/// # Arguments
/// * `key` - The name of the environment variable.
///
/// # Returns
/// The parsed value of the environment variable.
fn get_env_var<T: FromStr>(key: &str) -> Result<T> {
    let value = std::env::var(key).context(format!("Environment vaiable {:?} is required", key))?;

    let result = value
        .parse::<T>()
        .map_err(|_| anyhow::anyhow!("Failed to parse environment variable {}", key))?;
    Ok(result)
}

/// Struct representing YAML configuration data.
#[derive(Serialize, Deserialize)]
struct YamlConfigData {
    storage_dir_path: Option<String>,
    server_port: Option<u16>,
    request_timeout_ms: Option<u64>,
    access_token_exp_seconds: Option<u64>,
    refresh_token_exp_seconds: Option<u64>,
}

impl YamlConfigData {
    /// Returns the default YAML configuration.
    fn default() -> Self {
        Self {
            storage_dir_path: Some("./".to_string()),
            server_port: Some(9200),
            request_timeout_ms: Some(3000),
            access_token_exp_seconds: Some(24 * 3600),
            refresh_token_exp_seconds: Some(7 * 24 * 3600),
        }
    }

    /// Loads configuration from the given path or creates a default configuration if none exists.
    fn load(config_path: &Path) -> Result<Self> {
        let config_dir = config_path.parent().unwrap();

        check_directory_existence(config_dir)?;

        if !config_path.exists() {
            let default_config = Self::default();
            default_config.save(config_path)?;
            return Ok(default_config);
        }

        let config_content = fs::read_to_string(config_path).context(format!(
            "Failed to read configuration file at {:?}",
            config_path
        ))?;
        let config_data = serde_yaml::from_str(&config_content).context(format!(
            "Failed to parse configuration at {:?} to YAML",
            config_path
        ))?;
        Ok(config_data)
    }

    /// Saves the current configuration to the file by the given path.
    fn save(&self, config_path: &Path) -> Result<()> {
        let config_dir = config_path.parent().unwrap();

        check_directory_existence(config_dir)?;

        let yaml_content = serde_yaml::to_string(self).context(format!(
            "Failed to parse configuration {:?} to YAML",
            config_path
        ))?;

        let mut file = fs::File::create(config_path).context(format!(
            "Failed to create configuration file at {:?}",
            config_path
        ))?;
        file.write(yaml_content.as_bytes()).context(format!(
            "Failed to write configuration to file at {:?}",
            config_path
        ))?;

        Ok(())
    }
}

/// Struct representing environment variable configuration data.
struct EnvConfigData {
    root_token: String,
    jwt_secret: String,
}

impl EnvConfigData {
    /// Loads configuration data from environment variables.
    fn load_from_env() -> Result<Self> {
        dotenv::dotenv().context("Failed to load values from .env file")?;

        Ok(Self {
            root_token: get_env_var(ENV_ROOT_TOKEN)?,
            jwt_secret: get_env_var(ENV_AUTH_SECRET)?,
        })
    }
}

/// Main configuration struct combining YAML and environment configurations.
pub struct Config {
    // Variables from yaml config
    pub _storage_dir_path: String,
    pub server_port: u16,
    pub request_timeout: Duration,
    pub access_token_exp: Duration,
    pub refresh_token_exp: Duration,

    // Variables from env config
    pub root_token: String,
    pub jwt_secret: String,
}

impl Config {
    /// Initializes the configuration by loading YAML and environment data.
    pub fn setup() -> Result<Self> {
        let yaml_config_path = Path::new(CONFIG_FILEPATH);

        let yaml_config_data = YamlConfigData::load(yaml_config_path)?;
        let env_config_data = EnvConfigData::load_from_env()?;

        let config = Self::from_configs(yaml_config_data, env_config_data)?;
        Ok(config)
    }

    /// Combines YAML and environment configurations into a `Config` instance.
    fn from_configs(yaml_config: YamlConfigData, env_config: EnvConfigData) -> Result<Self> {
        fn required(variable_name: &str) -> String {
            format!("{} is required configuration parameter", variable_name)
        }

        let config = Self {
            _storage_dir_path: yaml_config
                .storage_dir_path
                .context(required("storage_dir_path"))?,
            server_port: yaml_config.server_port.context(required("server_port"))?,
            request_timeout: Duration::from_millis(
                yaml_config
                    .request_timeout_ms
                    .context(required("request_timeout_ms"))?,
            ),
            access_token_exp: Duration::from_secs(
                yaml_config
                    .access_token_exp_seconds
                    .context(required("access_token_exp_seconds"))?,
            ),
            refresh_token_exp: Duration::from_secs(
                yaml_config
                    .refresh_token_exp_seconds
                    .context(required("refresh_token_exp_seconds"))?,
            ),

            root_token: env_config.root_token,
            jwt_secret: env_config.jwt_secret,
        };

        Ok(config)
    }
}
