use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path, str::FromStr, time::Duration};

const CONFIG_FILEPATH: &str = "./rvault_data/storage.yaml";
const ENV_ROOT_TOKEN: &str = "RVAULT_ROOT_TOKEN";
const ENV_AUTH_SECRET: &str = "RVAULT_AUTH_SECRET";
const ENV_DB_CONNECTION_STRING: &str = "RVAULT_DB_CONNECTION_STRING";

fn check_directory_existence(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).context(format!("Failed to create directory {:?}", path,))?;
    }

    Ok(())
}

fn get_env_var<T: FromStr>(key: &str) -> Result<T> {
    let value = std::env::var(key).context(format!("Environment vaiable {:?} is required", key))?;

    let result = value
        .parse::<T>()
        .map_err(|_| anyhow::anyhow!("Failed to parse environment variable {}", key))?;
    Ok(result)
}

#[derive(Serialize, Deserialize)]
struct YamlConfigData {
    server_port: Option<u16>,
    request_timeout_ms: Option<u64>,
    access_token_ttl_seconds: Option<u64>,
    refresh_token_ttl_seconds: Option<u64>,
}

impl YamlConfigData {
    fn default() -> Self {
        Self {
            server_port: Some(9200),
            request_timeout_ms: Some(3000),
            access_token_ttl_seconds: Some(24 * 3600),
            refresh_token_ttl_seconds: Some(7 * 24 * 3600),
        }
    }

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

struct EnvConfigData {
    root_token: String,
    jwt_secret: String,
    db_connection_string: String,
}

impl EnvConfigData {
    fn load_from_env() -> Result<Self> {
        Ok(Self {
            root_token: get_env_var(ENV_ROOT_TOKEN)?,
            jwt_secret: get_env_var(ENV_AUTH_SECRET)?,
            db_connection_string: get_env_var(ENV_DB_CONNECTION_STRING)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server_port: u16,
    pub request_timeout: Duration,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,

    pub root_token: String,
    pub jwt_secret: String,
    pub db_connection_string: String,
}

impl Config {
    pub fn setup() -> Result<Self> {
        let yaml_config_path = Path::new(CONFIG_FILEPATH);

        let yaml_config_data = YamlConfigData::load(yaml_config_path)?;
        let env_config_data = EnvConfigData::load_from_env()?;

        let config = Self::from_configs(yaml_config_data, env_config_data)?;
        Ok(config)
    }

    fn from_configs(yaml_config: YamlConfigData, env_config: EnvConfigData) -> Result<Self> {
        fn required(variable_name: &str) -> String {
            format!("{} is required configuration parameter", variable_name)
        }

        let config = Self {
            server_port: yaml_config.server_port.context(required("server_port"))?,
            request_timeout: Duration::from_millis(
                yaml_config
                    .request_timeout_ms
                    .context(required("request_timeout_ms"))?,
            ),
            access_token_ttl: Duration::from_secs(
                yaml_config
                    .access_token_ttl_seconds
                    .context(required("access_token_ttl_seconds"))?,
            ),
            refresh_token_ttl: Duration::from_secs(
                yaml_config
                    .refresh_token_ttl_seconds
                    .context(required("refresh_token_ttl_seconds"))?,
            ),

            root_token: env_config.root_token,
            jwt_secret: env_config.jwt_secret,
            db_connection_string: env_config.db_connection_string,
        };

        Ok(config)
    }
}
