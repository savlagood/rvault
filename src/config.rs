use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path, str::FromStr};

const CONFIG_FILEPATH: &str = "./rvault_data/storage.yaml";
const ENV_ROOT_TOKEN: &str = "RVAULT_ROOT_TOKEN";

fn check_directory_existence(dir_path: &Path) -> Result<()> {
    if !dir_path.exists() {
        fs::create_dir_all(dir_path)
            .context(format!("Failed to create directory {:?}", dir_path,))?;
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
    storage_dir_path: Option<String>,
    server_ip: Option<String>,
    server_port: Option<u16>,
}

impl YamlConfigData {
    fn default() -> Self {
        Self {
            storage_dir_path: Some("./".to_string()),
            server_ip: Some("0.0.0.0".to_string()),
            server_port: Some(9200),
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
            "Failed to write configuration to file {:?}",
            config_path
        ))?;

        Ok(())
    }
}

struct EnvConfigData {
    pub root_token: String,
}

impl EnvConfigData {
    fn load_from_env() -> Result<Self> {
        dotenv::dotenv().context("Failed to load values from .env file")?;

        Ok(Self {
            root_token: get_env_var(ENV_ROOT_TOKEN)?,
        })
    }
}

pub struct Config {
    // Variables from yaml config
    pub storage_dir_path: String,
    pub server_ip: String,
    pub server_port: u16,

    // Variables from env config
    pub root_token: String,
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
        let config = Self {
            storage_dir_path: yaml_config
                .storage_dir_path
                .context("storage_dir_path is required config parameter")?,
            server_ip: yaml_config
                .server_ip
                .context("server_ip is required config parameter")?,
            server_port: yaml_config
                .server_port
                .context("server_port is required config parameter")?,

            root_token: env_config.root_token,
        };

        Ok(config)
    }
}
