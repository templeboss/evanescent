use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub tor: TorConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct TorConfig {
    pub control_port: u16,
    pub ws_port: u16,
    pub hidden_service_port: u16,
    pub socks_port: u16,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            control_port: 9051,
            ws_port: 8765,
            hidden_service_port: 443,
            socks_port: 9050,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    pub db_path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: "/var/lib/evanescent/provider.db".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "json".into(),
        }
    }
}

pub fn load(path: Option<&str>) -> Result<Config> {
    match path {
        Some(p) => {
            let text = fs::read_to_string(p).with_context(|| format!("read config {p}"))?;
            serde_yaml::from_str(&text).with_context(|| "parse config yaml")
        }
        None => Ok(Config::default()),
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tor: Default::default(),
            storage: Default::default(),
            logging: Default::default(),
        }
    }
}
