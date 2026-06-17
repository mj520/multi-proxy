//! Configuration module for multi-proxy.
//!
//! Loads settings from config.toml and CLI arguments.

use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use crate::dsn::Dsn;

/// Load balancing strategy for upstream selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigStrategy {
    /// Order-based fallback: try channels sequentially.
    Order,
    /// Hash-based session affinity: consistent hashing by target URL.
    Hash,
}

impl Default for ConfigStrategy {
    fn default() -> Self {
        Self::Order
    }
}

impl FromStr for ConfigStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "order" => Ok(ConfigStrategy::Order),
            "hash" => Ok(ConfigStrategy::Hash),
            _ => Err(format!("Unknown strategy: {}", s)),
        }
    }
}

/// Application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Listen address for the HTTP proxy server.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Load balancing strategy.
    #[serde(default)]
    pub strategy: ConfigStrategy,

    /// Interval in seconds for upstream health checks.
    #[serde(default = "default_probe_interval")]
    pub probe_interval: u64,

    /// Connection timeout in seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,

    /// List of upstream DSNs.
    pub upstreams: Vec<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_probe_interval() -> u64 {
    600
}

fn default_connect_timeout() -> u64 {
    3
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            strategy: ConfigStrategy::Order,
            probe_interval: default_probe_interval(),
            connect_timeout: default_connect_timeout(),
            upstreams: Vec::new(),
        }
    }
}

/// CLI arguments for runtime overrides.
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to configuration file.
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Override listen address.
    #[arg(short, long)]
    pub listen: Option<String>,

    /// Override strategy.
    #[arg(short)]
    pub strategy: Option<String>,

    /// Additional upstream DSNs (can be used multiple times).
    #[arg(short, long)]
    pub upstream: Vec<String>,
}

impl Config {
    /// Load configuration from file and merge with CLI arguments.
    pub fn load(args: &Args) -> Result<Self, String> {
        let mut config = if args.config.exists() {
            let content = std::fs::read_to_string(&args.config)
                .map_err(|e| format!("Failed to read config: {}", e))?;
            toml::from_str(&content)
                .map_err(|e| format!("Failed to parse config: {}", e))?
        } else {
            Config::default()
        };

        // Apply CLI overrides
        if let Some(listen) = &args.listen {
            config.listen = listen.clone();
        }
        if let Some(strategy) = &args.strategy {
            config.strategy = strategy.parse()?;
        }
        config.upstreams.extend(args.upstream.clone());

        Ok(config)
    }

    /// Parse upstreams into Dsn list.
    pub fn parse_upstreams(&self) -> Result<Vec<Dsn>, String> {
        self.upstreams.iter()
            .map(|s| s.parse())
            .collect()
    }
}

use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert_eq!(config.strategy, ConfigStrategy::Order);
    }

    #[test]
    fn test_strategy_from_str() {
        assert_eq!("order".parse::<ConfigStrategy>().unwrap(), ConfigStrategy::Order);
        assert_eq!("hash".parse::<ConfigStrategy>().unwrap(), ConfigStrategy::Hash);
        assert!("invalid".parse::<ConfigStrategy>().is_err());
    }
}