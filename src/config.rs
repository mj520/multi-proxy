//! Configuration module for multi-proxy.
//!
//! Loads settings from config.toml, CLI flags, and environment variables.

use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use crate::dsn::Dsn;

/// Load balancing strategy for upstream selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConfigStrategy {
    /// Order-based fallback: try channels sequentially.
    #[default]
    Order,
    /// Hash-based session affinity: consistent hashing by target URL.
    Hash,
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
    /// Bind host for the HTTP proxy server (IPv4 or IPv6).
    #[serde(default = "default_host")]
    pub host: String,

    /// Bind port for the HTTP proxy server.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Load balancing strategy.
    #[serde(default)]
    pub strategy: ConfigStrategy,

    /// When true, connect directly to the origin first; use proxy channels as
    /// fallback. When false (default), try proxy channels first and fall back to
    /// direct connection only when all channels fail.
    #[serde(default)]
    pub direct_first: bool,

    /// Interval in seconds for upstream health checks.
    #[serde(default = "default_probe_interval")]
    pub probe_interval: u64,

    /// Connection timeout in seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,

    /// List of upstream DSNs.
    pub upstreams: Vec<String>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    12380
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
            host: default_host(),
            port: default_port(),
            strategy: ConfigStrategy::Order,
            direct_first: false,
            probe_interval: default_probe_interval(),
            connect_timeout: default_connect_timeout(),
            upstreams: Vec::new(),
        }
    }
}

/// CLI arguments for runtime overrides.
///
/// `host`/`port` are bound to the `HOST`/`PORT` environment variables; a flag
/// wins over the env var (clap merges both). Priority overall:
/// CLI flag > env var > config file > default.
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to configuration file.
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Override bind host (env: HOST).
    #[arg(long, env = "HOST")]
    pub host: Option<String>,

    /// Override bind port (env: PORT).
    #[arg(short, long, env = "PORT")]
    pub port: Option<String>,

    /// Override strategy.
    #[arg(short)]
    pub strategy: Option<String>,

    /// Connect directly to origin first; use proxy channels as fallback.
    /// Accepts --direct-first (=true) or --direct-first=false (env: DIRECT_FIRST).
    #[arg(long, env = "DIRECT_FIRST", num_args = 0..=1, default_missing_value = "true")]
    pub direct_first: Option<bool>,

    /// Additional upstream DSNs (can be used multiple times).
    #[arg(short, long)]
    pub upstream: Vec<String>,
}

impl Config {
    /// Load configuration from file and merge with CLI/env overrides.
    pub fn load(args: &Args) -> Result<Self, String> {
        let mut config = if args.config.exists() {
            let content = std::fs::read_to_string(&args.config)
                .map_err(|e| format!("Failed to read config: {}", e))?;
            toml::from_str(&content)
                .map_err(|e| format!("Failed to parse config: {}", e))?
        } else {
            Config::default()
        };

        // Apply overrides (clap already merged CLI flag + env var, flag wins).
        if let Some(host) = &args.host {
            config.host = host.clone();
        }
        if let Some(port) = &args.port {
            config.port = port
                .parse()
                .map_err(|e| format!("Invalid PORT '{}': {}", port, e))?;
        }
        if let Some(strategy) = &args.strategy {
            config.strategy = strategy.parse()?;
        }
        if let Some(v) = args.direct_first {
            config.direct_first = v;
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
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 12380);
        assert_eq!(config.strategy, ConfigStrategy::Order);
    }

    #[test]
    fn test_strategy_from_str() {
        assert_eq!("order".parse::<ConfigStrategy>().unwrap(), ConfigStrategy::Order);
        assert_eq!("hash".parse::<ConfigStrategy>().unwrap(), ConfigStrategy::Hash);
        assert!("invalid".parse::<ConfigStrategy>().is_err());
    }
}
