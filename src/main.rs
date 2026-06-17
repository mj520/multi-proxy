//! multi-proxy - Lightweight multi-channel proxy tool
//!
//! Supports HTTP/SOCKS5/SSH tunnel upstream channels with automatic
//! health checking and fallback strategies.

mod config;
mod dsn;
mod proxy;
mod strategy;
mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;
use clap::Parser;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::{Args, Config};
use crate::strategy::Strategy;
use crate::upstream::{health, ssh, Channel, ChannelManager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Parse CLI arguments
    let args = Args::parse();

    // Load configuration
    let config = Config::load(&args)
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)) })?;

    info!("multi-proxy starting...");
    info!("Strategy: {:?}", config.strategy);
    info!("Upstreams: {}", config.upstreams.len());

    // Parse DSNs into channels
    let dsns = config.parse_upstreams()
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)) })?;
    let channels: Vec<Channel> = dsns
        .into_iter()
        .enumerate()
        .map(|(i, dsn)| Channel::new(i, dsn))
        .collect();

    if channels.is_empty() {
        error!("No upstreams configured!");
        return Ok(());
    }

    let config_arc = Arc::new(config.clone());
    let manager = ChannelManager::new(channels, config_arc);
    let strategy = Strategy::from(config.strategy);

    // Start health checker
    let health_manager = manager.clone();
    let _health_handle = health::start_health_checker(
        health_manager,
        config.probe_interval,
        config.connect_timeout,
    );

    // Start SSH session idle-reaper
    ssh::start_idle_reaper();

    // Parse listen address (host may be IPv4 or IPv6)
    let ip: std::net::IpAddr = config.host.parse()?;
    let listen_addr = SocketAddr::new(ip, config.port);
    info!("Listening on {}", listen_addr);

    // Start proxy server
    proxy::serve(
        listen_addr,
        manager,
        strategy,
        config.connect_timeout,
    ).await
}