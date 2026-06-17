//! SOCKS5 proxy channel implementation.

use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{error, info};
use crate::dsn::Socks5Dsn;

/// Check SOCKS5 proxy health.
pub async fn probe(dsn: &Socks5Dsn, timeout_duration: Duration) -> bool {
    let addr = format!("{}:{}", dsn.host, dsn.port);
    match timeout(timeout_duration, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            info!("SOCKS5 proxy {}:{} is healthy", dsn.host, dsn.port);
            true
        }
        _ => {
            error!("SOCKS5 proxy {}:{} is unhealthy", dsn.host, dsn.port);
            false
        }
    }
}