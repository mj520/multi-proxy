//! HTTP proxy channel implementation.

use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{error, info};
use crate::dsn::HttpDsn;

/// Check HTTP proxy health by connecting and closing.
pub async fn probe(dsn: &HttpDsn, timeout: Duration) -> bool {
    let addr = format!("{}:{}", dsn.host, dsn.port);
    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            info!("HTTP proxy {}:{} is healthy", dsn.host, dsn.port);
            true
        }
        _ => {
            error!("HTTP proxy {}:{} is unhealthy", dsn.host, dsn.port);
            false
        }
    }
}