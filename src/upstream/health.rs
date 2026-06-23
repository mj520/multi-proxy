//! Health checking for upstream channels.
//!
//! Probes run concurrently (one task per channel) so an N-channel check
//! completes in O(max timeout) rather than O(N × timeout).

use std::time::Duration;
use tokio::time::interval;
use tokio::task::JoinSet;
use tracing::{debug, info};
use crate::dsn::Dsn;
use crate::upstream::ChannelManager;
use super::http as http_proxy;
use super::socks5 as socks5_proxy;
use super::ssh as ssh_tunnel;

/// Start background health checker.
/// First check runs immediately on startup, subsequent checks every `probe_interval`.
pub fn start_health_checker(
    manager: ChannelManager,
    probe_interval_secs: u64,
    connect_timeout_secs: u64,
) -> tokio::task::JoinHandle<()> {
    let timeout = Duration::from_secs(connect_timeout_secs);
    let probe_interval = Duration::from_secs(probe_interval_secs);

    tokio::spawn(async move {
        // Initial health check on startup
        run_check(&manager, timeout).await;

        let mut ticker = interval(probe_interval);
        // Skip the first tick (already done above)
        ticker.tick().await;

        loop {
            ticker.tick().await;
            run_check(&manager, timeout).await;
        }
    })
}

/// Run a single health check pass — probes all channels concurrently.
async fn run_check(manager: &ChannelManager, timeout: Duration) {
    let channels = manager.channels();
    debug!("Running health check for {} channels", channels.len());

    let mut set: JoinSet<(usize, bool)> = JoinSet::new();
    for channel in &channels {
        let dsn = channel.dsn.clone();
        let id = channel.id;
        set.spawn(async move { (id, check_channel(&dsn, timeout).await) });
    }

    let total = channels.len();
    while let Some(res) = set.join_next().await {
        match res {
            Ok((id, healthy)) => {
                if healthy {
                    manager.mark_healthy(id);
                } else {
                    manager.mark_unhealthy(id);
                }
            }
            Err(e) => debug!("Health probe task panicked: {}", e),
        }
    }

    let healthy_count = manager.healthy_channels().len();
    info!("Health check complete: {}/{} channels healthy", healthy_count, total);
}

/// Check health of a single channel (TCP connectivity probe).
async fn check_channel(dsn: &Dsn, timeout: Duration) -> bool {
    match dsn {
        Dsn::Http(http_dsn) => http_proxy::probe(http_dsn, timeout).await,
        Dsn::Socks5(socks5_dsn) => socks5_proxy::probe(socks5_dsn, timeout).await,
        Dsn::Ssh(ssh_dsn) => ssh_tunnel::probe(ssh_dsn, timeout).await,
    }
}