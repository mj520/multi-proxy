//! Upstream channel management module.

pub mod http;
pub mod socks5;
pub mod ssh;
pub mod health;

use std::sync::Arc;
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::dsn::Dsn;
use crate::config::Config;

// ---------------------------------------------------------------------------
// Unified bidirectional stream type
// ---------------------------------------------------------------------------

/// Object-safe trait alias combining AsyncRead + AsyncWrite for dynamic dispatch.
///
/// `dyn AsyncRead + AsyncWrite` is not a valid trait object (two non-auto traits),
/// so we wrap them in a single marker trait and box that instead.
/// `Sync` is required so bodies boxing the stream satisfy `BoxBody::new`.
pub trait DynStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> DynStream for T {}

/// Boxed, type-erased bidirectional byte stream.
/// All channel types (TCP, TLS, SSH channel) unify into this.
pub type BoxStream = Box<dyn DynStream>;

// ---------------------------------------------------------------------------
// Health tracking
// ---------------------------------------------------------------------------

/// Health status of an upstream channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Channel is healthy and can be used.
    Healthy,
    /// Channel is currently unavailable.
    Unhealthy,
    /// Channel status is unknown (not yet probed).
    Unknown,
}

/// An upstream channel with health tracking.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Unique channel ID (index into the manager's channel list).
    pub id: usize,
    /// Parsed DSN configuration.
    pub dsn: Dsn,
    /// Current health status.
    pub health: Health,
    /// Failure count for backoff.
    pub failure_count: u32,
    /// Last successful probe timestamp.
    pub last_success: Option<std::time::Instant>,
    /// Last failure timestamp (for circuit-breaker backoff).
    pub last_failure: Option<std::time::Instant>,
}

impl Channel {
    pub fn new(id: usize, dsn: Dsn) -> Self {
        Self {
            id,
            dsn,
            health: Health::Unknown,
            failure_count: 0,
            last_success: None,
            last_failure: None,
        }
    }

    /// Mark channel as healthy.
    pub fn mark_healthy(&mut self) {
        self.health = Health::Healthy;
        self.failure_count = 0;
        self.last_success = Some(std::time::Instant::now());
    }

    /// Mark channel as unhealthy and record failure time for backoff.
    pub fn mark_unhealthy(&mut self) {
        self.health = Health::Unhealthy;
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_failure = Some(std::time::Instant::now());
    }

    /// Check if channel is usable now (circuit breaker).
    /// Returns false while within the backoff window after a failure.
    pub fn should_retry(&self) -> bool {
        if self.health != Health::Unhealthy {
            return true;
        }
        // Exponential backoff 3^n up to 5 failures, then fixed 300s so a
        // recovered node is periodically re-probed rather than abandoned.
        let backoff = if self.failure_count > 5 {
            300
        } else {
            3u64.saturating_pow(self.failure_count.min(6)).min(300)
        };
        match self.last_failure {
            Some(last) => last.elapsed().as_secs() >= backoff,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Channel manager
// ---------------------------------------------------------------------------

/// Manager for all upstream channels.
#[derive(Clone)]
pub struct ChannelManager {
    channels: Arc<RwLock<Vec<Channel>>>,
    config: Arc<Config>,
}

impl ChannelManager {
    pub fn new(channels: Vec<Channel>, config: Arc<Config>) -> Self {
        Self {
            channels: Arc::new(RwLock::new(channels)),
            config,
        }
    }

    /// Get a snapshot of all channels.
    pub fn channels(&self) -> Vec<Channel> {
        self.channels.read().clone()
    }

    /// Get currently-healthy, usable channels.
    pub fn healthy_channels(&self) -> Vec<Channel> {
        self.channels
            .read()
            .iter()
            .filter(|c| c.health == Health::Healthy && c.should_retry())
            .cloned()
            .collect()
    }

    /// Mark channel as healthy.
    pub fn mark_healthy(&self, id: usize) {
        if let Some(c) = self.channels.write().get_mut(id) {
            c.mark_healthy();
        }
    }

    /// Mark channel as unhealthy.
    pub fn mark_unhealthy(&self, id: usize) {
        if let Some(c) = self.channels.write().get_mut(id) {
            c.mark_unhealthy();
        }
    }

    /// Whether direct-to-origin is attempted before proxy channels.
    pub fn direct_first(&self) -> bool {
        self.config.direct_first
    }
}
