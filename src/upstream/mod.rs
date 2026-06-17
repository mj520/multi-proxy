//! Upstream channel management module.

pub mod http;
pub mod socks5;
pub mod ssh;
pub mod health;

use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use crate::dsn::Dsn;
use crate::config::Config;

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
    /// Unique channel ID.
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
        // Backoff: exponential 3^n until 5 failures, then fixed max (300s)
        // periodic recovery probe so a recovered node is never abandoned.
        let backoff = if self.failure_count > 5 {
            300 // max interval: keep probing every 5 min for recovery
        } else {
            3u64.saturating_pow(self.failure_count.min(6)).min(300)
        };
        match self.last_failure {
            Some(last) => last.elapsed().as_secs() >= backoff,
            None => true,
        }
    }
}

/// Manager for all upstream channels.
#[derive(Clone)]
pub struct ChannelManager {
    channels: Arc<RwLock<Vec<Channel>>>,
    #[allow(dead_code)]
    config: Arc<Config>,
    _shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ChannelManager {
    pub fn new(channels: Vec<Channel>, config: Arc<Config>) -> Self {
        Self {
            channels: Arc::new(RwLock::new(channels)),
            config,
            _shutdown_tx: None,
        }
    }

    /// Get number of channels.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.channels.read().len()
    }

    /// Check if empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.channels.read().is_empty()
    }

    /// Get all channels.
    pub fn channels(&self) -> Vec<Channel> {
        self.channels.read().clone()
    }

    /// Get healthy channels.
    pub fn healthy_channels(&self) -> Vec<(usize, Channel)> {
        let guard = self.channels.read();
        guard.iter()
            .enumerate()
            .filter(|(_, c)| c.health == Health::Healthy && c.should_retry())
            .map(|(i, c)| (i, c.clone()))
            .collect()
    }

    /// Mark channel as healthy.
    pub fn mark_healthy(&self, id: usize) {
        let mut channels = self.channels.write();
        if let Some(c) = channels.get_mut(id) {
            c.mark_healthy();
        }
    }

    /// Mark channel as unhealthy.
    pub fn mark_unhealthy(&self, id: usize) {
        let mut channels = self.channels.write();
        if let Some(c) = channels.get_mut(id) {
            c.mark_unhealthy();
        }
    }

    /// Get DSN by index.
    #[allow(dead_code)]
    pub fn get_dsn(&self, id: usize) -> Option<Dsn> {
        self.channels.read().get(id).map(|c| c.dsn.clone())
    }
}