//! SSH tunnel channel implementation using russh.
//!
//! Connection pooling: SSH session established once, reused across requests.
//! Sessions idle 60s auto-close. Concurrent channel-opens serialize via mutex
//! (russh Handle receiver is single-consumer).

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info};
use russh::*;
use russh_keys::*;
use async_trait::async_trait;

use crate::dsn::SshDsn;
use super::BoxStream;

// ---------------------------------------------------------------------------
// SSH client handler
// ---------------------------------------------------------------------------

/// Simple SSH client handler.
struct SimpleHandler;

#[async_trait]
impl client::Handler for SimpleHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // In production, verify the server key against known hosts here.
        Ok(true)
    }
}

/// Get default SSH key path for current user (Windows compatible).
fn get_default_key_path() -> Option<PathBuf> {
    let key_names = ["id_ed25519", "id_rsa", "id_ecdsa"];

    for dir_var in ["HOME", "USERPROFILE"] {
        if let Ok(dir) = env::var(dir_var) {
            let ssh_dir = PathBuf::from(&dir).join(".ssh");
            for name in &key_names {
                let key_path = ssh_dir.join(name);
                if key_path.exists() {
                    return Some(key_path);
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Connection pool
// ---------------------------------------------------------------------------

/// A reusable SSH session pool entry.
struct SshPoolEntry {
    /// Authenticated SSH session. Guarded by mutex: channel-open calls serialize.
    handle: Arc<Mutex<client::Handle<SimpleHandler>>>,
    /// Time of last request through this session.
    last_used: Instant,
    /// Identifier for logs.
    dsn_key: String,
}

/// Global SSH session pool (one entry per DSN).
/// Lazily initialized on first use, closed after 60s idle.
struct SshPool {
    inner: RwLock<Option<SshPoolEntry>>,
}

impl SshPool {
    /// Get or create a session. Updates last_used on access.
    async fn get_or_connect(
        &self,
        dsn: &SshDsn,
    ) -> Result<Arc<Mutex<client::Handle<SimpleHandler>>>, String> {
        // Fast path: reuse existing live session
        {
            let mut w = self.inner.write().await;
            if let Some(entry) = w.as_ref() {
                let closed = entry
                    .handle
                    .try_lock()
                    .map(|h| h.is_closed())
                    .unwrap_or(false);
                if !closed {
                    let handle = Arc::clone(&entry.handle);
                    debug!("Reusing SSH session for {}", entry.dsn_key);
                    if let Some(e) = w.as_mut() {
                        e.last_used = Instant::now();
                    }
                    return Ok(handle);
                }
                debug!("SSH session {} closed, reconnecting", entry.dsn_key);
                *w = None;
            }
        }

        // Slow path: connect + authenticate
        let dsn_key = format!("{}@{}:{}", dsn.user, dsn.host, dsn.port);
        info!("Opening new SSH session: {}", dsn_key);

        let ssh_addr = format!("{}:{}", dsn.host, dsn.port);
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(60)),
            keepalive_interval: Some(Duration::from_secs(dsn.keepalive)),
            keepalive_max: 3,
            ..Default::default()
        });

        let mut session = client::connect(Arc::clone(&config), &ssh_addr[..], SimpleHandler {})
            .await
            .map_err(|e| format!("SSH connect failed: {}", e))?;

        let authenticated = if let Some(ref pass) = dsn.pass {
            session
                .authenticate_password(dsn.user.as_str(), pass.as_str())
                .await
                .map_err(|e| e.to_string())?
        } else if let Some(ref key_path) = dsn.key_path {
            let key_str =
                fs::read_to_string(key_path).map_err(|e| format!("Failed to read key: {}", e))?;
            let key_pair = decode_secret_key(&key_str, None)
                .map_err(|e| format!("Failed to parse key: {}", e))?;
            session
                .authenticate_publickey(dsn.user.as_str(), Arc::new(key_pair))
                .await
                .map_err(|e| e.to_string())?
        } else if let Some(default_key) = get_default_key_path() {
            info!("Using default SSH key: {:?}", default_key);
            let key_str = fs::read_to_string(&default_key)
                .map_err(|e| format!("Failed to read default key: {}", e))?;
            let key_pair = decode_secret_key(&key_str, None)
                .map_err(|e| format!("Failed to parse key: {}", e))?;
            session
                .authenticate_publickey(dsn.user.as_str(), Arc::new(key_pair))
                .await
                .map_err(|e| e.to_string())?
        } else {
            return Err("SSH auth: need password or key".to_string());
        };

        if !authenticated {
            return Err("SSH authentication failed".to_string());
        }

        info!("SSH session {} established", dsn_key);

        let handle = Arc::new(Mutex::new(session));

        let mut w = self.inner.write().await;
        *w = Some(SshPoolEntry {
            handle: Arc::clone(&handle),
            last_used: Instant::now(),
            dsn_key,
        });

        Ok(handle)
    }

    /// Close the session if idle beyond timeout.
    async fn check_idle(&self, idle_timeout: Duration) {
        let mut w = self.inner.write().await;
        if let Some(ref entry) = *w {
            let closed = entry.handle.try_lock().map(|h| h.is_closed()).unwrap_or(false);
            if closed || entry.last_used.elapsed() > idle_timeout {
                debug!(
                    "Closing idle SSH session {} (idle {:.0}s)",
                    entry.dsn_key,
                    entry.last_used.elapsed().as_secs_f64()
                );
                *w = None;
            }
        }
    }
}

/// Static pool — initialized once per process.
static SSH_POOL: LazyLock<SshPool> = LazyLock::new(|| SshPool {
    inner: RwLock::new(None),
});

/// Idle timeout for pooled SSH sessions.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Establish a bidirectional stream to `target_host:target_port` through
/// an SSH direct-tcpip channel. The returned stream is a raw TCP tunnel;
/// callers wrap TLS themselves when forwarding HTTPS.
pub async fn establish(
    dsn: &SshDsn,
    target_host: &str,
    target_port: u16,
    _timeout_dur: Duration,
) -> Result<BoxStream, String> {
    // Get (or create) pooled SSH session
    let handle = SSH_POOL.get_or_connect(dsn).await?;

    debug!(
        "SSH tunnel to {}:{} via {}@{}",
        target_host, target_port, dsn.user, dsn.host
    );

    // Lock during channel-open (serializes), release before forwarding
    let channel = {
        let h = handle.lock().await;
        h.channel_open_direct_tcpip(target_host, target_port as u32, &dsn.host, dsn.port as u32)
            .await
            .map_err(|e| format!("SSH channel open failed: {}", e))?
    };

    // Convert russh channel into a tokio AsyncRead + AsyncWrite stream
    let stream = channel.into_stream();
    Ok(Box::new(stream))
}

/// Check SSH server health (TCP reachability of the SSH port).
pub async fn probe(dsn: &SshDsn, timeout_dur: Duration) -> bool {
    let addr = format!("{}:{}", dsn.host, dsn.port);
    match timeout(timeout_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            info!("SSH server {}:{} is reachable", dsn.host, dsn.port);
            true
        }
        _ => {
            error!("SSH server {}:{} is unreachable", dsn.host, dsn.port);
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Idle reaper
// ---------------------------------------------------------------------------

/// Start the background idle-reaper task. Call once from main at startup.
/// Returns the task handle so the caller can stop it during shutdown.
pub fn start_idle_reaper() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            SSH_POOL.check_idle(SESSION_IDLE_TIMEOUT).await;
        }
    })
}
