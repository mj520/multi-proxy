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

/// Simple SSH client handler.
struct SimpleHandler;

#[async_trait]
impl client::Handler for SimpleHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Get default SSH key path for current user (Windows compatible).
fn get_default_key_path() -> Option<PathBuf> {
    let key_names = ["id_ed25519", "id_rsa", "id_ecdsa"];

    if let Ok(home) = env::var("HOME") {
        let ssh_dir = PathBuf::from(&home).join(".ssh");
        for name in &key_names {
            let key_path = ssh_dir.join(name);
            if key_path.exists() {
                return Some(key_path);
            }
        }
    }

    if let Ok(userprofile) = env::var("USERPROFILE") {
        let ssh_dir = PathBuf::from(&userprofile).join(".ssh");
        for name in &key_names {
            let key_path = ssh_dir.join(name);
            if key_path.exists() {
                return Some(key_path);
            }
        }
    }

    None
}

/// A reusable SSH session pool entry.
struct SshPoolEntry {
    /// Authenticated SSH session. Guarded by mutex: channel-open calls serialize.
    handle: Arc<Mutex<client::Handle<SimpleHandler>>>,
    /// Time of last request through this session.
    last_used: Instant,
    /// Identifier for logs.
    dsn_key: String,
}

/// Global SSH session pool (one entry for the SSH DSN).
/// Lazily initialized on first use, closed after 60s idle.
struct SshPool {
    inner: RwLock<Option<SshPoolEntry>>,
}

impl SshPool {
    /// Get or create a session. Updates last_used on access.
    /// Returns the Arc<Mutex<Handle>> for the caller to lock during channel open.
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

/// Start the background idle-reaper task. Call once from main at startup.
pub fn start_idle_reaper() {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            SSH_POOL.check_idle(SESSION_IDLE_TIMEOUT).await;
        }
    });
}

/// Forward request through SSH tunnel and return raw response.
/// Handles HTTP (direct) and HTTPS (TLS over direct-tcpip channel).
/// Reuses the pooled SSH session.
pub async fn forward_raw(
    dsn: &SshDsn,
    target: &str,
    request_data: &[u8],
    _timeout_dur: Duration,
) -> Result<Vec<u8>, String> {
    // Parse target
    let target_clean = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);

    let is_https = target.starts_with("https://");

    let parts: Vec<&str> = target_clean.split(':').collect();
    let (target_domain, target_port) = if parts.len() >= 2 {
        let port_str = parts[1].split('/').next().unwrap_or(parts[1]);
        (
            parts[0].to_string(),
            port_str
                .parse::<u16>()
                .unwrap_or(if is_https { 443 } else { 80 }),
        )
    } else {
        (
            target_clean.split('/').next().unwrap_or(target_clean).to_string(),
            if is_https { 443 } else { 80 },
        )
    };

    // Get (or create) pooled SSH session
    let handle = SSH_POOL.get_or_connect(dsn).await?;

    debug!(
        "SSH tunnel to {}:{} via {}@{}",
        target_domain, target_port, dsn.user, dsn.host
    );

    // Lock during channel-open (serializes), release before forward
    let channel = {
        let h = handle.lock().await;
        h.channel_open_direct_tcpip(
            target_domain.as_str(),
            target_port as u32,
            &dsn.host,
            dsn.port as u32,
        )
        .await
        .map_err(|e| format!("SSH channel open failed: {}", e))?
    };

    if is_https {
        return ssh_tls_forward(channel, &target_domain, request_data).await;
    }

    ssh_http_forward(channel, request_data).await
}

/// Forward HTTP (plaintext) over an SSH channel.
async fn ssh_http_forward(
    mut channel: Channel<client::Msg>,
    request_data: &[u8],
) -> Result<Vec<u8>, String> {
    channel.data(request_data).await.map_err(|e| e.to_string())?;

    let mut response_buf = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { ref data }) => {
                response_buf.extend_from_slice(data);
            }
            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
            _ => {}
        }
    }

    if response_buf.is_empty() {
        return Err("Empty response from SSH tunnel".to_string());
    }

    Ok(response_buf)
}

/// Forward HTTPS over an SSH channel: convert channel to a stream, TLS handshake,
/// then send request and read the full response.
async fn ssh_tls_forward(
    channel: Channel<client::Msg>,
    host: &str,
    request_data: &[u8],
) -> Result<Vec<u8>, String> {
    use native_tls::TlsConnector;
    use tokio_native_tls::TlsConnector as TokioTlsConnector;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream = channel.into_stream();

    let tls_connector =
        TlsConnector::new().map_err(|e| format!("TLS connector error: {}", e))?;
    let tls_connector = TokioTlsConnector::from(tls_connector);
    let mut tls = tls_connector
        .connect(host, stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    tls.write_all(request_data).await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut response_buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, tls.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => response_buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                if response_buf.is_empty() {
                    return Err(format!("TLS read error: {}", e));
                }
                break;
            }
            Err(_) => break,
        }
    }

    if response_buf.is_empty() {
        return Err("Empty HTTPS response from SSH tunnel".to_string());
    }

    Ok(response_buf)
}

/// Check SSH server health.
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