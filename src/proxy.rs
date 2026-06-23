//! HTTP proxy server — CONNECT tunnel + streaming path-style forwarding.
//!
//! Supports two request styles:
//!   • Standard CONNECT tunnel:  "CONNECT ipinfo.io:443 HTTP/1.1"
//!   • HTTP-path style (legacy): "GET /https://ipinfo.io/ip HTTP/1.1"
//!
//! Both modes stream data end-to-end with no full-body buffering, so large
//! responses and SSE streams do not risk OOM.

use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::dsn::Dsn;
use crate::strategy::Strategy;
use crate::upstream::{BoxStream, ChannelManager};
use crate::upstream::ssh as ssh_tunnel;

/// Unified response body type. All responses box into this so CONNECT,
/// path-forward, error, and health responses share one service signature.
type RespBody = BoxBody<Bytes, io::Error>;

/// Wrap a fixed byte buffer as a response body.
fn full_body(bytes: Bytes) -> RespBody {
    BoxBody::new(Full::new(bytes).map_err(|e: std::convert::Infallible| match e {}))
}

// ---------------------------------------------------------------------------
// Streaming body: wraps an upstream byte stream as a hyper Body
// ---------------------------------------------------------------------------

/// A hyper `Body` backed by an upstream byte stream.
///
/// Emits any leading bytes (response body already read while parsing headers)
/// first, then continuously polls the upstream reader until EOF. No size hint
/// is provided, so hyper frames the body itself (chunked over HTTP/1.1).
struct ReaderBody {
    reader: BoxStream,
    leading: Option<Bytes>,
    buf: Box<[u8]>,
}

impl ReaderBody {
    fn new(leading: Bytes, reader: BoxStream) -> Self {
        Self {
            reader,
            leading: if leading.is_empty() { None } else { Some(leading) },
            buf: vec![0u8; 16384].into_boxed_slice(),
        }
    }
}

impl Body for ReaderBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        // Flush any leading bytes first
        if let Some(b) = this.leading.take() {
            return Poll::Ready(Some(Ok(Frame::data(b))));
        }
        // Then poll the upstream reader
        let mut rb = ReadBuf::new(this.buf.as_mut());
        match AsyncRead::poll_read(Pin::new(&mut *this.reader), cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(&rb.filled()[..n])))))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Parse "host:port" from the CONNECT authority string (supports IPv6).
fn parse_authority(authority: &str) -> Result<(String, u16), String> {
    if authority.starts_with('[') {
        let close = authority.find(']').ok_or("Unclosed IPv6 bracket")?;
        let host = authority[1..close].to_string();
        let rest = &authority[close + 1..];
        if rest.is_empty() {
            return Err("Missing port after IPv6 address".to_string());
        }
        let port: u16 = rest
            .trim_start_matches(':')
            .parse()
            .map_err(|_| "Invalid port".to_string())?;
        Ok((host, port))
    } else {
        let colon = authority.rfind(':').ok_or("Missing port in authority")?;
        let host = authority[..colon].to_string();
        let port: u16 = authority[colon + 1..]
            .parse()
            .map_err(|_| "Invalid port".to_string())?;
        if host.is_empty() {
            return Err("Empty host".to_string());
        }
        Ok((host, port))
    }
}

/// Parse target from legacy path style `/https://host[:port]` or `/http://host[:port]`.
fn parse_path_target(path: &str) -> Result<(String, bool), String> {
    if !path.starts_with("/http://") && !path.starts_with("/https://") {
        return Err(
            "Invalid path format. Expected /https://target.com or CONNECT host:port HTTP/1.1"
                .to_string(),
        );
    }
    Ok((path.trim_start_matches('/').to_string(), path.starts_with("/https://")))
}

// ---------------------------------------------------------------------------
// Channel establishment
// ---------------------------------------------------------------------------

/// Connect via an HTTP proxy using CONNECT (with optional Basic auth).
async fn establish_http(
    host: &str,
    port: u16,
    http_dsn: &crate::dsn::HttpDsn,
    timeout_dur: Duration,
) -> Result<BoxStream, String> {
    let proxy_addr = format!("{}:{}", http_dsn.host, http_dsn.port);
    let mut upstream = timeout(timeout_dur, TcpStream::connect(&proxy_addr))
        .await
        .map_err(|_| "HTTP proxy connection timeout")?
        .map_err(|e| e.to_string())?;

    let target_addr = format!("{}:{}", host, port);
    let mut connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}:{}\r\n", target_addr, host, port);

    if let (Some(user), Some(pass)) = (&http_dsn.user, &http_dsn.pass) {
        use base64::Engine;
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
        connect_req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", creds));
    }
    connect_req.push_str("\r\n");

    upstream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    // Read CONNECT response status line
    let mut line_buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = upstream.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        line_buf.extend_from_slice(&tmp[..n]);
        if line_buf.windows(2).any(|w| w == b"\r\n") || line_buf.len() > 1024 {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&line_buf);
    let first_line = response_str.lines().next().unwrap_or("Connection failed").trim();
    let ok = first_line.split_whitespace().nth(1).map(|c| c == "200").unwrap_or(false);
    if !ok {
        return Err(format!("CONNECT failed: {}", first_line));
    }

    debug!("HTTP tunnel established to {} via {}", target_addr, proxy_addr);
    Ok(Box::new(upstream))
}

/// Connect via a SOCKS5 proxy (with optional username/password auth).
async fn establish_socks5(
    host: &str,
    port: u16,
    socks5_dsn: &crate::dsn::Socks5Dsn,
    timeout_dur: Duration,
) -> Result<BoxStream, String> {
    let proxy_addr = format!("{}:{}", socks5_dsn.host, socks5_dsn.port);
    let mut upstream = timeout(timeout_dur, TcpStream::connect(&proxy_addr))
        .await
        .map_err(|_| "SOCKS5 connection timeout")?
        .map_err(|e| e.to_string())?;

    // Step 1: handshake with supported auth methods
    let methods = if socks5_dsn.user.is_some() && socks5_dsn.pass.is_some() {
        vec![0x02u8, 0x00]
    } else {
        vec![0x00u8]
    };
    upstream
        .write_all(&[0x05, methods.len() as u8])
        .await
        .map_err(|e| e.to_string())?;
    upstream.write_all(&methods).await.map_err(|e| e.to_string())?;

    let mut reply = [0u8; 2];
    upstream.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
    if reply[0] != 0x05 {
        return Err("SOCKS5 version mismatch".to_string());
    }

    // Step 2: authentication (RFC 1929)
    match reply[1] {
        0x00 => {}
        0x02 => {
            let user = socks5_dsn.user.as_ref().unwrap();
            let pass = socks5_dsn.pass.as_ref().unwrap();
            let mut buf = vec![0x01];
            buf.push(user.len() as u8);
            buf.extend_from_slice(user.as_bytes());
            buf.push(pass.len() as u8);
            buf.extend_from_slice(pass.as_bytes());
            upstream.write_all(&buf).await.map_err(|e| e.to_string())?;
            let mut auth_reply = [0u8; 2];
            upstream.read_exact(&mut auth_reply).await.map_err(|e| e.to_string())?;
            if auth_reply[1] != 0x00 {
                return Err(format!("SOCKS5 auth failed: status={}", auth_reply[1]));
            }
        }
        0xFF => return Err("SOCKS5: no acceptable auth method".to_string()),
        other => return Err(format!("SOCKS5: unexpected auth method reply: {}", other)),
    }

    // Step 3: connect command
    let mut request = vec![0x05, 0x01, 0x00, 0x03];
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    upstream.write_all(&request).await.map_err(|e| e.to_string())?;

    let mut reply = vec![0u8; 10];
    upstream.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
    if reply[1] != 0x00 {
        let reasons = [
            "succeeded", "general failure", "connection not allowed",
            "network unreachable", "host unreachable", "connection refused",
            "TTL expired", "command not supported", "address type not supported",
        ];
        let reason = if (reply[1] as usize) < reasons.len() {
            reasons[reply[1] as usize].to_string()
        } else {
            format!("code={}", reply[1])
        };
        return Err(format!("SOCKS5 connect failed: {}", reason));
    }

    debug!(
        "SOCKS5 tunnel established to {}:{} via {}:{}",
        host, port, socks5_dsn.host, socks5_dsn.port
    );
    Ok(Box::new(upstream))
}

/// Connect via SSH direct-tcpip channel.
async fn establish_ssh(
    host: &str,
    port: u16,
    ssh_dsn: &crate::dsn::SshDsn,
    timeout_dur: Duration,
) -> Result<BoxStream, String> {
    ssh_tunnel::establish(ssh_dsn, host, port, timeout_dur).await
}

/// Connect directly to the origin server (fallback).
async fn establish_direct(host: &str, port: u16, timeout_dur: Duration) -> Result<BoxStream, String> {
    let addr = format!("{}:{}", host, port);
    let stream = timeout(timeout_dur, TcpStream::connect(&addr))
        .await
        .map_err(|_| "Direct connection timeout")?
        .map_err(|e| format!("Direct connect failed: {}", e))?;
    Ok(Box::new(stream))
}

async fn establish_via_dsn(
    dsn: &Dsn,
    host: &str,
    port: u16,
    timeout_dur: Duration,
) -> Result<BoxStream, String> {
    match dsn {
        Dsn::Http(http_dsn) => establish_http(host, port, http_dsn, timeout_dur).await,
        Dsn::Socks5(socks5_dsn) => establish_socks5(host, port, socks5_dsn, timeout_dur).await,
        Dsn::Ssh(ssh_dsn) => establish_ssh(host, port, ssh_dsn, timeout_dur).await,
    }
}

/// Channels rotated so the strategy's start index comes first (for fallback).
fn ordered_channels(
    manager: &ChannelManager,
    strategy: Strategy,
    target_key: &str,
) -> Vec<crate::upstream::Channel> {
    let mut all = manager.channels();
    if all.is_empty() {
        return all;
    }
    let start = strategy.start_index(all.len(), target_key);
    all.rotate_left(start);
    all
}

// ---------------------------------------------------------------------------
// CONNECT tunnel
// ---------------------------------------------------------------------------

async fn acquire_tunnel(
    manager: &ChannelManager,
    strategy: Strategy,
    host: &str,
    port: u16,
    timeout_dur: Duration,
) -> Result<BoxStream, String> {
    let target_key = format!("{}:{}", host, port);

    if manager.direct_first() {
        if let Ok(s) = establish_direct(host, port, timeout_dur).await {
            return Ok(s);
        }
    }

    let mut last_err = String::new();
    for ch in &ordered_channels(manager, strategy, &target_key) {
        if !ch.should_retry() {
            continue;
        }
        match establish_via_dsn(&ch.dsn, host, port, timeout_dur).await {
            Ok(s) => {
                manager.mark_healthy(ch.id);
                return Ok(s);
            }
            Err(e) => {
                warn!("Channel {} ({:?}) failed: {}", ch.id, ch.dsn, e);
                last_err = e;
                manager.mark_unhealthy(ch.id);
            }
        }
    }

    if !manager.direct_first() {
        if let Ok(s) = establish_direct(host, port, timeout_dur).await {
            return Ok(s);
        }
    }

    Err(if last_err.is_empty() {
        "no usable upstream".to_string()
    } else {
        last_err
    })
}

/// Handle CONNECT: establish upstream, spawn bidirectional copy, return 200.
async fn handle_connect(
    req: Request<Incoming>,
    manager: ChannelManager,
    strategy: Strategy,
    timeout_dur: Duration,
    host: String,
    port: u16,
) -> Result<Response<RespBody>, Box<dyn std::error::Error + Send + Sync>> {
    debug!("CONNECT tunnel request: {}:{}", host, port);

    let upstream = match acquire_tunnel(&manager, strategy, &host, port, timeout_dur).await {
        Ok(s) => s,
        Err(e) => {
            error!("CONNECT {}:{} no upstream: {}", host, port, e);
            return Ok(error_response(StatusCode::BAD_GATEWAY, "No usable upstream for CONNECT"));
        }
    };

    // hyper::upgrade::on only resolves AFTER the response is sent, so the
    // copy must run in a spawned task — otherwise we'd deadlock the handler.
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                debug!("CONNECT {}:{} upgrade error: {}", host, port, e);
                return;
            }
        };
        let mut client_io = TokioIo::new(upgraded);
        let mut up = upstream;
        match tokio::io::copy_bidirectional(&mut client_io, &mut up).await {
            Ok((a, b)) => debug!("CONNECT {}:{} closed: {}B up, {}B down", host, port, a, b),
            Err(e) => debug!("CONNECT {}:{} copy error: {}", host, port, e),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(full_body(Bytes::new()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Path-style forward (streaming)
// ---------------------------------------------------------------------------

/// Handle legacy path-style request: "GET /https://target/path".
async fn handle_path_forward(
    req: Request<Incoming>,
    manager: ChannelManager,
    strategy: Strategy,
    timeout_dur: Duration,
) -> Result<Response<RespBody>, Box<dyn std::error::Error + Send + Sync>> {
    let path = req.uri().path();
    let (target, is_https) = match parse_path_target(path) {
        Ok(t) => t,
        Err(e) => {
            warn!("Invalid path: {} - {}", path, e);
            return Ok(error_response(StatusCode::BAD_REQUEST, &e));
        }
    };

    let target_url = if !target.starts_with("http://") && !target.starts_with("https://") {
        format!("http://{}", target)
    } else {
        target
    };
    let parsed = url::Url::parse(&target_url)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(io::Error::new(io::ErrorKind::InvalidInput, e))
        })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Missing host"))
        })?
        .to_string();
    let port = parsed.port().unwrap_or(if is_https { 443 } else { 80 });
    let path_only = parsed.path();
    let request_path = match parsed.query() {
        Some(q) => format!("{}?{}", path_only, q),
        None => path_only.to_string(),
    };

    debug!("Forwarding to {}:{} (path={})", host, port, request_path);

    // Build request bytes
    let mut request_bytes = Vec::new();
    request_bytes.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method(), request_path).as_bytes());
    for (name, value) in req.headers() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host") {
            request_bytes.extend_from_slice(b"Host: ");
            if port == 443 {
                request_bytes.extend_from_slice(host.as_bytes());
            } else {
                request_bytes.extend_from_slice(format!("{}:{}", host, port).as_bytes());
            }
            request_bytes.extend_from_slice(b"\r\n");
        } else if n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("keep-alive")
            || n.eq_ignore_ascii_case("proxy-connection")
        {
            // force close
        } else {
            request_bytes.extend_from_slice(n.as_bytes());
            request_bytes.extend_from_slice(b": ");
            request_bytes.extend_from_slice(value.as_bytes());
            request_bytes.extend_from_slice(b"\r\n");
        }
    }
    request_bytes.extend_from_slice(b"Connection: close\r\n\r\n");

    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(io::Error::other(format!("Failed to read body: {}", e)))
        })?
        .to_bytes();
    request_bytes.extend_from_slice(&body_bytes);

    let target_key = format!("{}:{}", host, port);
    let mut last_err = String::new();

    // direct_first: try direct first
    if manager.direct_first() {
        if let Ok(upstream) = establish_direct(&host, port, timeout_dur).await {
            match forward_through(upstream, &host, is_https, &request_bytes, timeout_dur).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
    }

    for ch in &ordered_channels(&manager, strategy, &target_key) {
        if !ch.should_retry() {
            continue;
        }
        match establish_via_dsn(&ch.dsn, &host, port, timeout_dur).await {
            Ok(upstream) => match forward_through(upstream, &host, is_https, &request_bytes, timeout_dur).await {
                Ok(resp) => {
                    manager.mark_healthy(ch.id);
                    return Ok(resp);
                }
                Err(e) => {
                    warn!("Channel {} forward failed: {}", ch.id, e);
                    last_err = e;
                    manager.mark_unhealthy(ch.id);
                }
            },
            Err(e) => {
                warn!("Channel {} ({:?}) failed: {}", ch.id, ch.dsn, e);
                last_err = e;
                manager.mark_unhealthy(ch.id);
            }
        }
    }

    // proxy-first: direct as last resort
    if !manager.direct_first() {
        if let Ok(upstream) = establish_direct(&host, port, timeout_dur).await {
            match forward_through(upstream, &host, is_https, &request_bytes, timeout_dur).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
    }

    error!("All channels failed for {}:{}: {}", host, port, last_err);
    Ok(error_response(
        StatusCode::BAD_GATEWAY,
        &format!("All channels failed: {}", last_err),
    ))
}

/// Wrap a stream in TLS (for `/https://` targets where the proxy must perform
/// the TLS handshake itself, unlike CONNECT where the client does it).
async fn make_tls(host: &str, stream: BoxStream) -> Result<BoxStream, String> {
    use native_tls::TlsConnector;
    use tokio_native_tls::TlsConnector as TokioTlsConnector;
    let connector = TlsConnector::new().map_err(|e| format!("TLS connector: {}", e))?;
    let connector = TokioTlsConnector::from(connector);
    let tls = connector
        .connect(host, stream)
        .await
        .map_err(|e| format!("TLS handshake: {}", e))?;
    Ok(Box::new(tls))
}

/// Send request bytes, then read the upstream response headers and return a
/// streaming response (body is relayed chunk-by-chunk, never fully buffered).
async fn forward_through(
    upstream: BoxStream,
    host: &str,
    is_https: bool,
    request_bytes: &[u8],
    timeout_dur: Duration,
) -> Result<Response<RespBody>, String> {
    let mut stream = if is_https {
        make_tls(host, upstream).await?
    } else {
        upstream
    };
    stream
        .write_all(request_bytes)
        .await
        .map_err(|e| format!("write request: {}", e))?;
    stream.flush().await.map_err(|e| format!("flush request: {}", e))?;
    read_streaming_response(stream, timeout_dur).await
}

/// Read response headers within a deadline, then hand the (still-open) upstream
/// stream to a `ReaderBody` so the body is streamed to the client.
///
/// Upstream framing (Content-Length / Transfer-Encoding) is preserved as-is so
/// the client decodes the body correctly; we only strip hop-by-hop headers.
async fn read_streaming_response(
    mut upstream: BoxStream,
    timeout_dur: Duration,
) -> Result<Response<RespBody>, String> {
    let deadline = tokio::time::Instant::now() + timeout_dur.mul_f32(10.0).max(Duration::from_secs(30));

    // Phase 1: read until end of headers (\r\n\r\n)
    let mut header_buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, upstream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                header_buf.extend_from_slice(&chunk[..n]);
                if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if header_buf.len() > 65536 {
                    return Err("response headers too large".to_string());
                }
            }
            Ok(Err(e)) => return Err(format!("read headers: {}", e)),
            Err(_) => return Err("response header timeout".to_string()),
        }
    }

    let sep_idx = header_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(header_buf.len());
    let headers = &header_buf[..sep_idx];
    let leading = Bytes::copy_from_slice(&header_buf[sep_idx + 4..]);

    // Parse status line + headers
    let headers_str = String::from_utf8_lossy(headers);
    let mut lines = headers_str.lines();
    let status_code = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(200);
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);

    let mut builder = Response::builder().status(status);
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(col) = line.find(':') {
            let name = line[..col].trim();
            let value = line[col + 1..].trim();
            // Strip hop-by-hop / self-managed headers; keep framing headers
            // (content-length, transfer-encoding) so the client decodes correctly.
            if name.eq_ignore_ascii_case("connection") {
                continue;
            }
            builder = builder.header(name, value);
        }
    }

    let body = ReaderBody::new(leading, upstream);
    Ok(builder.body(BoxBody::new(body)).unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn error_response(status: StatusCode, message: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(full_body(Bytes::from(message.to_string())))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Dispatch + server
// ---------------------------------------------------------------------------

async fn handle_request(
    req: Request<Incoming>,
    manager: ChannelManager,
    strategy: Strategy,
    timeout_dur: Duration,
) -> Result<Response<RespBody>, Box<dyn std::error::Error + Send + Sync>> {
    // Liveness probe
    if req.uri().path() == "/health" {
        let healthy = manager.healthy_channels().len();
        let total = manager.channels().len();
        let body = format!(
            r#"{{"status":"ok","healthy":{},"total":{}}}"#,
            healthy, total
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(full_body(Bytes::from(body)))
            .unwrap());
    }

    let method = req.method().as_str();
    let authority = req.uri().authority().map(|a| a.as_str()).unwrap_or("");

    if method == "CONNECT" && !authority.is_empty() {
        let (host, port) = parse_authority(authority)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(io::Error::new(io::ErrorKind::InvalidInput, e))
            })?;
        handle_connect(req, manager, strategy, timeout_dur, host, port).await
    } else {
        handle_path_forward(req, manager, strategy, timeout_dur).await
    }
}

/// Start the proxy server.
pub async fn serve(
    listen_addr: SocketAddr,
    manager: ChannelManager,
    strategy: Strategy,
    connect_timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Proxy server listening on {}", listen_addr);

    let timeout_dur = Duration::from_secs(connect_timeout_secs);

    // Graceful shutdown on SIGINT or SIGTERM
    let mut shutdown = Box::pin(async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("Received SIGINT, shutting down"),
            _ = unix::signal_unix() => info!("Received SIGTERM, shutting down"),
        }
    });

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutdown signal received; stopping accept loop");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, addr)) => {
                        let manager = manager.clone();

                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let manager = manager.clone();
                                handle_request(req, manager, strategy, timeout_dur)
                            });
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await
                            {
                                debug!("Error serving connection from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        }
    }

    info!("Server stopped");
    Ok(())
}

#[cfg(unix)]
mod unix {
    use tokio::signal::unix::{signal, SignalKind};

    pub async fn signal_unix() {
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        sigterm.recv().await;
    }
}

#[cfg(not(unix))]
mod unix {
    /// On non-Unix (Windows) there is no SIGTERM.
    pub async fn signal_unix() {
        std::future::pending::<()>().await;
    }
}
