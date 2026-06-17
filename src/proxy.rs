//! HTTP proxy server implementation with raw TCP passthrough.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::dsn::Dsn;
use crate::upstream::ChannelManager;
use crate::strategy::Strategy;
use crate::upstream::ssh as ssh_tunnel;
use ssh_tunnel::forward_raw as ssh_forward;

/// Parse request path to extract target URL.
fn parse_path(path: &str) -> Result<(String, bool), String> {
    if !path.starts_with("/http://") && !path.starts_with("/https://") {
        return Err("Invalid path format. Expected /https://target.com".to_string());
    }
    let is_https = path.starts_with("/https://");
    let target = path.trim_start_matches('/');
    Ok((target.to_string(), is_https))
}

/// Parse target to get host, port.
fn parse_target(target: &str) -> Result<(String, u16, bool), String> {
    let target_url = if !target.starts_with("http://") && !target.starts_with("https://") {
        format!("http://{}", target)
    } else {
        target.to_string()
    };

    let parsed = url::Url::parse(&target_url)
        .map_err(|e| format!("Invalid URL: {}", e))?;

    let host = parsed.host_str()
        .ok_or_else(|| "Missing host".to_string())?
        .to_string();

    let is_https = target.starts_with("https://");
    let port = parsed.port().unwrap_or(if is_https { 443 } else { 80 });

    Ok((host, port, is_https))
}

/// Build error response.
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}

/// Raw HTTP request forwarding through proxy.
async fn raw_forward_http(
    proxy_addr: &str,
    target: &str,
    original_request: &[u8],
    timeout_dur: Duration,
) -> Result<Vec<u8>, String> {
    let mut upstream = timeout(timeout_dur, TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| "Proxy connection timeout")?
        .map_err(|e| e.to_string())?;

    // Extract target host/port
    let (host, port, _) = parse_target(target)?;
    let target_addr = format!("{}:{}", host, port);

    // Build CONNECT request
    let connect_req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target_addr, host, port
    );

    upstream.write_all(connect_req.as_bytes()).await.map_err(|e| e.to_string())?;

    // Read CONNECT response
    let mut response_buf = vec![0u8; 1024];
    let n = upstream.read(&mut response_buf).await.map_err(|e| e.to_string())?;
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    if !response_str.contains("200") {
        return Err(format!("CONNECT failed: {}", response_str.trim()));
    }

    // Forward original request
    upstream.write_all(original_request).await.map_err(|e| e.to_string())?;
    upstream.flush().await.map_err(|e| e.to_string())?;

    // Read full response: loop until EOF (Connection: close) or idle timeout
    read_full_response(&mut upstream, timeout_dur).await
}

/// Raw SOCKS5 forwarding.
async fn raw_forward_socks5(
    proxy_addr: &str,
    target: &str,
    original_request: &[u8],
    timeout_dur: Duration,
) -> Result<Vec<u8>, String> {
    let mut upstream = timeout(timeout_dur, TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| "SOCKS5 connection timeout")?
        .map_err(|e| e.to_string())?;

    // Extract target
    let (host, port, is_https) = parse_target(target)?;

    // SOCKS5 handshake
    upstream.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
    let mut reply = [0u8; 2];
    upstream.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
    if reply[0] != 0x05 || reply[1] == 0xFF {
        return Err("SOCKS5 handshake failed".to_string());
    }

    // Connect command
    let mut request = vec![0x05, 0x01, 0x00, 0x03];
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    upstream.write_all(&request).await.map_err(|e| e.to_string())?;

    // Read reply
    let mut reply = vec![0u8; 10];
    upstream.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
    if reply[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed: {}", reply[1]));
    }

    // For HTTPS, need TLS handshake
    if is_https {
        use native_tls::TlsConnector;
        use tokio_native_tls::TlsConnector as TokioTlsConnector;

        let tls_connector = TlsConnector::new()
            .map_err(|e| format!("TLS connector error: {}", e))?;
        let tls_connector = TokioTlsConnector::from(tls_connector);

        let mut tls_stream = tls_connector.connect(&host, upstream).await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        // Forward request through TLS
        tls_stream.write_all(original_request).await.map_err(|e| e.to_string())?;
        tls_stream.flush().await.map_err(|e| e.to_string())?;

        // Read full response: loop until EOF or idle timeout
        return read_full_response(&mut tls_stream, timeout_dur).await;
    }

    // Forward original request
    upstream.write_all(original_request).await.map_err(|e| e.to_string())?;
    upstream.flush().await.map_err(|e| e.to_string())?;

    // Read full response: loop until EOF (Connection: close) or idle timeout
    read_full_response(&mut upstream, timeout_dur).await
}

/// Read full upstream response: accumulate chunks until EOF or total deadline.
/// Handles responses split across TCP/TLS packets so all headers + body pass through.
/// Uses a total deadline from start of read (15s) so client doesn't timeout.
async fn read_full_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    _connect_timeout: Duration,
) -> Result<Vec<u8>, String> {
    let total_timeout = Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut response_buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, reader.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => response_buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                if response_buf.is_empty() {
                    return Err(format!("Read error: {}", e));
                }
                break;
            }
            Err(_) => break,
        }
    }
    if response_buf.is_empty() {
        return Err("Empty response".to_string());
    }
    Ok(response_buf)
}

/// Forward request through single channel with raw passthrough.
async fn forward_channel(
    dsn: &Dsn,
    target: &str,
    original_request: &[u8],
    timeout_dur: Duration,
) -> Result<Vec<u8>, String> {
    match dsn {
        Dsn::Http(http_dsn) => {
            let proxy_addr = format!("{}:{}", http_dsn.host, http_dsn.port);
            raw_forward_http(&proxy_addr, target, original_request, timeout_dur).await
        }
        Dsn::Socks5(socks5_dsn) => {
            let proxy_addr = format!("{}:{}", socks5_dsn.host, socks5_dsn.port);
            raw_forward_socks5(&proxy_addr, target, original_request, timeout_dur).await
        }
        Dsn::Ssh(ssh_dsn) => {
            ssh_forward(ssh_dsn, target, original_request, timeout_dur).await
        }
    }
}

/// Forward request directly to the origin server, bypassing all upstream
/// proxies. Used as last-resort fallback when every channel fails.
/// NOTE: exposes the client's real IP (no proxy), so only used as fallback.
async fn direct_forward(
    target: &str,
    original_request: &[u8],
    timeout_dur: Duration,
) -> Result<Vec<u8>, String> {
    let (host, port, is_https) = parse_target(target)?;
    let addr = format!("{}:{}", host, port);

    let stream = timeout(timeout_dur, TcpStream::connect(&addr))
        .await
        .map_err(|_| "Direct connection timeout")?
        .map_err(|e| format!("Direct connect failed: {}", e))?;

    if is_https {
        use native_tls::TlsConnector;
        use tokio_native_tls::TlsConnector as TokioTlsConnector;

        let tls_connector = TlsConnector::new()
            .map_err(|e| format!("TLS connector error: {}", e))?;
        let tls_connector = TokioTlsConnector::from(tls_connector);

        let mut tls_stream = tls_connector.connect(&host, stream).await
            .map_err(|e| format!("Direct TLS handshake failed: {}", e))?;

        tls_stream.write_all(original_request).await.map_err(|e| e.to_string())?;
        tls_stream.flush().await.map_err(|e| e.to_string())?;
        return read_full_response(&mut tls_stream, timeout_dur).await;
    }

    let mut stream = stream;
    stream.write_all(original_request).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    read_full_response(&mut stream, timeout_dur).await
}

/// Build HTTP response from raw bytes, preserving all upstream headers.
/// Parses the upstream HTTP response line + headers and reconstructs
/// a hyper Response with the exact same headers intact, body = upstream body only.
fn raw_response(data: Vec<u8>) -> Response<Full<Bytes>> {
    // Find header/body boundary (\r\n\r\n)
    let sep = find_header_end(&data);
    let (head, body) = match sep {
        Some(idx) => (&data[..idx], &data[idx + 4..]),
        None => (&data[..], &[][..]),
    };

    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.lines();

    // Parse status line: "HTTP/1.1 200 OK"
    let status_code = lines.next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(200);
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);

    let mut builder = Response::builder().status(status);

    // Parse header lines; detect chunked transfer-encoding
    let mut is_chunked = false;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(col) = line.find(':') {
            let name = line[..col].trim();
            let value = line[col + 1..].trim();
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if value.eq_ignore_ascii_case("chunked") {
                    is_chunked = true;
                }
                continue; // we dechunk and set Content-Length
            }
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            builder = builder.header(name, value);
        }
    }

    // Decode chunked transfer-encoding into a plain body
    let body_final = if is_chunked {
        dechunk(body)
    } else {
        body.to_vec()
    };

    builder = builder.header("Content-Length", body_final.len().to_string());

    builder.body(Full::new(Bytes::from(body_final))).unwrap()
}

/// Find the index of the \r\n\r\n header/body separator.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Decode HTTP/1.1 chunked transfer-encoding body into plain bytes.
/// Format: <hex-size>\r\n<data>\r\n ... 0\r\n\r\n
fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    while pos < data.len() {
        // Read chunk size line up to \r\n
        let line_end = match data[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(i) => pos + i,
            None => break,
        };
        let size_str = match std::str::from_utf8(&data[pos..line_end]) {
            Ok(s) => s.trim(),
            Err(_) => break,
        };
        // Chunk size may have extensions after ';'
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = match usize::from_str_radix(size_hex, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        pos = line_end + 2; // skip \r\n
        if chunk_size == 0 {
            break; // last chunk
        }
        if pos + chunk_size > data.len() {
            break; // incomplete
        }
        out.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size + 2; // skip data + trailing \r\n
    }
    out
}

/// Handle proxy request with automatic fallback.
async fn handle_request(
    req: Request<Incoming>,
    manager: ChannelManager,
    _strategy: Strategy,
    timeout_dur: Duration,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let path = req.uri().path().to_string();

    // Liveness probe endpoint (short-circuit before proxy routing)
    if path == "/health" {
        let healthy_count = manager.healthy_channels().len();
        let total = manager.channels().len();
        let body = format!(
            "{{\"status\":\"ok\",\"healthy\":{},\"total\":{}}}",
            healthy_count, total
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }

    // Validate path format
    let (target, _is_https) = match parse_path(&path) {
        Ok(t) => t,
        Err(e) => {
            warn!("Invalid request path: {} - {}", path, e);
            return Ok(error_response(StatusCode::BAD_REQUEST, &e));
        }
    };

    debug!("Proxying request to: {}", target);

    // Parse target to get path
    let (host, port, is_https) = parse_target(&target)?;

    // Build original HTTP request with all headers and body
    let mut original_request = Vec::new();

    // Extract path from target (e.g., "http://ip.sb/ip" -> "/ip")
    let target_path = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .and_then(|s| s.splitn(2, '/').nth(1))
        .map(|p| format!("/{}", p))
        .unwrap_or_else(|| "/".to_string());

    // Request line: GET /path HTTP/1.1 (only path, not full URL)
    let request_line = format!("{} {} HTTP/1.1\r\n", req.method(), target_path);
    original_request.extend_from_slice(request_line.as_bytes());

    // Headers - update Host header, force Connection: close so upstream closes after response
    let mut has_connection = false;
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if name_str.eq_ignore_ascii_case("host") {
            if is_https {
                original_request.extend_from_slice(b"Host: ");
                original_request.extend_from_slice(host.as_bytes());
                original_request.extend_from_slice(b"\r\n");
            } else {
                original_request.extend_from_slice(b"Host: ");
                original_request.extend_from_slice(format!("{}:{}", host, port).as_bytes());
                original_request.extend_from_slice(b"\r\n");
            }
        } else if name_str.eq_ignore_ascii_case("connection") {
            // Replace with close
            has_connection = true;
        } else {
            original_request.extend_from_slice(name_str.as_bytes());
            original_request.extend_from_slice(b": ");
            original_request.extend_from_slice(value.as_bytes());
            original_request.extend_from_slice(b"\r\n");
        }
    }
    let _ = has_connection;
    // Force Connection: close so the upstream closes the socket after the full
    // response — this guarantees EOF for our read loop regardless of channel type.
    original_request.extend_from_slice(b"Connection: close\r\n");

    // End of headers
    original_request.extend_from_slice(b"\r\n");

    // Body
    let body_bytes = req.into_body()
        .collect()
        .await
        .map_err(|e| format!("Failed to read body: {}", e))?
        .to_bytes();
    original_request.extend_from_slice(&body_bytes);

    // Get all channels
    let all_channels = manager.channels();

    if all_channels.is_empty() {
        return Ok(error_response(StatusCode::BAD_GATEWAY, "No upstreams configured"));
    }

    // Circuit breaker: prefer channels not in backoff window (should_retry=true).
    // Failed channels are skipped short-term to avoid retrying known-bad nodes.
    let usable: Vec<_> = all_channels.iter().filter(|c| c.should_retry()).collect();
    let candidates = if usable.is_empty() {
        // All in backoff — as last resort, try all (backoff expired next attempt)
        warn!("All channels in backoff; attempting all as last resort");
        all_channels.iter().collect::<Vec<_>>()
    } else {
        usable
    };

    // Try candidate channels in order with automatic fallback
    let mut last_err = String::new();

    for channel in &candidates {
        match forward_channel(&channel.dsn, &target, &original_request, timeout_dur).await {
            Ok(response_data) => {
                manager.mark_healthy(channel.id);
                return Ok(raw_response(response_data));
            }
            Err(e) => {
                warn!("Channel {} ({:?}) failed: {}", channel.id, channel.dsn, e);
                last_err = e;
                manager.mark_unhealthy(channel.id);
            }
        }
    }

    // All channels failed — last-resort fallback: connect directly to origin.
    // This exposes the client's real IP (no proxy), so it is only used when
    // every upstream channel is unavailable, to keep service reachable.
    warn!("All channels failed ({}); falling back to direct origin connection", last_err);
    match direct_forward(&target, &original_request, timeout_dur).await {
        Ok(response_data) => {
            info!("Direct origin fallback succeeded for {}", target);
            Ok(raw_response(response_data))
        }
        Err(e) => {
            error!("All channels failed and direct fallback also failed: {}", e);
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("All channels failed and direct connection failed: {} | {}", last_err, e),
            ))
        }
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

    let timeout = Duration::from_secs(connect_timeout_secs);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let manager = manager.clone();
                let timeout = timeout;

                tokio::spawn(async move {
                    let io = TokioIo::new(stream);

                    let service = service_fn(move |req| {
                        let manager = manager.clone();
                        handle_request(req, manager, strategy, timeout)
                    });

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        error!("Error serving connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}