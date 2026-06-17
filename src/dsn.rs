//! DSN (Data Source Name) parsing for upstream configuration.
//!
//! Supported formats:
//! - `http://[user[:pass]@]host[:port]`
//! - `socks5://[user[:pass]@]host[:port]`
//! - `ssh://user[:pass]@host[:port][?key=path&keepalive=secs]`

use std::str::FromStr;
use url::Url;

/// Represents a parsed DSN for an upstream proxy channel.
#[derive(Debug, Clone)]
pub enum Dsn {
    /// HTTP proxy connection.
    Http(HttpDsn),
    /// SOCKS5 proxy connection.
    Socks5(Socks5Dsn),
    /// SSH tunnel (built-in client).
    Ssh(SshDsn),
}

#[derive(Debug, Clone)]
pub struct HttpDsn {
    pub host: String,
    pub port: u16,
    #[allow(dead_code)]
    pub user: Option<String>,
    #[allow(dead_code)]
    pub pass: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Socks5Dsn {
    pub host: String,
    pub port: u16,
    #[allow(dead_code)]
    pub user: Option<String>,
    #[allow(dead_code)]
    pub pass: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SshDsn {
    pub user: String,
    pub pass: Option<String>,
    pub host: String,
    pub port: u16,
    pub key_path: Option<String>,
    pub keepalive: u64,
}

impl FromStr for Dsn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.starts_with("http://") {
            Ok(Dsn::Http(s.parse()?))
        } else if s.starts_with("socks5://") {
            Ok(Dsn::Socks5(s.parse()?))
        } else if s.starts_with("ssh://") {
            Ok(Dsn::Ssh(s.parse()?))
        } else {
            Err(format!("Unknown DSN scheme: {}", s))
        }
    }
}

impl FromStr for HttpDsn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|e| e.to_string())?;

        let host = url.host_str()
            .ok_or_else(|| "HTTP DSN missing host".to_string())?
            .to_string();
        let port = url.port().unwrap_or(8080);
        let user = if url.username().is_empty() { None } else { Some(url.username().to_string()) };
        let pass = url.password().map(String::from);

        Ok(HttpDsn { host, port, user, pass })
    }
}

impl FromStr for Socks5Dsn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|e| e.to_string())?;

        let host = url.host_str()
            .ok_or_else(|| "SOCKS5 DSN missing host".to_string())?
            .to_string();
        let port = url.port().unwrap_or(1080);
        let user = if url.username().is_empty() { None } else { Some(url.username().to_string()) };
        let pass = url.password().map(String::from);

        Ok(Socks5Dsn { host, port, user, pass })
    }
}

impl FromStr for SshDsn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|e| e.to_string())?;

        let user = url.username().to_string();
        let host = url.host_str()
            .ok_or_else(|| "SSH DSN missing host".to_string())?
            .to_string();
        let port = url.port().unwrap_or(22);
        let pass = url.password().map(String::from);

        // Parse query parameters
        let key_path = url.query_pairs()
            .find(|(k, _)| k == "key")
            .map(|(_, v)| v.to_string());

        let keepalive = url.query_pairs()
            .find(|(k, _)| k == "keepalive")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(30);

        Ok(SshDsn {
            user,
            pass,
            host,
            port,
            key_path,
            keepalive,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_dsn() {
        let dsn: HttpDsn = "http://user:pass@127.0.0.1:1080".parse().unwrap();
        assert_eq!(dsn.host, "127.0.0.1");
        assert_eq!(dsn.port, 1080);
        assert_eq!(dsn.user, Some("user".to_string()));
        assert_eq!(dsn.pass, Some("pass".to_string()));
    }

    #[test]
    fn test_parse_socks5_dsn() {
        let dsn: Socks5Dsn = "socks5://127.0.0.1:1080".parse().unwrap();
        assert_eq!(dsn.host, "127.0.0.1");
        assert_eq!(dsn.port, 1080);
        assert_eq!(dsn.user, None);
    }

    #[test]
    fn test_parse_ssh_dsn() {
        let dsn: SshDsn = "ssh://root@host?key=~/.ssh/id_rsa&keepalive=20".parse().unwrap();
        assert_eq!(dsn.user, "root");
        assert_eq!(dsn.host, "host");
        assert_eq!(dsn.port, 22);
        assert_eq!(dsn.key_path, Some("~/.ssh/id_rsa".to_string()));
        assert_eq!(dsn.keepalive, 20);
    }

    #[test]
    fn test_parse_ssh_dsn_with_password() {
        let dsn: SshDsn = "ssh://root:123456@127.0.0.1".parse().unwrap();
        assert_eq!(dsn.user, "root");
        assert_eq!(dsn.pass, Some("123456".to_string()));
        assert_eq!(dsn.keepalive, 30); // default
    }
}