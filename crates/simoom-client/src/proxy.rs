//! HTTP proxies: `CONNECT` tunnels (with Basic credentials) and `NO_PROXY` exclusions.

use crate::error::{Error, ErrorKind, Result};
use crate::url::{parse_authority, percent_decode, Url};
use std::net::IpAddr;

/// The proxy protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ProxyKind {
    /// An HTTP proxy: `CONNECT` tunnels, absolute-form requests for plain HTTP.
    #[default]
    Http,
    /// SOCKS5 (RFC 1928), target names resolved by the client.
    Socks5,
    /// SOCKS5 with target names resolved by the proxy (`socks5h://`).
    Socks5h,
}

/// A proxy: `http://[user:pass@]host:port`, `socks5://...` or `socks5h://...`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyAddr {
    /// Proxy host.
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// `user:password` (`Proxy-Authorization: Basic` for HTTP, RFC 1929 for SOCKS5).
    pub credentials: Option<String>,
    /// The protocol.
    pub kind: ProxyKind,
}

impl ProxyAddr {
    /// A proxy at `host:port` without credentials.
    pub fn new(host: impl Into<String>, port: u16) -> ProxyAddr {
        ProxyAddr { host: host.into(), port, credentials: None, kind: ProxyKind::Http }
    }

    /// A SOCKS5 proxy; `remote_dns` lets the proxy resolve target names (`socks5h`).
    pub fn socks5(host: impl Into<String>, port: u16, remote_dns: bool) -> ProxyAddr {
        ProxyAddr { host: host.into(), port, credentials: None, kind: if remote_dns { ProxyKind::Socks5h } else { ProxyKind::Socks5 } }
    }

    /// Adds Basic credentials.
    pub fn with_credentials(mut self, user: &str, password: &str) -> ProxyAddr {
        self.credentials = Some(format!("{user}:{password}"));
        self
    }

    /// Parses `host:port`, `http://host:port` or `http://user:pass@host:port/`.
    pub fn parse(s: &str) -> Result<ProxyAddr> {
        let s = s.trim();
        let (kind, rest) = match s.split_once("://") {
            Some((scheme, r)) => {
                let k = match scheme.to_ascii_lowercase().as_str() {
                    "http" => ProxyKind::Http,
                    "socks5" => ProxyKind::Socks5,
                    "socks5h" => ProxyKind::Socks5h,
                    _ => return Err(Error::new(ErrorKind::InvalidUrl, format!("unsupported proxy scheme '{scheme}' (http, socks5, socks5h): {s}"))),
                };
                (k, r)
            }
            None => (ProxyKind::Http, s),
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        let (credentials, hostport) = match authority.rsplit_once('@') {
            Some((c, h)) => (Some(percent_decode(c)), h),
            None => (None, authority),
        };
        let default = if kind == ProxyKind::Http { 80 } else { 1080 };
        let (host, port) = parse_authority(hostport, default).map_err(|m| Error::new(ErrorKind::InvalidUrl, format!("invalid proxy '{s}': {m}")))?;
        Ok(ProxyAddr { host, port, credentials, kind })
    }

    /// The `Proxy-Authorization` value, if the proxy has credentials.
    pub fn authorization(&self) -> Option<String> {
        self.credentials.as_ref().map(|c| format!("Basic {}", crate::url::b64(c.as_bytes())))
    }
}

/// Proxy settings: a proxy for `http` targets and one for `https` targets, plus `NO_PROXY`
/// exclusions (host names, `.domain` suffixes, `*`, IP addresses and CIDR ranges).
///
/// `https` and `wss` targets always go through a `CONNECT` tunnel; `http` targets are sent to
/// the proxy in absolute form (as Cameleer and Apache HttpClient do) unless
/// [`ProxyConfig::tunnel_http`] is set; `ws` targets always tunnel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProxyConfig {
    /// Proxy for `http` and `ws` targets.
    pub http: Option<ProxyAddr>,
    /// Proxy for `https` and `wss` targets.
    pub https: Option<ProxyAddr>,
    /// `NO_PROXY` entries.
    pub no_proxy: Vec<String>,
    /// Tunnel `http` targets with `CONNECT` too, instead of absolute-form requests.
    pub tunnel_http: bool,
}

impl ProxyConfig {
    /// One proxy for every scheme.
    pub fn new(proxy: ProxyAddr) -> ProxyConfig {
        ProxyConfig { http: Some(proxy.clone()), https: Some(proxy), no_proxy: Vec::new(), tunnel_http: false }
    }

    /// Adds `NO_PROXY`-style exclusions (comma separated).
    pub fn with_no_proxy(mut self, list: &str) -> ProxyConfig {
        self.no_proxy.extend(list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
        self
    }

    /// `HTTPS_PROXY`/`https_proxy`, `HTTP_PROXY`/`http_proxy` and `NO_PROXY`/`no_proxy` from
    /// the environment; `None` when no proxy variable is set.
    pub fn from_env() -> Option<ProxyConfig> {
        ProxyConfig::from_vars(&|k| std::env::var(k).ok())
    }

    /// Like [`ProxyConfig::from_env`] with a custom lookup.
    pub fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Option<ProxyConfig> {
        let var = |names: &[&str]| names.iter().find_map(|n| get(n)).filter(|v| !v.trim().is_empty());
        let https = var(&["HTTPS_PROXY", "https_proxy"]).and_then(|v| ProxyAddr::parse(&v).ok());
        let http = var(&["HTTP_PROXY", "http_proxy"]).and_then(|v| ProxyAddr::parse(&v).ok());
        if http.is_none() && https.is_none() {
            return None;
        }
        let cfg = ProxyConfig { http, https, no_proxy: Vec::new(), tunnel_http: false };
        Some(match var(&["NO_PROXY", "no_proxy"]) {
            Some(n) => cfg.with_no_proxy(&n),
            None => cfg,
        })
    }

    /// Whether `host` matches a `NO_PROXY` entry.
    pub fn bypass(&self, host: &str) -> bool {
        let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        let ip: Option<IpAddr> = host.parse().ok();
        self.no_proxy.iter().any(|entry| {
            let e = entry.trim().to_ascii_lowercase();
            if e == "*" {
                return true;
            }
            if let Some((net, bits)) = e.split_once('/') {
                return ip.is_some_and(|ip| cidr_contains(net, bits, ip));
            }
            let e = e.trim_start_matches("*.");
            let e = e.strip_prefix('.').unwrap_or(e);
            let e = e.trim_start_matches('[');
            let e = if e.parse::<IpAddr>().is_ok() { e } else { e.split(']').next().unwrap_or(e).split(':').next().unwrap_or(e) };
            host == e || host.ends_with(&format!(".{e}"))
        })
    }

    /// The proxy for `url`, if any.
    pub fn proxy_for(&self, url: &Url) -> Option<&ProxyAddr> {
        let p = if url.is_secure() { self.https.as_ref() } else { self.http.as_ref() };
        p.filter(|_| !self.bypass(&url.host))
    }
}

fn cidr_contains(net: &str, bits: &str, ip: IpAddr) -> bool {
    let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else { return false };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) if bits <= 32 => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) if bits <= 128 => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_config_and_no_proxy() {
        let vars = |k: &str| match k {
            "HTTPS_PROXY" => Some("http://u:p%40ss@proxy.local:3128".to_string()),
            "no_proxy" => Some("localhost,.internal,10.0.0.0/8,example.org:443,::1".to_string()),
            _ => None,
        };
        let cfg = ProxyConfig::from_vars(&vars).unwrap();
        let p = cfg.https.clone().unwrap();
        assert_eq!((p.host.as_str(), p.port, p.credentials.as_deref()), ("proxy.local", 3128, Some("u:p@ss")));
        assert_eq!(p.authorization().unwrap(), format!("Basic {}", crate::url::b64(b"u:p@ss")));
        assert!(cfg.http.is_none());
        assert!(cfg.bypass("localhost") && cfg.bypass("a.internal") && cfg.bypass("10.1.2.3") && cfg.bypass("example.org"));
        assert!(cfg.bypass("[::1]"));
        assert!(!cfg.bypass("example.com") && !cfg.bypass("11.0.0.1") && !cfg.bypass("notinternal"));
        assert!(cfg.proxy_for(&Url::parse("https://example.com/").unwrap()).is_some());
        assert!(cfg.proxy_for(&Url::parse("wss://example.com/").unwrap()).is_some());
        assert!(cfg.proxy_for(&Url::parse("http://example.com/").unwrap()).is_none());
        assert!(cfg.proxy_for(&Url::parse("https://svc.internal/").unwrap()).is_none());
        assert!(ProxyConfig::from_vars(&|_| None).is_none());
        assert!(ProxyAddr::parse("socks4://h:1").is_err());
        let s = ProxyAddr::parse("socks5h://u:p@h").unwrap();
        assert_eq!((s.kind, s.port, s.credentials.as_deref()), (ProxyKind::Socks5h, 1080, Some("u:p")));
    }
}
