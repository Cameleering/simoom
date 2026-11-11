//! Absolute `http`, `https`, `ws` and `wss` URLs.

use crate::error::{Error, ErrorKind, Result};

/// A parsed absolute URL. Only what a client needs: scheme, host, port, path and query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// `http`, `https`, `ws` or `wss` (lower case).
    pub scheme: String,
    /// Host name or address (IPv6 without brackets).
    pub host: String,
    /// Port (the scheme's default when the URL has none).
    pub port: u16,
    /// Raw path, always starting with `/`.
    pub path: String,
    /// Raw query without `?`.
    pub query: Option<String>,
    /// `user:password` from the URL (percent-decoded), sent as Basic credentials.
    pub userinfo: Option<String>,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidUrl, msg)
}

impl Url {
    /// Parses `scheme://[user:pass@]host[:port][/path][?query][#fragment]`.
    pub fn parse(url: &str) -> Result<Url> {
        let url = url.trim();
        let (scheme, rest) = url.split_once("://").ok_or_else(|| bad(format!("invalid URL (missing scheme): {url}")))?;
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
            return Err(bad(format!("unsupported URL scheme '{scheme}': {url}")));
        }
        let rest = rest.split('#').next().unwrap_or("");
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path_query) = rest.split_at(split);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(percent_decode(u)), h),
            None => (None, authority),
        };
        let default_port = default_port(&scheme);
        let (host, port) = parse_authority(hostport, default_port).map_err(|m| bad(format!("{m}: {url}")))?;
        if host.bytes().any(|b| b <= b' ' || b >= 0x7f || b"/?#@\\".contains(&b)) {
            return Err(bad(format!("invalid host: {url}")));
        }
        let (path, query) = match path_query.find('?') {
            Some(i) => (&path_query[..i], Some(path_query[i + 1..].to_string())),
            None => (path_query, None),
        };
        let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
        let u = Url { scheme, host, port, path, query, userinfo };
        if u.request_target().bytes().any(|b| b <= b' ' || b >= 0x7f) {
            return Err(bad(format!("invalid character in the path or query (percent-encode it): {url}")));
        }
        Ok(u)
    }

    /// `host:port`, IPv6 hosts in brackets.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The `Host` header value (the port only when it is not the default).
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == default_port(&self.scheme) {
            h
        } else {
            format!("{}:{}", h, self.port)
        }
    }

    /// `https` or `wss`.
    pub fn is_secure(&self) -> bool {
        self.scheme == "https" || self.scheme == "wss"
    }

    /// `/path?query`.
    pub fn request_target(&self) -> String {
        match &self.query {
            Some(q) if !q.is_empty() => format!("{}?{}", self.path, q),
            _ => self.path.clone(),
        }
    }

    /// The origin `scheme://host:port`, with `ws` mapped to `http` and `wss` to `https`.
    pub fn origin(&self) -> String {
        let s = match self.scheme.as_str() {
            "ws" => "http",
            "wss" => "https",
            s => s,
        };
        format!("{}://{}", s, self.authority())
    }

    /// Resolves a reference, such as a `Location` header, against this URL (RFC 3986 §5.2,
    /// with dot segments removed).
    pub fn join(&self, reference: &str) -> Result<Url> {
        let reference = reference.trim();
        if let Some(i) = reference.find("://") {
            if reference[..i].bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) {
                return Url::parse(reference);
            }
        }
        if let Some(r) = reference.strip_prefix("//") {
            return Url::parse(&format!("{}://{}", self.scheme, r));
        }
        let reference = reference.split('#').next().unwrap_or("");
        let mut u = self.clone();
        u.userinfo = None;
        let (p, q) = match reference.find('?') {
            Some(i) => (&reference[..i], Some(reference[i + 1..].to_string())),
            None => (reference, None),
        };
        if p.is_empty() {
            if q.is_some() {
                u.query = q;
            }
            return Ok(u);
        }
        let merged = if p.starts_with('/') {
            p.to_string()
        } else {
            let base = match self.path.rfind('/') {
                Some(i) => &self.path[..=i],
                None => "/",
            };
            format!("{base}{p}")
        };
        u.path = remove_dot_segments(&merged);
        u.query = q;
        if u.request_target().bytes().any(|b| b <= b' ' || b >= 0x7f) {
            return Err(bad(format!("invalid redirect location: {reference}")));
        }
        Ok(u)
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.host_header(), self.request_target())
    }
}

/// The default port of a scheme: 443 for `https`/`wss`, 80 otherwise.
pub fn default_port(scheme: &str) -> u16 {
    if scheme == "https" || scheme == "wss" {
        443
    } else {
        80
    }
}

fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').collect();
    let last = segs.len() - 1;
    for (i, s) in segs.iter().enumerate() {
        match *s {
            "." => {
                if i == last {
                    out.push("");
                }
            }
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
                if i == last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    let j = out.join("/");
    if j.starts_with('/') {
        j
    } else {
        format!("/{j}")
    }
}

/// Parses `host[:port]` or `[v6][:port]`.
pub fn parse_authority(authority: &str, default_port: u16) -> std::result::Result<(String, u16), String> {
    if authority.is_empty() {
        return Err("missing host".into());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or("invalid IPv6 host")?;
        let host = rest[..end].to_string();
        let port = match rest[end + 1..].strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("invalid port '{p}'"))?,
            None if rest[end + 1..].is_empty() => default_port,
            None => return Err("invalid authority".into()),
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            if h.is_empty() {
                return Err("missing host".into());
            }
            Ok((h.to_string(), p.parse().map_err(|_| format!("invalid port '{p}'"))?))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

/// Standard base64 with padding.
pub(crate) fn b64(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    simoom_http1::base64_encode(data, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

/// Percent-decodes `%XX` sequences (invalid ones are kept as they are).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes everything except RFC 3986 unreserved characters (for query names and
/// values).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        let u = Url::parse("http://example.com:8080/a/b?x=1#frag").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str(), u.query.as_deref()), ("example.com", 8080, "/a/b", Some("x=1")));
        let u = Url::parse("http://[::1]/").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.authority()), ("::1", 80, "[::1]:80".to_string()));
        assert_eq!(Url::parse("http://h?q").unwrap().request_target(), "/?q");
        let u = Url::parse("https://h/").unwrap();
        assert_eq!((u.port, u.host_header()), (443, "h".to_string()));
        assert_eq!(Url::parse("https://h:8443/").unwrap().host_header(), "h:8443");
        assert_eq!(Url::parse("wss://h/x").unwrap().origin(), "https://h:443");
        let u = Url::parse("http://u:p%40ss@h/").unwrap();
        assert_eq!(u.userinfo.as_deref(), Some("u:p@ss"));
        assert!(Url::parse("ftp://h/").is_err());
        assert!(Url::parse("http:///x").is_err());
        assert!(Url::parse("http://h/a b").is_err());
        assert!(Url::parse("http://h:99999/").is_err());
    }

    #[test]
    fn join_references() {
        let base = Url::parse("http://h:1/a/b/c?q").unwrap();
        assert_eq!(base.join("d").unwrap().path, "/a/b/d");
        assert_eq!(base.join("../d").unwrap().path, "/a/d");
        assert_eq!(base.join("./").unwrap().path, "/a/b/");
        assert_eq!(base.join("/z?q=1").unwrap().request_target(), "/z?q=1");
        assert_eq!(base.join("?y").unwrap().request_target(), "/a/b/c?y");
        assert_eq!(base.join("http://o/p").unwrap().host, "o");
        assert_eq!(base.join("//o2:5/p").unwrap().authority(), "o2:5");
        assert_eq!(base.join("../../../../x").unwrap().path, "/x");
    }

    #[test]
    fn percent() {
        assert_eq!(percent_decode("a%20b%zz%4"), "a b%zz%4");
        assert_eq!(percent_encode("a b&é"), "a%20b%26%C3%A9");
    }
}
