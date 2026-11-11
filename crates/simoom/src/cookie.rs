//! Cookies (RFC 6265bis) for servers (feature `cookies`): reading the `Cookie` header
//! ([`crate::Request::cookie`], [`parse_cookies`]) and building `Set-Cookie`
//! ([`SetCookie`], [`crate::Reply::cookie`]).
//!
//! ```
//! # #[cfg(feature = "cookies")] {
//! use simoom::cookie::{SameSite, SetCookie};
//! let c = SetCookie::new("sid", "abc123").path("/").secure(true).http_only(true).same_site(SameSite::Lax).max_age(3600);
//! assert_eq!(c.to_header().unwrap(), "sid=abc123; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Lax");
//! # }
//! ```

use std::time::SystemTime;

/// The `name=value` pairs of a `Cookie` header value, in order (values unquoted).
pub fn parse_cookies(header: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    header.split(|&b| b == b';').filter_map(|pair| {
        let pair = trim(pair);
        let eq = pair.iter().position(|&b| b == b'=')?;
        let name = trim(&pair[..eq]);
        let mut value = trim(&pair[eq + 1..]);
        if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
            value = &value[1..value.len() - 1];
        }
        if name.is_empty() {
            return None;
        }
        Some((name, value))
    })
}

fn trim(v: &[u8]) -> &[u8] {
    let s = v.iter().position(|b| !matches!(b, b' ' | b'\t')).unwrap_or(v.len());
    let e = v.iter().rposition(|b| !matches!(b, b' ' | b'\t')).map_or(s, |i| i + 1);
    &v[s..e]
}

impl<'a> crate::Request<'a> {
    /// The value of cookie `name` (the first one when it occurs more than once), from every
    /// `Cookie` header (HTTP/2 and HTTP/3 may split them).
    pub fn cookie(&self, name: &str) -> Option<&'a [u8]> {
        self.headers().filter(|(n, _)| n.eq_ignore_ascii_case(b"cookie")).flat_map(|(_, v)| parse_cookies(v)).find(|(n, _)| *n == name.as_bytes()).map(|(_, v)| v)
    }

    /// Every cookie, in order.
    pub fn cookies(&self) -> Vec<(&'a [u8], &'a [u8])> {
        self.headers().filter(|(n, _)| n.eq_ignore_ascii_case(b"cookie")).flat_map(|(_, v)| parse_cookies(v)).collect()
    }
}

/// The `SameSite` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    /// Needs `Secure` (browsers refuse `SameSite=None` without it).
    None,
}

/// A `Set-Cookie` header value with every RFC 6265bis attribute, plus `Partitioned` (CHIPS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetCookie {
    name: String,
    value: String,
    expires: Option<SystemTime>,
    max_age: Option<i64>,
    domain: Option<String>,
    path: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
    partitioned: bool,
}

/// Why a cookie can't be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CookieError {
    /// The name is not a token.
    Name,
    /// The value has characters outside cookie-octet (or is a broken quoted value).
    Value,
    /// `Domain` or `Path` holds a `;` or a control character.
    Attribute,
    /// `SameSite=None` without `Secure`, or `Partitioned` without `Secure`.
    NeedsSecure,
}

impl std::fmt::Display for CookieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CookieError::Name => "invalid cookie name",
            CookieError::Value => "invalid cookie value",
            CookieError::Attribute => "invalid cookie attribute",
            CookieError::NeedsSecure => "SameSite=None and Partitioned need Secure",
        })
    }
}

impl std::error::Error for CookieError {}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn is_cookie_octet(b: u8) -> bool {
    b == 0x21 || (0x23..=0x2B).contains(&b) || (0x2D..=0x3A).contains(&b) || (0x3C..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b)
}

impl SetCookie {
    /// A session cookie `name=value` without attributes.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> SetCookie {
        SetCookie { name: name.into(), value: value.into(), expires: None, max_age: None, domain: None, path: None, secure: false, http_only: false, same_site: None, partitioned: false }
    }

    /// A cookie that deletes `name` (empty value, `Max-Age=0`, `Expires` in 1970). Set the
    /// same `Path` and `Domain` as the cookie it removes.
    pub fn removal(name: impl Into<String>) -> SetCookie {
        SetCookie::new(name, "").max_age(0).expires(SystemTime::UNIX_EPOCH)
    }

    pub fn expires(mut self, t: SystemTime) -> Self {
        self.expires = Some(t);
        self
    }
    /// Seconds; 0 or less deletes the cookie.
    pub fn max_age(mut self, secs: i64) -> Self {
        self.max_age = Some(secs);
        self
    }
    pub fn domain(mut self, d: impl Into<String>) -> Self {
        self.domain = Some(d.into());
        self
    }
    pub fn path(mut self, p: impl Into<String>) -> Self {
        self.path = Some(p.into());
        self
    }
    pub fn secure(mut self, on: bool) -> Self {
        self.secure = on;
        self
    }
    pub fn http_only(mut self, on: bool) -> Self {
        self.http_only = on;
        self
    }
    pub fn same_site(mut self, s: SameSite) -> Self {
        self.same_site = Some(s);
        self
    }
    pub fn partitioned(mut self, on: bool) -> Self {
        self.partitioned = on;
        self
    }

    /// The header value, after checking every part.
    pub fn to_header(&self) -> Result<String, CookieError> {
        if !is_token(&self.name) {
            return Err(CookieError::Name);
        }
        let v = self.value.as_bytes();
        let inner = if v.len() >= 2 && v[0] == b'"' && v[v.len() - 1] == b'"' { &v[1..v.len() - 1] } else { v };
        if !inner.iter().all(|&b| is_cookie_octet(b)) {
            return Err(CookieError::Value);
        }
        let attr_ok = |s: &str| s.bytes().all(|b| b >= 0x20 && b != 0x7F && b != b';');
        if !self.domain.as_deref().map_or(true, attr_ok) || !self.path.as_deref().map_or(true, attr_ok) {
            return Err(CookieError::Attribute);
        }
        if (self.same_site == Some(SameSite::None) || self.partitioned) && !self.secure {
            return Err(CookieError::NeedsSecure);
        }
        let mut s = format!("{}={}", self.name, self.value);
        if let Some(t) = self.expires {
            s.push_str("; Expires=");
            s.push_str(&crate::httpdate::format(t));
        }
        if let Some(a) = self.max_age {
            s.push_str(&format!("; Max-Age={}", a.max(0)));
        }
        if let Some(d) = &self.domain {
            s.push_str("; Domain=");
            s.push_str(d);
        }
        if let Some(p) = &self.path {
            s.push_str("; Path=");
            s.push_str(p);
        }
        if self.secure {
            s.push_str("; Secure");
        }
        if self.http_only {
            s.push_str("; HttpOnly");
        }
        if let Some(ss) = self.same_site {
            s.push_str(match ss {
                SameSite::Strict => "; SameSite=Strict",
                SameSite::Lax => "; SameSite=Lax",
                SameSite::None => "; SameSite=None",
            });
        }
        if self.partitioned {
            s.push_str("; Partitioned");
        }
        Ok(s)
    }
}

impl crate::Reply<'_> {
    /// Adds a `Set-Cookie` header. An invalid cookie turns the response into a 500.
    pub fn cookie(self, c: &SetCookie) -> Self {
        match c.to_header() {
            Ok(v) => self.header("set-cookie", v),
            Err(_) => self.header("set-cookie", "\0"),
        }
    }
}

impl crate::Response {
    /// Adds a `Set-Cookie` header (deferred replies). An invalid cookie makes it a 500.
    pub fn cookie(self, c: &SetCookie) -> Self {
        match c.to_header() {
            Ok(v) => self.header("set-cookie", v),
            Err(_) => self.header("set-cookie", "\0"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn parse_cookie_header() {
        let v: Vec<_> = parse_cookies(b"a=1; b=\"two\";c=;  d = x y ; =bad; noeq").collect();
        assert_eq!(v, [(&b"a"[..], &b"1"[..]), (b"b", b"two"), (b"c", b""), (b"d", b"x y")]);
    }

    #[test]
    fn set_cookie_attributes() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
        let c = SetCookie::new("id", "a3fWa").expires(t).max_age(-5).domain("example.com").path("/docs").secure(true).http_only(true).same_site(SameSite::None).partitioned(true);
        assert_eq!(c.to_header().unwrap(), "id=a3fWa; Expires=Sun, 06 Nov 1994 08:49:37 GMT; Max-Age=0; Domain=example.com; Path=/docs; Secure; HttpOnly; SameSite=None; Partitioned");
        assert_eq!(SetCookie::removal("x").to_header().unwrap(), "x=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0");
        assert_eq!(SetCookie::new("a b", "x").to_header(), Err(CookieError::Name));
        assert_eq!(SetCookie::new("a", "x;y").to_header(), Err(CookieError::Value));
        assert_eq!(SetCookie::new("a", "\"q\"").to_header().unwrap(), "a=\"q\"");
        assert_eq!(SetCookie::new("a", "x").path("/;x").to_header(), Err(CookieError::Attribute));
        assert_eq!(SetCookie::new("a", "x").same_site(SameSite::None).to_header(), Err(CookieError::NeedsSecure));
    }
}
