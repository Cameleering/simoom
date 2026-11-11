//! An RFC 6265bis cookie jar (feature `cookies`), opt-in per client:
//! [`ClientBuilder::cookie_jar`](crate::ClientBuilder::cookie_jar).
//!
//! ```no_run
//! use simoom_client::{cookie::CookieJar, Client};
//! use std::sync::Arc;
//!
//! let jar = Arc::new(CookieJar::new());
//! let client = Client::builder().cookie_jar(jar.clone()).follow_redirects(true).build();
//! client.post("https://shop.example/login").body("user=ann").send().unwrap();
//! // the session cookie set by the login response (and its redirects) goes with later requests
//! client.get("https://shop.example/basket").send().unwrap();
//! std::fs::write("cookies.txt", jar.export()).unwrap();
//! ```
//!
//! What it does (draft-ietf-httpbis-rfc6265bis):
//!
//! - **Parsing** of `Set-Cookie` per §5.6: control characters refuse the whole cookie, names and
//!   values together at most 4096 bytes, attribute values at most 1024 bytes, `Expires` through
//!   the cookie-date algorithm (§5.1.1), `Max-Age` taking precedence, both capped at 400 days;
//!   `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite` (`Strict`, `Lax`, `None`, anything else
//!   is "default") and `Partitioned`. The last occurrence of an attribute wins.
//! - **Storage** per §5.7: host-only cookies when there is no `Domain`; a `Domain` the request
//!   host does not domain-match is refused; `Secure` cookies only from secure origins, and an
//!   insecure origin cannot shadow an existing `Secure` cookie; the `__Secure-` and `__Host-`
//!   prefixes (case-insensitive); `SameSite=None` and `Partitioned` need `Secure`; a cookie
//!   with the same name, domain, host-only flag, path and partition replaces the old one and
//!   keeps its creation time; an expired cookie deletes it.
//! - **Public suffixes.** Without a list, the jar is conservative: a `Domain` attribute naming a
//!   single label (`com`, `localhost`) or an IP address other than the request host is
//!   refused, and a `Domain` equal to the host makes a host-only cookie. This blocks cookies for
//!   whole TLDs but **not** for multi-label public suffixes such as `co.uk` or `github.io`; to
//!   refuse those, load the Mozilla Public Suffix List (`public_suffix_list.dat`) with
//!   [`PublicSuffixList::parse`] and [`CookieJar::with_public_suffixes`]. No list is embedded,
//!   so the feature costs no data in the binary.
//! - **Limits**: at most 50 cookies per domain and 3000 in all by default
//!   ([`CookieJar::with_limits`]); expired cookies go first, then the least recently used.
//! - **Sending** per §5.8.3: domain and path matching, `Secure` only over `https`/`wss` (and to
//!   loopback hosts, as browsers treat them as secure contexts; see
//!   [`CookieJar::with_localhost_secure`]), longer paths first, then older cookies first. A
//!   `Cookie` header the caller set is kept and the jar's cookies are appended to it.
//! - **SameSite and partitions.** An HTTP client has no browsing context, so by default every
//!   request is same-site and every cookie is sent. With [`CookieJar::with_top_level_site`] the
//!   jar acts for a page of that site: requests to other sites are cross-site (`Strict` cookies
//!   are withheld, `Lax` ones only go with safe methods, and responses cannot set `Lax` or
//!   `Strict` cookies), and `Partitioned` cookies are keyed by that site. Sites are compared
//!   without the scheme; without a public suffix list the site of a host is its last two
//!   labels.
//! - **Export and import** in the Netscape `cookies.txt` format that curl and wget read and
//!   write ([`CookieJar::export`], [`CookieJar::import`]); `SameSite` and partition keys, which
//!   that format cannot hold, go in an optional eighth column.

use crate::body::Response;
use crate::hooks::{Action, Interceptor};
use crate::types::Request;
use crate::url::Url;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// 400 days, the longest lifetime 6265bis allows (§5.6.1, §5.6.2).
const MAX_AGE_CAP: i64 = 400 * 24 * 3600;
/// Name plus value (§5.6 step 5).
const MAX_NAME_VALUE: usize = 4096;
/// One attribute value (§5.6 step 7).
const MAX_ATTR_VALUE: usize = 1024;

/// The `SameSite` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// Absent or unrecognised: enforcement "default", which behaves like `None` here.
    Default,
    /// `SameSite=None` (needs `Secure`).
    None,
    /// `SameSite=Lax`.
    Lax,
    /// `SameSite=Strict`.
    Strict,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Default => "default",
            SameSite::None => "none",
            SameSite::Lax => "lax",
            SameSite::Strict => "strict",
        }
    }
}

/// A stored cookie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie {
    /// The name (may be empty: `Set-Cookie: value` stores a nameless cookie).
    pub name: String,
    /// The value.
    pub value: String,
    /// The domain, lower case, without a leading dot.
    pub domain: String,
    /// Sent only to `domain` itself (no `Domain` attribute), not to its subdomains.
    pub host_only: bool,
    /// The path.
    pub path: String,
    /// Expiry as seconds since the Unix epoch; `None` for a session cookie.
    pub expires: Option<i64>,
    /// Sent only over secure connections.
    pub secure: bool,
    /// `HttpOnly` (kept and exported; an HTTP client sends these like any other).
    pub http_only: bool,
    /// `SameSite`.
    pub same_site: SameSite,
    /// The partition key (top-level site) of a `Partitioned` cookie.
    pub partition: Option<String>,
    /// Creation time, seconds since the epoch.
    pub created: i64,
    /// Last time the cookie was sent or set.
    pub last_access: i64,
    seq: u64,
}

impl Cookie {
    fn same_key(&self, o: &Cookie) -> bool {
        self.name == o.name && self.domain == o.domain && self.host_only == o.host_only && self.path == o.path && self.partition == o.partition
    }

    fn expired(&self, now: i64) -> bool {
        self.expires.is_some_and(|e| e <= now)
    }

    /// `name=value` as sent in `Cookie` (just the value for a nameless cookie).
    pub fn pair(&self) -> String {
        if self.name.is_empty() {
            self.value.clone()
        } else {
            format!("{}={}", self.name, self.value)
        }
    }
}

/// Why a `Set-Cookie` value was not stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejected {
    /// Control characters, an empty name and value, or name and value over 4096 bytes.
    Syntax,
    /// The `Domain` attribute does not cover the request host, or is not ASCII.
    DomainMismatch,
    /// The `Domain` attribute is a public suffix (or, without a list, a single label or an IP
    /// address).
    PublicSuffix,
    /// `Secure` from an insecure origin, or an insecure cookie that would shadow a `Secure` one.
    Insecure,
    /// A `__Secure-` or `__Host-` cookie that breaks its prefix's rules.
    Prefix,
    /// `SameSite=None` or `Partitioned` without `Secure`.
    NeedsSecure,
    /// A `Lax` or `Strict` cookie set by a cross-site response.
    CrossSite,
    /// The cookie was already expired (an existing one with the same key was deleted).
    Expired,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Rejected::Syntax => "invalid Set-Cookie syntax",
            Rejected::DomainMismatch => "Domain attribute does not match the host",
            Rejected::PublicSuffix => "Domain attribute is a public suffix",
            Rejected::Insecure => "Secure cookie from an insecure origin, or would shadow a Secure cookie",
            Rejected::Prefix => "cookie name prefix rules broken",
            Rejected::NeedsSecure => "SameSite=None or Partitioned without Secure",
            Rejected::CrossSite => "Lax or Strict cookie set cross-site",
            Rejected::Expired => "cookie already expired",
        })
    }
}

impl std::error::Error for Rejected {}

/// A malformed line in [`CookieJar::import`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportError {
    /// 1-based line number.
    pub line: usize,
    /// What is wrong.
    pub reason: &'static str,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cookies.txt line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for ImportError {}

/// Public suffix rules in the format of the Mozilla Public Suffix List (one rule per line,
/// `*.` wildcards, `!` exceptions, `//` comments).
#[derive(Clone, Debug, Default)]
pub struct PublicSuffixList {
    rules: HashSet<String>,
    wildcards: HashSet<String>,
    exceptions: HashSet<String>,
}

impl PublicSuffixList {
    /// Parses the list text (for example `public_suffix_list.dat`). Rules are lower-cased;
    /// non-ASCII rules are skipped (hosts reach the jar in ASCII form).
    pub fn parse(text: &str) -> PublicSuffixList {
        let mut l = PublicSuffixList::default();
        for line in text.lines() {
            let rule = line.split_whitespace().next().unwrap_or("");
            if rule.is_empty() || rule.starts_with("//") || !rule.is_ascii() {
                continue;
            }
            let rule = rule.to_ascii_lowercase();
            if let Some(r) = rule.strip_prefix('!') {
                l.exceptions.insert(r.to_string());
            } else if let Some(r) = rule.strip_prefix("*.") {
                l.wildcards.insert(r.to_string());
            } else {
                l.rules.insert(rule);
            }
        }
        l
    }

    /// The public suffix of `domain` (lower case, ASCII); the implicit `*` rule makes the last
    /// label a suffix when nothing else matches.
    pub fn public_suffix<'a>(&self, domain: &'a str) -> &'a str {
        let mut starts = vec![0usize];
        starts.extend(domain.match_indices('.').map(|(i, _)| i + 1));
        for (k, &s) in starts.iter().enumerate() {
            let cand = &domain[s..];
            let parent = starts.get(k + 1).map(|&p| &domain[p..]);
            if self.exceptions.contains(cand) {
                return parent.unwrap_or(cand);
            }
            if self.rules.contains(cand) || parent.is_some_and(|p| self.wildcards.contains(p)) {
                return cand;
            }
        }
        domain.rsplit('.').next().unwrap_or(domain)
    }

    /// Whether `domain` is itself a public suffix.
    pub fn is_public_suffix(&self, domain: &str) -> bool {
        self.public_suffix(domain).len() == domain.len()
    }

    /// The registrable domain (public suffix plus one label), or `None` for a public suffix.
    pub fn registrable_domain<'a>(&self, domain: &'a str) -> Option<&'a str> {
        let ps = self.public_suffix(domain);
        if ps.len() == domain.len() {
            return None;
        }
        let head = &domain[..domain.len() - ps.len() - 1];
        let start = head.rfind('.').map_or(0, |i| i + 1);
        Some(&domain[start..])
    }
}

struct State {
    cookies: Vec<Cookie>,
    seq: u64,
    /// `Cookie` values this jar put on requests, with the caller's own part (see
    /// `before_send`), newest last.
    produced: VecDeque<(String, Option<String>)>,
}

/// A thread-safe cookie jar; share it between clients with an `Arc`. See the
/// [module documentation](self).
pub struct CookieJar {
    state: Mutex<State>,
    max_per_domain: usize,
    max_total: usize,
    psl: Option<Arc<PublicSuffixList>>,
    top_level_site: Option<String>,
    localhost_secure: bool,
}

impl std::fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieJar").field("cookies", &self.len()).field("top_level_site", &self.top_level_site).finish()
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        CookieJar::new()
    }
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn is_ip(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// §5.1.3: `host` domain-matches `domain`.
pub fn domain_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    !is_ip(host) && host.len() > domain.len() && host.ends_with(domain) && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// §5.1.4: the request path `path` path-matches the cookie path `cookie_path`.
pub fn path_match(path: &str, cookie_path: &str) -> bool {
    path == cookie_path
        || (path.starts_with(cookie_path) && (cookie_path.ends_with('/') || path.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}

/// §5.1.4: the default path of a request URI path.
pub fn default_path(path: &str) -> String {
    if !path.starts_with('/') {
        return "/".into();
    }
    match path.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => path[..i].to_string(),
    }
}

/// The cookie-date algorithm (§5.1.1): seconds since the Unix epoch, or `None`.
pub fn parse_cookie_date(s: &str) -> Option<i64> {
    let delim = |c: u8| c == 0x09 || (0x20..=0x2f).contains(&c) || (0x3b..=0x40).contains(&c) || (0x5b..=0x60).contains(&c) || (0x7b..=0x7e).contains(&c);
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    for tok in s.as_bytes().split(|&c| delim(c)).filter(|t| !t.is_empty()) {
        // leading 1*2DIGIT, then a non-digit or the end
        let digits = |t: &[u8], min: usize, max: usize| -> Option<(u32, usize)> {
            let n = t.iter().take_while(|c| c.is_ascii_digit()).count();
            if n < min || n > max {
                return None;
            }
            Some((t[..n].iter().fold(0u32, |a, &c| a * 10 + (c - b'0') as u32), n))
        };
        if time.is_none() {
            let parse_time = || -> Option<(u32, u32, u32)> {
                let (h, n1) = digits(tok, 1, 2)?;
                let r = tok.get(n1..)?.strip_prefix(b":")?;
                let (m, n2) = digits(r, 1, 2)?;
                let r = r.get(n2..)?.strip_prefix(b":")?;
                let (s, _) = digits(r, 1, 2)?;
                Some((h, m, s))
            };
            if let Some(t) = parse_time() {
                time = Some(t);
                continue;
            }
        }
        if day.is_none() {
            if let Some((d, _)) = digits(tok, 1, 2) {
                day = Some(d);
                continue;
            }
        }
        if month.is_none() && tok.len() >= 3 {
            const M: [&[u8; 3]; 12] = [b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov", b"dec"];
            if let Some(i) = M.iter().position(|m| tok[..3].eq_ignore_ascii_case(*m)) {
                month = Some(i as u32 + 1);
                continue;
            }
        }
        if year.is_none() {
            if let Some((y, _)) = digits(tok, 2, 4) {
                year = Some(y);
                continue;
            }
        }
    }
    let (h, mi, sec) = time?;
    let (d, mo, mut y) = (day?, month?, year?);
    if (70..=99).contains(&y) {
        y += 1900;
    } else if y <= 69 {
        y += 2000;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo as usize - 1];
    if d < 1 || d > dim || y < 1601 || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let (yy, m) = (if mo <= 2 { y as i64 - 1 } else { y as i64 }, mo as i64);
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h as i64 * 3600 + mi as i64 * 60 + sec as i64)
}

fn has_ctl(s: &str) -> bool {
    s.bytes().any(|c| (c < 0x20 && c != 0x09) || c == 0x7f)
}

fn trim_ws(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// A parsed `Set-Cookie` before the storage model ran.
struct Parsed<'a> {
    name: &'a str,
    value: &'a str,
    expires: Option<i64>,
    domain: Option<String>,
    path: Option<&'a str>,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    partitioned: bool,
}

/// §5.6: parses a `Set-Cookie` value. `now` turns `Max-Age` into an expiry.
fn parse_set_cookie(s: &str, now: i64) -> Result<Parsed<'_>, Rejected> {
    if has_ctl(s) {
        return Err(Rejected::Syntax);
    }
    let (nv, attrs) = match s.find(';') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };
    let (name, value) = match nv.find('=') {
        Some(i) => (trim_ws(&nv[..i]), trim_ws(&nv[i + 1..])),
        None => ("", trim_ws(nv)),
    };
    if (name.is_empty() && value.is_empty()) || name.len() + value.len() > MAX_NAME_VALUE {
        return Err(Rejected::Syntax);
    }
    if name.is_empty() {
        let v = value.as_bytes();
        let pre = |p: &[u8]| v.len() >= p.len() && v[..p.len()].eq_ignore_ascii_case(p);
        if pre(b"__Secure-") || pre(b"__Host-") {
            return Err(Rejected::Prefix);
        }
    }
    let mut p = Parsed { name, value, expires: None, domain: None, path: None, secure: false, http_only: false, same_site: SameSite::Default, partitioned: false };
    let (mut max_age, mut expires) = (None, None);
    for av in attrs.split(';') {
        let (an, aval) = match av.find('=') {
            Some(i) => (trim_ws(&av[..i]), trim_ws(&av[i + 1..])),
            None => (trim_ws(av), ""),
        };
        if aval.len() > MAX_ATTR_VALUE {
            continue;
        }
        match an.to_ascii_lowercase().as_str() {
            "expires" => {
                if let Some(t) = parse_cookie_date(aval) {
                    expires = Some(t.min(now.saturating_add(MAX_AGE_CAP)));
                }
            }
            "max-age" => {
                let b = aval.as_bytes();
                let ok = !b.is_empty() && (b[0].is_ascii_digit() || b[0] == b'-') && b[1..].iter().all(u8::is_ascii_digit) && b != b"-";
                if ok {
                    let delta: i64 = aval.parse().unwrap_or(if b[0] == b'-' { i64::MIN } else { i64::MAX });
                    max_age = Some(if delta <= 0 { i64::MIN } else { now.saturating_add(delta.min(MAX_AGE_CAP)) });
                }
            }
            "domain" => {
                if !aval.is_empty() {
                    let d = aval.strip_prefix('.').unwrap_or(aval);
                    p.domain = Some(d.to_ascii_lowercase());
                }
            }
            "path" => p.path = if aval.starts_with('/') { Some(aval) } else { None },
            "secure" => p.secure = true,
            "httponly" => p.http_only = true,
            "samesite" => {
                p.same_site = match aval.to_ascii_lowercase().as_str() {
                    "none" => SameSite::None,
                    "lax" => SameSite::Lax,
                    "strict" => SameSite::Strict,
                    _ => SameSite::Default,
                }
            }
            "partitioned" => p.partitioned = true,
            _ => {}
        }
    }
    p.expires = max_age.or(expires);
    Ok(p)
}

impl CookieJar {
    /// An empty jar with the default limits (50 per domain, 3000 in all).
    pub fn new() -> CookieJar {
        CookieJar {
            state: Mutex::new(State { cookies: Vec::new(), seq: 0, produced: VecDeque::new() }),
            max_per_domain: 50,
            max_total: 3000,
            psl: None,
            top_level_site: None,
            localhost_secure: true,
        }
    }

    /// Changes the per-domain and total caps (each at least 1).
    pub fn with_limits(mut self, per_domain: usize, total: usize) -> CookieJar {
        self.max_per_domain = per_domain.max(1);
        self.max_total = total.max(1);
        self
    }

    /// Refuses `Domain` attributes that are public suffixes by these rules (instead of the
    /// conservative single-label default) and uses them for sites.
    pub fn with_public_suffixes(mut self, psl: Arc<PublicSuffixList>) -> CookieJar {
        self.psl = Some(psl);
        self
    }

    /// Acts for a page of `site` (a host name such as `shop.example`; reduced to its
    /// registrable domain): requests to other sites are cross-site for `SameSite`, and
    /// `Partitioned` cookies are keyed by it. `None` (the default): every request is same-site.
    pub fn with_top_level_site(mut self, site: Option<&str>) -> CookieJar {
        self.top_level_site = site.map(|s| self.site_of(&s.to_ascii_lowercase()));
        self
    }

    /// Whether `http://` requests to loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) count as
    /// secure, as in browsers (default true).
    pub fn with_localhost_secure(mut self, on: bool) -> CookieJar {
        self.localhost_secure = on;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The site of a host: its registrable domain (public suffix plus one label), or the host
    /// itself for IP addresses and suffixes; without a list, the last two labels.
    fn site_of(&self, host: &str) -> String {
        if is_ip(host) {
            return host.to_string();
        }
        match &self.psl {
            Some(l) => l.registrable_domain(host).unwrap_or(host).to_string(),
            None => {
                let mut it = host.rmatch_indices('.');
                it.next();
                match it.next() {
                    Some((i, _)) => host[i + 1..].to_string(),
                    None => host.to_string(),
                }
            }
        }
    }

    fn is_secure(&self, url: &Url) -> bool {
        url.is_secure() || (self.localhost_secure && is_loopback(&url.host))
    }

    fn cross_site(&self, host: &str) -> bool {
        self.top_level_site.as_ref().is_some_and(|s| *s != self.site_of(host))
    }

    fn partition_key(&self, host: &str) -> String {
        self.top_level_site.clone().unwrap_or_else(|| self.site_of(host))
    }

    /// Stores a `Set-Cookie` value received from `url`.
    pub fn set_cookie(&self, url: &Url, set_cookie: &str) -> Result<(), Rejected> {
        self.set_cookie_at(url, set_cookie, now_secs())
    }

    /// [`CookieJar::set_cookie`] at a given time (seconds since the epoch).
    pub fn set_cookie_at(&self, url: &Url, set_cookie: &str, now: i64) -> Result<(), Rejected> {
        let p = parse_set_cookie(set_cookie, now)?;
        let host = url.host.to_ascii_lowercase();
        let secure_origin = self.is_secure(url);
        // §5.7 steps 5-6: Domain
        let (domain, host_only) = match p.domain {
            None => (host.clone(), true),
            Some(d) => {
                if !d.is_ascii() {
                    return Err(Rejected::DomainMismatch);
                }
                let suffix = match &self.psl {
                    Some(l) => l.is_public_suffix(&d),
                    None => !d.contains('.') || is_ip(&d),
                };
                if suffix {
                    if d == host {
                        (host.clone(), true)
                    } else {
                        return Err(Rejected::PublicSuffix);
                    }
                } else if !domain_match(&host, &d) {
                    return Err(Rejected::DomainMismatch);
                } else {
                    (d, false)
                }
            }
        };
        let path = p.path.map_or_else(|| default_path(&url.path), str::to_string);
        if p.secure && !secure_origin {
            return Err(Rejected::Insecure);
        }
        let lname = p.name.as_bytes();
        let pre = |x: &[u8]| lname.len() >= x.len() && lname[..x.len()].eq_ignore_ascii_case(x);
        if pre(b"__Secure-") && !p.secure {
            return Err(Rejected::Prefix);
        }
        if pre(b"__Host-") && !(p.secure && host_only && path == "/") {
            return Err(Rejected::Prefix);
        }
        if (p.same_site == SameSite::None || p.partitioned) && !p.secure {
            return Err(Rejected::NeedsSecure);
        }
        if matches!(p.same_site, SameSite::Lax | SameSite::Strict) && self.cross_site(&host) {
            return Err(Rejected::CrossSite);
        }
        let partition = if p.partitioned { Some(self.partition_key(&host)) } else { None };
        let mut st = self.lock();
        // §5.7 step 16: an insecure cookie must not shadow a Secure one
        if !p.secure && !secure_origin {
            let shadows = st.cookies.iter().any(|c| {
                c.secure && c.name == p.name && (domain_match(&domain, &c.domain) || domain_match(&c.domain, &domain)) && path_match(&path, &c.path)
            });
            if shadows {
                return Err(Rejected::Insecure);
            }
        }
        st.seq += 1;
        let seq = st.seq;
        let mut c = Cookie {
            name: p.name.to_string(),
            value: p.value.to_string(),
            domain,
            host_only,
            path,
            expires: p.expires,
            secure: p.secure,
            http_only: p.http_only,
            same_site: p.same_site,
            partition,
            created: now,
            last_access: now,
            seq,
        };
        if let Some(i) = st.cookies.iter().position(|o| o.same_key(&c)) {
            let old = st.cookies.remove(i);
            c.created = old.created;
            c.seq = old.seq;
        }
        if c.expired(now) {
            return Err(Rejected::Expired);
        }
        let d = c.domain.clone();
        st.cookies.push(c);
        self.evict(&mut st, &d, now);
        Ok(())
    }

    /// §5.7.1 (limits): expired cookies first, then the least recently used.
    fn evict(&self, st: &mut State, domain: &str, now: i64) {
        let per = st.cookies.iter().filter(|c| c.domain == domain).count();
        if per > self.max_per_domain || st.cookies.len() > self.max_total {
            st.cookies.retain(|c| !c.expired(now));
        }
        while st.cookies.iter().filter(|c| c.domain == domain).count() > self.max_per_domain {
            let i = st.cookies.iter().enumerate().filter(|(_, c)| c.domain == domain).min_by_key(|(_, c)| (c.last_access, c.seq)).map(|(i, _)| i);
            match i {
                Some(i) => st.cookies.remove(i),
                None => break,
            };
        }
        while st.cookies.len() > self.max_total {
            let i = st.cookies.iter().enumerate().min_by_key(|(_, c)| (c.last_access, c.seq)).map(|(i, _)| i);
            match i {
                Some(i) => st.cookies.remove(i),
                None => break,
            };
        }
    }

    /// The `Cookie` value for a same-site `GET` to `url`, or `None` when no cookie applies.
    pub fn cookie_header(&self, url: &Url) -> Option<String> {
        self.cookie_header_for(url, "GET", now_secs())
    }

    /// The `Cookie` value for a request with `method` to `url` at time `now`, honouring
    /// `SameSite` against [`CookieJar::with_top_level_site`]. Updates last-access times.
    pub fn cookie_header_for(&self, url: &Url, method: &str, now: i64) -> Option<String> {
        let host = url.host.to_ascii_lowercase();
        let secure = self.is_secure(url);
        let cross = self.cross_site(&host);
        let safe = matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE");
        let pkey = self.partition_key(&host);
        let mut st = self.lock();
        st.cookies.retain(|c| !c.expired(now));
        let mut hits: Vec<usize> = st
            .cookies
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                (if c.host_only { host == c.domain } else { domain_match(&host, &c.domain) })
                    && path_match(&url.path, &c.path)
                    && (!c.secure || secure)
                    && (!cross || match c.same_site {
                        SameSite::Strict => false,
                        SameSite::Lax => safe,
                        _ => true,
                    })
                    && c.partition.as_ref().is_none_or(|p| *p == pkey)
            })
            .map(|(i, _)| i)
            .collect();
        if hits.is_empty() {
            return None;
        }
        hits.sort_by(|&a, &b| {
            let (a, b) = (&st.cookies[a], &st.cookies[b]);
            b.path.len().cmp(&a.path.len()).then(a.created.cmp(&b.created)).then(a.seq.cmp(&b.seq))
        });
        let mut out = String::new();
        for i in hits {
            st.cookies[i].last_access = now;
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(&st.cookies[i].pair());
        }
        Some(out)
    }

    /// A snapshot of the cookies that have not expired.
    pub fn cookies(&self) -> Vec<Cookie> {
        let now = now_secs();
        self.lock().cookies.iter().filter(|c| !c.expired(now)).cloned().collect()
    }

    /// Number of stored cookies (expired ones included until the next access).
    pub fn len(&self) -> usize {
        self.lock().cookies.len()
    }

    /// True when the jar holds no cookie.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes the cookie with this domain, path and name; true if there was one.
    pub fn remove(&self, domain: &str, path: &str, name: &str) -> bool {
        let mut st = self.lock();
        let before = st.cookies.len();
        st.cookies.retain(|c| !(c.domain.eq_ignore_ascii_case(domain) && c.path == path && c.name == name));
        before != st.cookies.len()
    }

    /// Removes every cookie.
    pub fn clear(&self) {
        self.lock().cookies.clear();
    }

    /// Removes the session cookies (those without an expiry), as at the end of a session.
    pub fn clear_session(&self) {
        self.lock().cookies.retain(|c| c.expires.is_some());
    }

    /// The cookies in the Netscape `cookies.txt` format (curl's `-c`, wget's
    /// `--save-cookies`): `domain`, include-subdomains flag, `path`, secure flag, expiry (0 for
    /// session cookies), `name`, `value`, tab-separated, `#HttpOnly_` before the domain of
    /// HttpOnly cookies. An eighth column `samesite=...;partition=...` appears only for cookies
    /// that have those (curl does not read such lines).
    pub fn export(&self) -> String {
        let now = now_secs();
        let st = self.lock();
        let mut out = String::from("# Netscape HTTP Cookie File\n# Written by simoom-client.\n\n");
        let mut cs: Vec<&Cookie> = st.cookies.iter().filter(|c| !c.expired(now)).collect();
        cs.sort_by_key(|c| c.seq);
        for c in cs {
            let dom = if c.host_only { c.domain.clone() } else { format!(".{}", c.domain) };
            out.push_str(&format!(
                "{}{}\t{}\t{}\t{}\t{}\t{}\t{}",
                if c.http_only { "#HttpOnly_" } else { "" },
                dom,
                if c.host_only { "FALSE" } else { "TRUE" },
                c.path,
                if c.secure { "TRUE" } else { "FALSE" },
                c.expires.unwrap_or(0).max(0),
                c.name,
                c.value
            ));
            let mut ext = Vec::new();
            if c.same_site != SameSite::Default {
                ext.push(format!("samesite={}", c.same_site.as_str()));
            }
            if let Some(p) = &c.partition {
                ext.push(format!("partition={p}"));
            }
            if !ext.is_empty() {
                out.push('\t');
                out.push_str(&ext.join(";"));
            }
            out.push('\n');
        }
        out
    }

    /// Adds the cookies of a Netscape `cookies.txt` text (see [`CookieJar::export`]); expired
    /// ones are skipped. Returns how many were added; a malformed line fails the whole import
    /// and adds nothing.
    pub fn import(&self, text: &str) -> Result<usize, ImportError> {
        let now = now_secs();
        let mut parsed = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim_end_matches('\r');
            let err = |reason| ImportError { line: n + 1, reason };
            let (http_only, line) = match line.strip_prefix("#HttpOnly_") {
                Some(r) => (true, r),
                None => (false, line),
            };
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 7 && f.len() != 8 {
                return Err(err("expected 7 or 8 tab-separated fields"));
            }
            let flag = |s: &str| match s {
                "TRUE" => Ok(true),
                "FALSE" => Ok(false),
                _ => Err(err("flag is neither TRUE nor FALSE")),
            };
            let subdomains = flag(f[1])?;
            let secure = flag(f[3])?;
            let expiry: i64 = f[4].parse().map_err(|_| err("expiry is not a number"))?;
            let domain = f[0].strip_prefix('.').unwrap_or(f[0]).to_ascii_lowercase();
            if domain.is_empty() || !domain.is_ascii() || has_ctl(f[5]) || has_ctl(f[6]) || !f[2].starts_with('/') {
                return Err(err("invalid domain, path, name or value"));
            }
            if f[5].is_empty() && f[6].is_empty() || f[5].len() + f[6].len() > MAX_NAME_VALUE {
                return Err(err("invalid name or value"));
            }
            let (mut same_site, mut partition) = (SameSite::Default, None);
            if let Some(ext) = f.get(7) {
                for kv in ext.split(';').filter(|s| !s.is_empty()) {
                    match kv.split_once('=') {
                        Some(("samesite", v)) => {
                            same_site = match v {
                                "none" => SameSite::None,
                                "lax" => SameSite::Lax,
                                "strict" => SameSite::Strict,
                                _ => SameSite::Default,
                            }
                        }
                        Some(("partition", v)) if !v.is_empty() => partition = Some(v.to_ascii_lowercase()),
                        _ => return Err(err("unknown extension column entry")),
                    }
                }
            }
            let expires = if expiry == 0 { None } else { Some(expiry.min(now.saturating_add(MAX_AGE_CAP))) };
            if expires.is_some_and(|e| e <= now) {
                continue;
            }
            parsed.push(Cookie {
                name: f[5].to_string(),
                value: f[6].to_string(),
                domain,
                host_only: !subdomains,
                path: f[2].to_string(),
                expires,
                secure,
                http_only,
                same_site,
                partition,
                created: now,
                last_access: now,
                seq: 0,
            });
        }
        let mut st = self.lock();
        let n = parsed.len();
        for mut c in parsed {
            st.seq += 1;
            c.seq = st.seq;
            if let Some(i) = st.cookies.iter().position(|o| o.same_key(&c)) {
                st.cookies.remove(i);
            }
            let d = c.domain.clone();
            st.cookies.push(c);
            self.evict(&mut st, &d, now);
        }
        Ok(n)
    }
}

/// Splits a `Cookie` value the caller set from the part this jar added on an earlier attempt.
fn caller_part(st: &State, current: Option<&str>) -> Option<String> {
    let cur = current?;
    match st.produced.iter().rev().find(|(v, _)| v == cur) {
        Some((_, user)) => user.clone(),
        None => Some(cur.to_string()),
    }
}

impl Interceptor for CookieJar {
    /// Adds the jar's cookies for this attempt's URL, after any `Cookie` value the caller set.
    /// A value this jar added on an earlier attempt (a redirect, an authentication retry) is
    /// recomputed rather than kept.
    fn before_send(&self, req: &mut Request) {
        let jar = self.cookie_header_for(&req.url, &req.method, now_secs());
        let mut st = self.lock();
        let user = caller_part(&st, req.headers.get("cookie"));
        let value = match (&user, &jar) {
            (Some(u), Some(j)) if !u.trim().is_empty() => format!("{u}; {j}"),
            (_, Some(j)) => j.clone(),
            (Some(u), None) => u.clone(),
            (None, None) => {
                req.headers.remove("cookie");
                return;
            }
        };
        if jar.is_some() {
            if st.produced.len() >= 128 {
                st.produced.pop_front();
            }
            st.produced.push_back((value.clone(), user));
        }
        drop(st);
        req.headers.set("Cookie", value);
    }

    /// Stores every `Set-Cookie` of the response (redirects and `401`s included); refused
    /// cookies are dropped silently.
    fn on_response(&self, _req: &Request, resp: &Response) -> Action {
        let now = now_secs();
        for v in resp.headers().get_all("set-cookie") {
            let _ = self.set_cookie_at(resp.url(), v, now);
        }
        Action::Continue
    }
}

impl crate::client::ClientBuilder {
    /// Keeps cookies in `jar` (RFC 6265bis): every response's `Set-Cookie` is stored and every
    /// request carries the matching cookies. Share one jar between clients by cloning the `Arc`.
    pub fn cookie_jar(self, jar: Arc<CookieJar>) -> Self {
        self.interceptor(jar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// A fixed "now" for the whole test run (`cookies()` filters by the real clock).
    fn t0() -> i64 {
        static T: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
        *T.get_or_init(now_secs)
    }

    #[test]
    fn cookie_dates() {
        // RFC 6265 / 6265bis examples and the formats seen in the wild
        assert_eq!(parse_cookie_date("Wed, 09 Jun 2021 10:18:14 GMT"), Some(1623233894));
        assert_eq!(parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784111777));
        assert_eq!(parse_cookie_date("Sunday, 06-Nov-94 08:49:37 GMT"), Some(784111777));
        assert_eq!(parse_cookie_date("Sun Nov  6 08:49:37 1994"), Some(784111777));
        assert_eq!(parse_cookie_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_cookie_date("1 jan 2030 0:0:0"), Some(1893456000));
        assert_eq!(parse_cookie_date("Mon, 01-Jan-69 00:00:00 GMT"), Some(3124224000)); // 2069
        // invalid: missing parts, out of range, non-existent day, year before 1601
        assert_eq!(parse_cookie_date("Wed, 09 Jun 2021"), None);
        assert_eq!(parse_cookie_date("Wed, 32 Jun 2021 10:18:14"), None);
        assert_eq!(parse_cookie_date("Wed, 31 Jun 2021 10:18:14"), None);
        assert_eq!(parse_cookie_date("Wed, 29 Feb 2021 10:18:14"), None);
        assert_eq!(parse_cookie_date("Wed, 29 Feb 2024 10:18:14").map(|t| t > 0), Some(true));
        assert_eq!(parse_cookie_date("09 Jun 1600 10:18:14"), None);
        assert_eq!(parse_cookie_date("09 Jun 2021 24:00:00"), None);
        assert_eq!(parse_cookie_date("09 Jun 2021 10:60:00"), None);
    }

    #[test]
    fn matching_helpers() {
        assert!(domain_match("www.example.com", "example.com"));
        assert!(domain_match("example.com", "example.com"));
        assert!(!domain_match("badexample.com", "example.com"));
        assert!(!domain_match("example.com", "www.example.com"));
        assert!(!domain_match("1.2.3.4", "2.3.4"));
        assert!(path_match("/", "/"));
        assert!(path_match("/docs/web", "/docs"));
        assert!(path_match("/docs/", "/docs"));
        assert!(path_match("/docs/web", "/docs/"));
        assert!(!path_match("/docsets", "/docs"));
        assert!(!path_match("/", "/docs"));
        assert_eq!(default_path("/a/b/c"), "/a/b");
        assert_eq!(default_path("/a"), "/");
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path(""), "/");
    }

    #[test]
    fn parse_and_send_basics() {
        let j = CookieJar::new();
        let a = u("https://www.example.com/docs/index.html");
        j.set_cookie_at(&a, "SID=31d4d96e407aad42", t0()).unwrap();
        j.set_cookie_at(&a, "lang=en-US; Path=/; Domain=example.com", t0()).unwrap();
        // host-only SID with the default path /docs; lang for the domain
        assert_eq!(j.cookie_header_for(&a, "GET", t0()).as_deref(), Some("SID=31d4d96e407aad42; lang=en-US"));
        assert_eq!(j.cookie_header_for(&u("https://example.com/docs/x"), "GET", t0()).as_deref(), Some("lang=en-US"));
        assert_eq!(j.cookie_header_for(&u("https://sub.www.example.com/docs/x"), "GET", t0()).as_deref(), Some("lang=en-US"));
        assert_eq!(j.cookie_header_for(&u("https://www.example.com/"), "GET", t0()).as_deref(), Some("lang=en-US"));
        assert_eq!(j.cookie_header_for(&u("https://example.org/"), "GET", t0()), None);
        // whitespace, a nameless cookie, attribute case, last attribute wins
        j.set_cookie_at(&a, "  sp =  v 1 ; PATH=/x ; path=/", t0()).unwrap();
        j.set_cookie_at(&a, "nameless", t0()).unwrap();
        let h = j.cookie_header_for(&u("https://www.example.com/docs/"), "GET", t0()).unwrap();
        assert!(h.contains("sp=v 1") && h.contains("; nameless"), "{h}");
        // syntax errors
        assert_eq!(j.set_cookie_at(&a, "=", t0()), Err(Rejected::Syntax));
        assert_eq!(j.set_cookie_at(&a, "a=b\x01c", t0()), Err(Rejected::Syntax));
        assert_eq!(j.set_cookie_at(&a, &format!("a={}", "x".repeat(4096)), t0()), Err(Rejected::Syntax));
        assert!(j.set_cookie_at(&a, "tab=a\tb", t0()).is_ok());
        // an over-long attribute value is ignored, not the cookie
        j.set_cookie_at(&a, &format!("long=1; Path=/{}", "p".repeat(1100)), t0()).unwrap();
        assert!(j.cookies().iter().any(|c| c.name == "long" && c.path == "/docs"));
    }

    #[test]
    fn domain_rules_and_public_suffixes() {
        let j = CookieJar::new();
        let a = u("http://www.example.com/");
        assert_eq!(j.set_cookie_at(&a, "a=1; Domain=example.org", t0()), Err(Rejected::DomainMismatch));
        assert_eq!(j.set_cookie_at(&a, "a=1; Domain=ww.example.com", t0()), Err(Rejected::DomainMismatch));
        assert_eq!(j.set_cookie_at(&a, "a=1; Domain=com", t0()), Err(Rejected::PublicSuffix));
        assert_eq!(j.set_cookie_at(&a, "a=1; Domain=.com", t0()), Err(Rejected::PublicSuffix));
        j.set_cookie_at(&a, "a=1; Domain=.EXAMPLE.com", t0()).unwrap();
        assert!(j.cookies()[0].domain == "example.com" && !j.cookies()[0].host_only);
        // a single-label host may set a cookie for itself only: host-only
        let l = u("http://intranet/");
        j.set_cookie_at(&l, "b=2; Domain=intranet", t0()).unwrap();
        assert!(j.cookies().iter().any(|c| c.name == "b" && c.host_only));
        // IP hosts: only the exact address, host-only
        let ip = u("http://10.0.0.1/");
        assert_eq!(j.set_cookie_at(&ip, "c=3; Domain=0.0.1", t0()), Err(Rejected::DomainMismatch));
        assert_eq!(j.set_cookie_at(&ip, "c=3; Domain=10.0.0.2", t0()), Err(Rejected::PublicSuffix));
        j.set_cookie_at(&ip, "c=3; Domain=10.0.0.1", t0()).unwrap();
        assert_eq!(j.cookie_header_for(&ip, "GET", t0()).as_deref(), Some("c=3"));
        // without a list co.uk is accepted (documented); with one it is refused
        let uk = u("http://www.shop.co.uk/");
        assert!(j.set_cookie_at(&uk, "d=4; Domain=co.uk", t0()).is_ok());
        let psl = Arc::new(PublicSuffixList::parse("// comment\ncom\nuk\nco.uk\n*.ck\n!www.ck\ngithub.io\n"));
        let j2 = CookieJar::new().with_public_suffixes(psl.clone());
        assert_eq!(j2.set_cookie_at(&uk, "d=4; Domain=co.uk", t0()), Err(Rejected::PublicSuffix));
        j2.set_cookie_at(&uk, "d=4; Domain=shop.co.uk", t0()).unwrap();
        assert_eq!(j2.set_cookie_at(&u("http://a.github.io/"), "e=5; Domain=github.io", t0()), Err(Rejected::PublicSuffix));
        j2.set_cookie_at(&u("http://github.io/"), "e=5; Domain=github.io", t0()).unwrap();
        assert!(j2.cookies().iter().any(|c| c.name == "e" && c.host_only));
        assert!(psl.is_public_suffix("foo.ck") && !psl.is_public_suffix("www.ck"));
        assert_eq!(psl.registrable_domain("a.b.shop.co.uk"), Some("shop.co.uk"));
        assert_eq!(psl.registrable_domain("x.www.ck"), Some("www.ck"));
        assert_eq!(psl.registrable_domain("co.uk"), None);
        assert_eq!(psl.public_suffix("example.unknowntld"), "unknowntld");
    }

    #[test]
    fn overwrite_expiry_and_max_age() {
        let j = CookieJar::new();
        let a = u("https://example.com/");
        j.set_cookie_at(&a, "k=1; Max-Age=100", t0()).unwrap();
        let created = j.cookies()[0].created;
        j.set_cookie_at(&a, "k=2; Max-Age=100", t0() + 10).unwrap();
        let c = j.cookies();
        assert_eq!((c.len(), c[0].value.as_str(), c[0].created), (1, "2", created));
        // a different path is a different cookie
        j.set_cookie_at(&a, "k=3; Path=/p", t0()).unwrap();
        assert_eq!(j.len(), 2);
        // expiry: Max-Age wins over Expires, whatever the order
        j.set_cookie_at(&a, "m=1; Max-Age=10; Expires=Wed, 09 Jun 2100 10:18:14 GMT", t0()).unwrap();
        assert_eq!(j.cookies().iter().find(|c| c.name == "m").unwrap().expires, Some(t0() + 10));
        assert!(j.cookie_header_for(&a, "GET", t0() + 9).unwrap().contains("m=1"));
        assert!(!j.cookie_header_for(&a, "GET", t0() + 10).unwrap().contains("m=1"));
        // capped at 400 days
        j.set_cookie_at(&a, "n=1; Expires=Wed, 09 Jun 2100 10:18:14 GMT", t0()).unwrap();
        assert_eq!(j.cookies().iter().find(|c| c.name == "n").unwrap().expires, Some(t0() + MAX_AGE_CAP));
        // Max-Age=0 or negative deletes; invalid Max-Age is ignored
        assert_eq!(j.set_cookie_at(&a, "k=x; Max-Age=0", t0() + 20), Err(Rejected::Expired));
        assert!(!j.cookies().iter().any(|c| c.name == "k" && c.path == "/"));
        j.set_cookie_at(&a, "o=1; Max-Age=abc", t0()).unwrap();
        assert_eq!(j.cookies().iter().find(|c| c.name == "o").unwrap().expires, None);
        assert_eq!(j.set_cookie_at(&a, "o=1; Max-Age=-5", t0()), Err(Rejected::Expired));
        // an Expires in the past deletes
        j.set_cookie_at(&a, "p=1", t0()).unwrap();
        assert_eq!(j.set_cookie_at(&a, "p=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT", t0()), Err(Rejected::Expired));
        assert!(!j.cookies().iter().any(|c| c.name == "p"));
        j.clear_session();
        assert!(j.cookies().iter().all(|c| c.expires.is_some()));
    }

    #[test]
    fn secure_prefixes_and_shadowing() {
        let j = CookieJar::new().with_localhost_secure(false);
        let http = u("http://example.com/");
        let https = u("https://example.com/");
        assert_eq!(j.set_cookie_at(&http, "s=1; Secure", t0()), Err(Rejected::Insecure));
        j.set_cookie_at(&https, "s=1; Secure", t0()).unwrap();
        // not sent over http
        assert_eq!(j.cookie_header_for(&http, "GET", t0()), None);
        assert_eq!(j.cookie_header_for(&https, "GET", t0()).as_deref(), Some("s=1"));
        // an insecure origin cannot shadow it (same name, overlapping domain and path)
        assert_eq!(j.set_cookie_at(&http, "s=evil", t0()), Err(Rejected::Insecure));
        assert_eq!(j.set_cookie_at(&u("http://sub.example.com/"), "s=evil; Domain=example.com", t0()), Err(Rejected::Insecure));
        // prefixes
        assert_eq!(j.set_cookie_at(&https, "__Secure-a=1", t0()), Err(Rejected::Prefix));
        j.set_cookie_at(&https, "__Secure-a=1; Secure", t0()).unwrap();
        assert_eq!(j.set_cookie_at(&https, "__Host-b=1; Secure; Path=/; Domain=example.com", t0()), Err(Rejected::Prefix));
        assert_eq!(j.set_cookie_at(&https, "__Host-b=1; Secure; Path=/x", t0()), Err(Rejected::Prefix));
        assert_eq!(j.set_cookie_at(&https, "__host-b=1; Path=/", t0()), Err(Rejected::Prefix));
        j.set_cookie_at(&https, "__Host-b=1; Secure; Path=/", t0()).unwrap();
        assert_eq!(j.set_cookie_at(&https, "=__Secure-x", t0()), Err(Rejected::Prefix));
        // localhost counts as secure by default
        let lj = CookieJar::new();
        lj.set_cookie_at(&u("http://127.0.0.1:8080/"), "l=1; Secure", t0()).unwrap();
        assert_eq!(lj.cookie_header_for(&u("http://127.0.0.1:9/"), "GET", t0()).as_deref(), Some("l=1"));
    }

    #[test]
    fn same_site_and_partitions() {
        let a = u("https://a.example/");
        let b = u("https://b.test/");
        // no top-level site: everything is same-site
        let j = CookieJar::new();
        j.set_cookie_at(&a, "st=1; SameSite=Strict", t0()).unwrap();
        assert_eq!(j.set_cookie_at(&a, "n=1; SameSite=None", t0()), Err(Rejected::NeedsSecure));
        assert_eq!(j.cookie_header_for(&a, "POST", t0()).as_deref(), Some("st=1"));
        // acting for a page of b.test: a.example is cross-site
        let j = CookieJar::new().with_top_level_site(Some("www.b.test"));
        assert_eq!(j.set_cookie_at(&a, "st=1; SameSite=Strict; Secure", t0()), Err(Rejected::CrossSite));
        assert_eq!(j.set_cookie_at(&a, "lx=1; SameSite=Lax", t0()), Err(Rejected::CrossSite));
        j.set_cookie_at(&a, "no=1; SameSite=None; Secure", t0()).unwrap();
        j.set_cookie_at(&a, "df=1; SameSite=bogus", t0()).unwrap();
        j.set_cookie_at(&b, "st=1; SameSite=Strict", t0()).unwrap();
        j.set_cookie_at(&b, "lx=1; SameSite=Lax", t0()).unwrap();
        assert_eq!(j.cookie_header_for(&a, "GET", t0()).as_deref(), Some("no=1; df=1"));
        assert_eq!(j.cookie_header_for(&b, "POST", t0()).as_deref(), Some("st=1; lx=1"));
        let cross = CookieJar::new().with_top_level_site(Some("other.site"));
        cross.import(&j.export()).unwrap();
        // from other.site, b.test's Lax cookie goes only with safe methods, Strict never
        assert_eq!(cross.cookie_header_for(&b, "GET", t0()).as_deref(), Some("lx=1"));
        assert_eq!(cross.cookie_header_for(&b, "POST", t0()), None);
        // Partitioned: needs Secure, keyed by the top-level site
        assert_eq!(j.set_cookie_at(&a, "p=1; Partitioned", t0()), Err(Rejected::NeedsSecure));
        j.set_cookie_at(&a, "p=1; Partitioned; Secure; SameSite=None", t0()).unwrap();
        let c = j.cookies().into_iter().find(|c| c.name == "p").unwrap();
        assert_eq!(c.partition.as_deref(), Some("b.test"));
        assert!(j.cookie_header_for(&a, "GET", t0()).unwrap().contains("p=1"));
        let other = CookieJar::new().with_top_level_site(Some("c.test"));
        other.import(&j.export()).unwrap();
        assert!(!other.cookie_header_for(&a, "GET", t0()).unwrap_or_default().contains("p=1"));
    }

    #[test]
    fn order_limits_and_eviction() {
        let j = CookieJar::new().with_limits(3, 5);
        let a = u("https://example.com/a/b/c");
        j.set_cookie_at(&a, "root=1; Path=/", t0()).unwrap();
        j.set_cookie_at(&a, "deep=1; Path=/a/b", t0() + 1).unwrap();
        j.set_cookie_at(&a, "mid=1; Path=/a", t0() + 2).unwrap();
        // longest path first; same path: older first
        assert_eq!(j.cookie_header_for(&a, "GET", t0() + 3).as_deref(), Some("deep=1; mid=1; root=1"));
        // a fourth cookie for the domain evicts the least recently used (all accessed at t0()+3,
        // so the oldest by creation: root)
        j.set_cookie_at(&a, "new=1; Path=/", t0() + 4).unwrap();
        let names: Vec<String> = j.cookies().into_iter().map(|c| c.name).collect();
        assert_eq!(names.len(), 3);
        assert!(!names.contains(&"root".to_string()), "{names:?}");
        // total cap across domains
        for (i, d) in ["x.test", "y.test", "z.test"].iter().enumerate() {
            j.set_cookie_at(&u(&format!("https://{d}/")), "c=1", t0() + 10 + i as i64).unwrap();
        }
        assert_eq!(j.len(), 5);
        assert!(j.cookies().iter().any(|c| c.domain == "z.test"));
    }

    #[test]
    fn export_import_round_trip() {
        let j = CookieJar::new();
        let a = u("https://www.example.com/");
        j.set_cookie_at(&a, &format!("s=1; Secure; HttpOnly; Path=/; Max-Age={}", 3600), now_secs()).unwrap();
        j.set_cookie_at(&a, "d=2; Domain=example.com; SameSite=Lax", now_secs()).unwrap();
        j.set_cookie_at(&a, "sess=3", now_secs()).unwrap();
        let txt = j.export();
        assert!(txt.contains("#HttpOnly_www.example.com\tFALSE\t/\tTRUE\t"), "{txt}");
        assert!(txt.contains(".example.com\tTRUE\t/\tFALSE\t0\td\t2\tsamesite=lax"), "{txt}");
        let k = CookieJar::new();
        assert_eq!(k.import(&txt), Ok(3));
        let mut x = j.cookies();
        let mut y = k.cookies();
        for c in x.iter_mut().chain(y.iter_mut()) {
            (c.created, c.last_access, c.seq) = (0, 0, 0);
        }
        assert_eq!(x, y);
        // curl's own lines, and errors
        let curl = "# Netscape HTTP Cookie File\n.curl.se\tTRUE\t/\tFALSE\t0\tname\tvalue\n\n";
        assert_eq!(k.import(curl), Ok(1));
        assert_eq!(k.import("a\tTRUE\t/\n").unwrap_err().line, 1);
        assert_eq!(k.import("\nx.test\tYES\t/\tFALSE\t0\ta\tb\n").unwrap_err().line, 2);
        assert_eq!(k.import("x.test\tTRUE\t/\tFALSE\t1\told\tb\n"), Ok(0));
    }
}
