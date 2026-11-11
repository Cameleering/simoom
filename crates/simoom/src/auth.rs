//! HTTP authentication for servers (feature `auth`): Basic (RFC 7617) with constant-time
//! checks, Digest (RFC 7616) with stateless signed nonces, nonce-count replay protection,
//! `stale=true` and `rspauth`, Bearer token extraction (RFC 6750), and [`Auth::wrap`], a
//! [`Service`] wrapper that challenges unauthenticated requests.
//!
//! ```no_run
//! # #[cfg(feature = "auth")] {
//! use simoom::auth::{Auth, Basic, Credential, Digest};
//! use simoom::{Outcome, Reply, Request, Server};
//!
//! let users = |user: &str| (user == "ann").then(|| "s3cret".to_string());
//! let digest = Digest::new("api@example", move |user: &str, _alg| users(user).map(Credential::Password));
//! let auth = Auth::new().digest(digest).basic(Basic::new("api@example", users));
//! let app = auth.wrap_with_user(|_req: &mut Request<'_>, reply: Reply<'_>, user: &str| -> Outcome {
//!     reply.body(format!("hello {user}"))
//! });
//! Server::builder().listen("127.0.0.1:8080").service(app).start().unwrap();
//! # }
//! ```
//!
//! **Digest nonces** carry their issue time and 8 random bytes and are signed with
//! HMAC-SHA-256 under a key of the [`Digest`] (random per process, or
//! [`Digest::secret`] for several instances behind one name), so issuing one stores nothing. A
//! nonce older than [`Digest::nonce_ttl`] (5 minutes by default) is answered with
//! `stale=true`, and a fresh one is offered in `Authentication-Info: nextnonce` once half its
//! life is over. Nonce counts are tracked per nonce in a 64-wide window, so a replayed or
//! too-old `nc` is refused while requests that overtake each other still pass; the table is
//! bounded ([`Digest::max_tracked_nonces`]) and forgets expired nonces first.
//!
//! **Limits**: `userhash` is not offered (looking a user up by hash needs every name);
//! `qop=auth-int` needs a buffered request body (a streamed one is refused) and its
//! `rspauth` is not sent (it would cover the response body, unknown before the handler runs);
//! the RFC 2069 form without `qop` is refused.

use crate::service::{Outcome, Service, WatchRef};
use crate::{Reply, Request};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Constant-time equality (the time depends on the lengths only).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    simoom_tls::util::ct_eq(a, b)
}

fn authorization<'a>(req: &Request<'a>, scheme: &str) -> Option<&'a [u8]> {
    let v = req.header("authorization")?;
    let v = trim(v);
    let n = scheme.len();
    (v.len() > n && v[..n].eq_ignore_ascii_case(scheme.as_bytes()) && v[n] == b' ').then(|| trim(&v[n + 1..]))
}

fn trim(v: &[u8]) -> &[u8] {
    let s = v.iter().position(|c| !matches!(c, b' ' | b'\t')).unwrap_or(v.len());
    let e = v.iter().rposition(|c| !matches!(c, b' ' | b'\t')).map_or(s, |i| i + 1);
    &v[s..e]
}

/// The user name and password of an `Authorization: Basic` header (RFC 7617; UTF-8, the
/// name ends at the first colon), or `None`.
pub fn basic_credentials(req: &Request<'_>) -> Option<(String, String)> {
    let b = authorization(req, "basic")?;
    let mut raw = Vec::new();
    if !simoom_http1::base64_decode(b, &mut raw) {
        return None;
    }
    let s = String::from_utf8(raw).ok()?;
    let (u, p) = s.split_once(':')?;
    if u.chars().chain(p.chars()).any(char::is_control) {
        return None;
    }
    Some((u.to_string(), p.to_string()))
}

/// The token of an `Authorization: Bearer` header (RFC 6750 §2.1: a token68), or `None`.
pub fn bearer_token<'a>(req: &Request<'a>) -> Option<&'a str> {
    let t = authorization(req, "bearer")?;
    let body = t.iter().rposition(|&c| c != b'=').map_or(0, |i| i + 1);
    let ok = body > 0 && t[..body].iter().all(|c| c.is_ascii_alphanumeric() || b"-._~+/".contains(c));
    if ok {
        std::str::from_utf8(t).ok()
    } else {
        None
    }
}

fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('"');
    o
}

// -------------------------------------------------------------------------------- Basic

type PasswordLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Basic authentication (RFC 7617). `lookup` returns the stored password of a user; it is
/// compared in constant time (unknown users are compared against a dummy, so the timing
/// does not tell which names exist).
#[derive(Clone)]
pub struct Basic {
    realm: String,
    lookup: PasswordLookup,
}

impl std::fmt::Debug for Basic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Basic").field("realm", &self.realm).finish_non_exhaustive()
    }
}

impl Basic {
    /// Basic for `realm` with a password lookup.
    pub fn new(realm: &str, lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Basic {
        Basic { realm: realm.into(), lookup: Arc::new(lookup) }
    }

    /// The `WWW-Authenticate` value.
    pub fn challenge(&self) -> String {
        format!("Basic realm={}, charset=\"UTF-8\"", quote(&self.realm))
    }

    /// The user, when the request carries valid Basic credentials.
    pub fn verify(&self, req: &Request<'_>) -> Option<String> {
        let (user, pass) = basic_credentials(req)?;
        let stored = (self.lookup)(&user);
        let ok = ct_eq(stored.as_deref().unwrap_or("\u{0}no-such-user").as_bytes(), pass.as_bytes());
        (ok && stored.is_some()).then_some(user)
    }
}

// ------------------------------------------------------------------------------- Digest

/// Digest algorithms (RFC 7616 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// `MD5`.
    Md5,
    /// `SHA-256`.
    Sha256,
    /// `SHA-512-256`.
    Sha512_256,
}

impl DigestAlgorithm {
    fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Md5 => "MD5",
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha512_256 => "SHA-512-256",
        }
    }

    /// The lower-case hex digest of the concatenation of `parts`.
    pub fn hash_hex(self, parts: &[&[u8]]) -> String {
        use simoom_tls::crypto::sha2::{Sha256, Sha512};
        let bytes: Vec<u8> = match self {
            DigestAlgorithm::Md5 => {
                let mut h = simoom_tls::crypto::legacy::Md5::new();
                for p in parts {
                    h.update(p);
                }
                h.finish().to_vec()
            }
            DigestAlgorithm::Sha256 => {
                let mut h = Sha256::new();
                for p in parts {
                    h.update(p);
                }
                h.finish().to_vec()
            }
            DigestAlgorithm::Sha512_256 => {
                let mut h = Sha512::new512_256();
                for p in parts {
                    h.update(p);
                }
                h.finish().to_vec()
            }
        };
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// What the Digest lookup returns for a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// The password.
    Password(String),
    /// The stored `H(user:realm:password)` in hex for the asked algorithm, so the password
    /// need not be kept.
    Ha1(String),
}

type CredentialLookup = Arc<dyn Fn(&str, DigestAlgorithm) -> Option<Credential> + Send + Sync>;

/// The result of [`Digest::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DigestOutcome {
    /// Valid: the user and the `Authentication-Info` value to send.
    Authorized {
        /// The user name.
        user: String,
        /// The `Authentication-Info` header value (`rspauth`, `qop`, `nc`, `cnonce`, maybe
        /// `nextnonce`).
        info: String,
    },
    /// Valid credentials on an expired nonce: challenge again with `stale=true`.
    Stale,
    /// No Digest credentials, or wrong ones, or a replay.
    Denied,
}

struct NonceState {
    issued: u64,
    max_nc: u64,
    window: u64,
}

/// Digest authentication (RFC 7616). See the [module documentation](self).
pub struct Digest {
    realm: String,
    algorithms: Vec<(DigestAlgorithm, bool)>,
    auth_int: bool,
    key: [u8; 32],
    ttl: Duration,
    opaque: String,
    lookup: CredentialLookup,
    seen: Mutex<HashMap<String, NonceState>>,
    max_tracked: usize,
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Digest").field("realm", &self.realm).field("algorithms", &self.algorithms).field("ttl", &self.ttl).finish_non_exhaustive()
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    if !simoom_sys::arch::os_random(&mut b) {
        // no OS source: never expected; mix the clock so nonces stay unique
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map_or(1, |d| d.as_nanos() as u64) | 1;
        let mut x = t;
        for v in b.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *v = x as u8;
        }
    }
    b
}

fn b64(d: &[u8]) -> String {
    let mut o = Vec::new();
    simoom_http1::base64_encode(d, &mut o);
    String::from_utf8(o).unwrap_or_default()
}

/// Parses `name=value, name="value"` auth-params (names lower case).
fn auth_params(v: &[u8]) -> Option<HashMap<String, String>> {
    let mut m = HashMap::new();
    let mut i = 0;
    let ws = |i: &mut usize| {
        while *i < v.len() && matches!(v[*i], b' ' | b'\t') {
            *i += 1;
        }
    };
    loop {
        ws(&mut i);
        while i < v.len() && v[i] == b',' {
            i += 1;
            ws(&mut i);
        }
        if i >= v.len() {
            return Some(m);
        }
        let s = i;
        while i < v.len() && (v[i].is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&v[i])) {
            i += 1;
        }
        if i == s {
            return None;
        }
        let name = String::from_utf8_lossy(&v[s..i]).to_ascii_lowercase();
        ws(&mut i);
        if i >= v.len() || v[i] != b'=' {
            return None;
        }
        i += 1;
        ws(&mut i);
        let value = if i < v.len() && v[i] == b'"' {
            i += 1;
            let mut out = Vec::new();
            loop {
                match v.get(i) {
                    None => return None,
                    Some(b'"') => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') => {
                        out.push(*v.get(i + 1)?);
                        i += 2;
                    }
                    Some(&c) => {
                        out.push(c);
                        i += 1;
                    }
                }
            }
            String::from_utf8(out).ok()?
        } else {
            let s = i;
            while i < v.len() && !matches!(v[i], b',' | b' ' | b'\t') {
                i += 1;
            }
            String::from_utf8(v[s..i].to_vec()).ok()?
        };
        if m.insert(name, value).is_some() {
            return None; // a repeated parameter is ambiguous
        }
    }
}

/// RFC 8187 `UTF-8''percent-encoded`.
fn ext_value(v: &str) -> Option<String> {
    let rest = v.strip_prefix("UTF-8''").or_else(|| v.strip_prefix("utf-8''"))?;
    let b = rest.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl Digest {
    /// Digest for `realm`. `lookup` returns a user's password or stored HA1. Offers SHA-256
    /// and MD5 with `qop=auth`, nonces valid for 5 minutes.
    pub fn new(realm: &str, lookup: impl Fn(&str, DigestAlgorithm) -> Option<Credential> + Send + Sync + 'static) -> Digest {
        Digest {
            realm: realm.into(),
            algorithms: vec![(DigestAlgorithm::Sha256, false), (DigestAlgorithm::Md5, false)],
            auth_int: false,
            key: random::<32>(),
            ttl: Duration::from_secs(300),
            opaque: b64(&random::<12>()),
            lookup: Arc::new(lookup),
            seen: Mutex::new(HashMap::new()),
            max_tracked: 100_000,
        }
    }

    /// The algorithms offered, one challenge each, in this order (`true`: the `-sess`
    /// variant).
    pub fn algorithms(mut self, algs: &[(DigestAlgorithm, bool)]) -> Digest {
        if !algs.is_empty() {
            self.algorithms = algs.to_vec();
        }
        self
    }

    /// Also offer `qop=auth-int` (the request body is hashed too; buffered bodies only).
    pub fn auth_int(mut self, on: bool) -> Digest {
        self.auth_int = on;
        self
    }

    /// How long a nonce is accepted (default 5 minutes).
    pub fn nonce_ttl(mut self, ttl: Duration) -> Digest {
        self.ttl = ttl.max(Duration::from_secs(1));
        self
    }

    /// The nonce-signing key (any length; hashed to 32 bytes), shared by instances that must
    /// accept each other's nonces. Default: random per process.
    pub fn secret(mut self, key: &[u8]) -> Digest {
        use simoom_tls::crypto::sha2::Sha256;
        self.key = Sha256::digest(key);
        self
    }

    /// Most nonces whose counts are tracked (default 100,000).
    pub fn max_tracked_nonces(mut self, n: usize) -> Digest {
        self.max_tracked = n.max(16);
        self
    }

    fn sign(&self, data: &[u8]) -> [u8; 16] {
        let mac = simoom_tls::crypto::sha2::HashAlg::Sha256.hmac(&self.key, &[data, self.realm.as_bytes()]);
        let mut o = [0u8; 16];
        o.copy_from_slice(&mac[..16]);
        o
    }

    fn new_nonce_at(&self, now: u64) -> String {
        let mut n = [0u8; 32];
        n[..8].copy_from_slice(&now.to_be_bytes());
        n[8..16].copy_from_slice(&random::<8>());
        let mac = self.sign(&n[..16]);
        n[16..].copy_from_slice(&mac);
        b64(&n)
    }

    /// The issue time of a nonce this Digest signed, or `None`.
    fn nonce_time(&self, nonce: &str) -> Option<u64> {
        let mut raw = Vec::new();
        if !simoom_http1::base64_decode(nonce.as_bytes(), &mut raw) || raw.len() != 32 {
            return None;
        }
        if !ct_eq(&self.sign(&raw[..16]), &raw[16..]) {
            return None;
        }
        Some(u64::from_be_bytes(raw[..8].try_into().ok()?))
    }

    /// The `WWW-Authenticate` values, one per algorithm, with a fresh nonce.
    pub fn challenges(&self, stale: bool) -> Vec<String> {
        self.challenges_at(stale, now_secs())
    }

    fn challenges_at(&self, stale: bool, now: u64) -> Vec<String> {
        let nonce = self.new_nonce_at(now);
        let qop = if self.auth_int { "auth, auth-int" } else { "auth" };
        self.algorithms
            .iter()
            .map(|(a, sess)| {
                format!(
                    "Digest realm={}, qop=\"{qop}\", algorithm={}{}, nonce=\"{nonce}\", opaque=\"{}\", charset=UTF-8{}",
                    quote(&self.realm),
                    a.name(),
                    if *sess { "-sess" } else { "" },
                    self.opaque,
                    if stale { ", stale=true" } else { "" }
                )
            })
            .collect()
    }

    /// Checks the request's Digest credentials.
    pub fn verify(&self, req: &Request<'_>) -> DigestOutcome {
        let body = if req.is_streamed() { None } else { Some(req.body()) };
        let Some(v) = authorization(req, "digest") else { return DigestOutcome::Denied };
        self.verify_parts(v, req.method(), req.target(), body, now_secs())
    }

    fn verify_parts(&self, header: &[u8], method: &[u8], target: &[u8], body: Option<&[u8]>, now: u64) -> DigestOutcome {
        use DigestOutcome::Denied;
        let Some(p) = auth_params(header) else { return Denied };
        let get = |k: &str| p.get(k).map(String::as_str);
        let user = match (get("username"), get("username*")) {
            (Some(u), None) => u.to_string(),
            (None, Some(x)) => match ext_value(x) {
                Some(u) => u,
                None => return Denied,
            },
            _ => return Denied,
        };
        if get("userhash").is_some_and(|v| v.eq_ignore_ascii_case("true")) || get("realm") != Some(self.realm.as_str()) {
            return Denied;
        }
        if get("uri").map(str::as_bytes) != Some(target) || get("opaque") != Some(self.opaque.as_str()) {
            return Denied;
        }
        let alg_name = get("algorithm").unwrap_or("MD5").to_ascii_uppercase();
        let Some(&(alg, sess)) = self.algorithms.iter().find(|(a, s)| format!("{}{}", a.name(), if *s { "-SESS" } else { "" }) == alg_name) else { return Denied };
        let (Some(qop), Some(nc_s), Some(cnonce), Some(nonce), Some(response)) = (get("qop"), get("nc"), get("cnonce"), get("nonce"), get("response")) else { return Denied };
        let auth_int = match qop {
            "auth" => false,
            "auth-int" if self.auth_int => true,
            _ => return Denied,
        };
        if auth_int && body.is_none() {
            return Denied;
        }
        let nc = match u64::from_str_radix(nc_s, 16) {
            Ok(n) if n > 0 && nc_s.len() == 8 => n,
            _ => return Denied,
        };
        let Some(issued) = self.nonce_time(nonce) else { return Denied };
        let h = |parts: &[&[u8]]| alg.hash_hex(parts);
        let cred = (self.lookup)(&user, alg);
        let mut ha1 = match &cred {
            Some(Credential::Password(pw)) => h(&[user.as_bytes(), b":", self.realm.as_bytes(), b":", pw.as_bytes()]),
            Some(Credential::Ha1(x)) => x.to_ascii_lowercase(),
            None => h(&[b"\0no-such-user"]),
        };
        if sess {
            ha1 = h(&[ha1.as_bytes(), b":", nonce.as_bytes(), b":", cnonce.as_bytes()]);
        }
        let ha2 = if auth_int { h(&[method, b":", target, b":", h(&[body.unwrap_or_default()]).as_bytes()]) } else { h(&[method, b":", target]) };
        let want = h(&[ha1.as_bytes(), b":", nonce.as_bytes(), b":", nc_s.as_bytes(), b":", cnonce.as_bytes(), b":", qop.as_bytes(), b":", ha2.as_bytes()]);
        if !(ct_eq(want.as_bytes(), response.to_ascii_lowercase().as_bytes()) && cred.is_some()) {
            return Denied;
        }
        // valid credentials: an old nonce is stale, not wrong
        let ttl = self.ttl.as_secs();
        if now.saturating_sub(issued) >= ttl || issued > now + 60 {
            return DigestOutcome::Stale;
        }
        if !self.count(nonce, issued, nc, now) {
            return Denied;
        }
        let mut info = String::new();
        if !auth_int {
            let ha2 = h(&[b":", target]);
            let rsp = h(&[ha1.as_bytes(), b":", nonce.as_bytes(), b":", nc_s.as_bytes(), b":", cnonce.as_bytes(), b":auth:", ha2.as_bytes()]);
            info.push_str(&format!("rspauth=\"{rsp}\", "));
        }
        info.push_str(&format!("qop={qop}, nc={nc_s}, cnonce={}", quote(cnonce)));
        if now.saturating_sub(issued) * 2 >= ttl {
            info.push_str(&format!(", nextnonce=\"{}\"", self.new_nonce_at(now)));
        }
        DigestOutcome::Authorized { user, info }
    }

    /// Records `nc` for `nonce`: false for a replay or a count more than 64 behind the highest.
    fn count(&self, nonce: &str, issued: u64, nc: u64, now: u64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if !seen.contains_key(nonce) && seen.len() >= self.max_tracked {
            let ttl = self.ttl.as_secs();
            seen.retain(|_, s| now.saturating_sub(s.issued) < ttl);
            while seen.len() >= self.max_tracked {
                let Some(oldest) = seen.iter().min_by_key(|(_, s)| s.issued).map(|(k, _)| k.clone()) else { break };
                seen.remove(&oldest);
            }
        }
        let s = seen.entry(nonce.to_string()).or_insert(NonceState { issued, max_nc: 0, window: 0 });
        if nc > s.max_nc {
            let shift = nc - s.max_nc;
            s.window = if shift >= 64 { 0 } else { s.window << shift };
            s.window |= 1;
            s.max_nc = nc;
            true
        } else {
            let back = s.max_nc - nc;
            if back >= 64 || s.window & (1 << back) != 0 {
                return false;
            }
            s.window |= 1 << back;
            true
        }
    }
}

// --------------------------------------------------------------------------------- Auth

type TokenCheck = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The schemes a service accepts; [`Auth::wrap`] puts them in front of a service. With
/// several schemes, unauthenticated requests get one challenge per scheme (Digest first).
#[derive(Default)]
pub struct Auth {
    basic: Option<Basic>,
    digest: Option<Digest>,
    bearer: Option<(String, TokenCheck)>,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth").field("basic", &self.basic).field("digest", &self.digest).field("bearer", &self.bearer.as_ref().map(|b| &b.0)).finish()
    }
}

/// Who a request authenticated as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The user (for Bearer, what the validator returned).
    pub user: String,
    /// `basic`, `digest` or `bearer`.
    pub scheme: &'static str,
    /// The `Authentication-Info` value to send (Digest).
    pub info: Option<String>,
}

impl Auth {
    /// No schemes: every request is refused until one is added.
    pub fn new() -> Auth {
        Auth::default()
    }

    /// Accepts Basic.
    pub fn basic(mut self, b: Basic) -> Auth {
        self.basic = Some(b);
        self
    }

    /// Accepts Digest.
    pub fn digest(mut self, d: Digest) -> Auth {
        self.digest = Some(d);
        self
    }

    /// Accepts Bearer tokens: `validate` returns the user a token stands for, or `None`.
    pub fn bearer(mut self, realm: &str, validate: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Auth {
        self.bearer = Some((realm.into(), Arc::new(validate)));
        self
    }

    /// Authenticates `req`; on failure, the `WWW-Authenticate` values to send.
    pub fn authenticate(&self, req: &Request<'_>) -> Result<Principal, Vec<String>> {
        let mut stale = false;
        let mut bad_token = false;
        if let Some(d) = &self.digest {
            match d.verify(req) {
                DigestOutcome::Authorized { user, info } => return Ok(Principal { user, scheme: "digest", info: Some(info) }),
                DigestOutcome::Stale => stale = true,
                DigestOutcome::Denied => {}
            }
        }
        if let Some(b) = &self.basic {
            if let Some(user) = b.verify(req) {
                return Ok(Principal { user, scheme: "basic", info: None });
            }
        }
        if let Some((_, check)) = &self.bearer {
            if let Some(t) = bearer_token(req) {
                match check(t) {
                    Some(user) => return Ok(Principal { user, scheme: "bearer", info: None }),
                    None => bad_token = true,
                }
            }
        }
        let mut ch = Vec::new();
        if let Some(d) = &self.digest {
            ch.extend(d.challenges(stale));
        }
        if let Some(b) = &self.basic {
            ch.push(b.challenge());
        }
        if let Some((realm, _)) = &self.bearer {
            ch.push(if bad_token { format!("Bearer realm={}, error=\"invalid_token\"", quote(realm)) } else { format!("Bearer realm={}", quote(realm)) });
        }
        Err(ch)
    }

    /// `inner` behind authentication: unauthenticated requests get `401` with the challenges.
    pub fn wrap<S: Service>(self, inner: S) -> AuthService<Plain<S>> {
        AuthService { auth: self, inner: Plain(inner) }
    }

    /// `f` behind authentication, called with the authenticated user.
    pub fn wrap_with_user<F>(self, f: F) -> AuthService<F>
    where
        F: Fn(&mut Request<'_>, Reply<'_>, &str) -> Outcome + Send + Sync + 'static,
    {
        AuthService { auth: self, inner: f }
    }
}

/// A service that ignores the user (see [`Auth::wrap`]).
#[derive(Debug)]
pub struct Plain<S>(S);

/// A handler that is told the authenticated user.
pub trait AuthedService: Send + Sync + 'static {
    /// Answers a request authenticated as `user`.
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>, user: &str) -> Outcome;
    /// See [`Service::watch`].
    #[doc(hidden)]
    fn watch(&self, req: &Request<'_>) -> Option<WatchRef<'_>> {
        let _ = req;
        None
    }
}

impl<S: Service> AuthedService for Plain<S> {
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>, _user: &str) -> Outcome {
        self.0.call(req, reply)
    }
    fn watch(&self, req: &Request<'_>) -> Option<WatchRef<'_>> {
        self.0.watch(req)
    }
}

impl<F> AuthedService for F
where
    F: Fn(&mut Request<'_>, Reply<'_>, &str) -> Outcome + Send + Sync + 'static,
{
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>, user: &str) -> Outcome {
        self(req, reply, user)
    }
}

/// A service behind [`Auth`].
pub struct AuthService<S> {
    auth: Auth,
    inner: S,
}

impl<S> std::fmt::Debug for AuthService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService").field("auth", &self.auth).finish_non_exhaustive()
    }
}

impl<S: AuthedService> Service for AuthService<S> {
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        match self.auth.authenticate(req) {
            Ok(p) => {
                let reply = match &p.info {
                    Some(i) => reply.header("authentication-info", i),
                    None => reply,
                };
                self.inner.call(req, reply, &p.user)
            }
            Err(challenges) => {
                let mut r = reply.status(401).header("content-type", "text/plain");
                for c in &challenges {
                    r = r.header("www-authenticate", c);
                }
                r.body_static(b"401 Unauthorized\n")
            }
        }
    }

    fn watch(&self, req: &Request<'_>) -> Option<WatchRef<'_>> {
        self.inner.watch(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> Digest {
        Digest::new("test@simoom", |u: &str, _| (u == "Mufasa").then(|| Credential::Password("Circle of Life".into())))
            .algorithms(&[(DigestAlgorithm::Sha256, false), (DigestAlgorithm::Md5, true), (DigestAlgorithm::Sha512_256, false)])
            .auth_int(true)
    }

    /// An Authorization value computed independently of `verify_parts`.
    fn answer(d: &Digest, alg: DigestAlgorithm, sess: bool, nonce: &str, nc: &str, qop: &str, uri: &str, body: &[u8], pw: &str) -> String {
        let h = |p: &[&[u8]]| alg.hash_hex(p);
        let cn = "c0ffee";
        let mut ha1 = h(&[format!("Mufasa:test@simoom:{pw}").as_bytes()]);
        if sess {
            ha1 = h(&[format!("{ha1}:{nonce}:{cn}").as_bytes()]);
        }
        let ha2 = if qop == "auth-int" { h(&[format!("GET:{uri}:{}", h(&[body])).as_bytes()]) } else { h(&[format!("GET:{uri}").as_bytes()]) };
        let r = h(&[format!("{ha1}:{nonce}:{nc}:{cn}:{qop}:{ha2}").as_bytes()]);
        format!(
            "username=\"Mufasa\", realm=\"test@simoom\", uri=\"{uri}\", algorithm={}{}, nonce=\"{nonce}\", nc={nc}, cnonce=\"{cn}\", qop={qop}, response=\"{r}\", opaque=\"{}\"",
            alg.name(),
            if sess { "-sess" } else { "" },
            d.opaque
        )
    }

    #[test]
    fn digest_verify_counts_stale_and_rspauth() {
        let d = digest();
        let t0 = 1_800_000_000;
        let ch = d.challenges_at(false, t0);
        assert_eq!(ch.len(), 3);
        assert!(ch[1].contains("algorithm=MD5-sess") && ch[0].contains("qop=\"auth, auth-int\""));
        let nonce = ch[0].split("nonce=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        for (alg, sess) in [(DigestAlgorithm::Sha256, false), (DigestAlgorithm::Md5, true), (DigestAlgorithm::Sha512_256, false)] {
            let d = digest();
            let nonce = d.new_nonce_at(t0);
            let a = answer(&d, alg, sess, &nonce, "00000001", "auth", "/x?y=1", b"", "Circle of Life");
            match d.verify_parts(a.as_bytes(), b"GET", b"/x?y=1", Some(b""), t0 + 1) {
                DigestOutcome::Authorized { user, info } => {
                    assert_eq!(user, "Mufasa");
                    // rspauth = H(HA1:nonce:nc:cnonce:qop:H(":" uri))
                    let h = |p: &[&[u8]]| alg.hash_hex(p);
                    let mut ha1 = h(&[b"Mufasa:test@simoom:Circle of Life"]);
                    if sess {
                        ha1 = h(&[format!("{ha1}:{nonce}:c0ffee").as_bytes()]);
                    }
                    let want = h(&[format!("{ha1}:{nonce}:00000001:c0ffee:auth:{}", h(&[b":/x?y=1"])).as_bytes()]);
                    assert!(info.starts_with(&format!("rspauth=\"{want}\"")), "{info}");
                    assert!(!info.contains("nextnonce"));
                }
                o => panic!("{alg:?}: {o:?}"),
            }
            // replay of the same nc refused; a higher one passes; an overtaken lower one passes once
            assert_eq!(d.verify_parts(a.as_bytes(), b"GET", b"/x?y=1", Some(b""), t0 + 1), DigestOutcome::Denied);
            let a3 = answer(&d, alg, sess, &nonce, "00000003", "auth", "/x?y=1", b"", "Circle of Life");
            assert!(matches!(d.verify_parts(a3.as_bytes(), b"GET", b"/x?y=1", Some(b""), t0 + 1), DigestOutcome::Authorized { .. }));
            let a2 = answer(&d, alg, sess, &nonce, "00000002", "auth", "/x?y=1", b"", "Circle of Life");
            assert!(matches!(d.verify_parts(a2.as_bytes(), b"GET", b"/x?y=1", Some(b""), t0 + 1), DigestOutcome::Authorized { .. }));
            assert_eq!(d.verify_parts(a2.as_bytes(), b"GET", b"/x?y=1", Some(b""), t0 + 1), DigestOutcome::Denied);
        }
        // wrong password, wrong uri, unknown user, forged nonce, unoffered algorithm
        let a = answer(&d, DigestAlgorithm::Sha256, false, &nonce, "00000001", "auth", "/", b"", "nope");
        assert_eq!(d.verify_parts(a.as_bytes(), b"GET", b"/", None, t0), DigestOutcome::Denied);
        let a = answer(&d, DigestAlgorithm::Sha256, false, &nonce, "00000001", "auth", "/a", b"", "Circle of Life");
        assert_eq!(d.verify_parts(a.as_bytes(), b"GET", b"/b", None, t0), DigestOutcome::Denied);
        assert_eq!(d.verify_parts(a.replace("Mufasa", "Scar").as_bytes(), b"GET", b"/a", None, t0), DigestOutcome::Denied);
        let other = digest();
        let forged = other.new_nonce_at(t0);
        let a = answer(&d, DigestAlgorithm::Sha256, false, &forged, "00000001", "auth", "/", b"", "Circle of Life");
        assert_eq!(d.verify_parts(a.as_bytes(), b"GET", b"/", None, t0), DigestOutcome::Denied);
        let a = answer(&d, DigestAlgorithm::Md5, false, &nonce, "00000001", "auth", "/", b"", "Circle of Life");
        assert_eq!(d.verify_parts(a.as_bytes(), b"GET", b"/", None, t0), DigestOutcome::Denied);
        // auth-int: hashed body, needs a buffered body, no rspauth
        let a = answer(&d, DigestAlgorithm::Sha256, false, &nonce, "00000009", "auth-int", "/i", b"payload", "Circle of Life");
        assert_eq!(d.verify_parts(a.as_bytes(), b"GET", b"/i", None, t0), DigestOutcome::Denied);
        match d.verify_parts(a.as_bytes(), b"GET", b"/i", Some(b"payload"), t0) {
            DigestOutcome::Authorized { info, .. } => assert!(!info.contains("rspauth") && info.contains("qop=auth-int")),
            o => panic!("{o:?}"),
        }
        // expiry: stale after the TTL (valid credentials), nextnonce after half of it
        let a = answer(&d, DigestAlgorithm::Sha256, false, &nonce, "00000020", "auth", "/s", b"", "Circle of Life");
        assert_eq!(d.verify_parts(a.as_bytes(), b"GET", b"/s", None, t0 + 300), DigestOutcome::Stale);
        match d.verify_parts(a.as_bytes(), b"GET", b"/s", None, t0 + 200) {
            DigestOutcome::Authorized { info, .. } => assert!(info.contains("nextnonce=\""), "{info}"),
            o => panic!("{o:?}"),
        }
        assert!(d.challenges_at(true, t0)[0].ends_with("stale=true"));
        // stored HA1 instead of a password, and a shared secret across instances
        let ha1 = DigestAlgorithm::Sha256.hash_hex(&[b"Mufasa:test@simoom:Circle of Life"]);
        let d1 = Digest::new("test@simoom", move |_, _| Some(Credential::Ha1(ha1.clone()))).secret(b"shared");
        let d2 = Digest::new("test@simoom", |_, _| None).secret(b"shared");
        let n = d2.new_nonce_at(t0);
        let a = answer(&d1, DigestAlgorithm::Sha256, false, &n, "00000001", "auth", "/", b"", "Circle of Life");
        assert!(matches!(d1.verify_parts(a.as_bytes(), b"GET", b"/", None, t0), DigestOutcome::Authorized { .. }));
        // malformed headers
        for bad in ["", "username", "username=\"a\", username=\"b\"", "username=\"unterminated"] {
            assert_eq!(d.verify_parts(bad.as_bytes(), b"GET", b"/", None, t0), DigestOutcome::Denied);
        }
    }

    #[test]
    fn nonce_count_table_is_bounded() {
        let d = digest().max_tracked_nonces(16);
        for i in 0..100u64 {
            let n = format!("n{i}");
            assert!(d.count(&n, 1000 + i, 1, 1000 + i));
        }
        assert!(d.seen.lock().unwrap().len() <= 16);
        assert!(d.count("w", 1, 100, 1));
        assert!(!d.count("w", 1, 36, 1)); // 64 or more behind
        assert!(d.count("w", 1, 37, 1));
    }

    #[test]
    fn helpers() {
        assert_eq!(ext_value("UTF-8''J%C3%A4s%C3%B8n%20Doe").as_deref(), Some("J\u{e4}s\u{f8}n Doe"));
        assert_eq!(ext_value("latin1''x"), None);
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
        let p = auth_params(br#"a=1, b="x\"y" ,c=""  "#).unwrap();
        assert_eq!((p["a"].as_str(), p["b"].as_str(), p["c"].as_str()), ("1", "x\"y", ""));
    }
}
