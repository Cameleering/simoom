//! HTTP authentication with challenges: Basic, Bearer tokens from a provider, Digest
//! (RFC 7616, feature `auth-digest`) and NTLMv2 (MS-NLMP, feature `auth-ntlm`), for origin
//! servers (`401`) and proxies (`407`, also on `CONNECT` tunnels).
//!
//! ```no_run
//! use simoom_client::{auth::Auth, Client};
//! use std::sync::Arc;
//!
//! # #[cfg(feature = "auth-digest")]
//! let auth = Auth::new().digest("Mufasa", "Circle of Life");
//! # #[cfg(not(feature = "auth-digest"))]
//! # let auth = Auth::new();
//! let client = Client::builder().auth(Arc::new(auth)).build();
//! let resp = client.get("https://api.example/dir/index.html").send().unwrap();
//! ```
//!
//! How it works: a request goes out without credentials (or with the ones remembered for its
//! origin); on a `401` or `407` the challenges in `WWW-Authenticate` / `Proxy-Authenticate` are
//! parsed (RFC 9110 §11), the strongest scheme there are credentials for is chosen (Bearer,
//! then Digest with the best algorithm, then NTLM, then Basic), and the request is sent again.
//! After a success the scheme is remembered per origin (per proxy for `407`) and later requests
//! authenticate up front: Digest with the next nonce count, Basic and Bearer as they are. NTLM
//! authenticates connections, not requests: its handshake runs on one HTTP/1.1 connection
//! (requests that carry an NTLM token are pinned to HTTP/1.1) and later requests reuse that
//! connection from the pool.
//!
//! Limits, all deliberate:
//!
//! - A retry needs a replayable body (bytes, not a reader): a streamed request answered with a
//!   challenge returns the `401`. Requests after the first to the same origin authenticate up
//!   front, so streaming then works for Basic, Bearer and Digest (`auth`, not `auth-int`).
//! - Credentials the server refused are not sent again in the same request (no loops);
//!   a Digest challenge with `stale=true` is answered once more with the new nonce.
//! - Basic credentials go only over `https`, to loopback hosts, or when
//!   [`Auth::basic_over_http`] allows it. Server credentials can be limited to origins with
//!   [`Auth::only_origins`]; Bearer tokens are always bound to one origin.
//! - Interceptor retries are capped by [`crate::hooks::MAX_INTERCEPTOR_RETRIES`]: NTLM takes
//!   two, so NTLM through an NTLM proxy in absolute form (four) is not reached.
//! - NTLM: no MIC, no channel bindings (Extended Protection), no signing or sealing; Digest:
//!   `rspauth` in `Authentication-Info` is checked for `qop=auth` (a mismatch fails the request)
//!   but not for `auth-int`; `nextnonce` is used.

use crate::body::Response;
use crate::hooks::{Action, Interceptor};
#[cfg(feature = "auth-ntlm")]
use crate::types::HttpVersion;
use crate::types::Request;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

/// Supplies bearer tokens (for example OAuth 2.0 access tokens). `refresh` is true when the
/// server refused the last token (`401` with a `Bearer` challenge): return a new one, or `None`
/// to give up. Closures `Fn(bool) -> Option<String>` implement it.
pub trait TokenProvider: Send + Sync {
    /// The token to send.
    fn token(&self, refresh: bool) -> Option<String>;
}

impl<F: Fn(bool) -> Option<String> + Send + Sync> TokenProvider for F {
    fn token(&self, refresh: bool) -> Option<String> {
        self(refresh)
    }
}

/// One challenge from `WWW-Authenticate` or `Proxy-Authenticate` (RFC 9110 §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The scheme, lower case (`basic`, `digest`, `ntlm`, `bearer`...).
    pub scheme: String,
    /// A token68 (`NTLM TlRMTVNT...`).
    pub token68: Option<String>,
    /// Parameters: names lower case, values unquoted.
    pub params: Vec<(String, String)>,
}

impl Challenge {
    /// A parameter value by name (case-insensitive).
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn is_token68_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-._~+/".contains(&c)
}

/// Parses the challenges of one or more `WWW-Authenticate` / `Proxy-Authenticate` values
/// (RFC 9110 §11.6.1; several challenges may share a field, separated by commas). Malformed
/// trailing input ends parsing; the challenges before it are returned.
pub fn parse_challenges<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<Challenge> {
    let mut out = Vec::new();
    for v in values {
        parse_challenge_list(v.as_bytes(), &mut out);
    }
    out
}

fn parse_challenge_list(b: &[u8], out: &mut Vec<Challenge>) {
    let mut i = 0;
    let ws = |i: &mut usize| {
        while *i < b.len() && (b[*i] == b' ' || b[*i] == b'\t') {
            *i += 1;
        }
    };
    let token = |i: &mut usize| -> Option<String> {
        let s = *i;
        while *i < b.len() && is_tchar(b[*i]) {
            *i += 1;
        }
        (*i > s).then(|| String::from_utf8_lossy(&b[s..*i]).into_owned())
    };
    loop {
        // skip empty list elements
        loop {
            ws(&mut i);
            if i < b.len() && b[i] == b',' {
                i += 1;
            } else {
                break;
            }
        }
        if i >= b.len() {
            return;
        }
        let Some(scheme) = token(&mut i) else { return };
        let mut ch = Challenge { scheme: scheme.to_ascii_lowercase(), token68: None, params: Vec::new() };
        ws(&mut i);
        // token68: token68 chars then '='*, followed by end or ','
        let s = i;
        let mut j = i;
        while j < b.len() && is_token68_char(b[j]) {
            j += 1;
        }
        let run_end = j;
        while j < b.len() && b[j] == b'=' {
            j += 1;
        }
        let mut k = j;
        while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
            k += 1;
        }
        if run_end > s && (k >= b.len() || b[k] == b',') {
            // `abc==` (also `name=` with nothing after) is a token68; `name=value` is a param
            ch.token68 = Some(String::from_utf8_lossy(&b[s..j]).into_owned());
            i = k;
            out.push(ch);
            continue;
        }
        // auth-params
        loop {
            ws(&mut i);
            let save = i;
            let Some(name) = token(&mut i) else {
                i = save;
                break;
            };
            ws(&mut i);
            if i >= b.len() || b[i] != b'=' {
                // the next challenge's scheme
                i = save;
                break;
            }
            i += 1;
            ws(&mut i);
            let value = if i < b.len() && b[i] == b'"' {
                i += 1;
                let mut v = Vec::new();
                loop {
                    if i >= b.len() {
                        out.push(ch);
                        return;
                    }
                    match b[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' if i + 1 < b.len() => {
                            v.push(b[i + 1]);
                            i += 2;
                        }
                        c => {
                            v.push(c);
                            i += 1;
                        }
                    }
                }
                String::from_utf8_lossy(&v).into_owned()
            } else {
                token(&mut i).unwrap_or_default()
            };
            ch.params.push((name.to_ascii_lowercase(), value));
            ws(&mut i);
            if i < b.len() && b[i] == b',' {
                i += 1;
                continue;
            }
            break;
        }
        out.push(ch);
        ws(&mut i);
        if i < b.len() && b[i] != b',' && !is_tchar(b[i]) {
            return;
        }
    }
}

/// A quoted-string with `\` and `"` escaped.
#[cfg(feature = "auth-digest")]
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

#[cfg(any(feature = "auth-digest", all(test, feature = "auth-ntlm")))]
fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[cfg(any(feature = "auth-digest", feature = "auth-ntlm"))]
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    if !simoom_sys::arch::os_random(&mut b) {
        // no OS source: a time and counter mix (cnonces need uniqueness, not secrecy)
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15);
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
        let mut x = t ^ CTR.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
        for v in b.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *v = x as u8;
        }
    }
    b
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

// ------------------------------------------------------------------------------- Digest

/// Digest algorithms (RFC 7616 §3.3; feature `auth-digest`).
#[cfg(feature = "auth-digest")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestAlgorithm {
    /// `MD5` (also when the challenge names no algorithm).
    Md5,
    /// `SHA-256`.
    Sha256,
    /// `SHA-512-256`.
    Sha512_256,
}

#[cfg(feature = "auth-digest")]
impl DigestAlgorithm {
    /// Parses `MD5`, `SHA-256`, `SHA-512-256`, each optionally with `-sess`; returns the
    /// algorithm and the session flag.
    pub fn parse(s: &str) -> Option<(DigestAlgorithm, bool)> {
        let u = s.to_ascii_uppercase();
        let (base, sess) = match u.strip_suffix("-SESS") {
            Some(b) => (b.to_string(), true),
            None => (u, false),
        };
        let a = match base.as_str() {
            "MD5" => DigestAlgorithm::Md5,
            "SHA-256" => DigestAlgorithm::Sha256,
            "SHA-512-256" => DigestAlgorithm::Sha512_256,
            _ => return None,
        };
        Some((a, sess))
    }

    /// The hex digest of the concatenation of `parts`.
    pub fn hash_hex(self, parts: &[&[u8]]) -> String {
        use simoom_tls::crypto::sha2::{Sha256, Sha512};
        match self {
            DigestAlgorithm::Md5 => {
                let mut h = simoom_tls::crypto::legacy::Md5::new();
                for p in parts {
                    h.update(p);
                }
                hex(&h.finish())
            }
            DigestAlgorithm::Sha256 => {
                let mut h = Sha256::new();
                for p in parts {
                    h.update(p);
                }
                hex(&h.finish())
            }
            DigestAlgorithm::Sha512_256 => {
                let mut h = Sha512::new512_256();
                for p in parts {
                    h.update(p);
                }
                hex(&h.finish())
            }
        }
    }
}

/// A Digest challenge (RFC 7616 §3.3).
#[cfg(feature = "auth-digest")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestChallenge {
    /// `realm`.
    pub realm: String,
    /// `nonce`.
    pub nonce: String,
    /// `opaque`, echoed back.
    pub opaque: Option<String>,
    /// The algorithm.
    pub algorithm: DigestAlgorithm,
    /// A `-sess` variant.
    pub sess: bool,
    /// `qop=auth` offered.
    pub qop_auth: bool,
    /// `qop=auth-int` offered.
    pub qop_auth_int: bool,
    /// `userhash=true`.
    pub userhash: bool,
    /// `stale=true`.
    pub stale: bool,
    /// The algorithm name as the server wrote it (echoed back).
    algorithm_name: Option<String>,
}

#[cfg(feature = "auth-digest")]
impl DigestChallenge {
    /// From a parsed challenge; `None` if it is not Digest, lacks `realm` or `nonce`, or names
    /// an unknown algorithm.
    pub fn from_challenge(c: &Challenge) -> Option<DigestChallenge> {
        if c.scheme != "digest" {
            return None;
        }
        let alg_name = c.param("algorithm").map(str::to_string);
        let (algorithm, sess) = match &alg_name {
            Some(a) => DigestAlgorithm::parse(a)?,
            None => (DigestAlgorithm::Md5, false),
        };
        let qops: Vec<String> = c.param("qop").map(|q| q.split(',').map(|s| s.trim().to_ascii_lowercase()).collect()).unwrap_or_default();
        Some(DigestChallenge {
            realm: c.param("realm")?.to_string(),
            nonce: c.param("nonce")?.to_string(),
            opaque: c.param("opaque").map(str::to_string),
            algorithm,
            sess,
            qop_auth: qops.iter().any(|q| q == "auth"),
            qop_auth_int: qops.iter().any(|q| q == "auth-int"),
            userhash: c.param("userhash").is_some_and(|v| v.eq_ignore_ascii_case("true")),
            stale: c.param("stale").is_some_and(|v| v.eq_ignore_ascii_case("true")),
            algorithm_name: alg_name,
        })
    }

    /// The `Authorization` value (RFC 7616 §3.4) for `method` on `uri`. `body` is the entity
    /// body for `auth-int` (used only when `auth_int` is asked for and offered; otherwise
    /// `auth` when offered, or the RFC 2069 form without `qop`). `nc` counts uses of this
    /// nonce from 1; `cnonce` is the client nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn authorization(&self, user: &str, password: &str, method: &str, uri: &str, body: Option<&[u8]>, auth_int: bool, nc: u32, cnonce: &str) -> String {
        let alg = self.algorithm;
        let h = |parts: &[&[u8]]| alg.hash_hex(parts);
        let mut ha1 = h(&[user.as_bytes(), b":", self.realm.as_bytes(), b":", password.as_bytes()]);
        if self.sess {
            ha1 = h(&[ha1.as_bytes(), b":", self.nonce.as_bytes(), b":", cnonce.as_bytes()]);
        }
        let qop = match (self.qop_auth, self.qop_auth_int && body.is_some()) {
            (_, true) if auth_int || !self.qop_auth => Some("auth-int"),
            (true, _) => Some("auth"),
            _ => None,
        };
        let ha2 = if qop == Some("auth-int") {
            let hb = h(&[body.unwrap_or_default()]);
            h(&[method.as_bytes(), b":", uri.as_bytes(), b":", hb.as_bytes()])
        } else {
            h(&[method.as_bytes(), b":", uri.as_bytes()])
        };
        let ncs = format!("{nc:08x}");
        let response = match qop {
            Some(q) => h(&[ha1.as_bytes(), b":", self.nonce.as_bytes(), b":", ncs.as_bytes(), b":", cnonce.as_bytes(), b":", q.as_bytes(), b":", ha2.as_bytes()]),
            None => h(&[ha1.as_bytes(), b":", self.nonce.as_bytes(), b":", ha2.as_bytes()]),
        };
        let mut v = String::from("Digest ");
        if self.userhash {
            v.push_str(&format!("username={}", quote(&h(&[user.as_bytes(), b":", self.realm.as_bytes()]))));
        } else if user.is_ascii() && !user.bytes().any(|c| c < 0x20 || c == 0x7f) {
            v.push_str(&format!("username={}", quote(user)));
        } else {
            // RFC 8187 ext-value
            let enc: String = user.bytes().map(|c| if c.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect();
            v.push_str(&format!("username*=UTF-8''{enc}"));
        }
        v.push_str(&format!(", realm={}, uri={}", quote(&self.realm), quote(uri)));
        if let Some(a) = &self.algorithm_name {
            v.push_str(&format!(", algorithm={a}"));
        }
        v.push_str(&format!(", nonce={}", quote(&self.nonce)));
        if let Some(q) = qop {
            v.push_str(&format!(", nc={ncs}, cnonce={}, qop={q}", quote(cnonce)));
        }
        v.push_str(&format!(", response={}", quote(&response)));
        if let Some(o) = &self.opaque {
            v.push_str(&format!(", opaque={}", quote(o)));
        }
        if self.userhash {
            v.push_str(", userhash=true");
        }
        v
    }
}

#[cfg(feature = "auth-digest")]
fn new_cnonce() -> String {
    hex(&random_bytes::<16>())
}

// --------------------------------------------------------------------------------- NTLM

/// NTLMSSP messages for NTLMv2 (MS-NLMP; feature `auth-ntlm`).
#[cfg(feature = "auth-ntlm")]
pub mod ntlm {
    use simoom_tls::crypto::legacy::{hmac_md5, Md4};

    const SIG: &[u8; 8] = b"NTLMSSP\0";
    /// NEGOTIATE_UNICODE.
    pub const UNICODE: u32 = 0x0000_0001;
    const OEM: u32 = 0x0000_0002;
    const REQUEST_TARGET: u32 = 0x0000_0004;
    const NTLM: u32 = 0x0000_0200;
    const ALWAYS_SIGN: u32 = 0x0000_8000;
    const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    const TARGET_INFO: u32 = 0x0080_0000;
    const N128: u32 = 0x2000_0000;
    const N56: u32 = 0x8000_0000;
    /// The flags the Negotiate message asks for.
    pub const NEGOTIATE_FLAGS: u32 = UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY | N128 | N56;

    /// MsvAvTimestamp.
    const AV_TIMESTAMP: u16 = 7;

    /// The NEGOTIATE_MESSAGE (type 1), without domain or workstation.
    pub fn negotiate() -> Vec<u8> {
        let mut m = Vec::with_capacity(32);
        m.extend_from_slice(SIG);
        m.extend_from_slice(&1u32.to_le_bytes());
        m.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
        m.extend_from_slice(&[0u8; 16]); // empty domain and workstation fields
        m
    }

    /// A parsed CHALLENGE_MESSAGE (type 2).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ChallengeMessage {
        /// NegotiateFlags.
        pub flags: u32,
        /// ServerChallenge.
        pub server_challenge: [u8; 8],
        /// TargetName (raw).
        pub target_name: Vec<u8>,
        /// TargetInfo: AV pairs (raw).
        pub target_info: Vec<u8>,
    }

    fn field(m: &[u8], at: usize) -> Option<&[u8]> {
        let len = u16::from_le_bytes(m.get(at..at + 2)?.try_into().ok()?) as usize;
        let off = u32::from_le_bytes(m.get(at + 4..at + 8)?.try_into().ok()?) as usize;
        if len == 0 {
            return Some(&[]);
        }
        m.get(off..off.checked_add(len)?)
    }

    /// Parses a CHALLENGE_MESSAGE; `None` when it is not one or a field is out of bounds.
    pub fn parse_challenge(m: &[u8]) -> Option<ChallengeMessage> {
        if m.len() < 32 || &m[..8] != SIG || m[8..12] != 2u32.to_le_bytes() {
            return None;
        }
        let target_name = field(m, 12)?.to_vec();
        let flags = u32::from_le_bytes(m[20..24].try_into().ok()?);
        let server_challenge: [u8; 8] = m[24..32].try_into().ok()?;
        let target_info = if m.len() >= 48 { field(m, 40)?.to_vec() } else { Vec::new() };
        // the AV pair list must be well formed
        let mut i = 0;
        while i + 4 <= target_info.len() {
            let id = u16::from_le_bytes([target_info[i], target_info[i + 1]]);
            let len = u16::from_le_bytes([target_info[i + 2], target_info[i + 3]]) as usize;
            i += 4 + len;
            if id == 0 {
                break;
            }
        }
        if i > target_info.len() {
            return None;
        }
        Some(ChallengeMessage { flags, server_challenge, target_name, target_info })
    }

    impl ChallengeMessage {
        /// The MsvAvTimestamp AV pair (a FILETIME), if present.
        pub fn timestamp(&self) -> Option<u64> {
            let t = &self.target_info;
            let mut i = 0;
            while i + 4 <= t.len() {
                let id = u16::from_le_bytes([t[i], t[i + 1]]);
                let len = u16::from_le_bytes([t[i + 2], t[i + 3]]) as usize;
                if id == 0 {
                    break;
                }
                if id == AV_TIMESTAMP && len == 8 && i + 12 <= t.len() {
                    return Some(u64::from_le_bytes(t[i + 4..i + 12].try_into().ok()?));
                }
                i += 4 + len;
            }
            None
        }
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// NTOWFv2 (MS-NLMP 3.3.2): HMAC-MD5(MD4(UTF-16LE(password)), UTF-16LE(UPPER(user) + domain)).
    pub fn ntowf_v2(user: &str, password: &str, domain: &str) -> [u8; 16] {
        let nt = Md4::digest(&utf16(password));
        hmac_md5(&nt, &[&utf16(&(user.to_uppercase() + domain))])
    }

    /// The NTLMv2 and LMv2 responses (MS-NLMP 3.3.2) for a challenge: `(nt_response,
    /// lm_response, session_base_key)`. `time` is a FILETIME (the challenge's timestamp when
    /// it has one). The LMv2 response is 24 zero bytes when the challenge carries a timestamp.
    pub fn responses(ch: &ChallengeMessage, key: &[u8; 16], client_challenge: &[u8; 8], time: u64) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
        let mut temp = Vec::with_capacity(28 + ch.target_info.len() + 4);
        temp.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
        temp.extend_from_slice(&time.to_le_bytes());
        temp.extend_from_slice(client_challenge);
        temp.extend_from_slice(&[0; 4]);
        temp.extend_from_slice(&ch.target_info);
        temp.extend_from_slice(&[0; 4]);
        let proof = hmac_md5(key, &[&ch.server_challenge, &temp]);
        let mut nt = proof.to_vec();
        nt.extend_from_slice(&temp);
        let lm = if ch.timestamp().is_some() {
            vec![0u8; 24]
        } else {
            let mut l = hmac_md5(key, &[&ch.server_challenge, client_challenge]).to_vec();
            l.extend_from_slice(client_challenge);
            l
        };
        let session = hmac_md5(key, &[&proof]);
        (nt, lm, session)
    }

    /// The AUTHENTICATE_MESSAGE (type 3) for NTLMv2, without MIC or version.
    pub fn authenticate(ch: &ChallengeMessage, user: &str, password: &str, domain: &str, workstation: &str, client_challenge: &[u8; 8], now_filetime: u64) -> Vec<u8> {
        let key = ntowf_v2(user, password, domain);
        let time = ch.timestamp().unwrap_or(now_filetime);
        let (nt, lm, _) = responses(ch, &key, client_challenge, time);
        let unicode = ch.flags & UNICODE != 0;
        let enc = |s: &str| if unicode { utf16(s) } else { s.chars().map(|c| if c.is_ascii() { c as u8 } else { b'?' }).collect() };
        let (d, u, w) = (enc(domain), enc(user), enc(workstation));
        let flags = (ch.flags & (NEGOTIATE_FLAGS | TARGET_INFO)) & if unicode { !OEM } else { !UNICODE };
        let mut m = Vec::with_capacity(64 + d.len() + u.len() + w.len() + lm.len() + nt.len());
        m.extend_from_slice(SIG);
        m.extend_from_slice(&3u32.to_le_bytes());
        m.resize(64, 0);
        let mut off = 64u32;
        let mut put = |m: &mut Vec<u8>, at: usize, data: &[u8]| {
            let len = data.len() as u16;
            m[at..at + 2].copy_from_slice(&len.to_le_bytes());
            m[at + 2..at + 4].copy_from_slice(&len.to_le_bytes());
            m[at + 4..at + 8].copy_from_slice(&off.to_le_bytes());
            off += data.len() as u32;
        };
        put(&mut m, 28, &d);
        put(&mut m, 36, &u);
        put(&mut m, 44, &w);
        put(&mut m, 12, &lm);
        put(&mut m, 20, &nt);
        put(&mut m, 52, &[]);
        m[60..64].copy_from_slice(&flags.to_le_bytes());
        for part in [&d, &u, &w, &lm, &nt] {
            m.extend_from_slice(part);
        }
        m
    }

    /// The current time as a FILETIME (100 ns since 1601-01-01).
    pub fn filetime_now() -> u64 {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        (d.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(d.subsec_nanos() / 100)
    }
}

// --------------------------------------------------------------------------------- Auth

#[derive(Clone, Default)]
struct Creds {
    basic: Option<(String, String)>,
    #[cfg(feature = "auth-digest")]
    digest: Option<(String, String)>,
    #[cfg(feature = "auth-ntlm")]
    ntlm: Option<NtlmCreds>,
}

#[cfg(feature = "auth-ntlm")]
#[derive(Clone)]
struct NtlmCreds {
    domain: String,
    user: String,
    password: String,
    workstation: String,
}

/// What an origin (or proxy) authenticated with last.
enum Space {
    Basic(String),
    #[cfg(feature = "auth-digest")]
    Digest {
        ch: DigestChallenge,
        nc: u32,
        cnonce: String,
    },
    Bearer,
    /// Authenticated connections: requests that could go out on HTTP/2 are pinned to HTTP/1.1
    /// so they reuse the authenticated connection.
    #[cfg(feature = "auth-ntlm")]
    Ntlm,
}

/// NTLM authenticates an HTTP/1.1 connection; pin requests that could otherwise use HTTP/2.
#[cfg(feature = "auth-ntlm")]
fn pin_http1(req: &mut Request) {
    if req.url.is_secure() && req.version.is_none() || req.version == Some(HttpVersion::Http2) {
        req.version = Some(HttpVersion::Http1);
    }
}

#[derive(Default)]
struct State {
    spaces: HashMap<String, Space>,
    /// Header values chosen in `on_response` for the next attempt of the request running on
    /// this thread (the blocking client runs a request's attempts on one thread).
    pending: HashMap<(ThreadId, String, String), String>,
    /// Values this authenticator put on requests, so a later attempt can tell them from the
    /// caller's own header.
    produced: VecDeque<String>,
}

/// Credentials and the authentication state for one client (see the [module
/// documentation](self)). Install with [`ClientBuilder::auth`](crate::ClientBuilder::auth).
pub struct Auth {
    server: Creds,
    proxy: Creds,
    bearer: Vec<(String, Arc<dyn TokenProvider>)>,
    origins: Option<Vec<String>>,
    basic_over_http: bool,
    #[cfg(feature = "auth-digest")]
    auth_int: bool,
    state: Mutex<State>,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth").field("origins", &self.origins).field("bearer_origins", &self.bearer.iter().map(|b| &b.0).collect::<Vec<_>>()).finish_non_exhaustive()
    }
}

impl Default for Auth {
    fn default() -> Self {
        Auth::new()
    }
}

/// Which header pair a step works on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Server,
    Proxy,
}

impl Side {
    fn request_header(self) -> &'static str {
        match self {
            Side::Server => "Authorization",
            Side::Proxy => "Proxy-Authorization",
        }
    }
}

fn origin_of(s: &str) -> String {
    match crate::url::Url::parse(s) {
        Ok(u) => u.origin(),
        Err(_) => s.to_string(),
    }
}

impl Auth {
    /// No credentials yet.
    pub fn new() -> Auth {
        Auth {
            server: Creds::default(),
            proxy: Creds::default(),
            bearer: Vec::new(),
            origins: None,
            basic_over_http: false,
            #[cfg(feature = "auth-digest")]
            auth_int: false,
            state: Mutex::new(State::default()),
        }
    }

    /// Basic credentials, sent when a server asks for Basic (not up front: use
    /// [`RequestBuilder::basic_auth`](crate::RequestBuilder::basic_auth) for that).
    pub fn basic(mut self, user: &str, password: &str) -> Auth {
        self.server.basic = Some((user.into(), password.into()));
        self
    }

    /// Basic credentials for proxies (`407`).
    pub fn proxy_basic(mut self, user: &str, password: &str) -> Auth {
        self.proxy.basic = Some((user.into(), password.into()));
        self
    }

    /// Digest credentials (feature `auth-digest`).
    #[cfg(feature = "auth-digest")]
    pub fn digest(mut self, user: &str, password: &str) -> Auth {
        self.server.digest = Some((user.into(), password.into()));
        self
    }

    /// Digest credentials for proxies (feature `auth-digest`).
    #[cfg(feature = "auth-digest")]
    pub fn proxy_digest(mut self, user: &str, password: &str) -> Auth {
        self.proxy.digest = Some((user.into(), password.into()));
        self
    }

    /// Prefer `qop=auth-int` (the body is hashed too) when the server offers both; requests
    /// with a streamed body still use `auth`.
    #[cfg(feature = "auth-digest")]
    pub fn digest_auth_int(mut self, on: bool) -> Auth {
        self.auth_int = on;
        self
    }

    /// NTLMv2 credentials (feature `auth-ntlm`). `user` may be `DOMAIN\user`, in which case
    /// `domain` may be empty.
    #[cfg(feature = "auth-ntlm")]
    pub fn ntlm(mut self, domain: &str, user: &str, password: &str) -> Auth {
        self.server.ntlm = Some(ntlm_creds(domain, user, password));
        self
    }

    /// NTLMv2 credentials for proxies (feature `auth-ntlm`).
    #[cfg(feature = "auth-ntlm")]
    pub fn proxy_ntlm(mut self, domain: &str, user: &str, password: &str) -> Auth {
        self.proxy.ntlm = Some(ntlm_creds(domain, user, password));
        self
    }

    /// The workstation name sent in NTLM messages (default empty).
    #[cfg(feature = "auth-ntlm")]
    pub fn ntlm_workstation(mut self, name: &str) -> Auth {
        for n in [&mut self.server.ntlm, &mut self.proxy.ntlm].into_iter().flatten() {
            n.workstation = name.into();
        }
        self
    }

    /// Bearer tokens for `origin` (`https://api.example` or any URL of it): sent with every
    /// request to that origin, and refreshed through `provider.token(true)` when the origin
    /// answers `401` with a `Bearer` challenge. Never sent to other origins.
    pub fn bearer(mut self, origin: &str, provider: impl TokenProvider + 'static) -> Auth {
        self.bearer.push((origin_of(origin), Arc::new(provider)));
        self
    }

    /// Sends server credentials (Basic, Digest, NTLM) only to these origins.
    pub fn only_origins(mut self, origins: &[&str]) -> Auth {
        self.origins = Some(origins.iter().map(|o| origin_of(o)).collect());
        self
    }

    /// Allows Basic credentials over plain `http` to non-loopback hosts (off by default: they
    /// would travel in clear text).
    pub fn basic_over_http(mut self, on: bool) -> Auth {
        self.basic_over_http = on;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn key(side: Side, origin: &str) -> String {
        match side {
            Side::Server => origin.to_string(),
            Side::Proxy => format!("proxy {origin}"),
        }
    }

    fn bearer_for(&self, origin: &str) -> Option<&Arc<dyn TokenProvider>> {
        self.bearer.iter().find(|(o, _)| o == origin).map(|(_, p)| p)
    }

    fn record(st: &mut State, v: &str) {
        if st.produced.len() >= 128 {
            st.produced.pop_front();
        }
        st.produced.push_back(v.to_string());
    }

    /// The header value for `challenges` (a `401` or `407`), given what this request already
    /// sent (`sent`, if it came from us). Updates the remembered space.
    #[allow(clippy::too_many_arguments)]
    fn answer(&self, st: &mut State, side: Side, key: &str, origin: &str, secure: bool, challenges: &[Challenge], sent: Option<&str>, method: &str, uri: &str, body: Option<&[u8]>) -> Option<String> {
        let empty = Creds::default();
        let creds = match side {
            Side::Server if self.origins.as_ref().is_some_and(|os| !os.iter().any(|o| o == origin)) => &empty,
            Side::Server => &self.server,
            Side::Proxy => &self.proxy,
        };
        let sent_scheme = sent.map(|s| s.split(' ').next().unwrap_or("").to_ascii_lowercase());
        let _ = (method, uri, body);
        // Bearer
        if side == Side::Server && challenges.iter().any(|c| c.scheme == "bearer") {
            if let Some(p) = self.bearer_for(origin) {
                let refresh = sent_scheme.as_deref() == Some("bearer");
                if let Some(t) = p.token(refresh) {
                    let v = format!("Bearer {t}");
                    if sent != Some(v.as_str()) {
                        st.spaces.insert(key.to_string(), Space::Bearer);
                        return Some(v);
                    }
                }
            }
        }
        // Digest: the strongest algorithm offered
        #[cfg(feature = "auth-digest")]
        if let Some((user, pass)) = &creds.digest {
            let best = challenges.iter().filter_map(DigestChallenge::from_challenge).max_by_key(|d| d.algorithm);
            if let Some(ch) = best {
                let retry_ok = sent_scheme.as_deref() != Some("digest") || ch.stale;
                if retry_ok {
                    let cnonce = new_cnonce();
                    let v = ch.authorization(user, pass, method, uri, body, self.auth_int, 1, &cnonce);
                    st.spaces.insert(key.to_string(), Space::Digest { ch, nc: 1, cnonce });
                    return Some(v);
                }
                st.spaces.remove(key);
                return None;
            }
        }
        // NTLM
        #[cfg(feature = "auth-ntlm")]
        if let Some(n) = &creds.ntlm {
            if let Some(c) = challenges.iter().find(|c| c.scheme == "ntlm") {
                let mut raw = Vec::new();
                match &c.token68 {
                    None if sent_scheme.as_deref() != Some("ntlm") => {
                        st.spaces.insert(key.to_string(), Space::Ntlm);
                        let mut out = Vec::new();
                        simoom_http1::base64_encode(&ntlm::negotiate(), &mut out);
                        return Some(format!("NTLM {}", String::from_utf8_lossy(&out)));
                    }
                    Some(t) if sent_scheme.as_deref() == Some("ntlm") && simoom_http1::base64_decode(t.as_bytes(), &mut raw) => {
                        let ch = ntlm::parse_challenge(&raw)?;
                        let msg = ntlm::authenticate(&ch, &n.user, &n.password, &n.domain, &n.workstation, &random_bytes::<8>(), ntlm::filetime_now());
                        let mut out = Vec::new();
                        simoom_http1::base64_encode(&msg, &mut out);
                        return Some(format!("NTLM {}", String::from_utf8_lossy(&out)));
                    }
                    _ => return None,
                }
            }
        }
        // Basic
        if let Some((user, pass)) = &creds.basic {
            if challenges.iter().any(|c| c.scheme == "basic") && (secure || self.basic_over_http) && sent_scheme.as_deref() != Some("basic") {
                let v = format!("Basic {}", crate::url::b64(format!("{user}:{pass}").as_bytes()));
                st.spaces.insert(key.to_string(), Space::Basic(v.clone()));
                return Some(v);
            }
        }
        let _ = creds;
        None
    }

    /// The header to send up front for a remembered space.
    fn preemptive(&self, st: &mut State, side: Side, key: &str, origin: &str, method: &str, uri: &str, body: Option<&[u8]>) -> Option<String> {
        let _ = (side, method, uri, body);
        match st.spaces.get_mut(key)? {
            Space::Basic(v) => Some(v.clone()),
            Space::Bearer => self.bearer_for(origin).and_then(|p| p.token(false)).map(|t| format!("Bearer {t}")),
            #[cfg(feature = "auth-ntlm")]
            Space::Ntlm => None,
            #[cfg(feature = "auth-digest")]
            Space::Digest { ch, nc, cnonce } => {
                let (user, pass) = if side == Side::Proxy { self.proxy.digest.as_ref()? } else { self.server.digest.as_ref()? };
                *nc += 1;
                Some(ch.authorization(user, pass, method, uri, body, self.auth_int, *nc, cnonce))
            }
        }
    }

    /// The `Proxy-Authorization` for a `CONNECT` to `authority`: up front from a remembered
    /// space (`challenge` `None`), or in answer to a `407` (`challenge` = its
    /// `Proxy-Authenticate` values; `sent` = what the refused attempt carried).
    pub(crate) fn tunnel_answer(&self, proxy: &crate::proxy::ProxyAddr, authority: &str, challenge: Option<&[Challenge]>, sent: Option<&str>) -> Option<String> {
        let key = format!("tunnel {}:{}", proxy.host, proxy.port);
        let mut st = self.lock();
        match challenge {
            None => self.preemptive(&mut st, Side::Proxy, &key, "", "CONNECT", authority, None),
            Some(c) => self.answer(&mut st, Side::Proxy, &key, "", true, c, sent, "CONNECT", authority, None),
        }
    }
}

#[cfg(feature = "auth-digest")]
impl Auth {
    /// Checks `rspauth` (RFC 7616 §3.5) against the Digest `Authorization` this authenticator
    /// sent with `req`: `Some(true)` matches, `Some(false)` does not, `None` when it cannot be
    /// checked (the request carried no Digest of ours, or `qop=auth-int`, whose `rspauth`
    /// covers the response body).
    fn rspauth_ok(&self, req: &Request, info: &Challenge, rspauth: &str) -> Option<bool> {
        let sent = req.headers.get("authorization")?;
        if !self.lock().produced.iter().any(|p| p == sent) {
            return None;
        }
        let c = parse_challenges([sent]);
        let a = c.first().filter(|c| c.scheme == "digest")?;
        let qop = a.param("qop")?;
        if qop != "auth" {
            return None;
        }
        let (user, pass) = self.server.digest.as_ref()?;
        let (alg, sess) = DigestAlgorithm::parse(a.param("algorithm").unwrap_or("MD5"))?;
        let (realm, nonce, uri, nc, cnonce) = (a.param("realm")?, a.param("nonce")?, a.param("uri")?, a.param("nc")?, a.param("cnonce")?);
        // the server echoes our nc and cnonce; anything else is a mismatch
        if info.param("nc").is_some_and(|v| v != nc) || info.param("cnonce").is_some_and(|v| v != cnonce) {
            return Some(false);
        }
        let h = |parts: &[&[u8]]| alg.hash_hex(parts);
        let mut ha1 = h(&[user.as_bytes(), b":", realm.as_bytes(), b":", pass.as_bytes()]);
        if sess {
            ha1 = h(&[ha1.as_bytes(), b":", nonce.as_bytes(), b":", cnonce.as_bytes()]);
        }
        let ha2 = h(&[b":", uri.as_bytes()]);
        let want = h(&[ha1.as_bytes(), b":", nonce.as_bytes(), b":", nc.as_bytes(), b":", cnonce.as_bytes(), b":auth:", ha2.as_bytes()]);
        Some(simoom_tls::util::ct_eq(want.as_bytes(), rspauth.to_ascii_lowercase().as_bytes()))
    }
}

#[cfg(feature = "auth-ntlm")]
fn ntlm_creds(domain: &str, user: &str, password: &str) -> NtlmCreds {
    let (domain, user) = match (domain.is_empty(), user.split_once('\\')) {
        (true, Some((d, u))) => (d.to_string(), u.to_string()),
        _ => (domain.to_string(), user.to_string()),
    };
    NtlmCreds { domain, user, password: password.into(), workstation: String::new() }
}

fn body_bytes(req: &Request) -> Option<&[u8]> {
    match &req.body {
        crate::types::Body::Empty => Some(&[]),
        crate::types::Body::Bytes(b) => Some(b),
        crate::types::Body::Reader { .. } => None,
    }
}

impl Interceptor for Auth {
    fn before_send(&self, req: &mut Request) {
        let origin = req.url.origin();
        let uri = req.url.request_target();
        let tid = std::thread::current().id();
        let ident = format!("{} {}", req.method, req.url);
        let mut st = self.lock();
        for side in [Side::Server, Side::Proxy] {
            let name = side.request_header();
            let key = Self::key(side, &origin);
            if let Some(v) = st.pending.remove(&(tid, key.clone(), ident.clone())) {
                #[cfg(feature = "auth-ntlm")]
                if v.starts_with("NTLM ") {
                    pin_http1(req);
                }
                Self::record(&mut st, &v);
                req.headers.set(name, v);
                continue;
            }
            #[cfg(feature = "auth-ntlm")]
            if matches!(st.spaces.get(&key), Some(Space::Ntlm)) {
                pin_http1(req);
            }
            if let Some(cur) = req.headers.get(name) {
                if !st.produced.iter().any(|p| p == cur) {
                    continue; // the caller's own credentials
                }
                req.headers.remove(name);
            }
            // Bearer for its origin even before any challenge
            let v = if side == Side::Server && !st.spaces.contains_key(&key) {
                self.bearer_for(&origin).and_then(|p| p.token(false)).map(|t| format!("Bearer {t}"))
            } else {
                self.preemptive(&mut st, side, &key, &origin, &req.method, &uri, body_bytes(req))
            };
            if let Some(v) = v {
                if side == Side::Server && v.starts_with("Bearer ") {
                    st.spaces.entry(key).or_insert(Space::Bearer);
                }
                Self::record(&mut st, &v);
                req.headers.set(name, v);
            }
        }
    }

    fn on_response(&self, req: &Request, resp: &Response) -> Action {
        let (side, hname) = match resp.status() {
            401 => (Side::Server, "www-authenticate"),
            407 => (Side::Proxy, "proxy-authenticate"),
            _ => {
                // RFC 7616 §3.5: Authentication-Info (rspauth, nextnonce)
                #[cfg(feature = "auth-digest")]
                if let Some(info) = resp.header("authentication-info") {
                    let c = parse_challenges([format!("x {info}").as_str()]);
                    let Some(info) = c.first() else { return Action::Continue };
                    if let Some(rsp) = info.param("rspauth") {
                        if let Some(false) = self.rspauth_ok(req, info, rsp) {
                            return Action::Fail("the Digest rspauth in Authentication-Info does not match");
                        }
                    }
                    if let Some(nn) = info.param("nextnonce") {
                        let key = Self::key(Side::Server, &req.url.origin());
                        if let Some(Space::Digest { ch, nc, .. }) = self.lock().spaces.get_mut(&key) {
                            ch.nonce = nn.to_string();
                            *nc = 0;
                        }
                    }
                }
                return Action::Continue;
            }
        };
        let challenges = parse_challenges(resp.headers().get_all(hname));
        if challenges.is_empty() {
            return Action::Continue;
        }
        let origin = req.url.origin();
        let key = Self::key(side, &origin);
        let mut st = self.lock();
        let sent = req.headers.get(side.request_header()).filter(|v| st.produced.iter().any(|p| p == v)).map(str::to_string);
        if req.headers.contains(side.request_header()) && sent.is_none() {
            return Action::Continue; // the caller's credentials were refused: their call
        }
        let secure = req.url.is_secure() || is_loopback(&req.url.host);
        let target = if side == Side::Proxy { req.url.to_string() } else { req.url.request_target() };
        if !req.body.replayable() {
            return Action::Continue; // cannot be sent again
        }
        match self.answer(&mut st, side, &key, &origin, secure, &challenges, sent.as_deref(), &req.method, &target, body_bytes(req)) {
            Some(v) => {
                // a thread runs one request at a time: older entries are from requests whose
                // retry was not taken
                let tid = std::thread::current().id();
                st.pending.retain(|k, _| k.0 != tid);
                st.pending.insert((tid, key, format!("{} {}", req.method, req.url)), v);
                Action::Retry
            }
            None => Action::Continue,
        }
    }
}

/// Opens a `CONNECT` tunnel, answering `407` challenges with `auth` (Basic, Digest or NTLM on
/// the same connection; at most three rounds). Used instead of the plain tunnel when the client
/// has an [`Auth`].
pub(crate) fn connect_tunnel(auth: &Auth, tcp: &std::net::TcpStream, authority: &str, proxy: &crate::proxy::ProxyAddr, deadline: Option<std::time::Instant>) -> crate::error::Result<()> {
    use crate::error::{Error, ErrorKind, TimeoutKind};
    use crate::transport::{is_timeout, remaining};
    use std::io::{Read, Write};
    let what = format!("proxy {}:{}", proxy.host, proxy.port);
    let mut value = auth.tunnel_answer(proxy, authority, None, None).or_else(|| proxy.authorization());
    let mut head = Vec::with_capacity(512);
    for _round in 0..4 {
        let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(a) = &value {
            req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
        }
        req.push_str("\r\n");
        let _ = tcp.set_write_timeout(remaining(deadline, TimeoutKind::Connect, &what)?);
        (&*tcp).write_all(req.as_bytes()).map_err(|e| Error::io(&e, &what))?;
        let mut buf = [0u8; 2048];
        // read one response head
        let (status, reason, challenges, body_len, close, head_len) = loop {
            let mut hs = [simoom_http1::EMPTY_HEADER; 48];
            match simoom_http1::parse_response(&head, &mut hs, &simoom_http1::Limits::default(), b"CONNECT") {
                Ok(simoom_http1::Status::Complete(r)) => {
                    if r.status / 100 == 1 {
                        let hl = r.head_len;
                        head.drain(..hl);
                        continue;
                    }
                    let hdr = |n: &str| -> Vec<String> { r.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(n.as_bytes())).map(|h| String::from_utf8_lossy(h.value).into_owned()).collect() };
                    let ch = parse_challenges(hdr("proxy-authenticate").iter().map(String::as_str));
                    let len: Option<usize> = hdr("content-length").first().and_then(|v| v.trim().parse().ok());
                    let chunked = !hdr("transfer-encoding").is_empty();
                    let close = hdr("connection").iter().any(|v| v.to_ascii_lowercase().contains("close")) || chunked;
                    break (r.status, String::from_utf8_lossy(r.reason).into_owned(), ch, len.unwrap_or(0), close, r.head_len);
                }
                Ok(simoom_http1::Status::Partial) => {}
                Err(e) => return Err(Error::new(ErrorKind::Proxy, format!("{what} sent an invalid CONNECT response ({e})"))),
            }
            let _ = tcp.set_read_timeout(remaining(deadline, TimeoutKind::Connect, &what)?);
            match (&*tcp).read(&mut buf) {
                Ok(0) => return Err(Error::new(ErrorKind::Proxy, format!("{what} closed the connection during CONNECT"))),
                Ok(n) => head.extend_from_slice(&buf[..n]),
                Err(e) if is_timeout(&e) => return Err(Error::timeout(TimeoutKind::Connect, &what)),
                Err(e) => return Err(Error::io(&e, &what)),
            }
        };
        if (200..300).contains(&status) {
            if head.len() != head_len {
                return Err(Error::new(ErrorKind::Proxy, format!("{what} sent data before the client spoke")));
            }
            return Ok(());
        }
        let refused = || Error::new(ErrorKind::Proxy, format!("{what} refused CONNECT {authority}: {status} {reason}"));
        if status != 407 || close || body_len > 1 << 20 {
            return Err(refused());
        }
        let next = auth.tunnel_answer(proxy, authority, Some(&challenges), value.as_deref());
        let Some(next) = next else { return Err(refused()) };
        // skip the 407 body, keep anything after it (there should be nothing)
        while head.len() < head_len + body_len {
            let _ = tcp.set_read_timeout(remaining(deadline, TimeoutKind::Connect, &what)?);
            match (&*tcp).read(&mut buf) {
                Ok(0) => return Err(refused()),
                Ok(n) => head.extend_from_slice(&buf[..n]),
                Err(e) if is_timeout(&e) => return Err(Error::timeout(TimeoutKind::Connect, &what)),
                Err(e) => return Err(Error::io(&e, &what)),
            }
        }
        head.drain(..head_len + body_len);
        {
            let mut st = auth.lock();
            Auth::record(&mut st, &next);
        }
        value = Some(next);
    }
    Err(Error::new(ErrorKind::Proxy, format!("{what}: too many authentication rounds for CONNECT {authority}")))
}

impl crate::client::ClientBuilder {
    /// Answers authentication challenges with `auth` (see [`crate::auth`]): `401` from origin
    /// servers, `407` from proxies in absolute form, and `407` on `CONNECT` tunnels.
    pub fn auth(self, auth: Arc<Auth>) -> Self {
        self.tunnel_auth(auth.clone()).interceptor(auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_parsing() {
        let c = parse_challenges([r#"Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].scheme, "digest");
        assert_eq!(c[0].param("qop"), Some("auth, auth-int"));
        assert_eq!(c[0].param("ALGORITHM"), Some("SHA-256"));
        // several challenges in one field, token68, empty elements, escapes
        let c = parse_challenges([r#"Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple", NTLM, , Negotiate TlRMTVNTUAABAAAAB4IIog==, Bearer"#]);
        let schemes: Vec<&str> = c.iter().map(|c| c.scheme.as_str()).collect();
        assert_eq!(schemes, ["newauth", "basic", "ntlm", "negotiate", "bearer"]);
        assert_eq!(c[0].param("title"), Some(r#"Login to "apps""#));
        assert_eq!(c[0].param("type"), Some("1"));
        assert_eq!(c[3].token68.as_deref(), Some("TlRMTVNTUAABAAAAB4IIog=="));
        assert_eq!(c[2].token68, None);
        // across several fields
        let c = parse_challenges(["Basic realm=a", "Bearer error=\"invalid_token\""]);
        assert_eq!((c.len(), c[1].param("error")), (2, Some("invalid_token")));
        // garbage stops parsing without panicking
        let _ = parse_challenges(["\"", "=x", "Basic realm=\"unterminated", "a b=c d e=", "Digest ,,=,"]);
    }

    #[test]
    fn bearer_and_basic_flow() {
        use crate::url::Url;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let a = Auth::new().bearer("https://api.test", move |refresh: bool| {
            c2.fetch_add(1, Ordering::SeqCst);
            Some(if refresh { "new".to_string() } else { "old".to_string() })
        });
        let mut r = Request::new("GET", Url::parse("https://api.test/x").unwrap());
        a.before_send(&mut r);
        assert_eq!(r.headers.get("authorization"), Some("Bearer old"));
        // other origins never see it
        let mut o = Request::new("GET", Url::parse("https://evil.test/x").unwrap());
        a.before_send(&mut o);
        assert!(!o.headers.contains("authorization"));
        // the caller's own header is kept
        let mut u = Request::new("GET", Url::parse("https://api.test/x").unwrap());
        u.headers.set("Authorization", "Bearer mine");
        a.before_send(&mut u);
        assert_eq!(u.headers.get("authorization"), Some("Bearer mine"));
        assert!(calls.load(Ordering::SeqCst) >= 1);
    }

    #[cfg(feature = "auth-digest")]
    #[test]
    fn rfc7616_and_rfc2617_vectors() {
        // RFC 7616 §3.9.1, MD5 and SHA-256
        let base = r#"realm="http-auth@example.org", qop="auth, auth-int", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#;
        let cn = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        for (alg, want) in [("MD5", "8ca523f5e9506fed4657c9700eebdbec"), ("SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1")] {
            let c = parse_challenges([format!("Digest {base}, algorithm={alg}").as_str()]);
            let d = DigestChallenge::from_challenge(&c[0]).unwrap();
            let v = d.authorization("Mufasa", "Circle of Life", "GET", "/dir/index.html", Some(b""), false, 1, cn);
            assert!(v.contains(&format!("response=\"{want}\"")), "{alg}: {v}");
            assert!(v.contains("nc=00000001") && v.contains("qop=auth,") && v.contains("opaque=\"FQhe"), "{v}");
        }
        // RFC 7616 §3.9.2: SHA-512-256 with userhash and a non-ASCII user name. The username
        // hash and response printed in the RFC (488869..., ae66e6...) match no SHA-512/256
        // implementation (the example is the subject of errata reports); these values were
        // cross-checked with Python's hashlib (OpenSSL) `sha512_256` on the same inputs.
        let c = parse_challenges([r#"Digest realm="api@example.org", qop="auth", algorithm=SHA-512-256, nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS", charset=UTF-8, userhash=true"#]);
        let d = DigestChallenge::from_challenge(&c[0]).unwrap();
        let v = d.authorization("J\u{e4}s\u{f8}n Doe", "Secret, or not?", "GET", "/doe.json", None, false, 1, "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v");
        assert!(v.contains("username=\"793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b\""), "{v}");
        assert!(v.contains("response=\"3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5\""), "{v}");
        assert!(v.ends_with("userhash=true"));
        // without userhash, the name goes as username* (RFC 8187)
        let mut d2 = d.clone();
        d2.userhash = false;
        assert!(d2.authorization("J\u{e4}s\u{f8}n Doe", "x", "GET", "/", None, false, 1, "c").contains("username*=UTF-8''J%C3%A4s%C3%B8n%20Doe"));
        // RFC 2617 §3.5 (MD5, qop=auth)
        let c = parse_challenges([r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#]);
        let d = DigestChallenge::from_challenge(&c[0]).unwrap();
        let v = d.authorization("Mufasa", "Circle Of Life", "GET", "/dir/index.html", None, false, 1, "0a4f113b");
        assert!(v.contains("response=\"6629fae49393a05397450978507c4ef1\""), "{v}");
        // RFC 2069 form (no qop) and auth-int
        let c = parse_challenges([r#"Digest realm="r", nonce="n""#]);
        let d = DigestChallenge::from_challenge(&c[0]).unwrap();
        let ha1 = DigestAlgorithm::Md5.hash_hex(&[b"u:r:p"]);
        let ha2 = DigestAlgorithm::Md5.hash_hex(&[b"GET:/"]);
        let want = DigestAlgorithm::Md5.hash_hex(&[ha1.as_bytes(), b":n:", ha2.as_bytes()]);
        let v = d.authorization("u", "p", "GET", "/", None, false, 1, "c");
        assert!(v.contains(&format!("response=\"{want}\"")) && !v.contains("qop"), "{v}");
        let c = parse_challenges([r#"Digest realm="r", nonce="n", qop="auth-int", algorithm=SHA-256-sess"#]);
        let d = DigestChallenge::from_challenge(&c[0]).unwrap();
        assert!(d.sess && d.qop_auth_int && !d.qop_auth);
        let v = d.authorization("u", "p", "POST", "/", Some(b"body"), false, 2, "c");
        let h = |p: &[&[u8]]| DigestAlgorithm::Sha256.hash_hex(p);
        let ha1 = h(&[h(&[b"u:r:p"]).as_bytes(), b":n:c"]);
        let ha2 = h(&[b"POST:/:", h(&[b"body"]).as_bytes()]);
        let want = h(&[ha1.as_bytes(), b":n:00000002:c:auth-int:", ha2.as_bytes()]);
        assert!(v.contains(&format!("response=\"{want}\"")) && v.contains("qop=auth-int") && v.contains("algorithm=SHA-256-sess"), "{v}");
        assert_eq!(DigestAlgorithm::parse("sha-512-256-SESS"), Some((DigestAlgorithm::Sha512_256, true)));
        assert_eq!(DigestAlgorithm::parse("SHA-1"), None);
    }

    #[cfg(feature = "auth-ntlm")]
    #[test]
    fn ms_nlmp_ntlmv2_vectors() {
        // MS-NLMP 4.2.4: User "User", domain "Domain", password "Password", server challenge
        // 0123456789abcdef, client challenge aa*8, time 0, AV pairs NbDomainName "Domain" and
        // NbComputerName "Server".
        let key = ntlm::ntowf_v2("User", "Password", "Domain");
        assert_eq!(hex(&key), "0c868a403bfd7a93a3001ef22ef02e3f");
        let mut ti = Vec::new();
        for (id, s) in [(2u16, "Domain"), (1, "Server")] {
            let v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            ti.extend_from_slice(&id.to_le_bytes());
            ti.extend_from_slice(&(v.len() as u16).to_le_bytes());
            ti.extend_from_slice(&v);
        }
        ti.extend_from_slice(&[0; 4]);
        let ch = ntlm::ChallengeMessage { flags: 0xe28a8233, server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], target_name: Vec::new(), target_info: ti.clone() };
        let (nt, lm, session) = ntlm::responses(&ch, &key, &[0xaa; 8], 0);
        assert_eq!(hex(&lm), "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");
        assert_eq!(hex(&nt[..16]), "68cd0ab851e51c96aabc927bebef6a1c");
        assert_eq!(hex(&session), "8de40ccadbc14a82f15cb0ad0de95ca3");
        // a CHALLENGE_MESSAGE round trip through the parser, and the AUTHENTICATE layout
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\0");
        m.extend_from_slice(&2u32.to_le_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 48, 0, 0, 0]); // empty target name
        m.extend_from_slice(&0xe28a8233u32.to_le_bytes());
        m.extend_from_slice(&ch.server_challenge);
        m.extend_from_slice(&[0; 8]);
        m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
        m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
        m.extend_from_slice(&48u32.to_le_bytes());
        m.extend_from_slice(&ti);
        let p = ntlm::parse_challenge(&m).unwrap();
        assert_eq!(p, ch);
        let auth = ntlm::authenticate(&p, "User", "Password", "Domain", "COMPUTER", &[0xaa; 8], 0);
        assert_eq!(&auth[..12], b"NTLMSSP\0\x03\0\0\0");
        let f = |at: usize| (u16::from_le_bytes([auth[at], auth[at + 1]]) as usize, u32::from_le_bytes(auth[at + 4..at + 8].try_into().unwrap()) as usize);
        let (ul, uo) = f(36);
        assert_eq!(&auth[uo..uo + ul], "User".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>().as_slice());
        let (nl, no) = f(20);
        assert_eq!(&auth[no..no + nl], nt.as_slice());
        // malformed challenges
        assert!(ntlm::parse_challenge(&m[..20]).is_none());
        let mut bad = m.clone();
        bad[44] = 0xff; // target info offset out of bounds
        assert!(ntlm::parse_challenge(&bad).is_none());
        assert_eq!(&ntlm::negotiate()[..12], b"NTLMSSP\0\x01\0\0\0");
    }
}
