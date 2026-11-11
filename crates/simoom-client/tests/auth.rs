//! Authentication against in-test servers that verify independently (their own Digest and
//! NTLMv2 computations from simoom-tls primitives): Digest with every algorithm, nonce counts,
//! stale nonces, auth-int, Bearer refresh, Basic, NTLM on one connection, proxies in absolute
//! form and on CONNECT tunnels, cookies set on a 401. When `curl` is installed, it is run
//! against the same servers to show that their checks accept a real implementation.

mod common;

use common::{raw, read_head};
use simoom_client::auth::Auth;
use simoom_client::Client;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(any(feature = "auth-digest", feature = "auth-ntlm"))]
use {
    common::read_n,
    simoom_client::{Body, ProxyAddr, ProxyConfig},
    std::net::TcpStream,
};
#[cfg(feature = "auth-digest")]
use {std::collections::HashMap, std::sync::Mutex};

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[cfg(any(feature = "auth-digest", feature = "auth-ntlm"))]
fn body_of(s: &mut TcpStream, head: &str) -> Vec<u8> {
    let n: usize = header(head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    read_n(s, n)
}

fn target(head: &str) -> (String, String) {
    let mut p = head.lines().next().unwrap_or("").split_whitespace();
    (p.next().unwrap_or("").to_string(), p.next().unwrap_or("").to_string())
}

#[cfg(feature = "auth-digest")]
/// `k=v, k="v"` parameters (test-local parser, deliberately not the client's).
fn params(s: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b' ' || b[i] == b',') {
            i += 1;
        }
        let ks = i;
        while i < b.len() && b[i] != b'=' {
            i += 1;
        }
        let k = s[ks..i].trim().to_ascii_lowercase();
        i += 1;
        let v = if i < b.len() && b[i] == b'"' {
            i += 1;
            let mut v = String::new();
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                v.push(b[i] as char);
                i += 1;
            }
            i += 1;
            v
        } else {
            let vs = i;
            while i < b.len() && b[i] != b',' {
                i += 1;
            }
            s[vs..i].trim().to_string()
        };
        if !k.is_empty() {
            m.insert(k, v);
        }
    }
    m
}

#[cfg(feature = "auth-digest")]
fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(feature = "auth-digest")]
fn hash(alg: &str, data: &[u8]) -> String {
    use simoom_tls::crypto::sha2::{Sha256, Sha512};
    match alg.trim_end_matches("-sess").trim_end_matches("-SESS") {
        "MD5" => hx(&simoom_tls::crypto::legacy::Md5::digest(data)),
        "SHA-256" => hx(&Sha256::digest(data)),
        "SHA-512-256" => {
            let mut h = Sha512::new512_256();
            h.update(data);
            hx(&h.finish())
        }
        a => panic!("algorithm {a}"),
    }
}

#[cfg(feature = "auth-digest")]
/// Verifies a Digest `Authorization` value; returns the nonce count.
fn verify_digest(auth: &str, method: &str, uri: &str, body: &[u8], nonce: &str, user: &str, pass: &str, realm: &str) -> Result<u32, String> {
    let p = params(auth.strip_prefix("Digest ").ok_or("not digest")?);
    let alg = p.get("algorithm").cloned().unwrap_or_else(|| "MD5".into());
    if p.get("nonce").map(String::as_str) != Some(nonce) {
        return Err("stale".into());
    }
    if p.get("uri").map(String::as_str) != Some(uri) || p.get("realm").map(String::as_str) != Some(realm) {
        return Err(format!("uri/realm {p:?}"));
    }
    let uname_ok = if p.get("userhash").map(String::as_str) == Some("true") {
        p.get("username") == Some(&hash(&alg, format!("{user}:{realm}").as_bytes()))
    } else {
        p.get("username").map(String::as_str) == Some(user)
    };
    if !uname_ok {
        return Err("username".into());
    }
    let cnonce = p.get("cnonce").cloned().unwrap_or_default();
    let mut ha1 = hash(&alg, format!("{user}:{realm}:{pass}").as_bytes());
    if alg.to_ascii_lowercase().ends_with("-sess") {
        ha1 = hash(&alg, format!("{ha1}:{nonce}:{cnonce}").as_bytes());
    }
    let qop = p.get("qop").cloned().ok_or("no qop")?;
    let ha2 = if qop == "auth-int" { hash(&alg, format!("{method}:{uri}:{}", hash(&alg, body)).as_bytes()) } else { hash(&alg, format!("{method}:{uri}").as_bytes()) };
    let nc = p.get("nc").cloned().ok_or("no nc")?;
    let want = hash(&alg, format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes());
    if p.get("response") != Some(&want) {
        return Err(format!("bad response for {alg} {qop}"));
    }
    if p.get("opaque").map(String::as_str) != Some("op4que") {
        return Err("opaque".into());
    }
    u32::from_str_radix(&nc, 16).map_err(|e| e.to_string())
}

#[cfg(feature = "auth-digest")]
struct DigestSrv {
    addr: std::net::SocketAddr,
    nonce: Arc<Mutex<String>>,
    log: Arc<Mutex<Vec<String>>>,
}

#[cfg(feature = "auth-digest")]
/// A Digest server: `algs` are offered in order; `/rotate` makes the next answer stale;
/// with `cookie`, the 401 sets `route=7` and success needs it back.
fn digest_server(algs: &'static [&'static str], qop: &'static str, cookie: bool) -> DigestSrv {
    let nonce = Arc::new(Mutex::new("n0nce-1".to_string()));
    let log = Arc::new(Mutex::new(Vec::new()));
    let (n2, l2) = (nonce.clone(), log.clone());
    let last_nc = Arc::new(Mutex::new(0u32));
    let r = raw(move |mut s, _| {
        while let Some(head) = read_head(&mut s) {
            let body = body_of(&mut s, &head);
            let (method, uri) = target(&head);
            let cur = n2.lock().unwrap().clone();
            let res = match header(&head, "authorization") {
                Some(a) => verify_digest(a, &method, &uri, &body, &cur, "Mufasa", "Circle of Life", "test@simoom"),
                None => Err("none".into()),
            };
            let res = res.and_then(|nc| {
                let mut l = last_nc.lock().unwrap();
                if nc <= *l && nc != 1 {
                    return Err(format!("nc {nc} not increasing"));
                }
                *l = nc;
                if cookie && !header(&head, "cookie").is_some_and(|c| c.contains("route=7")) {
                    return Err("no cookie".into());
                }
                Ok(nc)
            });
            l2.lock().unwrap().push(format!("{method} {uri} {res:?}"));
            let resp = match res {
                Ok(nc) => {
                    if uri == "/rotate" {
                        *n2.lock().unwrap() = format!("n0nce-{}", nc + 100);
                    }
                    let b = format!("ok nc={nc}");
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len())
                }
                Err(e) => {
                    let stale = if e == "stale" { ", stale=true" } else { "" };
                    let mut h = String::from("HTTP/1.1 401 Unauthorized\r\n");
                    for a in algs {
                        h.push_str(&format!("WWW-Authenticate: Digest realm=\"test@simoom\", qop=\"{qop}\", algorithm={a}, nonce=\"{cur}\", opaque=\"op4que\"{stale}\r\n"));
                    }
                    if cookie {
                        h.push_str("Set-Cookie: route=7\r\n");
                    }
                    h.push_str("Content-Length: 12\r\n\r\nunauthorized");
                    h
                }
            };
            if s.write_all(resp.as_bytes()).is_err() {
                return;
            }
        }
    });
    DigestSrv { addr: r.addr, nonce, log }
}

#[cfg(feature = "auth-digest")]
#[test]
fn digest_every_algorithm_nonce_counts_and_stale() {
    for (algs, want) in [(&["MD5"][..], "MD5"), (&["MD5", "SHA-256"][..], "SHA-256"), (&["SHA-256", "SHA-512-256", "MD5"][..], "SHA-512-256"), (&["SHA-256-sess"][..], "SHA-256-sess")] {
        let srv = digest_server(algs, "auth", false);
        let c = Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "Circle of Life"))).build();
        let u = |p: &str| format!("http://{}{p}", srv.addr);
        assert_eq!(c.get(&u("/a")).send().unwrap().text().unwrap(), "ok nc=1", "{want}");
        // later requests authenticate up front with the next nonce count (no 401)
        assert_eq!(c.get(&u("/b?x=1")).send().unwrap().text().unwrap(), "ok nc=2");
        assert_eq!(c.post(&u("/c")).body("data").send().unwrap().text().unwrap(), "ok nc=3");
        let log = srv.log.lock().unwrap().clone();
        assert_eq!(log.len(), 4, "{log:?}");
        assert!(log[1].contains("Ok(1)") && log[3].contains("Ok(3)"), "{log:?}");
        // a streamed body works once the nonce is known
        let r = c.put(&u("/d")).body(Body::sized_reader(std::io::Cursor::new(b"streamed".to_vec()), 8)).send().unwrap();
        assert_eq!(r.text().unwrap(), "ok nc=4");
        // the server rotates its nonce: the next request is stale, answered once more
        assert_eq!(c.get(&u("/rotate")).send().unwrap().text().unwrap(), "ok nc=5");
        assert_eq!(c.get(&u("/e")).send().unwrap().text().unwrap(), "ok nc=1");
        assert!(srv.log.lock().unwrap().iter().any(|l| l.contains("/e Err(\"stale\")")));
        let _ = &srv.nonce;
    }
}

#[cfg(feature = "auth-digest")]
#[test]
fn digest_auth_int_wrong_password_and_streamed_first_request() {
    let srv = digest_server(&["SHA-256"], "auth-int", false);
    let u = |p: &str| format!("http://{}{p}", srv.addr);
    let c = Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "Circle of Life").digest_auth_int(true))).build();
    assert_eq!(c.post(&u("/int")).body("hashed body").send().unwrap().text().unwrap(), "ok nc=1");
    assert!(srv.log.lock().unwrap()[1].contains("Ok(1)"));
    // a wrong password: one retry, then the 401 comes back (no loop)
    let srv = digest_server(&["MD5"], "auth", false);
    let c = Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "wrong"))).build();
    let r = c.get(&format!("http://{}/x", srv.addr)).send().unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(srv.log.lock().unwrap().len(), 2);
    // a streamed body on the first request cannot be replayed: the 401 is returned
    let c = Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "Circle of Life"))).build();
    let r = c.put(&format!("http://{}/s", srv.addr)).body(Body::sized_reader(std::io::Cursor::new(b"x".to_vec()), 1)).send().unwrap();
    assert_eq!(r.status(), 401);
    // the caller's own Authorization is not replaced
    let r = c.get(&format!("http://{}/m", srv.addr)).header("Authorization", "Digest username=\"me\"").send().unwrap();
    assert_eq!(r.status(), 401);
    // credentials limited to other origins are not used
    let c = Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "Circle of Life").only_origins(&["http://elsewhere.test"]))).build();
    assert_eq!(c.get(&format!("http://{}/o", srv.addr)).send().unwrap().status(), 401);
}

#[cfg(all(feature = "auth-digest", feature = "cookies"))]
#[test]
fn cookies_from_a_401_reach_the_retry() {
    let srv = digest_server(&["SHA-256"], "auth", true);
    let jar = Arc::new(simoom_client::cookie::CookieJar::new());
    let c = Client::builder().cookie_jar(jar.clone()).auth(Arc::new(Auth::new().digest("Mufasa", "Circle of Life"))).build();
    assert_eq!(c.get(&format!("http://{}/a", srv.addr)).send().unwrap().text().unwrap(), "ok nc=1");
    assert_eq!(jar.len(), 1);
}

#[test]
fn bearer_refresh_and_basic_on_challenge() {
    let srv = raw(|mut s, _| {
        while let Some(head) = read_head(&mut s) {
            let a = header(&head, "authorization").unwrap_or("");
            let resp = if a == "Bearer fresh" || a == "Basic dTpw" {
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{a}", a.len())
            } else if target(&head).1.starts_with("/basic") {
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"api\", error=\"invalid_token\"\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            if s.write_all(resp.as_bytes()).is_err() {
                return;
            }
        }
    });
    let origin = format!("http://{}", srv.addr);
    let refreshes = Arc::new(AtomicUsize::new(0));
    let r2 = refreshes.clone();
    let auth = Auth::new()
        .bearer(&origin, move |refresh: bool| {
            if refresh {
                r2.fetch_add(1, Ordering::SeqCst);
                Some("fresh".to_string())
            } else if r2.load(Ordering::SeqCst) > 0 {
                Some("fresh".to_string())
            } else {
                Some("expired".to_string())
            }
        })
        .basic("u", "p");
    let c = Client::builder().auth(Arc::new(auth)).build();
    assert_eq!(c.get(&format!("{origin}/a")).send().unwrap().text().unwrap(), "Bearer fresh");
    assert_eq!(c.get(&format!("{origin}/b")).send().unwrap().text().unwrap(), "Bearer fresh");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    // Basic over plain http to a loopback host, only after a challenge
    let c = Client::builder().auth(Arc::new(Auth::new().basic("u", "p"))).build();
    assert_eq!(c.get(&format!("{origin}/basic")).send().unwrap().text().unwrap(), "Basic dTpw");
}

// ------------------------------------------------------------------------------- NTLM

#[cfg(feature = "auth-ntlm")]
const NTLM_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

#[cfg(feature = "auth-ntlm")]
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

#[cfg(feature = "auth-ntlm")]
fn b64(d: &[u8]) -> String {
    let mut o = Vec::new();
    simoom_http1::base64_encode(d, &mut o);
    String::from_utf8(o).unwrap()
}

#[cfg(feature = "auth-ntlm")]
fn unb64(s: &str) -> Vec<u8> {
    let mut o = Vec::new();
    assert!(simoom_http1::base64_decode(s.as_bytes(), &mut o), "base64");
    o
}

#[cfg(feature = "auth-ntlm")]
/// A CHALLENGE_MESSAGE with NbDomainName, NbComputerName and a timestamp.
fn ntlm_type2() -> Vec<u8> {
    let mut ti = Vec::new();
    for (id, v) in [(2u16, utf16("TESTDOM")), (1, utf16("SRV")), (7, 0x01d9_0000_0000_0000u64.to_le_bytes().to_vec())] {
        ti.extend_from_slice(&id.to_le_bytes());
        ti.extend_from_slice(&(v.len() as u16).to_le_bytes());
        ti.extend_from_slice(&v);
    }
    ti.extend_from_slice(&[0; 4]);
    let name = utf16("TESTDOM");
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(&48u32.to_le_bytes());
    m.extend_from_slice(&0xe28a_8235u32.to_le_bytes());
    m.extend_from_slice(&NTLM_CHALLENGE);
    m.extend_from_slice(&[0; 8]);
    m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
    m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
    m.extend_from_slice(&((48 + name.len()) as u32).to_le_bytes());
    m.extend_from_slice(&name);
    m.extend_from_slice(&ti);
    m
}

#[cfg(feature = "auth-ntlm")]
/// Verifies an AUTHENTICATE_MESSAGE's NTLMv2 response with MD4 and HMAC-MD5 directly.
fn verify_ntlm(m: &[u8], password: &str) -> Result<String, String> {
    use simoom_tls::crypto::legacy::{hmac_md5, Md4};
    if m.len() < 64 || &m[..8] != b"NTLMSSP\0" || m[8] != 3 {
        return Err("not type 3".into());
    }
    let f = |at: usize| -> Result<&[u8], String> {
        let l = u16::from_le_bytes([m[at], m[at + 1]]) as usize;
        let o = u32::from_le_bytes(m[at + 4..at + 8].try_into().unwrap()) as usize;
        m.get(o..o + l).ok_or_else(|| "field out of bounds".to_string())
    };
    let from16 = |b: &[u8]| String::from_utf16_lossy(&b.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>());
    let (nt, domain, user) = (f(20)?, from16(f(28)?), from16(f(36)?));
    if nt.len() < 48 {
        return Err("NT response too short for NTLMv2".into());
    }
    let key = hmac_md5(&Md4::digest(&utf16(password)), &[&utf16(&(user.to_uppercase() + &domain))]);
    let proof = hmac_md5(&key, &[&NTLM_CHALLENGE, &nt[16..]]);
    if proof[..] != nt[..16] {
        return Err("bad NTProofStr".into());
    }
    Ok(format!("{domain}\\{user}"))
}

#[cfg(feature = "auth-ntlm")]
/// An NTLM server: the handshake must complete on one connection, which is authenticated
/// afterwards.
fn ntlm_server(conns: Arc<AtomicUsize>) -> std::net::SocketAddr {
    raw(move |mut s, _| {
        conns.fetch_add(1, Ordering::SeqCst);
        let mut authed: Option<String> = None;
        let mut challenged = false;
        while let Some(head) = read_head(&mut s) {
            let _ = body_of(&mut s, &head);
            let a = header(&head, "authorization").unwrap_or("").to_string();
            let resp = if let Some(who) = &authed {
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{who}", who.len())
            } else if let Some(t) = a.strip_prefix("NTLM ") {
                let m = unb64(t);
                if m.get(8) == Some(&1) {
                    challenged = true;
                    format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\n\r\n", b64(&ntlm_type2()))
                } else if challenged {
                    match verify_ntlm(&m, "Pa55w0rd") {
                        Ok(who) => {
                            authed = Some(who.clone());
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{who}", who.len())
                        }
                        Err(e) => format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: {}\r\n\r\n{e}", e.len()),
                    }
                } else {
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n".to_string()
                }
            } else {
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\nContent-Length: 6\r\n\r\nlogin!".to_string()
            };
            if s.write_all(resp.as_bytes()).is_err() {
                return;
            }
        }
    })
    .addr
}

#[cfg(feature = "auth-ntlm")]
#[test]
fn ntlm_handshake_on_one_connection() {
    let conns = Arc::new(AtomicUsize::new(0));
    let addr = ntlm_server(conns.clone());
    let c = Client::builder().auth(Arc::new(Auth::new().ntlm("", "CORP\\alice", "Pa55w0rd"))).build();
    assert_eq!(c.get(&format!("http://{addr}/")).send().unwrap().text().unwrap(), "CORP\\alice");
    // the authenticated connection is reused from the pool
    assert_eq!(c.post(&format!("http://{addr}/again")).body("x").send().unwrap().text().unwrap(), "CORP\\alice");
    assert_eq!(conns.load(Ordering::SeqCst), 1);
    // a wrong password stops after the server refuses the AUTHENTICATE message
    let c = Client::builder().auth(Arc::new(Auth::new().ntlm("CORP", "alice", "nope"))).build();
    let r = c.get(&format!("http://{addr}/")).send().unwrap();
    assert_eq!((r.status(), r.text().unwrap()), (401, "bad NTProofStr".to_string()));
}

// ------------------------------------------------------------------------------ proxies

#[cfg(all(feature = "auth-digest", feature = "auth-ntlm"))]
/// A proxy that wants Digest (absolute form and CONNECT) or NTLM (CONNECT) before it forwards.
fn auth_proxy(scheme: &'static str) -> std::net::SocketAddr {
    raw(move |mut c, _| {
        let mut challenged = false;
        while let Some(head) = read_head(&mut c) {
            let body = body_of(&mut c, &head);
            let (method, tgt) = target(&head);
            let pa = header(&head, "proxy-authorization").unwrap_or("").to_string();
            let ok = match scheme {
                "digest" => verify_digest(&pa, &method, &tgt, &body, "pn0nce", "Mufasa", "Circle of Life", "test@simoom").is_ok(),
                _ => match pa.strip_prefix("NTLM ") {
                    Some(t) => {
                        let m = unb64(t);
                        if m.get(8) == Some(&1) {
                            challenged = true;
                            let r = format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM {}\r\nContent-Length: 4\r\n\r\nmore", b64(&ntlm_type2()));
                            c.write_all(r.as_bytes()).unwrap();
                            continue;
                        }
                        challenged && verify_ntlm(&m, "Pa55w0rd").is_ok()
                    }
                    None => false,
                },
            };
            if !ok {
                let ch = if scheme == "digest" {
                    "Proxy-Authenticate: Digest realm=\"test@simoom\", qop=\"auth\", algorithm=SHA-256, nonce=\"pn0nce\", opaque=\"op4que\"".to_string()
                } else {
                    "Proxy-Authenticate: NTLM".to_string()
                };
                c.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\n{ch}\r\nContent-Length: 0\r\n\r\n").as_bytes()).unwrap();
                continue;
            }
            if method == "CONNECT" {
                let mut up = TcpStream::connect(&tgt).unwrap();
                c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
                let mut c2 = c.try_clone().unwrap();
                let mut up2 = up.try_clone().unwrap();
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c2, &mut up2);
                });
                let _ = std::io::copy(&mut up, &mut c);
                return;
            }
            let auth = tgt.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("").to_string();
            let mut up = TcpStream::connect(&auth).unwrap();
            let fwd: String = head.lines().filter(|l| !l.to_ascii_lowercase().starts_with("proxy-authorization") && !l.is_empty()).map(|l| format!("{l}\r\n")).collect();
            up.write_all(fwd.as_bytes()).unwrap();
            up.write_all(b"\r\n").unwrap();
            up.write_all(&body).unwrap();
            let mut c2 = c.try_clone().unwrap();
            let mut up2 = up.try_clone().unwrap();
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut c2, &mut up2);
            });
            let _ = std::io::copy(&mut up, &mut c);
            return;
        }
    })
    .addr
}

#[cfg(all(feature = "auth-digest", feature = "auth-ntlm"))]
#[test]
fn proxy_digest_absolute_form_and_tunnel() {
    let h = common::plain();
    let p = auth_proxy("digest");
    let auth = Arc::new(Auth::new().proxy_digest("Mufasa", "Circle of Life"));
    // absolute form: the 407 is a response, answered by the interceptor
    let c = Client::builder().proxy(Some(ProxyConfig::new(ProxyAddr::new(p.ip().to_string(), p.port())))).auth(auth.clone()).build();
    let t = c.get(&common::url(&h, "/echo")).send().unwrap().text().unwrap();
    assert!(t.starts_with("Http11 GET /echo"), "{t}");
    // CONNECT tunnel: answered while the tunnel opens
    let mut pc = ProxyConfig::new(ProxyAddr::new(p.ip().to_string(), p.port()));
    pc.tunnel_http = true;
    let c = Client::builder().proxy(Some(pc)).auth(auth).build();
    let t = c.get(&common::url(&h, "/echo")).send().unwrap().text().unwrap();
    assert!(t.starts_with("Http11 GET /echo"), "{t}");
    // without credentials the CONNECT refusal is a proxy error
    let mut pc = ProxyConfig::new(ProxyAddr::new(p.ip().to_string(), p.port()));
    pc.tunnel_http = true;
    let e = Client::builder().proxy(Some(pc)).auth(Arc::new(Auth::new())).build().get(&common::url(&h, "/echo")).send().unwrap_err();
    assert_eq!(e.kind, simoom_client::ErrorKind::Proxy, "{e}");
}

#[cfg(all(feature = "auth-digest", feature = "auth-ntlm"))]
#[test]
fn proxy_ntlm_tunnel() {
    let h = common::plain();
    let p = auth_proxy("ntlm");
    let mut pc = ProxyConfig::new(ProxyAddr::new(p.ip().to_string(), p.port()));
    pc.tunnel_http = true;
    let c = Client::builder().proxy(Some(pc)).auth(Arc::new(Auth::new().proxy_ntlm("CORP", "alice", "Pa55w0rd"))).build();
    let t = c.get(&common::url(&h, "/echo")).send().unwrap().text().unwrap();
    assert!(t.starts_with("Http11 GET /echo"), "{t}");
}

// ------------------------------------------------------------------- real implementation

#[cfg(all(feature = "auth-digest", feature = "auth-ntlm"))]
fn curl() -> Option<&'static str> {
    let ok = std::process::Command::new("curl").arg("--version").output().is_ok_and(|o| o.status.success());
    ok.then_some("curl")
}

#[cfg(all(feature = "auth-digest", feature = "auth-ntlm"))]
/// curl (a real Digest and NTLM implementation) against the same in-test servers: proves their
/// checks accept what curl sends, so the tests above check against real behaviour.
#[test]
fn curl_is_accepted_by_the_test_servers() {
    let Some(curl) = curl() else {
        eprintln!("skipped: curl is not installed");
        return;
    };
    let srv = digest_server(&["MD5"], "auth", false);
    let out = std::process::Command::new(curl).args(["-s", "--digest", "-u", "Mufasa:Circle of Life", &format!("http://{}/curl", srv.addr)]).output().unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert_eq!(body, "ok nc=1", "curl digest: {body} {:?}", srv.log.lock().unwrap());
    // NTLM: the first curl that supports it (Windows' own curl.exe uses SSPI)
    let addr = ntlm_server(Arc::new(AtomicUsize::new(0)));
    for cand in [curl, "C:\\Windows\\System32\\curl.exe"] {
        let Ok(out) = std::process::Command::new(cand).args(["-s", "--ntlm", "-u", "CORP\\alice:Pa55w0rd", &format!("http://{addr}/")]).output() else { continue };
        let body = String::from_utf8_lossy(&out.stdout);
        if body.is_empty() && !out.status.success() {
            eprintln!("{cand} has no NTLM support ({})", String::from_utf8_lossy(&out.stderr).trim());
            continue;
        }
        assert!(body.eq_ignore_ascii_case("CORP\\alice"), "{cand} ntlm: {body}");
        eprintln!("{cand}: NTLM accepted");
        return;
    }
    eprintln!("skipped NTLM: no curl with NTLM support");
}
