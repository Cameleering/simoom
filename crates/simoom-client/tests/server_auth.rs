//! simoom's server-side authentication (`simoom::auth`, facade feature `auth`) against this
//! client and against curl: Digest with every algorithm, nonce counts, stale nonces,
//! `nextnonce`, `rspauth` checked by the client, `auth-int`, Basic, Bearer; plus the client's
//! interceptors on WebSocket handshakes and `Client::call`.
#![cfg(feature = "auth-digest")]

mod common;

use common::{raw, read_head};
use simoom::auth::{Auth as SrvAuth, Basic, Credential, Digest, DigestAlgorithm};
use simoom::{Outcome, Reply, Request, Server, ServerHandle};
use simoom_client::auth::Auth;
use simoom_client::{Client, ErrorKind};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

fn users(u: &str) -> Option<String> {
    (u == "Mufasa").then(|| "Circle of Life".to_string())
}

fn server(algs: &[(DigestAlgorithm, bool)], ttl: Duration) -> ServerHandle {
    let digest = Digest::new("test@simoom", |u: &str, _| users(u).map(Credential::Password)).algorithms(algs).auth_int(true).nonce_ttl(ttl);
    let auth = SrvAuth::new().digest(digest).basic(Basic::new("test@simoom", users)).bearer("api", |t: &str| (t == "tok3n").then(|| "svc".to_string()));
    let app = auth.wrap_with_user(|req: &mut Request<'_>, reply: Reply<'_>, user: &str| -> Outcome {
        if req.is_websocket_upgrade() {
            return reply.websocket(Echo);
        }
        let b = format!("hello {user} {}", req.body().len());
        reply.header("set-cookie", "seen=1").body(b)
    });
    Server::builder().listen("127.0.0.1:0").threads(2).service(app).start().expect("server")
}

struct Echo;
impl simoom::WebSocketHandler for Echo {
    fn on_message(&mut self, ws: &mut simoom::WebSocket<'_>, msg: simoom::WsMessage<'_>) {
        if let simoom::WsMessage::Text(t) = msg {
            ws.send_text(&format!("echo:{t}"));
        }
    }
}

fn url(h: &ServerHandle, p: &str) -> String {
    format!("http://127.0.0.1:{}{p}", h.local_addrs()[0].port())
}

fn digest_client() -> Client {
    Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "Circle of Life").digest_auth_int(false))).build()
}

#[test]
fn digest_every_algorithm_with_rspauth() {
    for algs in [
        &[(DigestAlgorithm::Sha256, false)][..],
        &[(DigestAlgorithm::Md5, false)][..],
        &[(DigestAlgorithm::Md5, true)][..],
        &[(DigestAlgorithm::Sha256, true), (DigestAlgorithm::Sha512_256, false), (DigestAlgorithm::Md5, false)][..],
    ] {
        let h = server(algs, Duration::from_secs(300));
        let c = digest_client();
        // 401, retry, 200 with Authentication-Info whose rspauth the client checks
        let r = c.get(&url(&h, "/a?x=1")).send().unwrap();
        assert!(r.header("authentication-info").unwrap().starts_with("rspauth=\""), "{algs:?}");
        assert_eq!(r.text().unwrap(), "hello Mufasa 0");
        // later requests go up front with the next nonce count
        assert_eq!(c.post(&url(&h, "/b")).body("12345").send().unwrap().text().unwrap(), "hello Mufasa 5");
        assert_eq!(c.get(&url(&h, "/c")).send().unwrap().text().unwrap(), "hello Mufasa 0");
    }
}

#[test]
fn digest_stale_nextnonce_auth_int_and_refusals() {
    let h = server(&[(DigestAlgorithm::Sha256, false)], Duration::from_secs(2));
    let c = digest_client();
    assert_eq!(c.get(&url(&h, "/1")).send().unwrap().text().unwrap(), "hello Mufasa 0");
    // past half the nonce's life the server offers nextnonce; the client switches to it
    std::thread::sleep(Duration::from_millis(1100));
    let r = c.get(&url(&h, "/2")).send().unwrap();
    assert!(r.header("authentication-info").unwrap().contains("nextnonce="));
    assert_eq!(r.text().unwrap(), "hello Mufasa 0");
    // the nonce expires: stale=true, answered once more
    std::thread::sleep(Duration::from_millis(2100));
    assert_eq!(c.get(&url(&h, "/3")).send().unwrap().text().unwrap(), "hello Mufasa 0");
    // auth-int over a body
    let ci = Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "Circle of Life").digest_auth_int(true))).build();
    assert_eq!(ci.put(&url(&h, "/int")).body("hashed").send().unwrap().text().unwrap(), "hello Mufasa 6");
    // wrong password and no credentials
    let bad = Client::builder().auth(Arc::new(Auth::new().digest("Mufasa", "nope"))).build();
    let r = bad.get(&url(&h, "/x")).send().unwrap();
    assert_eq!(r.status(), 401);
    let r = Client::new().get(&url(&h, "/x")).send().unwrap();
    assert_eq!(r.status(), 401);
    let ch: Vec<&str> = r.headers().get_all("www-authenticate").collect();
    assert!(ch[0].starts_with("Digest realm=\"test@simoom\"") && ch.iter().any(|c| c.starts_with("Basic")) && ch.iter().any(|c| c.starts_with("Bearer")), "{ch:?}");
}

#[test]
fn basic_and_bearer() {
    let h = server(&[(DigestAlgorithm::Sha256, false)], Duration::from_secs(300));
    let c = Client::builder().auth(Arc::new(Auth::new().basic("Mufasa", "Circle of Life"))).build();
    assert_eq!(c.get(&url(&h, "/b")).send().unwrap().text().unwrap(), "hello Mufasa 0");
    let r = Client::new().get(&url(&h, "/b")).basic_auth("Mufasa", "wrong").send().unwrap();
    assert_eq!(r.status(), 401);
    let origin = format!("http://127.0.0.1:{}", h.local_addrs()[0].port());
    let c = Client::builder().auth(Arc::new(Auth::new().bearer(&origin, |_| Some("tok3n".to_string())))).build();
    assert_eq!(c.get(&url(&h, "/t")).send().unwrap().text().unwrap(), "hello svc 0");
    let r = Client::new().get(&url(&h, "/t")).bearer_auth("expired").send().unwrap();
    assert!(r.headers().get_all("www-authenticate").any(|v| v.contains("error=\"invalid_token\"")));
}

#[test]
fn client_refuses_a_wrong_rspauth() {
    let srv = raw(|mut s, _| {
        while let Some(head) = read_head(&mut s) {
            let auth = head.lines().find(|l| l.to_ascii_lowercase().starts_with("authorization:")).map(str::to_string);
            let resp = match auth {
                None => "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"r\", qop=\"auth\", nonce=\"n\", algorithm=SHA-256\r\nContent-Length: 0\r\n\r\n".to_string(),
                Some(a) => {
                    let cnonce = a.split("cnonce=\"").nth(1).and_then(|r| r.split('"').next()).unwrap_or("").to_string();
                    format!("HTTP/1.1 200 OK\r\nAuthentication-Info: rspauth=\"{}\", qop=auth, nc=00000001, cnonce=\"{cnonce}\"\r\nContent-Length: 2\r\n\r\nok", "0".repeat(64))
                }
            };
            if s.write_all(resp.as_bytes()).is_err() {
                return;
            }
        }
    });
    let e = digest_client().get(&format!("http://{}/", srv.addr)).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Protocol, "{e}");
    assert!(e.to_string().contains("rspauth"), "{e}");
}

#[cfg(feature = "client-ws")]
#[test]
fn interceptors_on_websocket_handshakes() {
    let h = server(&[(DigestAlgorithm::Sha256, false)], Duration::from_secs(300));
    let ws_url = format!("ws://127.0.0.1:{}/ws", h.local_addrs()[0].port());
    // without credentials the handshake is refused
    assert!(Client::new().websocket(&ws_url).connect().is_err());
    // Digest: 401, a new connection with credentials, 101
    let ws = digest_client().websocket(&ws_url).connect().unwrap();
    ws.send_text("hi").unwrap();
    assert_eq!(ws.recv().unwrap(), simoom_client::Message::Text("echo:hi".into()));
}

#[cfg(all(feature = "client-h2", feature = "cookies"))]
#[test]
fn interceptors_on_calls() {
    let h = server(&[(DigestAlgorithm::Sha256, false)], Duration::from_secs(300));
    let origin = format!("http://127.0.0.1:{}", h.local_addrs()[0].port());
    let jar = Arc::new(simoom_client::cookie::CookieJar::new());
    let c = Client::builder().cookie_jar(jar.clone()).auth(Arc::new(Auth::new().bearer(&origin, |_| Some("tok3n".to_string())))).build();
    // the bearer token goes in before the call starts; the cookie of the response is stored
    let mut call = c.call("POST", &format!("{origin}/call"), &simoom_client::Headers::new()).unwrap();
    call.send(b"abc").unwrap();
    call.finish().unwrap();
    let (status, _) = call.response().unwrap();
    assert_eq!(status, 200);
    let mut buf = [0u8; 64];
    let mut out = Vec::new();
    loop {
        let n = call.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    assert_eq!(String::from_utf8(out).unwrap(), "hello svc 3");
    assert_eq!(jar.len(), 1);
}

fn curl() -> Option<&'static str> {
    std::process::Command::new("curl").arg("--version").output().is_ok_and(|o| o.status.success()).then_some("curl")
}

/// curl, a real Digest and Basic client, against simoom's server-side authentication.
#[test]
fn curl_against_server_auth() {
    let Some(curl) = curl() else {
        eprintln!("skipped: curl is not installed");
        return;
    };
    for algs in [&[(DigestAlgorithm::Md5, false)][..], &[(DigestAlgorithm::Sha256, false)][..], &[(DigestAlgorithm::Sha512_256, false)][..]] {
        let h = server(algs, Duration::from_secs(300));
        let out = std::process::Command::new(curl).args(["-s", "-i", "--digest", "-u", "Mufasa:Circle of Life", &url(&h, "/curl?q=1")]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if algs[0].0 != DigestAlgorithm::Md5 && !text.contains("hello Mufasa") {
            // Schannel builds of curl (Windows) do MD5 only, and curl before 8.8 answers
            // SHA-512-256 with a SHA-256 hash (checked by hand against curl 8.5), which is refused
            eprintln!("curl did not answer {:?}: {}", algs[0].0, text.lines().next().unwrap_or(""));
            continue;
        }
        assert!(text.ends_with("hello Mufasa 0"), "{algs:?}: {text}");
        assert!(text.to_ascii_lowercase().contains("authentication-info: rspauth="), "{text}");
        eprintln!("curl Digest {:?}: accepted", algs[0].0);
    }
    let h = server(&[(DigestAlgorithm::Sha256, false)], Duration::from_secs(300));
    let out = std::process::Command::new(curl).args(["-s", "--basic", "-u", "Mufasa:Circle of Life", &url(&h, "/b")]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello Mufasa 0");
    let out = std::process::Command::new(curl).args(["-s", "-w", "%{http_code}", "-u", "Mufasa:wrong", &url(&h, "/b")]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).ends_with("401"));
}
