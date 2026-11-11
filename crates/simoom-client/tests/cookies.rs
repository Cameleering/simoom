//! The cookie jar against simoom and scripted servers: a login redirect, paths, deletion,
//! the caller's own `Cookie` header, cross-origin redirects, HTTP/2, export and import.
#![cfg(feature = "cookies")]

mod common;

use common::{raw, read_head};
use simoom::{Outcome, Reply, Request, Server, ServerHandle};
use simoom_client::cookie::CookieJar;
use simoom_client::{Client, HttpVersion};
use std::io::Write;
use std::sync::Arc;

fn shop(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let cookie = req.header("cookie").map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
    match req.path() {
        b"/login" => reply
            .status(302)
            .header("location", "/account/home")
            .header("set-cookie", "sid=s3cr3t; Path=/; HttpOnly")
            .header("set-cookie", "theme=dark; Path=/account")
            .header("set-cookie", "tracking=1; Domain=example.com")
            .empty(),
        b"/logout" => reply.header("set-cookie", "sid=; Max-Age=0; Path=/").body("bye"),
        _ => reply.body(format!("cookie=[{cookie}]")),
    }
}

fn server() -> ServerHandle {
    Server::builder().listen("127.0.0.1:0").threads(2).service(shop).start().expect("server")
}

fn url(h: &ServerHandle, p: &str) -> String {
    format!("http://127.0.0.1:{}{p}", h.local_addrs()[0].port())
}

#[test]
fn login_redirect_paths_and_logout() {
    let h = server();
    let jar = Arc::new(CookieJar::new());
    let c = Client::builder().cookie_jar(jar.clone()).follow_redirects(true).build();
    // the 302 sets the cookies and the redirected request already carries them; the cookie for
    // another domain is refused
    let t = c.post(&url(&h, "/login")).body("user=ann").send().unwrap().text().unwrap();
    assert_eq!(t, "cookie=[theme=dark; sid=s3cr3t]");
    assert_eq!(jar.len(), 2);
    // path scoping
    assert_eq!(c.get(&url(&h, "/other")).send().unwrap().text().unwrap(), "cookie=[sid=s3cr3t]");
    // the caller's own Cookie header is kept, the jar's cookies follow
    let t = c.get(&url(&h, "/other")).header("Cookie", "mine=1").send().unwrap().text().unwrap();
    assert_eq!(t, "cookie=[mine=1; sid=s3cr3t]");
    // HTTP/2 (h2c) requests carry them too
    let t = c.get(&url(&h, "/account/x")).version(HttpVersion::Http2).send().unwrap().text().unwrap();
    assert_eq!(t, "cookie=[theme=dark; sid=s3cr3t]");
    // Max-Age=0 deletes
    assert_eq!(c.get(&url(&h, "/logout")).send().unwrap().text().unwrap(), "bye");
    assert_eq!(c.get(&url(&h, "/account/x")).send().unwrap().text().unwrap(), "cookie=[theme=dark]");
    // export, import into a fresh client
    let jar2 = Arc::new(CookieJar::new());
    assert_eq!(jar2.import(&jar.export()), Ok(1));
    let c2 = Client::builder().cookie_jar(jar2).build();
    assert_eq!(c2.get(&url(&h, "/account/y")).send().unwrap().text().unwrap(), "cookie=[theme=dark]");
    // a client without a jar sends nothing
    assert_eq!(Client::new().get(&url(&h, "/account/x")).send().unwrap().text().unwrap(), "cookie=[]");
}

#[test]
fn cross_origin_redirect_gets_that_origins_cookies_only() {
    let other = server();
    let target = url(&other, "/landing");
    let first = raw(move |mut s, _| {
        while let Some(head) = read_head(&mut s) {
            let resp = if head.starts_with("GET /start") {
                format!("HTTP/1.1 302 Found\r\nLocation: {target}\r\nSet-Cookie: a=1\r\nContent-Length: 0\r\n\r\n")
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            s.write_all(resp.as_bytes()).unwrap();
        }
    });
    let jar = Arc::new(CookieJar::new());
    // a cookie the jar holds for the second origin (same host, other port: cookies ignore ports,
    // so both origins share host-only cookies for 127.0.0.1, as in browsers)
    let c = Client::builder().cookie_jar(jar.clone()).follow_redirects(true).build();
    let t = c.get(&format!("http://{}/start", first.addr)).header("Cookie", "secret=caller").send().unwrap().text().unwrap();
    // the caller's header was dropped at the origin change; the jar's cookie for the host follows
    assert_eq!(t, "cookie=[a=1]");
}

#[test]
fn many_threads_share_a_jar() {
    let h = server();
    let jar = Arc::new(CookieJar::new());
    let c = Client::builder().cookie_jar(jar.clone()).follow_redirects(true).build();
    c.post(&url(&h, "/login")).send().unwrap().bytes().unwrap();
    let ts: Vec<_> = (0..8)
        .map(|i| {
            let (c, u) = (c.clone(), url(&h, &format!("/account/{i}")));
            std::thread::spawn(move || c.get(&u).header("Cookie", format!("t={i}")).send().unwrap().text().unwrap())
        })
        .collect();
    for (i, t) in ts.into_iter().enumerate() {
        assert_eq!(t.join().unwrap(), format!("cookie=[t={i}; theme=dark; sid=s3cr3t]"));
    }
}
