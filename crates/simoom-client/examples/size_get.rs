//! One request through the client, used by scripts/size-client.sh to measure what each cargo
//! feature adds: `size_get <url> [1|2|3]` (the HTTP version), plus a WebSocket connection with
//! `client-ws`, a request on an event loop with `rt`, a cookie jar with `cookies`, an
//! authenticator with `auth-digest` / `auth-ntlm`, and a multipart POST with `multipart`.

use simoom_client::{Client, HttpVersion};

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:8080/".into());
    let v = match std::env::args().nth(2).as_deref() {
        Some("1") => HttpVersion::Http1,
        Some("2") => HttpVersion::Http2,
        Some("3") => HttpVersion::Http3,
        _ => HttpVersion::Auto,
    };
    #[allow(unused_mut)]
    let mut b = Client::builder();
    #[cfg(feature = "cookies")]
    {
        b = b.cookie_jar(std::sync::Arc::new(simoom_client::cookie::CookieJar::new()));
    }
    #[cfg(any(feature = "auth-digest", feature = "auth-ntlm"))]
    {
        let a = simoom_client::auth::Auth::new();
        #[cfg(feature = "auth-digest")]
        let a = a.digest("user", "password");
        #[cfg(feature = "auth-ntlm")]
        let a = a.ntlm("DOMAIN", "user", "password");
        b = b.auth(std::sync::Arc::new(a));
    }
    let c = b.build();
    #[cfg(feature = "multipart")]
    {
        let form = simoom_client::multipart::Multipart::new().text("a", "b").file_reader("f", "f.bin", "application/octet-stream", std::io::stdin(), None);
        let _ = c.post(&url).multipart(form).send();
    }
    match c.get(&url).version(v).send().and_then(|r| r.bytes()) {
        Ok(b) => println!("{} bytes", b.len()),
        Err(e) => eprintln!("{e}"),
    }
    #[cfg(feature = "client-ws")]
    if let Ok(ws) = c.websocket(&url).connect() {
        let _ = ws.send_text("hi");
        let _ = ws.recv();
    }
    #[cfg(feature = "rt")]
    if let Ok(rc) = simoom_client::rt::RtClient::spawn(1, Default::default()) {
        let (tx, rx) = std::sync::mpsc::channel();
        if let Ok(req) = simoom_client::rt::RtRequest::get(&url) {
            rc.send(req, move |r| {
                let _ = tx.send(r.map(|r| r.status));
            });
            let _ = rx.recv();
        }
    }
}
