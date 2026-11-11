//! The WebSocket client (RFC 6455): `ws://` and `wss://`, through `CONNECT` proxies, with
//! subprotocols, masking, fragmentation, automatic pongs and the close handshake.

use crate::client::Client;
use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::h1::Out;
use crate::transport::{is_timeout, Duplex};
use std::io;
use crate::types::{Body, Headers};
use crate::url::Url;
use simoom_http1::ws::{self as codec, FrameDecoder, Opcode, Role, WsEvent, WsLimits};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A received message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A ping (already answered with a pong).
    Ping(Vec<u8>),
    /// A pong.
    Pong(Vec<u8>),
    /// The peer closed the connection: code (none when it sent none) and reason. Our close
    /// answer has been sent.
    Close(Option<u16>, String),
}

/// Fresh random bytes for keys and masks: an OS-seeded generator per connection.
struct Rng(u64, u64);

impl Rng {
    fn new() -> Result<Rng> {
        let mut s = [0u8; 16];
        if !simoom_sys::arch::os_random(&mut s) {
            return Err(Error::new(ErrorKind::Io(std::io::ErrorKind::Other), "the OS random source failed"));
        }
        let a = u64::from_le_bytes(s[..8].try_into().unwrap_or([1; 8]));
        let b = u64::from_le_bytes(s[8..].try_into().unwrap_or([2; 8]));
        Ok(Rng(a | 1, b))
    }

    /// xoshiro-style 128-bit generator (splitmix output), enough for masks (RFC 6455 §10.3
    /// asks for unpredictability towards scripts, which do not exist here).
    fn next(&mut self) -> u64 {
        self.1 = self.1.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.1 ^ self.0.rotate_left(17);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        z ^ (z >> 31)
    }

    fn mask(&mut self) -> [u8; 4] {
        (self.next() as u32).to_le_bytes()
    }
}

struct Reader {
    dec: FrameDecoder,
    buf: Vec<u8>,
    pos: usize,
    msg: Vec<u8>,
    text: bool,
    max_message: u64,
    /// permessage-deflate: the inflating half, and whether the current message is compressed.
    #[cfg_attr(not(feature = "client-ws-deflate"), allow(dead_code))]
    pm: Pm,
    compressed: bool,
}

struct Writer {
    rng: Rng,
    out: Vec<u8>,
    /// permessage-deflate: the compressing half.
    #[cfg_attr(not(feature = "client-ws-deflate"), allow(dead_code))]
    pm: Pm,
}

/// The permessage-deflate codec (feature `client-ws-deflate`).
#[cfg(feature = "client-ws-deflate")]
type Pm = Option<simoom_http1::ws::deflate::PerMessage>;
#[cfg(not(feature = "client-ws-deflate"))]
type Pm = ();

/// Both halves of the codec for a server's `Sec-WebSocket-Extensions` answer.
#[allow(unused_variables)]
fn deflate_halves(cfg: &Option<DeflateCfg>, answer: Option<&[u8]>, what: &str) -> Result<(Pm, Pm)> {
    #[cfg(feature = "client-ws-deflate")]
    {
        use simoom_http1::ws::deflate::{accept_response, PerMessage, Side};
        let Some(cfg) = cfg else {
            if answer.is_some_and(|a| !a.trim_ascii().is_empty()) {
                return Err(ws_err(format!("the server chose an extension we did not offer: {what}")));
            }
            return Ok((None, None));
        };
        match accept_response(answer, cfg) {
            Ok(Some(p)) => Ok((Some(PerMessage::new(Side::Client, &p, cfg)), Some(PerMessage::new(Side::Client, &p, cfg)))),
            Ok(None) => Ok((None, None)),
            Err(_) => Err(ws_err(format!("invalid permessage-deflate answer: {what}"))),
        }
    }
    #[cfg(not(feature = "client-ws-deflate"))]
    {
        if answer.is_some_and(|a| !a.trim_ascii().is_empty()) {
            return Err(ws_err(format!("the server chose an extension we did not offer: {what}")));
        }
        Ok(((), ()))
    }
}

#[cfg(feature = "client-ws-deflate")]
type DeflateCfg = simoom_http1::ws::deflate::DeflateConfig;
#[cfg(not(feature = "client-ws-deflate"))]
type DeflateCfg = ();

/// What a WebSocket runs on: an upgraded HTTP/1.1 connection, or an HTTP/2 stream opened with
/// extended CONNECT (RFC 8441).
enum WsIo {
    Tcp(Duplex),
    #[cfg(feature = "client-h2")]
    H2 { sender: crate::call::CallSender, call: Mutex<crate::call::Call> },
}

impl std::fmt::Debug for WsIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsIo::Tcp(d) => d.fmt(f),
            #[cfg(feature = "client-h2")]
            WsIo::H2 { sender, .. } => sender.fmt(f),
        }
    }
}

impl WsIo {
    fn write_all(&self, data: &[u8]) -> io::Result<()> {
        match self {
            WsIo::Tcp(d) => d.write_all(data),
            #[cfg(feature = "client-h2")]
            WsIo::H2 { sender, .. } => sender.send(data).map_err(io::Error::from),
        }
    }

    fn read(&self, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        match self {
            WsIo::Tcp(d) => d.read(buf, timeout),
            #[cfg(feature = "client-h2")]
            WsIo::H2 { call, .. } => {
                let mut c = call.lock().unwrap_or_else(|p| p.into_inner());
                c.read_until(buf, timeout.map(|t| Instant::now() + t)).map_err(io::Error::from)
            }
        }
    }

    fn close(&self) {
        match self {
            WsIo::Tcp(d) => d.close(),
            #[cfg(feature = "client-h2")]
            WsIo::H2 { sender, .. } => {
                let _ = sender.finish();
            }
        }
    }
}

/// An open WebSocket. `send_*` and [`WebSocket::recv`] may run on different threads at the same
/// time (one reader at a time).
pub struct WebSocket {
    io: WsIo,
    reader: Mutex<Reader>,
    writer: Mutex<Writer>,
    protocol: Option<String>,
    frame_size: usize,
    read_timeout: Option<Duration>,
    close_sent: AtomicBool,
    closed: AtomicBool,
}

impl std::fmt::Debug for WebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocket").field("io", &self.io).field("protocol", &self.protocol).finish()
    }
}

/// Builds a WebSocket connection: [`Client::websocket`].
pub struct WsBuilder {
    client: Client,
    url: Result<Url>,
    protocols: Vec<String>,
    headers: Headers,
    max_message: u64,
    frame_size: usize,
    read_timeout: Option<Option<Duration>>,
    http2: bool,
    http3: bool,
    deflate: Option<DeflateCfg>,
}

impl std::fmt::Debug for WsBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsBuilder").field("url", &self.url).field("protocols", &self.protocols).finish()
    }
}

impl Client {
    /// Starts a WebSocket connection to a `ws://` or `wss://` URL (`http`/`https` also work).
    pub fn websocket(&self, url: &str) -> WsBuilder {
        WsBuilder { client: self.clone(), url: Url::parse(url), protocols: Vec::new(), headers: Headers::new(), max_message: 64 << 20, frame_size: 64 << 10, read_timeout: None, http2: false, http3: false, deflate: None }
    }
}

impl WsBuilder {
    /// Offers a subprotocol (Camel `subProtocol`); the server picks at most one.
    pub fn protocol(mut self, p: &str) -> Self {
        self.protocols.push(p.to_string());
        self
    }

    /// Adds a handshake header (`Origin`, `Authorization`...).
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Largest incoming message (Camel `maxMessageSize`, default 64 MiB).
    pub fn max_message(mut self, n: u64) -> Self {
        self.max_message = n;
        self
    }

    /// Outgoing messages are split into frames of at most this size (Camel `maxFrameSize`,
    /// default 64 KiB).
    pub fn frame_size(mut self, n: usize) -> Self {
        self.frame_size = n.max(1);
        self
    }

    /// Read timeout of [`WebSocket::recv`] (default: none; a WebSocket may be idle for long).
    pub fn read_timeout(mut self, t: Option<Duration>) -> Self {
        self.read_timeout = Some(t);
        self
    }

    /// Offers permessage-deflate (RFC 7692); messages are compressed when the server accepts.
    /// Inflated messages are bounded by `cfg.max_message` and [`WsBuilder::max_message`].
    #[cfg(feature = "client-ws-deflate")]
    pub fn permessage_deflate(mut self, cfg: simoom_http1::ws::deflate::DeflateConfig) -> Self {
        self.deflate = Some(cfg);
        self
    }

    /// Runs the WebSocket on an HTTP/2 stream with extended CONNECT (RFC 8441): `ws://` over
    /// h2c with prior knowledge, `wss://` over TLS with ALPN `h2`; the connection is the
    /// client's shared HTTP/2 connection to that origin. Fails when the server does not allow
    /// extended CONNECT. Needs `client-h2`.
    pub fn http2(mut self, on: bool) -> Self {
        self.http2 = on;
        self
    }

    /// Runs the WebSocket on an HTTP/3 stream with extended CONNECT (RFC 9220), `wss://` only.
    /// Fails when the server does not allow extended CONNECT. Needs `client-h2` and
    /// `client-h3`.
    pub fn http3(mut self, on: bool) -> Self {
        self.http3 = on;
        self
    }

    /// Connects and performs the opening handshake.
    pub fn connect(self) -> Result<WebSocket> {
        if self.http2 || self.http3 {
            return self.connect_h2();
        }
        let mut url = self.url?;
        let cfg = &self.client.inner.cfg;
        url.scheme = match url.scheme.as_str() {
            "http" | "ws" => "ws".into(),
            _ => "wss".into(),
        };
        let what = url.to_string();
        let deadline = cfg.timeout.or(cfg.connect_timeout).map(|t| Instant::now() + t);
        let mut attempts = 0;
        let (mut conn, head, rng) = loop {
            let mut conn = self.client.connect_h1_raw(&url, deadline)?;
            let mut rng = Rng::new()?;
            let mut kb = [0u8; 16];
            kb[..8].copy_from_slice(&rng.next().to_le_bytes());
            kb[8..].copy_from_slice(&rng.next().to_le_bytes());
            let key = crate::url::b64(&kb);
            // interceptors (cookies, authentication) see the handshake like any request
            let mut hreq = crate::types::Request::new("GET", url.clone());
            hreq.headers = self.headers.clone();
            self.client.run_before_send(&mut hreq);
            let mut h = hreq.headers.clone();
            h.set("Upgrade", "websocket");
            h.set("Connection", "Upgrade");
            h.set("Sec-WebSocket-Key", &key);
            h.set("Sec-WebSocket-Version", "13");
            if !self.protocols.is_empty() {
                h.set("Sec-WebSocket-Protocol", self.protocols.join(", "));
            }
            #[cfg(feature = "client-ws-deflate")]
            if let Some(c) = &self.deflate {
                h.set("Sec-WebSocket-Extensions", simoom_http1::ws::deflate::offer(c));
            }
            if let Some(ui) = &url.userinfo {
                if !h.contains("authorization") {
                    h.set("Authorization", format!("Basic {}", crate::url::b64(ui.as_bytes())));
                }
            }
            if let Some(ua) = &cfg.user_agent {
                if !h.contains("user-agent") {
                    h.set("User-Agent", ua);
                }
            }
            let o = Out { method: "GET", url: &url, absolute: false, extra: &[], headers: &h, proxy_auth: None, expect_continue: false, expect_timeout: Duration::ZERO, idle: cfg.read_timeout, close: false };
            let head = conn.exchange(&o, &mut Body::Empty, deadline, &what)?;
            if self.client.has_interceptors() {
                let resp = crate::client::head_response(head.status, head.version, head.reason.clone(), head.headers.clone(), &url);
                match self.client.run_on_response(&hreq, &resp) {
                    crate::hooks::Action::Fail(why) => {
                        conn.io.close();
                        return Err(Error::new(ErrorKind::Protocol, format!("{why}: {what}")));
                    }
                    crate::hooks::Action::Retry if head.status != 101 && attempts < crate::hooks::MAX_INTERCEPTOR_RETRIES => {
                        // a new connection: the server may close the refused one
                        conn.io.close();
                        attempts += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            let ok = head.status == 101
                && head.headers.has_token("upgrade", "websocket")
                && head.headers.has_token("connection", "upgrade")
                && head.headers.get_bytes("sec-websocket-accept") == Some(&codec::accept_key(key.as_bytes())[..]);
            if !ok {
                conn.io.close();
                return Err(Error::new(ErrorKind::WebSocket, format!("WebSocket handshake refused ({} {}): {what}", head.status, head.reason)));
            }
            break (conn, head, rng);
        };
        let protocol = head.headers.get("sec-websocket-protocol").map(|p| p.trim().to_string());
        if let Some(p) = &protocol {
            if !self.protocols.iter().any(|o| o == p) {
                conn.io.close();
                return Err(Error::new(ErrorKind::WebSocket, format!("the server chose a subprotocol we did not offer ({p}): {what}")));
            }
        }
        let (rpm, wpm) = match deflate_halves(&self.deflate, head.headers.get_bytes("sec-websocket-extensions"), &what) {
            Ok(x) => x,
            Err(e) => {
                conn.io.close();
                return Err(e);
            }
        };
        let leftover = conn.take_leftover();
        let limits = WsLimits { max_frame: self.max_message, max_message: self.max_message };
        Ok(WebSocket {
            io: WsIo::Tcp(conn.io),
            reader: Mutex::new(Reader::new(limits, leftover, self.max_message, rpm)),
            writer: Mutex::new(Writer { rng, out: Vec::new(), pm: wpm }),
            protocol,
            frame_size: self.frame_size,
            read_timeout: self.read_timeout.unwrap_or(None),
            close_sent: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }
}

impl WsBuilder {
    #[cfg(feature = "client-h2")]
    fn connect_h2(self) -> Result<WebSocket> {
        let url = self.url?;
        let cfg = &self.client.inner.cfg;
        let mut http_url = url.clone();
        http_url.scheme = if url.is_secure() { "https".into() } else { "http".into() };
        let what = url.to_string();
        let deadline = cfg.timeout.or(cfg.connect_timeout).map(|t| Instant::now() + t);
        let version = if self.http3 { crate::types::HttpVersion::Http3 } else { crate::types::HttpVersion::Http2 };
        if self.http3 && !cfg!(feature = "client-h3") {
            return Err(Error::new(ErrorKind::Unsupported, "WebSocket over HTTP/3 needs the `client-h3` feature of simoom-client"));
        }
        let m = self.client.mux_for(&http_url, version)?;
        let mut hreq = crate::types::Request::new("CONNECT", http_url.clone());
        hreq.headers = self.headers.clone();
        self.client.run_before_send(&mut hreq);
        let mut h = hreq.headers.clone();
        h.set("sec-websocket-version", "13");
        if !self.protocols.is_empty() {
            h.set("sec-websocket-protocol", self.protocols.join(", "));
        }
        #[cfg(feature = "client-ws-deflate")]
        if let Some(c) = &self.deflate {
            h.set("sec-websocket-extensions", simoom_http1::ws::deflate::offer(c));
        }
        if let Some(ua) = &cfg.user_agent {
            if !h.contains("user-agent") {
                h.set("user-agent", ua);
            }
        }
        let (host, fields) = crate::mux::request_fields(&h, None, "CONNECT");
        let authority = host.unwrap_or_else(|| url.host_header());
        let target = url.request_target();
        let head = crate::mux::ReqHead { method: "CONNECT", scheme: &http_url.scheme, authority: &authority, path: &target, fields };
        let id = m.open_extended("websocket", &head, deadline)?;
        let mut call = crate::call::Call::new(m, id, cfg.read_timeout, cfg.write_timeout);
        let (status, rh) = call.response_until(deadline).map(|(s, h)| (s, h.clone()))?;
        if self.client.has_interceptors() {
            let v = if self.http3 { crate::types::Version::Http3 } else { crate::types::Version::Http2 };
            let resp = crate::client::head_response(status, v, String::new(), rh.clone(), &http_url);
            if let crate::hooks::Action::Fail(why) = self.client.run_on_response(&hreq, &resp) {
                return Err(Error::new(ErrorKind::Protocol, format!("{why}: {what}")));
            }
        }
        if !(200..300).contains(&status) {
            return Err(Error::new(ErrorKind::WebSocket, format!("WebSocket over HTTP/2 refused ({status}): {what}")));
        }
        let protocol = rh.get("sec-websocket-protocol").map(|p| p.trim().to_string());
        if let Some(p) = &protocol {
            if !self.protocols.iter().any(|o| o == p) {
                return Err(Error::new(ErrorKind::WebSocket, format!("the server chose a subprotocol we did not offer ({p}): {what}")));
            }
        }
        let (rpm, wpm) = deflate_halves(&self.deflate, rh.get("sec-websocket-extensions").map(str::as_bytes), &what)?;
        let limits = WsLimits { max_frame: self.max_message, max_message: self.max_message };
        Ok(WebSocket {
            io: WsIo::H2 { sender: call.sender(), call: Mutex::new(call) },
            reader: Mutex::new(Reader::new(limits, Vec::new(), self.max_message, rpm)),
            writer: Mutex::new(Writer { rng: Rng::new()?, out: Vec::new(), pm: wpm }),
            protocol,
            frame_size: self.frame_size,
            read_timeout: self.read_timeout.unwrap_or(None),
            close_sent: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }

    #[cfg(not(feature = "client-h2"))]
    fn connect_h2(self) -> Result<WebSocket> {
        Err(Error::new(ErrorKind::Unsupported, "WebSocket over HTTP/2 needs the `client-h2` feature of simoom-client"))
    }
}

impl Reader {
    #[allow(unused_mut)]
    fn new(limits: WsLimits, buf: Vec<u8>, max_message: u64, pm: Pm) -> Reader {
        let mut dec = FrameDecoder::new(Role::Client, limits);
        #[cfg(feature = "client-ws-deflate")]
        dec.set_permessage_deflate(pm.is_some());
        Reader { dec, buf, pos: 0, msg: Vec::new(), text: false, max_message, pm, compressed: false }
    }
}

fn ws_err(msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::WebSocket, msg.to_string())
}

impl WebSocket {
    /// The subprotocol the server chose.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    fn send_frames(&self, opcode: Opcode, payload: &[u8]) -> Result<()> {
        if self.close_sent.load(Ordering::Acquire) {
            return Err(ws_err("WebSocket is closing"));
        }
        let mut w = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        let w = &mut *w;
        w.out.clear();
        let fs = self.frame_size;
        #[cfg(feature = "client-ws-deflate")]
        let compressed;
        #[cfg(feature = "client-ws-deflate")]
        let payload: &[u8] = match &mut w.pm {
            Some(pm) if pm.worth(payload.len()) => {
                compressed = Some(pm.compress(payload));
                compressed.as_deref().unwrap_or_default()
            }
            _ => {
                compressed = None;
                payload
            }
        };
        if payload.is_empty() {
            let m = w.rng.mask();
            codec::write_frame(&mut w.out, true, opcode, payload, Some(m));
        } else {
            let n = payload.len().div_ceil(fs);
            for (i, chunk) in payload.chunks(fs).enumerate() {
                let op = if i == 0 { opcode } else { Opcode::Continuation };
                let m = w.rng.mask();
                let at = w.out.len();
                codec::write_frame(&mut w.out, i + 1 == n, op, chunk, Some(m));
                #[cfg(feature = "client-ws-deflate")]
                if i == 0 && compressed.is_some() {
                    w.out[at] |= 0x40; // RSV1: a compressed message
                }
                let _ = at;
                if w.out.len() >= 256 * 1024 {
                    self.io.write_all(&w.out).map_err(|e| Error::io(&e, "WebSocket"))?;
                    w.out.clear();
                }
            }
        }
        if !w.out.is_empty() {
            self.io.write_all(&w.out).map_err(|e| Error::io(&e, "WebSocket"))?;
        }
        Ok(())
    }

    fn send_control(&self, opcode: Opcode, payload: &[u8]) -> Result<()> {
        if payload.len() > 125 {
            return Err(ws_err("control frame payload over 125 bytes"));
        }
        let mut w = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        let w = &mut *w;
        w.out.clear();
        let m = w.rng.mask();
        codec::write_frame(&mut w.out, true, opcode, payload, Some(m));
        self.io.write_all(&w.out).map_err(|e| Error::io(&e, "WebSocket"))
    }

    /// Sends a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        self.send_frames(Opcode::Text, text.as_bytes())
    }

    /// Sends a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.send_frames(Opcode::Binary, data)
    }

    /// Sends a ping (at most 125 bytes).
    pub fn ping(&self, data: &[u8]) -> Result<()> {
        self.send_control(Opcode::Ping, data)
    }

    /// Sends a pong.
    pub fn pong(&self, data: &[u8]) -> Result<()> {
        self.send_control(Opcode::Pong, data)
    }

    /// Sends a Close frame (once); the peer's answer arrives through [`WebSocket::recv`].
    pub fn send_close(&self, code: u16, reason: &str) -> Result<()> {
        if self.close_sent.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut w = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        let w = &mut *w;
        w.out.clear();
        let m = w.rng.mask();
        if !codec::write_close(&mut w.out, code, reason, Some(m)) {
            return Err(ws_err(format!("invalid close code {code} or reason over 123 bytes")));
        }
        self.io.write_all(&w.out).map_err(|e| Error::io(&e, "WebSocket"))
    }

    /// Closes: sends Close, waits up to `wait` for the peer's Close (unless another thread is
    /// reading), then closes the connection.
    pub fn close(&self, code: u16, reason: &str, wait: Duration) -> Result<()> {
        let r = self.send_close(code, reason);
        if let Ok(mut rd) = self.reader.try_lock() {
            let end = Instant::now() + wait;
            while !self.closed.load(Ordering::Acquire) && Instant::now() < end {
                match self.recv_inner(&mut rd, Some(end)) {
                    Ok(Message::Close(..)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        self.closed.store(true, Ordering::Release);
        self.io.close();
        r
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Waits for the next message. Fragments are joined; pings are answered and also returned.
    pub fn recv(&self) -> Result<Message> {
        let mut rd = self.reader.lock().unwrap_or_else(|p| p.into_inner());
        let d = self.read_timeout.map(|t| Instant::now() + t);
        self.recv_inner(&mut rd, d)
    }

    /// Like [`WebSocket::recv`], with a timeout for this call.
    pub fn recv_timeout(&self, t: Duration) -> Result<Message> {
        let mut rd = self.reader.lock().unwrap_or_else(|p| p.into_inner());
        self.recv_inner(&mut rd, Some(Instant::now() + t))
    }

    fn recv_inner(&self, rd: &mut Reader, deadline: Option<Instant>) -> Result<Message> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(ErrorKind::Closed, "WebSocket closed"));
        }
        loop {
            if rd.pos < rd.buf.len() {
                let start = rd.pos;
                let (used, ev) = {
                    let r = rd.dec.decode(&mut rd.buf[start..]);
                    match r {
                        Ok((used, ev)) => (used, own(ev)),
                        Err(e) => {
                            let code = e.close_code();
                            let _ = self.send_close(code, "");
                            self.closed.store(true, Ordering::Release);
                            self.io.close();
                            return Err(ws_err(format!("WebSocket protocol error ({e:?})")));
                        }
                    }
                };
                rd.pos = start + used;
                if rd.pos == rd.buf.len() {
                    rd.buf.clear();
                    rd.pos = 0;
                }
                match ev {
                    Owned::NeedMore => {}
                    Owned::Data { text, payload, fin } => {
                        if rd.msg.is_empty() {
                            rd.text = text;
                            rd.compressed = rd.dec.message_compressed();
                        }
                        if rd.msg.len() as u64 + payload.len() as u64 > rd.max_message {
                            let _ = self.send_close(1009, "message too big");
                            return Err(ws_err("WebSocket message larger than the limit"));
                        }
                        rd.msg.extend_from_slice(&payload);
                        if fin {
                            let m = std::mem::take(&mut rd.msg);
                            #[cfg(feature = "client-ws-deflate")]
                            let m = if rd.compressed {
                                let mut plain = Vec::new();
                                let r = match &mut rd.pm {
                                    Some(pm) => pm.decompress(&m, &mut plain),
                                    None => Err(simoom_http1::ws::WsError::ReservedBits),
                                };
                                if let Err(e) = r.and_then(|_| if plain.len() as u64 > rd.max_message { Err(simoom_http1::ws::WsError::MessageTooLarge) } else { Ok(()) }) {
                                    let _ = self.send_close(e.close_code(), "");
                                    self.closed.store(true, Ordering::Release);
                                    self.io.close();
                                    return Err(ws_err(format!("WebSocket permessage-deflate error ({e:?})")));
                                }
                                plain
                            } else {
                                m
                            };
                            return Ok(if rd.text { Message::Text(String::from_utf8(m).map_err(|_| ws_err("invalid UTF-8 in a text message"))?) } else { Message::Binary(m) });
                        }
                    }
                    Owned::Ping(p) => {
                        if !self.close_sent.load(Ordering::Acquire) {
                            let _ = self.send_control(Opcode::Pong, &p);
                        }
                        return Ok(Message::Ping(p));
                    }
                    Owned::Pong(p) => return Ok(Message::Pong(p)),
                    Owned::Close { code, reason } => {
                        if !self.close_sent.load(Ordering::Acquire) {
                            let _ = self.send_close(code.unwrap_or(1000), "");
                        }
                        self.closed.store(true, Ordering::Release);
                        self.io.close();
                        return Ok(Message::Close(code, reason));
                    }
                }
                continue;
            }
            let t = crate::transport::remaining(deadline, TimeoutKind::Idle, "WebSocket")?;
            let start = rd.buf.len();
            rd.buf.resize(start + 16 * 1024, 0);
            let r = self.io.read(&mut rd.buf[start..], t);
            match r {
                Ok(0) => {
                    rd.buf.truncate(start);
                    self.closed.store(true, Ordering::Release);
                    return Err(Error::new(ErrorKind::Closed, "WebSocket connection closed without a Close frame (1006)"));
                }
                Ok(n) => rd.buf.truncate(start + n),
                Err(e) => {
                    rd.buf.truncate(start);
                    if is_timeout(&e) {
                        return Err(Error::timeout(TimeoutKind::Idle, "WebSocket"));
                    }
                    self.closed.store(true, Ordering::Release);
                    return Err(Error::io(&e, "WebSocket"));
                }
            }
        }
    }
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            let _ = self.send_close(1001, "");
            self.io.close();
        }
    }
}

/// A decoded event detached from the receive buffer.
enum Owned {
    NeedMore,
    Data { text: bool, payload: Vec<u8>, fin: bool },
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close { code: Option<u16>, reason: String },
}

fn own(ev: WsEvent<'_>) -> Owned {
    match ev {
        WsEvent::NeedMore => Owned::NeedMore,
        WsEvent::Data { text, payload, fin } => Owned::Data { text, payload: payload.to_vec(), fin },
        WsEvent::Ping(p) => Owned::Ping(p.to_vec()),
        WsEvent::Pong(p) => Owned::Pong(p.to_vec()),
        WsEvent::Close { code, reason } => Owned::Close { code, reason: reason.to_string() },
    }
}
