//! The non-blocking client: HTTP/1.1 (plain or TLS) requests run on simoom-rt event loops and
//! finish with a callback.
//!
//! Each loop keeps its own idle connections per origin. A request goes to a loop (round robin),
//! takes an idle connection there or has one opened: name resolution and the TCP handshake run
//! on one connector thread per client (the system resolver blocks), everything after that
//! (TLS, the request, the response) runs on the loop. The callback runs on the loop thread
//! (on the connector thread when the connection could not be opened), so it must not block;
//! hand slow work to another thread.
//!
//! ```no_run
//! use simoom_client::rt::{RtClient, RtConfig, RtRequest};
//! let client = RtClient::spawn(2, RtConfig::default()).unwrap();
//! let (tx, rx) = std::sync::mpsc::channel();
//! client.send(RtRequest::get("http://127.0.0.1:8080/hello").unwrap(), move |r| tx.send(r.map(|r| r.status)).unwrap());
//! println!("{:?}", rx.recv().unwrap());
//! ```
//!
//! Not supported here (use the blocking [`crate::Client`]): HTTP/2, HTTP/3, proxies, redirects,
//! streamed request bodies; response bodies are delivered whole.

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::h1::Out;
use crate::types::{Body, Headers, Version};
use crate::url::Url;
use simoom_http1::{BodyDecoder, BodyEvent, Framing, Status, EMPTY_HEADER};
use simoom_rt::timer::TimerId;
use simoom_rt::{CloseReason, ConnHandle, Connection, Ctx, LoopHandle, Message, Socket};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::TcpStream;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "tls")]
use simoom_tls::{ClientConfig, ClientConnection};

/// Settings of an [`RtClient`].
#[derive(Clone, Debug)]
pub struct RtConfig {
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Time from handing the request to the loop to the complete response.
    pub timeout: Duration,
    /// Largest response body.
    pub max_body: u64,
    /// Reuse connections.
    pub keep_alive: bool,
    /// Idle connections kept per origin on each loop.
    pub max_idle_per_origin: usize,
    /// `User-Agent` when the request has none.
    pub user_agent: Option<String>,
    /// TLS settings for `https`.
    #[cfg(feature = "tls")]
    pub tls: crate::client::TlsOptions,
    /// Follow 301, 302, 303, 307 and 308 (on the loop).
    pub follow_redirects: bool,
    /// Most redirects followed for one request.
    pub max_redirects: usize,
    /// Advertise `Accept-Encoding` and decode `gzip`/`deflate` bodies (feature `compress`).
    pub decompress: bool,
    /// Proxies: HTTP (absolute form for `http`, `CONNECT` for `https`) and SOCKS5. The tunnel
    /// is set up on the connector thread; the request runs on the loop.
    pub proxy: Option<crate::proxy::ProxyConfig>,
    /// `Http2` or `Http3` (or `Auto` with requests that ask for them) run on the client's
    /// worker threads through the blocking engine, which multiplexes them; HTTP/1.1 runs on
    /// the loops.
    pub version: crate::types::HttpVersion,
    /// Worker threads for HTTP/2, HTTP/3, streamed request bodies and streamed responses.
    pub workers: usize,
}

impl Default for RtConfig {
    fn default() -> Self {
        RtConfig {
            connect_timeout: Duration::from_secs(30),
            timeout: Duration::from_secs(60),
            max_body: 256 << 20,
            keep_alive: true,
            max_idle_per_origin: 64,
            user_agent: None,
            #[cfg(feature = "tls")]
            tls: crate::client::TlsOptions::default(),
            follow_redirects: false,
            max_redirects: 10,
            decompress: true,
            proxy: None,
            version: crate::types::HttpVersion::Auto,
            workers: 4,
        }
    }
}

/// A request for [`RtClient::send`]: the body is in memory.
#[derive(Clone, Debug)]
pub struct RtRequest {
    /// Method.
    pub method: String,
    /// Target (`http` or `https`).
    pub url: Url,
    /// Headers.
    pub headers: Headers,
    /// Body.
    pub body: Vec<u8>,
}

impl RtRequest {
    /// A request without body.
    pub fn new(method: &str, url: &str) -> Result<RtRequest> {
        Ok(RtRequest { method: method.to_ascii_uppercase(), url: Url::parse(url)?, headers: Headers::new(), body: Vec::new() })
    }

    /// `GET`.
    pub fn get(url: &str) -> Result<RtRequest> {
        RtRequest::new("GET", url)
    }

    /// Adds a header.
    pub fn header(mut self, name: &str, value: &str) -> RtRequest {
        self.headers.append(name, value);
        self
    }

    /// Sets the body.
    pub fn body(mut self, b: impl Into<Vec<u8>>) -> RtRequest {
        self.body = b.into();
        self
    }
}

/// A complete response.
#[derive(Clone, Debug)]
pub struct RtResponse {
    /// Status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Version.
    pub version: Version,
    /// Headers.
    pub headers: Headers,
    /// Body.
    pub body: Vec<u8>,
    /// Trailers (chunked responses).
    pub trailers: Headers,
}

type Callback = Box<dyn FnOnce(Result<RtResponse>) + Send>;

struct Job {
    req: RtRequest,
    cb: Callback,
    deadline: Instant,
    /// The request was tried on a reused connection that closed before answering.
    retried: bool,
    redirects: usize,
}

struct RtInner {
    loops: Vec<LoopHandle>,
    next: AtomicUsize,
    cfg: RtConfig,
    #[cfg(feature = "tls")]
    tls: Arc<ClientConfig>,
    connector: Mutex<Option<Sender<(Job, LoopHandle)>>>,
    /// The blocking engine for what does not run on the loops, and its workers.
    engine: crate::client::Client,
    workers: Mutex<Option<Sender<Box<dyn FnOnce(&crate::client::Client) + Send>>>>,
    decoder: Option<Arc<dyn crate::decode::ContentDecoder>>,
    runtime: Mutex<Option<simoom_rt::RuntimeHandle>>,
}

impl Drop for RtInner {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.lock().unwrap_or_else(|p| p.into_inner()).take() {
            rt.stop(Duration::from_millis(100));
            rt.join();
        }
    }
}

/// The non-blocking client. Cheap to clone.
#[derive(Clone)]
pub struct RtClient {
    inner: Arc<RtInner>,
}

impl std::fmt::Debug for RtClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtClient").field("loops", &self.inner.loops.len()).finish()
    }
}

impl RtClient {
    /// A client on existing loops (from [`simoom_rt::RuntimeHandle::loops`]).
    pub fn new(loops: Vec<LoopHandle>, cfg: RtConfig) -> RtClient {
        assert!(!loops.is_empty(), "RtClient needs at least one loop");
        #[cfg(feature = "tls")]
        let tls = {
            let mut c = ClientConfig::new(cfg.tls.roots.clone()).with_alpn(&[b"http/1.1"]);
            c.client_cert = cfg.tls.client_cert.clone();
            if !cfg.tls.resumption {
                c.sessions = None;
            }
            Arc::new(c)
        };
        #[cfg_attr(not(feature = "tls"), allow(unused_mut))]
        let mut b = crate::client::Client::builder()
            .connect_timeout(Some(cfg.connect_timeout))
            .timeout(Some(cfg.timeout))
            .max_body(Some(cfg.max_body))
            .keep_alive(cfg.keep_alive)
            .follow_redirects(cfg.follow_redirects)
            .max_redirects(cfg.max_redirects)
            .decompress(cfg.decompress)
            .proxy(cfg.proxy.clone())
            .user_agent(cfg.user_agent.clone())
            .version(cfg.version);
        #[cfg(feature = "tls")]
        {
            b = b.tls(cfg.tls.clone());
        }
        let engine = b.build();
        RtClient {
            inner: Arc::new(RtInner {
                loops,
                next: AtomicUsize::new(0),
                cfg,
                #[cfg(feature = "tls")]
                tls,
                connector: Mutex::new(None),
                engine,
                workers: Mutex::new(None),
                decoder: crate::decode::builtin(),
                runtime: Mutex::new(None),
            }),
        }
    }

    /// A client with a runtime of its own (`threads` loops; 0 = one per CPU), stopped when the
    /// last clone is dropped.
    pub fn spawn(threads: usize, cfg: RtConfig) -> std::io::Result<RtClient> {
        let rt = simoom_rt::Runtime::builder().threads(threads).start()?;
        let c = RtClient::new(rt.loops(), cfg);
        *c.inner.runtime.lock().unwrap_or_else(|p| p.into_inner()) = Some(rt);
        Ok(c)
    }

    /// Sends a request; `cb` gets the response or the error. With `version` `Http2`/`Http3`
    /// it runs on a worker thread.
    pub fn send(&self, req: RtRequest, cb: impl FnOnce(Result<RtResponse>) + Send + 'static) {
        if matches!(self.inner.cfg.version, crate::types::HttpVersion::Http2 | crate::types::HttpVersion::Http3) {
            let mut r = crate::types::Request::new(&req.method, req.url);
            r.headers = req.headers;
            if !req.body.is_empty() {
                r.body = crate::types::Body::Bytes(req.body);
            }
            self.on_worker(Box::new(move |c| cb(c.execute(r).and_then(buffered))));
            return;
        }
        let i = self.inner.next.fetch_add(1, Ordering::Relaxed) % self.inner.loops.len();
        self.send_on(i, req, cb);
    }

    /// Sends a request on loop `index`.
    pub fn send_on(&self, index: usize, req: RtRequest, cb: impl FnOnce(Result<RtResponse>) + Send + 'static) {
        if req.url.scheme != "http" && req.url.scheme != "https" {
            cb(Err(Error::new(ErrorKind::InvalidUrl, format!("RtClient takes http and https URLs: {}", req.url))));
            return;
        }
        let job = Job { req, cb: Box::new(cb), deadline: Instant::now() + self.inner.cfg.timeout, retried: false, redirects: 0 };
        let lh = self.inner.loops[index % self.inner.loops.len()].clone();
        let inner = self.inner.clone();
        let lh2 = lh.clone();
        let mut job = Some(job);
        let slot: Arc<Mutex<Option<Job>>> = Arc::new(Mutex::new(job.take()));
        let s2 = slot.clone();
        if !lh.run(move |_| {
            if let Some(j) = s2.lock().unwrap_or_else(|p| p.into_inner()).take() {
                dispatch(&inner, j, lh2);
            }
        }) {
            if let Some(j) = slot.lock().unwrap_or_else(|p| p.into_inner()).take() {
                (j.cb)(Err(Error::new(ErrorKind::Closed, "the event loop has stopped")));
            }
        }
    }

    /// Runs `f` with the blocking engine on a worker thread.
    fn on_worker(&self, f: Box<dyn FnOnce(&crate::client::Client) + Send>) {
        let mut g = self.inner.workers.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            let (tx, rx) = channel::<Box<dyn FnOnce(&crate::client::Client) + Send>>();
            let rx = Arc::new(Mutex::new(rx));
            for i in 0..self.inner.cfg.workers.max(1) {
                let (rx, engine) = (rx.clone(), self.inner.engine.clone());
                let _ = std::thread::Builder::new().name(format!("simoom-client-worker-{i}")).spawn(move || loop {
                    let job = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                    match job {
                        Ok(j) => j(&engine),
                        Err(_) => return,
                    }
                });
            }
            *g = Some(tx);
        }
        if let Some(tx) = g.as_ref() {
            let _ = tx.send(f);
        }
    }

    /// Sends any request of the blocking API ([`crate::Request`]: streamed bodies, HTTP/2,
    /// HTTP/3, interceptors are not involved) and calls `cb` with the response, body read.
    /// HTTP/1.1 requests with in-memory bodies run on the loops; the rest on the workers.
    pub fn send_request(&self, req: crate::types::Request, cb: impl FnOnce(Result<RtResponse>) + Send + 'static) {
        let native = matches!(req.body, crate::types::Body::Empty | crate::types::Body::Bytes(_))
            && matches!(req.version.unwrap_or(self.inner.cfg.version), crate::types::HttpVersion::Auto | crate::types::HttpVersion::Http1)
            && (req.url.scheme == "http" || req.url.scheme == "https");
        if native {
            let body = match req.body {
                crate::types::Body::Bytes(b) => b,
                _ => Vec::new(),
            };
            self.send(RtRequest { method: req.method, url: req.url, headers: req.headers, body }, cb);
            return;
        }
        self.on_worker(Box::new(move |c| cb(c.execute(req).and_then(buffered))));
    }

    /// Streams a response: `on_head` with status and headers, `on_data` per piece of body as
    /// it arrives, `on_end` with the trailers or the error. Runs on a worker thread (any
    /// protocol, streamed request bodies allowed).
    pub fn send_streaming(
        &self,
        req: crate::types::Request,
        on_head: impl FnOnce(u16, &Headers) + Send + 'static,
        mut on_data: impl FnMut(&[u8]) + Send + 'static,
        on_end: impl FnOnce(Result<Headers>) + Send + 'static,
    ) {
        self.on_worker(Box::new(move |c| {
            let r = c.execute(req).and_then(|resp| {
                on_head(resp.status(), resp.headers());
                let mut body = resp.into_body();
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    let n = body.read_chunk(&mut buf)?;
                    if n == 0 {
                        return Ok(body.trailers().cloned().unwrap_or_default());
                    }
                    on_data(&buf[..n]);
                }
            });
            on_end(r);
        }));
    }

    /// Idle connections kept on loop `index` (for tests).
    pub fn idle_on(&self, index: usize) -> usize {
        let (tx, rx) = channel();
        if !self.inner.loops[index % self.inner.loops.len()].run(move |_| {
            let n = IDLE.with(|m| m.borrow().values().map(|v| v.len()).sum::<usize>());
            let _ = tx.send(n);
        }) {
            return 0;
        }
        rx.recv_timeout(Duration::from_secs(5)).unwrap_or(0)
    }
}

thread_local! {
    /// Idle connections of this loop, by origin.
    static IDLE: RefCell<HashMap<String, Vec<(Rc<RefCell<Shared>>, ConnHandle)>>> = RefCell::new(HashMap::new());
}

fn key_of(u: &Url) -> String {
    u.origin()
}

/// On a loop thread: reuse an idle connection or have one opened.
fn dispatch(inner: &Arc<RtInner>, job: Job, lh: LoopHandle) {
    let key = key_of(&job.req.url);
    let idle = IDLE.with(|m| m.borrow_mut().get_mut(&key).and_then(|v| v.pop()));
    if let Some((shared, h)) = idle {
        {
            let mut s = shared.borrow_mut();
            s.idle = false;
            s.pending = Some(job);
        }
        if h.send(Box::new(Wake)) {
            return;
        }
        let j = shared.borrow_mut().pending.take();
        if let Some(j) = j {
            connect(inner, j, lh);
        }
        return;
    }
    connect(inner, job, lh);
}

/// Hands a job to the connector thread.
fn connect(inner: &Arc<RtInner>, job: Job, lh: LoopHandle) {
    let mut g = inner.connector.lock().unwrap_or_else(|p| p.into_inner());
    if g.is_none() {
        let (tx, rx) = channel::<(Job, LoopHandle)>();
        let weak = Arc::downgrade(inner);
        let spawned = std::thread::Builder::new().name("simoom-client-connector".into()).spawn(move || {
            while let Ok((job, lh)) = rx.recv() {
                let Some(inner) = weak.upgrade() else {
                    (job.cb)(Err(Error::new(ErrorKind::Closed, "client dropped")));
                    continue;
                };
                open(&inner, job, lh);
            }
        });
        if spawned.is_err() {
            drop(g);
            (job.cb)(Err(Error::new(ErrorKind::Io(std::io::ErrorKind::Other), "cannot start the connector thread")));
            return;
        }
        *g = Some(tx);
    }
    if let Some(tx) = g.as_ref() {
        if let Err(e) = tx.send((job, lh)) {
            let (job, _) = e.0;
            (job.cb)(Err(Error::new(ErrorKind::Closed, "connector stopped")));
        }
    }
}

/// On the connector thread: TCP connect, then adopt the socket on the job's loop.
fn open(inner: &Arc<RtInner>, job: Job, lh: LoopHandle) {
    let url = job.req.url.clone();
    let deadline = (Instant::now() + inner.cfg.connect_timeout).min(job.deadline);
    let proxy = inner.cfg.proxy.as_ref().and_then(|p| p.proxy_for(&url)).cloned();
    let (host, port) = match &proxy {
        Some(p) => (p.host.as_str(), p.port),
        None => (url.host.as_str(), url.port),
    };
    let tcp: TcpStream = match crate::transport::tcp_connect(host, port, Some(deadline)) {
        Ok(t) => t,
        Err(e) => {
            (job.cb)(Err(e));
            return;
        }
    };
    let mut absolute = None;
    if let Some(p) = &proxy {
        let r = match p.kind {
            crate::proxy::ProxyKind::Http if !url.is_secure() && !inner.cfg.proxy.as_ref().is_some_and(|c| c.tunnel_http) => {
                absolute = Some(p.authorization());
                Ok(())
            }
            crate::proxy::ProxyKind::Http => crate::transport::connect_tunnel(&tcp, &url.authority(), p, Some(deadline)),
            _ => crate::client::socks_connect(&tcp, &url, p, Some(deadline)),
        };
        if let Err(e) = r {
            (job.cb)(Err(e));
            return;
        }
    }
    if let Err(e) = tcp.set_nonblocking(true) {
        (job.cb)(Err(Error::io(&e, &url.origin())));
        return;
    }
    let sock = Socket::from(tcp);
    let cell = Arc::new(Mutex::new(Some((sock, job))));
    let c2 = cell.clone();
    let inner2 = inner.clone();
    let key_proxy = proxy.is_some();
    let _ = key_proxy;
    let lh2 = lh.clone();
    let ok = lh.run(move |lcx| {
        if let Some((sock, job)) = c2.lock().unwrap_or_else(|p| p.into_inner()).take() {
            match RtConn::new(inner2, job, lh2) {
                // a handler that cannot be registered is dropped, and its Drop fails the job
                Ok(mut conn) => {
                    conn.absolute = absolute;
                    let _ = lcx.adopt(sock, Box::new(conn));
                }
                Err((job, e)) => (job.cb)(Err(e)),
            }
        }
    });
    if !ok {
        if let Some((_, job)) = cell.lock().unwrap_or_else(|p| p.into_inner()).take() {
            (job.cb)(Err(Error::new(ErrorKind::Closed, "the event loop has stopped")));
        }
    }
}

/// Wakes an idle connection that was given a job.
struct Wake;

/// State shared between a connection and the loop's idle list.
#[derive(Default)]
struct Shared {
    pending: Option<Job>,
    idle: bool,
}

enum Parse {
    Head,
    Body(BodyDecoder),
}

struct RtConn {
    /// Plain HTTP through an HTTP proxy: absolute-form targets, with this authorization.
    absolute: Option<Option<String>>,
    inner: Arc<RtInner>,
    lh: LoopHandle,
    shared: Rc<RefCell<Shared>>,
    key: String,
    #[cfg(feature = "tls")]
    tls: Option<ClientConnection>,
    input: Vec<u8>,
    pos: usize,
    job: Option<Job>,
    parse: Parse,
    resp: Option<RtResponse>,
    keep_alive: bool,
    timer: Option<TimerId>,
    /// Request bytes were sent and response bytes may have been seen.
    sent: bool,
    got_bytes: bool,
    requests: u32,
}

// The connection lives on one loop thread; `Shared` is `Rc` on purpose. The job's callback is
// `Send` and leaves with the result.
impl RtConn {
    fn new(inner: Arc<RtInner>, job: Job, lh: LoopHandle) -> std::result::Result<RtConn, (Job, Error)> {
        let key = key_of(&job.req.url);
        #[cfg(feature = "tls")]
        let tls = if job.req.url.is_secure() {
            match ClientConnection::new(inner.tls.clone(), &job.req.url.host) {
                Ok(c) => Some(c),
                Err(e) => {
                    let what = job.req.url.origin();
                    return Err((job, crate::transport::tls_error(&e, &what)));
                }
            }
        } else {
            None
        };
        #[cfg(not(feature = "tls"))]
        if job.req.url.is_secure() {
            return Err((job, Error::new(ErrorKind::Unsupported, "https needs the `tls` feature of simoom-client")));
        }
        Ok(RtConn {
            absolute: None,
            inner,
            lh,
            shared: Rc::new(RefCell::new(Shared::default())),
            key,
            #[cfg(feature = "tls")]
            tls,
            input: Vec::new(),
            pos: 0,
            job: Some(job),
            parse: Parse::Head,
            resp: None,
            keep_alive: true,
            timer: None,
            sent: false,
            got_bytes: false,
            requests: 0,
        })
    }

    fn handshaking(&self) -> bool {
        #[cfg(feature = "tls")]
        if let Some(t) = &self.tls {
            return t.is_handshaking();
        }
        false
    }

    #[cfg(feature = "tls")]
    fn flush_tls(&mut self, cx: &mut Ctx<'_>) {
        if let Some(t) = &mut self.tls {
            let out = t.tls_output();
            if !out.is_empty() {
                let n = out.len();
                let mut b = cx.buffer(n);
                b.extend_from_slice(out);
                t.consume_tls_output(n);
                cx.send(b);
            }
        }
    }

    fn write(&mut self, cx: &mut Ctx<'_>, data: Vec<u8>) {
        #[cfg(feature = "tls")]
        if let Some(t) = &mut self.tls {
            let mut off = 0;
            while off < data.len() {
                match t.write_plaintext(&data[off..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => off += n,
                }
            }
            self.flush_tls(cx);
            return;
        }
        cx.send(data);
    }

    /// Starts the job in `self.job` if the transport is ready.
    fn start(&mut self, cx: &mut Ctx<'_>) {
        if self.sent || self.handshaking() {
            return;
        }
        let Some(job) = self.job.as_mut() else { return };
        let left = job.deadline.saturating_duration_since(Instant::now());
        self.timer = Some(cx.set_timer(left.max(Duration::from_millis(1)), 1));
        let url = &job.req.url;
        let mut headers = job.req.headers.clone();
        if let Some(ua) = &self.inner.cfg.user_agent {
            if !headers.contains("user-agent") {
                headers.append("User-Agent", ua);
            }
        }
        if self.inner.cfg.decompress && job.req.method != "HEAD" {
            if let Some(d) = &self.inner.decoder {
                if !headers.contains("accept-encoding") {
                    headers.append("Accept-Encoding", d.accept_encoding());
                }
            }
        }
        let body = Body::Bytes(std::mem::take(&mut job.req.body));
        let auth = self.absolute.clone().flatten();
        let o = Out { method: &job.req.method, url, absolute: self.absolute.is_some(), extra: &[], headers: &headers, proxy_auth: auth.as_deref(), expect_continue: false, expect_timeout: Duration::ZERO, idle: None, close: !self.inner.cfg.keep_alive };
        let mut out = Vec::with_capacity(256);
        let r = crate::h1::H1Conn::write_head(&o, &body, &mut out);
        let Body::Bytes(b) = body else { unreachable!() };
        if let Err(e) = r {
            self.fail(cx, e);
            return;
        }
        out.extend_from_slice(&b);
        job.req.body = b;
        self.sent = true;
        self.got_bytes = false;
        self.requests += 1;
        self.parse = Parse::Head;
        self.resp = None;
        self.write(cx, out);
    }

    fn fail(&mut self, cx: &mut Ctx<'_>, e: Error) {
        if let Some(t) = self.timer.take() {
            cx.cancel_timer(t);
        }
        if let Some(j) = self.job.take() {
            (j.cb)(Err(e));
        }
        self.keep_alive = false;
        cx.abort();
    }

    fn what(&self) -> String {
        self.job.as_ref().map_or_else(|| self.key.clone(), |j| j.req.url.to_string())
    }

    /// Parses what is buffered; true while the connection should stay open.
    fn parse(&mut self, cx: &mut Ctx<'_>) {
        loop {
            if self.job.is_none() || !self.sent {
                return;
            }
            let method = self.job.as_ref().map(|j| j.req.method.clone()).unwrap_or_default();
            match &mut self.parse {
                Parse::Head => {
                    let mut hs = [EMPTY_HEADER; 128];
                    let lim = crate::h1::limits(64 * 1024);
                    let r = simoom_http1::parse_response(&self.input[self.pos..], &mut hs, &lim, method.as_bytes());
                    match r {
                        Ok(Status::Complete(h)) => {
                            let hl = h.head_len;
                            if h.status / 100 == 1 && h.status != 101 {
                                self.pos += hl;
                                continue;
                            }
                            let mut headers = Headers::new();
                            for f in h.headers {
                                headers.push_raw(f.name, f.value);
                            }
                            let resp = RtResponse {
                                status: h.status,
                                reason: String::from_utf8_lossy(h.reason).into_owned(),
                                version: if h.version == simoom_http1::Version::Http10 { Version::Http10 } else { Version::Http11 },
                                headers,
                                body: Vec::new(),
                                trailers: Headers::new(),
                            };
                            self.keep_alive = self.keep_alive && h.keep_alive && !h.upgraded;
                            let framing = if h.upgraded { Framing::None } else { h.framing };
                            self.pos += hl;
                            self.resp = Some(resp);
                            if framing == Framing::None {
                                self.complete(cx);
                                return;
                            }
                            self.parse = Parse::Body(BodyDecoder::new(framing, &lim));
                        }
                        Ok(Status::Partial) => return,
                        Err(e) => {
                            let w = self.what();
                            self.fail(cx, Error::protocol(format!("invalid response head ({e})"), &w));
                            return;
                        }
                    }
                }
                Parse::Body(dec) => {
                    if self.pos >= self.input.len() && !dec.is_done() {
                        return;
                    }
                    let r = dec.decode(&self.input[self.pos..]);
                    match r {
                        Ok((used, BodyEvent::Data(d))) => {
                            let resp = self.resp.as_mut().map(|r| &mut r.body);
                            if let Some(b) = resp {
                                b.extend_from_slice(d);
                                if b.len() as u64 > self.inner.cfg.max_body {
                                    self.pos += used;
                                    let w = self.what();
                                    self.fail(cx, Error::new(ErrorKind::Protocol, format!("response body larger than the limit: {w}")));
                                    return;
                                }
                            }
                            self.pos += used;
                        }
                        Ok((used, BodyEvent::End(section))) => {
                            if !section.is_empty() {
                                let mut hs = [EMPTY_HEADER; 64];
                                if let Ok(list) = simoom_http1::parse_trailers(section, &mut hs, &crate::h1::limits(64 * 1024)) {
                                    if let Some(r) = self.resp.as_mut() {
                                        for f in list {
                                            r.trailers.push_raw(f.name, f.value);
                                        }
                                    }
                                }
                            }
                            self.pos += used;
                            self.complete(cx);
                            return;
                        }
                        Ok((used, BodyEvent::NeedMore)) => {
                            self.pos += used;
                            return;
                        }
                        Err(e) => {
                            let w = self.what();
                            self.fail(cx, Error::protocol(format!("invalid response body ({e})"), &w));
                            return;
                        }
                    }
                }
            }
        }
    }

    fn complete(&mut self, cx: &mut Ctx<'_>) {
        if let Some(t) = self.timer.take() {
            cx.cancel_timer(t);
        }
        self.sent = false;
        let resp = self.resp.take();
        let job = self.job.take();
        if self.pos == self.input.len() {
            self.input.clear();
            self.pos = 0;
        } else {
            // more bytes than the response: the connection cannot be reused safely
            self.keep_alive = false;
        }
        if let (Some(j), Some(r)) = (job, resp) {
            self.deliver(j, r);
        }
        if !self.keep_alive {
            cx.close();
            return;
        }
        let lim = self.inner.cfg.max_idle_per_origin;
        let shared = self.shared.clone();
        let key = self.key.clone();
        let h = cx.handle();
        let pooled = IDLE.with(|m| {
            let mut m = m.borrow_mut();
            let v = m.entry(key).or_default();
            if v.len() < lim {
                shared.borrow_mut().idle = true;
                v.push((shared, h));
                true
            } else {
                false
            }
        });
        if !pooled {
            cx.close();
        }
    }

    /// Follows a redirect (a new job on this loop) or decodes the body and calls back.
    fn deliver(&mut self, mut j: Job, mut r: RtResponse) {
        let cfg = &self.inner.cfg;
        if cfg.follow_redirects && matches!(r.status, 301 | 302 | 303 | 307 | 308) {
            if let Some(next) = r.headers.get("location").and_then(|l| j.req.url.join(l).ok()) {
                if j.redirects >= cfg.max_redirects {
                    (j.cb)(Err(Error::new(ErrorKind::TooManyRedirects, format!("more than {} redirects: {}", cfg.max_redirects, j.req.url))));
                    return;
                }
                if !matches!(r.status, 307 | 308) && j.req.method != "HEAD" {
                    j.req.method = "GET".into();
                    j.req.body.clear();
                    j.req.headers.remove("content-type");
                }
                if next.origin() != j.req.url.origin() {
                    for h in ["authorization", "proxy-authorization", "cookie", "host"] {
                        j.req.headers.remove(h);
                    }
                }
                j.req.url = next;
                j.redirects += 1;
                j.retried = false;
                dispatch(&self.inner, j, self.lh.clone());
                return;
            }
        }
        if cfg.decompress && j.req.method != "HEAD" {
            if let (Some(d), Some(enc)) = (&self.inner.decoder, r.headers.get("content-encoding").map(|e| e.trim().to_ascii_lowercase())) {
                let known = enc == "x-gzip" || simoom_http1::has_token(d.accept_encoding().as_bytes(), enc.as_bytes());
                if known {
                    let raw = std::mem::take(&mut r.body);
                    match d.decoder(&enc, Box::new(std::io::Cursor::new(raw)), cfg.max_body) {
                        Some(mut rd) => {
                            let mut out = Vec::new();
                            if let Err(e) = std::io::Read::read_to_end(&mut rd, &mut out) {
                                (j.cb)(Err(Error::new(ErrorKind::Decode, format!("decoding the response body: {e}"))));
                                return;
                            }
                            r.body = out;
                            r.headers.remove("content-encoding");
                            r.headers.remove("content-length");
                        }
                        None => {
                            (j.cb)(Err(Error::new(ErrorKind::Decode, format!("unsupported Content-Encoding {enc}"))));
                            return;
                        }
                    }
                }
            }
        }
        (j.cb)(Ok(r));
    }

    fn unpool(&self) {
        let me = &self.shared;
        IDLE.with(|m| {
            if let Some(v) = m.borrow_mut().get_mut(&self.key) {
                v.retain(|(s, _)| !Rc::ptr_eq(s, me));
            }
        });
    }
}

impl Connection for RtConn {
    fn on_open(&mut self, cx: &mut Ctx<'_>) {
        #[cfg(feature = "tls")]
        self.flush_tls(cx);
        if let Some(j) = &self.job {
            let left = j.deadline.saturating_duration_since(Instant::now());
            self.timer = Some(cx.set_timer(left.max(Duration::from_millis(1)), 1));
        }
        self.start(cx);
    }

    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        self.got_bytes = true;
        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            let mut off = 0;
            let was = self.handshaking();
            // The TLS layer stops decrypting while its plaintext buffer is full: move the
            // plaintext out and process again until everything offered is taken and nothing
            // more comes out.
            loop {
                let Some(t) = self.tls.as_mut() else { break };
                let k = t.read_tls(&data[off..]);
                off += k;
                if let Err(e) = t.process_new_packets() {
                    self.flush_tls(cx);
                    let w = self.what();
                    self.fail(cx, crate::transport::tls_error(&e, &w));
                    return data.len();
                }
                let p = t.plaintext();
                let got = !p.is_empty();
                if got {
                    let n = p.len();
                    self.input.extend_from_slice(p);
                    t.consume_plaintext(n);
                }
                if !got && (k == 0 || off >= data.len()) {
                    break;
                }
            }
            self.flush_tls(cx);
            if was && !self.handshaking() {
                self.start(cx);
            }
            self.parse(cx);
            return off;
        }
        self.input.extend_from_slice(data);
        self.parse(cx);
        data.len()
    }

    fn on_eof(&mut self, cx: &mut Ctx<'_>) {
        if let (Some(_), Parse::Body(dec)) = (&self.job, &mut self.parse) {
            if dec.eof().is_ok() {
                self.keep_alive = false;
                self.complete(cx);
                return;
            }
        }
        cx.close();
    }

    fn on_timer(&mut self, cx: &mut Ctx<'_>, _token: u64) {
        self.timer = None;
        if self.job.is_some() {
            let w = self.what();
            self.fail(cx, Error::timeout(TimeoutKind::Total, &w));
        }
    }

    fn on_message(&mut self, cx: &mut Ctx<'_>, msg: Message) {
        if msg.downcast::<Wake>().is_ok() {
            let job = self.shared.borrow_mut().pending.take();
            if let Some(j) = job {
                self.job = Some(j);
                self.start(cx);
                self.parse(cx);
            }
        }
    }

    fn on_close(&mut self, reason: CloseReason) {
        self.unpool();
        let pending = self.shared.borrow_mut().pending.take();
        let inflight = self.job.take();
        let reused = self.requests > 1;
        for (j, unsent) in [(pending, true), (inflight, false)] {
            let Some(mut j) = j else { continue };
            if unsent || (reused && !self.got_bytes && !j.retried) {
                j.retried = true;
                // The request never reached the server: run it on a new connection.
                connect(&self.inner, j, self.lh.clone());
                continue;
            }
            let msg = match &reason {
                CloseReason::Error(e) => format!("connection error ({e}): {}", j.req.url),
                _ => format!("connection closed before the response: {}", j.req.url),
            };
            (j.cb)(Err(Error::new(ErrorKind::Closed, msg)));
        }
    }
}

impl Drop for RtConn {
    fn drop(&mut self) {
        if let Some(j) = self.job.take() {
            (j.cb)(Err(Error::new(ErrorKind::Closed, format!("connection dropped: {}", j.req.url))));
        }
    }
}

/// A blocking-API response with its body read, as an [`RtResponse`].
fn buffered(mut r: crate::body::Response) -> Result<RtResponse> {
    let body = r.buffer()?.to_vec();
    Ok(RtResponse { status: r.status(), reason: r.reason().to_string(), version: r.version(), headers: r.headers().clone(), trailers: r.trailers().cloned().unwrap_or_default(), body })
}
