//! The blocking client: configuration, request building, protocol selection, redirects.

use crate::body::{H1Body, Inner as BodyInner, Response, ResponseBody};
#[cfg(any(feature = "client-h2", feature = "client-h3"))]
use crate::body::reason_of;
use crate::decode::ContentDecoder;
use crate::error::{Error, ErrorKind, Result};
#[cfg(any(feature = "retry", feature = "client-h2", feature = "client-h3"))]
use crate::error::TimeoutKind;
use crate::h1::{H1Conn, Out};
use crate::pool::{Limits, OriginKey, Pool, Slot};
use crate::proxy::{ProxyAddr, ProxyConfig};
use crate::transport::{earliest, Duplex};
use crate::types::{Body, Headers, HttpVersion, Request};
use crate::url::Url;
use simoom_http1::{BodyDecoder, Framing};
#[cfg(feature = "client-h3")]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(any(feature = "client-h2", feature = "client-h3"))]
use crate::body::MuxBody;
#[cfg(any(feature = "client-h2", feature = "client-h3"))]
use crate::mux::{Mux, ReqHead};
#[cfg(feature = "tls")]
use simoom_tls::{x509::RootStore, CertifiedKey, ClientConfig, ClientConnection, SessionCache};
#[cfg(feature = "tls")]
use std::sync::OnceLock;

/// Client settings. Defaults follow Camel's `http` component where it has one.
#[derive(Clone, Debug)]
pub struct Config {
    /// TCP connect timeout (Camel `connectTimeout`, default 30 s).
    pub connect_timeout: Option<Duration>,
    /// TLS handshake timeout; `None` uses the connect timeout.
    pub tls_timeout: Option<Duration>,
    /// Time allowed from sending the request to the response head (Camel `responseTimeout`
    /// when set apart from the socket timeout). `None`: only the read timeout applies.
    pub response_timeout: Option<Duration>,
    /// Longest wait for any bytes while reading (Camel `socketTimeout`/`soTimeout`, default
    /// 60 s).
    pub read_timeout: Option<Duration>,
    /// Longest wait for a write to make progress.
    pub write_timeout: Option<Duration>,
    /// Deadline for the whole request, redirects included (`None`: no deadline).
    pub timeout: Option<Duration>,
    /// Longest wait for a pooled connection or a free HTTP/2 stream.
    pub pool_timeout: Option<Duration>,
    /// Idle connections older than this are closed (default 30 s).
    pub pool_idle_timeout: Duration,
    /// Idle HTTP/1.1 connections kept per origin (Camel `connectionsPerRoute`, default 20).
    pub pool_max_idle_per_origin: usize,
    /// HTTP/1.1 connections per origin, in use and idle (Camel `maxTotalConnections` per
    /// route; default unlimited).
    pub max_connections_per_origin: usize,
    /// HTTP/2 or HTTP/3 connections per origin (default 1; more open when every stream of
    /// the existing ones is busy).
    pub max_multiplexed_per_origin: usize,
    /// Streams in flight on one HTTP/2 or HTTP/3 connection before another connection to the
    /// origin is opened, up to `max_multiplexed_per_origin` (default: no threshold, so
    /// requests share one connection up to the server's stream limit).
    pub streams_per_connection: Option<usize>,
    /// Requests per HTTP/1.1 connection before it is closed (`None`: unlimited).
    pub max_requests_per_connection: Option<u32>,
    /// Reuse connections (Camel `connectionClose=false`); off sends `Connection: close`.
    pub keep_alive: bool,
    /// Follow 301, 302, 303, 307 and 308 (Camel `followRedirects`, default false).
    pub follow_redirects: bool,
    /// Most redirects followed for one request.
    pub max_redirects: usize,
    /// Which HTTP version to speak.
    pub version: HttpVersion,
    /// Use HTTP/3 for `https` origins that announce it in `Alt-Svc` (needs `client-h3`).
    pub alt_svc: bool,
    /// Proxies (none by default; see [`ProxyConfig::from_env`]); HTTP or SOCKS5.
    pub proxy: Option<ProxyConfig>,
    /// Longest wait for name resolution (the system resolver has no timeout of its own).
    pub dns_timeout: Option<Duration>,
    /// Happy Eyeballs (RFC 8305): when a name has several addresses, the next one is tried
    /// after this delay while earlier attempts continue.
    pub happy_eyeballs_delay: Duration,
    /// With [`HttpVersion::Http2`] on `http` URLs, offer h2c through an HTTP/1.1 `Upgrade`
    /// instead of prior knowledge (servers that do not speak h2c stay on HTTP/1.1).
    pub h2c_upgrade: bool,
    /// Extra attempts for idempotent requests (GET, HEAD, OPTIONS, TRACE, PUT, DELETE) with
    /// replayable bodies after a connection failure or a status in `retry_statuses` (default 0).
    pub retries: u32,
    /// The first backoff; doubled each attempt, with up to 25% jitter.
    pub retry_backoff: Duration,
    /// The longest backoff (also caps `Retry-After`).
    pub retry_backoff_max: Duration,
    /// Statuses that are retried (for example 502, 503, 504); empty by default.
    pub retry_statuses: Vec<u16>,
    /// `User-Agent` sent when the request has none (Camel `userAgent`).
    pub user_agent: Option<String>,
    /// Advertise `Accept-Encoding` and decode response bodies when a decoder is installed
    /// (Camel `contentCompressionDisabled=false`).
    pub decompress: bool,
    /// How long to wait for `100 Continue` before sending the body anyway.
    pub expect_timeout: Duration,
    /// Largest response head in bytes.
    pub max_head: usize,
    /// Largest response body read through the client (default 256 MiB, Cameleer's cap).
    pub max_body: Option<u64>,
    /// Accepted status ranges for every request (Camel `throwExceptionOnFailure=true` with
    /// `okStatusCodeRange`); `None` accepts every status.
    pub ok_status: Option<Vec<(u16, u16)>>,
    /// HTTP/2 settings and limits.
    #[cfg(feature = "client-h2")]
    pub h2: simoom_h2::Config,
    /// Send HTTP/2 (and HTTP/3) PINGs on connections idle this long (`None`: no keepalive).
    pub keepalive_interval: Option<Duration>,
    /// A keepalive PING unanswered for this long closes the connection.
    pub keepalive_timeout: Duration,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            connect_timeout: Some(Duration::from_secs(30)),
            tls_timeout: None,
            response_timeout: None,
            read_timeout: Some(Duration::from_secs(60)),
            write_timeout: Some(Duration::from_secs(60)),
            timeout: None,
            pool_timeout: Some(Duration::from_secs(30)),
            pool_idle_timeout: Duration::from_secs(30),
            pool_max_idle_per_origin: 20,
            max_connections_per_origin: usize::MAX,
            max_multiplexed_per_origin: 1,
            streams_per_connection: None,
            max_requests_per_connection: None,
            keep_alive: true,
            follow_redirects: false,
            max_redirects: 10,
            version: HttpVersion::Auto,
            alt_svc: false,
            proxy: None,
            dns_timeout: Some(Duration::from_secs(10)),
            happy_eyeballs_delay: Duration::from_millis(250),
            h2c_upgrade: false,
            retries: 0,
            retry_backoff: Duration::from_millis(100),
            retry_backoff_max: Duration::from_secs(10),
            retry_statuses: Vec::new(),
            user_agent: None,
            decompress: true,
            expect_timeout: Duration::from_secs(1),
            max_head: 64 * 1024,
            max_body: Some(256 * 1024 * 1024),
            ok_status: None,
            #[cfg(feature = "client-h2")]
            h2: simoom_h2::Config::default(),
            keepalive_interval: None,
            keepalive_timeout: Duration::from_secs(20),
        }
    }
}

/// TLS settings for `https` and `wss`. Certificate verification cannot be turned off; trust a
/// private server by adding its certificate or CA to `roots`.
#[cfg(feature = "tls")]
#[derive(Clone, Debug)]
pub struct TlsOptions {
    /// Trust anchors (default: the system bundle, [`RootStore::system`]).
    pub roots: RootStore,
    /// A client certificate for servers that ask for one.
    pub client_cert: Option<CertifiedKey>,
    /// Overrides the name sent as SNI and checked against the certificate (Camel
    /// `SSLContextParameters.serverName`).
    pub server_name: Option<String>,
    /// TLS session resumption.
    pub resumption: bool,
}

#[cfg(feature = "tls")]
impl Default for TlsOptions {
    fn default() -> TlsOptions {
        TlsOptions { roots: RootStore::system(), client_cert: None, server_name: None, resumption: true }
    }
}

#[cfg(feature = "tls")]
struct TlsState {
    opts: TlsOptions,
    /// By ALPN offer: http/1.1; h2 + http/1.1; h2; h3.
    cfgs: [OnceLock<Arc<ClientConfig>>; 4],
}

#[cfg(feature = "tls")]
impl TlsState {
    fn config(&self, alpn: usize) -> Arc<ClientConfig> {
        self.cfgs[alpn]
            .get_or_init(|| {
                let protos: &[&[u8]] = match alpn {
                    0 => &[b"http/1.1"],
                    1 => &[b"h2", b"http/1.1"],
                    2 => &[b"h2"],
                    _ => &[b"h3"],
                };
                let mut c = ClientConfig::new(self.opts.roots.clone()).with_alpn(protos);
                c.client_cert = self.opts.client_cert.clone();
                // A session cache per ALPN offer: a ticket from an h2 connection must not be
                // offered on an http/1.1-only handshake (the server would change ALPN).
                c.sessions = if self.opts.resumption { Some(Arc::new(SessionCache::new(256))) } else { None };
                Arc::new(c)
            })
            .clone()
    }
}

/// An origin's announced HTTP/3 endpoint.
#[cfg(feature = "client-h3")]
#[derive(Clone, Debug)]
struct AltSvc {
    host: Option<String>,
    port: u16,
    expires: Instant,
    broken_until: Option<Instant>,
}

pub(crate) struct Inner {
    pub(crate) cfg: Config,
    pub(crate) pool: Arc<Pool>,
    #[cfg(feature = "tls")]
    tls: TlsState,
    decoder: Option<Arc<dyn ContentDecoder>>,
    #[cfg(feature = "hooks")]
    interceptors: Vec<Arc<dyn crate::hooks::Interceptor>>,
    /// Answers `407` on `CONNECT` tunnels ([`ClientBuilder::auth`]).
    #[cfg(feature = "auth")]
    tunnel_auth: Option<Arc<crate::auth::Auth>>,
    #[cfg(feature = "client-h3")]
    alt: Mutex<HashMap<String, AltSvc>>,
    #[cfg_attr(not(any(feature = "client-h2", feature = "client-h3")), allow(dead_code))]
    keepalive: Mutex<bool>,
}

/// A connection just opened.
enum Conn {
    H1(H1Conn),
    #[cfg(feature = "client-h2")]
    Mux(Arc<Mux>),
}

/// The blocking HTTP client. Cheap to clone; clones share the pool. Thread-safe: requests run
/// in parallel on the caller's threads, and HTTP/2 and HTTP/3 requests share connections.
///
/// ```no_run
/// let client = simoom_client::Client::new();
/// let resp = client.get("http://127.0.0.1:8080/hello").header("Accept", "text/plain").send().unwrap();
/// println!("{} {}", resp.status(), resp.text().unwrap());
/// ```
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("config", &self.inner.cfg).finish()
    }
}

/// Builds a [`Client`].
pub struct ClientBuilder {
    cfg: Config,
    #[cfg(feature = "tls")]
    tls: TlsOptions,
    decoder: Option<Arc<dyn ContentDecoder>>,
    #[cfg(feature = "hooks")]
    interceptors: Vec<Arc<dyn crate::hooks::Interceptor>>,
    /// Answers `407` on `CONNECT` tunnels ([`ClientBuilder::auth`]).
    #[cfg(feature = "auth")]
    tunnel_auth: Option<Arc<crate::auth::Auth>>,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBuilder").field("config", &self.cfg).finish()
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder {
            cfg: Config::default(),
            #[cfg(feature = "tls")]
            tls: TlsOptions::default(),
            decoder: crate::decode::builtin(),
            #[cfg(feature = "hooks")]
            interceptors: Vec::new(),
            #[cfg(feature = "auth")]
            tunnel_auth: None,
        }
    }
}

macro_rules! setter {
    ($(#[$m:meta])* $name:ident: $t:ty) => {
        $(#[$m])*
        pub fn $name(mut self, v: $t) -> Self {
            self.cfg.$name = v;
            self
        }
    };
}

impl ClientBuilder {
    /// Replaces every setting.
    pub fn config(mut self, cfg: Config) -> Self {
        self.cfg = cfg;
        self
    }
    setter!(/// TCP connect timeout.
        connect_timeout: Option<Duration>);
    setter!(/// TLS handshake timeout.
        tls_timeout: Option<Duration>);
    setter!(/// Response-head timeout.
        response_timeout: Option<Duration>);
    setter!(/// Read (idle) timeout.
        read_timeout: Option<Duration>);
    setter!(/// Write timeout.
        write_timeout: Option<Duration>);
    setter!(/// Whole-request deadline.
        timeout: Option<Duration>);
    setter!(/// Pool wait timeout.
        pool_timeout: Option<Duration>);
    setter!(/// Idle connection lifetime.
        pool_idle_timeout: Duration);
    setter!(/// Idle HTTP/1.1 connections kept per origin.
        pool_max_idle_per_origin: usize);
    setter!(/// HTTP/1.1 connections per origin.
        max_connections_per_origin: usize);
    setter!(/// HTTP/2 / HTTP/3 connections per origin.
        max_multiplexed_per_origin: usize);
    setter!(/// Streams per HTTP/2 or HTTP/3 connection before another is opened.
        streams_per_connection: Option<usize>);
    setter!(/// Requests per HTTP/1.1 connection.
        max_requests_per_connection: Option<u32>);
    setter!(/// Connection reuse.
        keep_alive: bool);
    setter!(/// Redirect following.
        follow_redirects: bool);
    setter!(/// Redirect limit.
        max_redirects: usize);
    setter!(/// HTTP version.
        version: HttpVersion);
    setter!(/// HTTP/3 through `Alt-Svc`.
        alt_svc: bool);
    setter!(/// Proxies.
        proxy: Option<ProxyConfig>);
    setter!(/// Name resolution timeout.
        dns_timeout: Option<Duration>);
    setter!(/// Happy Eyeballs attempt delay.
        happy_eyeballs_delay: Duration);
    setter!(/// h2c through `Upgrade` instead of prior knowledge.
        h2c_upgrade: bool);
    setter!(/// Retries for idempotent requests.
        retries: u32);
    setter!(/// First retry backoff.
        retry_backoff: Duration);
    setter!(/// Longest retry backoff.
        retry_backoff_max: Duration);
    setter!(/// Statuses that are retried.
        retry_statuses: Vec<u16>);
    setter!(/// Default `User-Agent`.
        user_agent: Option<String>);
    setter!(/// Response decompression.
        decompress: bool);
    setter!(/// `100 Continue` wait.
        expect_timeout: Duration);
    setter!(/// Largest response head.
        max_head: usize);
    setter!(/// Largest response body.
        max_body: Option<u64>);
    setter!(/// Accepted status ranges (Camel `throwExceptionOnFailure`).
        ok_status: Option<Vec<(u16, u16)>>);
    setter!(/// HTTP/2 PING keepalive interval for idle connections.
        keepalive_interval: Option<Duration>);
    setter!(/// HTTP/2 PING answer timeout.
        keepalive_timeout: Duration);

    /// HTTP/2 settings.
    #[cfg(feature = "client-h2")]
    pub fn h2_config(mut self, c: simoom_h2::Config) -> Self {
        self.cfg.h2 = c;
        self
    }

    /// TLS settings.
    #[cfg(feature = "tls")]
    pub fn tls(mut self, t: TlsOptions) -> Self {
        self.tls = t;
        self
    }

    /// Trust these roots instead of the system bundle.
    #[cfg(feature = "tls")]
    pub fn roots(mut self, roots: RootStore) -> Self {
        self.tls.roots = roots;
        self
    }

    /// Adds an interceptor (see [`crate::hooks`]): cookie jars, challenge-based
    /// authentication, logging.
    #[cfg(feature = "hooks")]
    pub fn interceptor(mut self, i: Arc<dyn crate::hooks::Interceptor>) -> Self {
        self.interceptors.push(i);
        self
    }

    /// The authenticator for `CONNECT` tunnels (set by [`ClientBuilder::auth`]).
    #[cfg(feature = "auth")]
    pub(crate) fn tunnel_auth(mut self, a: Arc<crate::auth::Auth>) -> Self {
        self.tunnel_auth = Some(a);
        self
    }

    /// Installs a response decoder (see [`crate::decode`]; feature `compress`).
    #[cfg(feature = "compress")]
    pub fn content_decoder(mut self, d: Arc<dyn ContentDecoder>) -> Self {
        self.decoder = Some(d);
        self
    }

    /// Builds the client.
    pub fn build(self) -> Client {
        let lim = Limits {
            max_per_origin: self.cfg.max_connections_per_origin.max(1),
            max_idle_per_origin: if self.cfg.keep_alive { self.cfg.pool_max_idle_per_origin } else { 0 },
            idle_timeout: self.cfg.pool_idle_timeout,
            max_requests: self.cfg.max_requests_per_connection,
            max_mux_per_origin: self.cfg.max_multiplexed_per_origin.max(1),
            streams_per_mux: self.cfg.streams_per_connection.unwrap_or(usize::MAX).max(1),
        };
        Client {
            inner: Arc::new(Inner {
                pool: Arc::new(Pool::new(lim)),
                #[cfg(feature = "tls")]
                tls: TlsState { opts: self.tls, cfgs: Default::default() },
                decoder: self.decoder,
                #[cfg(feature = "hooks")]
                interceptors: self.interceptors,
                #[cfg(feature = "auth")]
                tunnel_auth: self.tunnel_auth,
                #[cfg(feature = "client-h3")]
                alt: Mutex::new(HashMap::new()),
                keepalive: Mutex::new(false),
                cfg: self.cfg,
            }),
        }
    }
}

/// Builds and sends one request.
#[must_use = "a request is sent only by send()"]
pub struct RequestBuilder {
    client: Client,
    req: Result<Request>,
}

impl std::fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestBuilder").field("req", &self.req).finish()
    }
}

impl RequestBuilder {
    pub(crate) fn map(mut self, f: impl FnOnce(&mut Request)) -> Self {
        if let Ok(r) = &mut self.req {
            f(r);
        }
        self
    }

    /// Adds a header (Camel: any non-Camel message header).
    pub fn header(self, name: &str, value: impl AsRef<[u8]>) -> Self {
        let (n, v) = (name.to_string(), value.as_ref().to_vec());
        self.map(|r| r.headers.append(n, v))
    }

    /// Replaces the headers.
    pub fn headers(self, h: Headers) -> Self {
        self.map(|r| r.headers = h)
    }

    /// Appends `name=value` to the query, percent-encoded (Camel `CamelHttpQuery` builds the
    /// whole query instead: set it on the URL).
    pub fn query(self, name: &str, value: &str) -> Self {
        let pair = format!("{}={}", crate::url::percent_encode(name), crate::url::percent_encode(value));
        self.map(|r| {
            r.url.query = Some(match r.url.query.take() {
                Some(q) if !q.is_empty() => format!("{q}&{pair}"),
                _ => pair,
            })
        })
    }

    /// The body.
    pub fn body(self, b: impl Into<Body>) -> Self {
        let b = b.into();
        self.map(|r| r.body = b)
    }

    /// Basic credentials (Camel `authUsername`/`authPassword`, `authMethod=Basic`).
    pub fn basic_auth(self, user: &str, password: &str) -> Self {
        let v = format!("Basic {}", crate::url::b64(format!("{user}:{password}").as_bytes()));
        self.map(|r| r.headers.set("Authorization", v))
    }

    /// A bearer token.
    pub fn bearer_auth(self, token: &str) -> Self {
        let v = format!("Bearer {token}");
        self.map(|r| r.headers.set("Authorization", v))
    }

    /// Whole-request deadline for this request.
    pub fn timeout(self, t: Duration) -> Self {
        self.map(|r| r.timeout = Some(t))
    }

    /// Response-head timeout for this request.
    pub fn response_timeout(self, t: Duration) -> Self {
        self.map(|r| r.response_timeout = Some(t))
    }

    /// HTTP version for this request.
    pub fn version(self, v: HttpVersion) -> Self {
        self.map(|r| r.version = Some(v))
    }

    /// Follow redirects (or not) for this request.
    pub fn follow_redirects(self, on: bool) -> Self {
        self.map(|r| r.follow_redirects = Some(on))
    }

    /// Accepted status ranges for this request (Camel `okStatusCodeRange`).
    pub fn ok_status(self, ranges: &[(u16, u16)]) -> Self {
        let v = ranges.to_vec();
        self.map(|r| r.ok_status = Some(v))
    }

    /// Accept every status (Camel `throwExceptionOnFailure=false`).
    pub fn accept_any_status(self) -> Self {
        self.map(|r| r.ok_status = Some(vec![(100, 999)]))
    }

    /// Send an in-memory body with chunked transfer coding instead of `Content-Length` (Camel
    /// `chunked=true`; HTTP/1.1 only, HTTP/2 and HTTP/3 frame bodies anyway). The body is then
    /// not replayable (no retries, 307/308 not followed).
    pub fn chunked(self, on: bool) -> Self {
        self.map(|r| {
            if on {
                if let Body::Bytes(b) = std::mem::replace(&mut r.body, Body::Empty) {
                    r.body = Body::Reader { reader: Box::new(std::io::Cursor::new(b)), len: None };
                }
            }
        })
    }

    /// Send `Expect: 100-continue` before the body.
    pub fn expect_continue(self, on: bool) -> Self {
        self.map(|r| r.expect_continue = on)
    }

    /// The request, for [`Client::execute`].
    pub fn build(self) -> Result<Request> {
        self.req
    }

    /// Sends the request; returns once the response head arrived. The body is read from the
    /// response.
    pub fn send(self) -> Result<Response> {
        let req = self.req?;
        self.client.execute(req)
    }
}

/// A response head without a body, for interceptors on WebSocket handshakes and calls.
#[cfg_attr(not(any(feature = "client-ws", feature = "client-h2", feature = "client-h3")), allow(dead_code))]
pub(crate) fn head_response(status: u16, version: crate::types::Version, reason: impl Into<std::borrow::Cow<'static, str>>, headers: Headers, url: &Url) -> Response {
    Response { status, version, reason: reason.into(), headers, url: Arc::new(url.clone()), body: ResponseBody::empty() }
}

/// Pool counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Idle HTTP/1.1 connections.
    pub idle: usize,
    /// HTTP/1.1 connections idle or in use.
    pub http1: usize,
    /// HTTP/2 and HTTP/3 connections.
    pub multiplexed: usize,
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

impl Client {
    /// A client with the default settings.
    pub fn new() -> Client {
        ClientBuilder::default().build()
    }

    /// A builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// The settings.
    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }

    /// Starts a request with any method.
    pub fn request(&self, method: &str, url: &str) -> RequestBuilder {
        RequestBuilder { client: self.clone(), req: Url::parse(url).map(|u| Request::new(method, u)) }
    }

    /// `GET`.
    pub fn get(&self, url: &str) -> RequestBuilder {
        self.request("GET", url)
    }
    /// `POST`.
    pub fn post(&self, url: &str) -> RequestBuilder {
        self.request("POST", url)
    }
    /// `PUT`.
    pub fn put(&self, url: &str) -> RequestBuilder {
        self.request("PUT", url)
    }
    /// `DELETE`.
    pub fn delete(&self, url: &str) -> RequestBuilder {
        self.request("DELETE", url)
    }
    /// `HEAD`.
    pub fn head(&self, url: &str) -> RequestBuilder {
        self.request("HEAD", url)
    }
    /// `PATCH`.
    pub fn patch(&self, url: &str) -> RequestBuilder {
        self.request("PATCH", url)
    }

    /// Pool counters.
    pub fn pool_stats(&self) -> PoolStats {
        let (http1, multiplexed) = self.inner.pool.counts();
        PoolStats { idle: self.inner.pool.idle_count(), http1, multiplexed }
    }

    /// Closes every pooled connection (in-flight requests finish on theirs).
    pub fn close_idle(&self) {
        self.inner.pool.clear();
    }

    /// Sends a request, following redirects when enabled, and checks the status when accepted
    /// ranges are set. Returns after the response head; read the body from the response.
    pub fn execute(&self, mut req: Request) -> Result<Response> {
        let cfg = &self.inner.cfg;
        let deadline = req.timeout.or(cfg.timeout).map(|t| Instant::now() + t);
        let follow = req.follow_redirects.unwrap_or(cfg.follow_redirects);
        let mut redirects = 0;
        #[cfg(feature = "hooks")]
        let mut retries = 0;
        loop {
            self.run_before_send(&mut req);
            let resp = self.send_retrying(&mut req, deadline)?;
            #[cfg(feature = "hooks")]
            if self.has_interceptors() {
                // every interceptor sees the response (a cookie jar must store a 401's cookies
                // even when the authenticator asks for a retry)
                let action = self.run_on_response(&req, &resp);
                if let crate::hooks::Action::Fail(why) = action {
                    return Err(Error::new(ErrorKind::Protocol, format!("{why}: {}", req.url)));
                }
                let again = action == crate::hooks::Action::Retry;
                if again && retries < crate::hooks::MAX_INTERCEPTOR_RETRIES && req.body.replayable() {
                    retries += 1;
                    let mut b = resp.into_body();
                    let mut sink = [0u8; 8192];
                    for _ in 0..8 {
                        match b.read_chunk(&mut sink) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    continue;
                }
            }
            if follow && is_redirect(resp.status) {
                if let Some(loc) = resp.header("location").map(str::to_string) {
                    if redirects >= cfg.max_redirects {
                        return Err(Error::new(ErrorKind::TooManyRedirects, format!("more than {} redirects: {}", cfg.max_redirects, req.url)));
                    }
                    let next = req.url.join(&loc)?;
                    let keep_method = matches!(resp.status, 307 | 308);
                    if keep_method && !req.body.replayable() {
                        return self.check_status(&req, resp);
                    }
                    // Read what is cheap to read so the connection can be reused.
                    let mut body = resp.into_body();
                    let mut sink = [0u8; 8192];
                    for _ in 0..8 {
                        match body.read_chunk(&mut sink) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    drop(body);
                    if !keep_method && req.method != "HEAD" {
                        req.method = "GET".into();
                        req.body = Body::Empty;
                        req.headers.remove("content-type");
                        req.headers.remove("content-encoding");
                    }
                    if next.origin() != req.url.origin() {
                        for h in ["authorization", "proxy-authorization", "cookie", "host"] {
                            req.headers.remove(h);
                        }
                    }
                    req.url = next;
                    redirects += 1;
                    continue;
                }
            }
            return self.check_status(&req, resp);
        }
    }

    /// `send_once` with retries and exponential backoff for idempotent requests with
    /// replayable bodies (`Config::retries`): after connection failures, and after the statuses
    /// in `Config::retry_statuses` (honouring `Retry-After` in seconds, up to the backoff cap).
    #[cfg(not(feature = "retry"))]
    fn send_retrying(&self, req: &mut Request, deadline: Option<Instant>) -> Result<Response> {
        self.send_once(req, deadline)
    }

    #[cfg(feature = "retry")]
    fn send_retrying(&self, req: &mut Request, deadline: Option<Instant>) -> Result<Response> {
        let cfg = &self.inner.cfg;
        let idempotent = matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE");
        let mut attempt = 0u32;
        loop {
            let r = self.send_once(req, deadline);
            let can = idempotent && attempt < cfg.retries && req.body.replayable();
            let wait = match &r {
                Err(e) if can && retryable_error(e) => Some(None),
                Ok(resp) if can && cfg.retry_statuses.contains(&resp.status) => {
                    Some(resp.header("retry-after").and_then(|v| v.trim().parse::<u64>().ok()).map(Duration::from_secs))
                }
                _ => None,
            };
            let Some(after) = wait else { return r };
            let base = cfg.retry_backoff.saturating_mul(1u32 << attempt.min(16));
            let mut d = after.unwrap_or(base).min(cfg.retry_backoff_max);
            // up to 25% jitter, so clients that failed together do not retry together
            let mut j = [0u8; 2];
            if simoom_sys::arch::os_random(&mut j) {
                d += d.mul_f64(f64::from(u16::from_le_bytes(j)) / f64::from(u16::MAX) / 4.0);
            }
            if deadline.is_some_and(|dl| Instant::now() + d >= dl) {
                return r;
            }
            drop(r);
            std::thread::sleep(d);
            attempt += 1;
        }
    }

    /// Runs every interceptor's `before_send` (also used by WebSocket handshakes and calls).
    pub(crate) fn run_before_send(&self, req: &mut Request) {
        #[cfg(feature = "hooks")]
        for i in &self.inner.interceptors {
            i.before_send(req);
        }
        #[cfg(not(feature = "hooks"))]
        let _ = req;
    }

    /// Runs every interceptor's `on_response` (each one sees the response); the result is the
    /// first `Fail`, else `Retry` if any asked for it, else `Continue`.
    #[cfg_attr(not(any(feature = "hooks", feature = "client-ws", feature = "client-h2", feature = "client-h3")), allow(dead_code))]
    pub(crate) fn run_on_response(&self, req: &Request, resp: &Response) -> crate::hooks::Action {
        use crate::hooks::Action;
        #[cfg(not(feature = "hooks"))]
        {
            let _ = (req, resp);
            Action::Continue
        }
        #[cfg(feature = "hooks")]
        self.inner.interceptors.iter().fold(Action::Continue, |acc, i| match (acc, i.on_response(req, resp)) {
            (Action::Fail(w), _) | (_, Action::Fail(w)) => Action::Fail(w),
            (Action::Retry, _) | (_, Action::Retry) => Action::Retry,
            _ => Action::Continue,
        })
    }

    /// Whether any interceptor is installed.
    #[cfg_attr(not(any(feature = "hooks", feature = "client-ws", feature = "client-h2", feature = "client-h3")), allow(dead_code))]
    pub(crate) fn has_interceptors(&self) -> bool {
        #[cfg(not(feature = "hooks"))]
        return false;
        #[cfg(feature = "hooks")]
        !self.inner.interceptors.is_empty()
    }

    fn check_status(&self, req: &Request, resp: Response) -> Result<Response> {
        match req.ok_status.as_ref().or(self.inner.cfg.ok_status.as_ref()) {
            Some(r) => resp.error_for_status(r),
            None => Ok(resp),
        }
    }

    #[cfg_attr(not(any(feature = "client-h2", feature = "client-h3", feature = "pipeline")), allow(dead_code))]
    pub(crate) fn headers_for(&self, req: &Request) -> Headers {
        let cfg = &self.inner.cfg;
        let mut h = req.headers.clone();
        if let Some(ua) = &cfg.user_agent {
            if !h.contains("user-agent") {
                h.append("User-Agent", ua);
            }
        }
        if cfg.decompress && req.method != "HEAD" {
            if let Some(d) = &self.inner.decoder {
                if !h.contains("accept-encoding") {
                    h.append("Accept-Encoding", d.accept_encoding());
                }
            }
        }
        if let Some(u) = &req.url.userinfo {
            if !h.contains("authorization") {
                h.append("Authorization", format!("Basic {}", crate::url::b64(u.as_bytes())));
            }
        }
        h
    }

    /// Notes `Alt-Svc` and decodes the body.
    fn after(&self, method: &str, r: Response) -> Response {
        #[cfg(feature = "client-h3")]
        if self.inner.cfg.alt_svc && r.url.is_secure() && r.version != crate::types::Version::Http3 {
            self.record_alt_svc(&r);
        }
        self.decode(method, r)
    }

    /// Wraps an encoded body in the installed decoder.
    #[cfg(not(feature = "compress"))]
    fn decode(&self, _method: &str, resp: Response) -> Response {
        resp
    }

    /// Wraps an encoded body in the installed decoder.
    #[cfg(feature = "compress")]
    fn decode(&self, method: &str, mut resp: Response) -> Response {
        if !self.inner.cfg.decompress || method == "HEAD" {
            return resp;
        }
        let Some(d) = &self.inner.decoder else { return resp };
        let Some(enc) = resp.headers.get("content-encoding").map(|e| e.trim().to_ascii_lowercase()) else { return resp };
        if enc.is_empty() || enc == "identity" {
            return resp;
        }
        let body = std::mem::replace(&mut resp.body, ResponseBody::empty());
        let raw: Box<dyn std::io::Read + Send> = Box::new(body);
        // A decoder that declines leaves the body as it was, but the original reader was
        // moved: give it a reader that yields it back.
        let holder = Arc::new(Mutex::new(Some(raw)));
        let h2 = holder.clone();
        let proxy: Box<dyn std::io::Read + Send> = Box::new(Handoff(h2));
        match d.decoder(&enc, proxy, self.inner.cfg.max_body.unwrap_or(u64::MAX)) {
            Some(r) => {
                resp.headers.remove("content-encoding");
                resp.headers.remove("content-length");
                resp.body = ResponseBody::new(BodyInner::Decoded(r), self.inner.cfg.max_body);
            }
            None => {
                let raw = holder.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(raw) = raw {
                    resp.body = ResponseBody::new(BodyInner::Decoded(raw), None);
                }
            }
        }
        resp
    }

    fn send_once(&self, req: &mut Request, deadline: Option<Instant>) -> Result<Response> {
        let cfg = &self.inner.cfg;
        let mode = req.version.unwrap_or(cfg.version);
        let secure = req.url.is_secure();
        let proxy: Option<ProxyAddr> = cfg.proxy.as_ref().and_then(|p| p.proxy_for(&req.url)).cloned();
        // HTTP/1.1 sends the client defaults beside the request's own fields (no copy);
        // HTTP/2 and HTTP/3 need one list, built only when they are used
        #[cfg(feature = "client-h2")]
        let mut mux_headers: Option<Headers> = None;

        #[cfg(feature = "client-h3")]
        if secure && proxy.is_none() && (mode == HttpVersion::Http3 || (mode == HttpVersion::Auto && cfg.alt_svc)) {
            let alt = if mode == HttpVersion::Http3 { Some((req.url.host.clone(), req.url.port)) } else { self.alt_svc_for(&req.url) };
            if let Some((host, port)) = alt {
                let headers = self.headers_for(req);
                match self.h3_request(req, &headers, &host, port, deadline) {
                    Ok(r) => return Ok(self.decode(&req.method, r)),
                    Err(e) if mode == HttpVersion::Auto && e.is_connect() || matches!(e.kind, ErrorKind::Timeout(TimeoutKind::Tls)) => {
                        self.mark_alt_broken(&req.url);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        if mode == HttpVersion::Http3 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                if cfg!(feature = "client-h3") { format!("HTTP/3 needs an https URL and no proxy: {}", req.url) } else { "HTTP/3 needs the `client-h3` feature of simoom-client".to_string() },
            ));
        }
        if mode == HttpVersion::Http2 && !cfg!(feature = "client-h2") {
            return Err(Error::new(ErrorKind::Unsupported, "HTTP/2 needs the `client-h2` feature of simoom-client"));
        }
        // fast path: this thread's cached idle connection to the origin, before any key is built
        if cfg.keep_alive && !self.inner.pool.has_mux() {
            if let Some((c, s)) = self.inner.pool.take_local(secure, &req.url.host, req.url.port, proxy.as_ref(), mode as u8) {
                match self.h1_request(c, Some(s), req, proxy.as_ref(), deadline) {
                    Ok(r) => return Ok(self.after(&req.method, r)),
                    // a stale connection that failed before any answer: retried below
                    Err((e, got)) if !got && req.body.replayable() && !e.is_timeout() && !matches!(e.kind, ErrorKind::InvalidRequest) => {}
                    Err((e, _)) => return Err(e),
                }
            }
        }
        let key = OriginKey { secure, host: req.url.host.clone(), port: req.url.port, proxy: proxy.clone(), mode: mode as u8 };
        let mut attempt = 0;
        loop {
            attempt += 1;
            #[cfg(feature = "client-h2")]
            if cfg.keep_alive {
                if let Some(m) = self.inner.pool.mux(&key, true) {
                    if mux_headers.is_none() {
                        mux_headers = Some(self.headers_for(req));
                    }
                    let hs = mux_headers.as_ref().unwrap_or_else(|| unreachable!());
                    match self.mux_request(&m, req, hs, deadline) {
                        Err(e) if attempt < 3 && req.body.replayable() && retryable_mux(&e) => continue,
                        r => return r.map(|r| self.after(&req.method, r)),
                    }
                }
            }
            let pool_deadline = earliest(deadline, cfg.pool_timeout.map(|t| Instant::now() + t));
            let (conn, slot) = if cfg.keep_alive {
                let (c, s) = self.inner.pool.checkout(&key, pool_deadline, &req.url)?;
                (c, Some(s))
            } else {
                (None, None)
            };
            let reused = conn.is_some();
            let conn = match conn {
                Some(c) => c,
                None => match self.connect(&req.url, proxy.as_ref(), mode, deadline)? {
                    Conn::H1(c) => c,
                    #[cfg(feature = "client-h2")]
                    Conn::Mux(m) => {
                        drop(slot);
                        if cfg.keep_alive {
                            self.inner.pool.add_mux(key.clone(), m.clone());
                            self.start_keepalive();
                        }
                        if mux_headers.is_none() {
                            mux_headers = Some(self.headers_for(req));
                        }
                        let hs = mux_headers.as_ref().unwrap_or_else(|| unreachable!());
                        let r = self.mux_request(&m, req, hs, deadline);
                        if !cfg.keep_alive {
                            // the body keeps the connection alive; it closes when dropped
                        }
                        match r {
                            Err(e) if attempt < 3 && req.body.replayable() && retryable_mux(&e) => continue,
                            r => return r.map(|r| self.after(&req.method, r)),
                        }
                    }
                },
            };
            match self.h1_request(conn, slot, req, proxy.as_ref(), deadline) {
                Ok(r) => return Ok(self.after(&req.method, r)),
                Err((e, got_bytes)) => {
                    if reused && !got_bytes && attempt < 2 && req.body.replayable() && !e.is_timeout() && !matches!(e.kind, ErrorKind::InvalidRequest) {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Opens a connection to `url` (through `proxy`): HTTP/1.1, or a shared HTTP/2 connection
    /// when ALPN chose `h2` or prior knowledge is asked for.
    fn connect(&self, url: &Url, proxy: Option<&ProxyAddr>, mode: HttpVersion, deadline: Option<Instant>) -> Result<Conn> {
        let cfg = &self.inner.cfg;
        let what = url.origin();
        let now = Instant::now();
        let cdl = earliest(deadline, cfg.connect_timeout.map(|t| now + t));
        let (host, port) = match proxy {
            Some(p) => (p.host.as_str(), p.port),
            None => (url.host.as_str(), url.port),
        };
        let tcp = self.dial(host, port, cdl)?;
        let socks = proxy.is_some_and(|p| p.kind != crate::proxy::ProxyKind::Http);
        if let (true, Some(p)) = (socks, proxy) {
            socks_connect(&tcp, url, p, cdl)?;
        }
        let tunnel = !socks && proxy.is_some() && (url.is_secure() || mode == HttpVersion::Http2 || cfg.proxy.as_ref().is_some_and(|p| p.tunnel_http));
        if let (true, Some(p)) = (tunnel, proxy) {
            self.tunnel(&tcp, url, p, cdl)?;
        }
        let absolute = !socks && proxy.is_some() && !tunnel;
        if url.is_secure() {
            #[cfg(feature = "tls")]
            {
                let alpn = match mode {
                    HttpVersion::Http1 => 0,
                    HttpVersion::Http2 => 2,
                    _ if cfg!(feature = "client-h2") => 1,
                    _ => 0,
                };
                let d = self.tls_connect(tcp, url, alpn, deadline, &what)?;
                #[cfg(feature = "client-h2")]
                if d.alpn() == Some(b"h2") {
                    return Ok(Conn::Mux(self.h2_mux(d, what)));
                }
                if mode == HttpVersion::Http2 {
                    return Err(Error::protocol("the server did not choose ALPN h2", &what));
                }
                return Ok(Conn::H1(H1Conn::new(d, false, cfg.max_head)));
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = tcp;
                return Err(Error::new(ErrorKind::Unsupported, format!("https needs the `tls` feature of simoom-client: {what}")));
            }
        }
        let d = Duplex::plain(tcp);
        d.set_write_timeout(cfg.write_timeout);
        #[cfg(feature = "client-h2")]
        #[cfg(feature = "h2c-upgrade")]
        if mode == HttpVersion::Http2 && cfg.h2c_upgrade && !absolute {
            return self.h2c_upgrade(d, url, deadline, what);
        }
        #[cfg(feature = "client-h2")]
        if mode == HttpVersion::Http2 {
            return Ok(Conn::Mux(self.h2_mux(d, what)));
        }
        Ok(Conn::H1(H1Conn::new(d, absolute, cfg.max_head)))
    }

    /// A `CONNECT` tunnel through an HTTP proxy (answering its challenges with `auth`).
    fn tunnel(&self, tcp: &std::net::TcpStream, url: &Url, p: &ProxyAddr, cdl: Option<Instant>) -> Result<()> {
        #[cfg(feature = "auth")]
        if let Some(a) = &self.inner.tunnel_auth {
            return crate::auth::connect_tunnel(a, tcp, &url.authority(), p, cdl);
        }
        crate::transport::connect_tunnel(tcp, &url.authority(), p, cdl)
    }

    /// TCP to `host:port` with the resolver timeout and Happy Eyeballs.
    fn dial(&self, host: &str, port: u16, deadline: Option<Instant>) -> Result<std::net::TcpStream> {
        let cfg = &self.inner.cfg;
        crate::transport::tcp_connect_with(host, port, deadline, cfg.dns_timeout, cfg.happy_eyeballs_delay)
    }

    /// The TLS handshake on a connected socket.
    #[cfg(feature = "tls")]
    pub(crate) fn tls_connect(&self, tcp: std::net::TcpStream, url: &Url, alpn: usize, deadline: Option<Instant>, what: &str) -> Result<Duplex> {
        let cfg = &self.inner.cfg;
        let tdl = earliest(deadline, cfg.tls_timeout.or(cfg.connect_timeout).map(|t| Instant::now() + t));
        let name = self.inner.tls.opts.server_name.as_deref().unwrap_or(&url.host);
        let mut c = ClientConnection::new(self.inner.tls.config(alpn), name).map_err(|e| crate::transport::tls_error(&e, what))?;
        crate::transport::tls_handshake(&tcp, &mut c, tdl, what)?;
        let d = Duplex::tls(tcp, c);
        d.set_write_timeout(cfg.write_timeout);
        Ok(d)
    }

    /// h2c through HTTP/1.1 `Upgrade` (RFC 7540 §3.2): an `OPTIONS *` request offers h2c; on
    /// `101` the connection speaks HTTP/2 (the probe's own stream 1 is cancelled), otherwise it
    /// stays HTTP/1.1.
    #[cfg(feature = "h2c-upgrade")]
    fn h2c_upgrade(&self, d: Duplex, url: &Url, deadline: Option<Instant>, what: String) -> Result<Conn> {
        let cfg = &self.inner.cfg;
        let mut conn = H1Conn::new(d, false, cfg.max_head);
        let settings = simoom_h2::http2_settings_header(&cfg.h2);
        let mut probe = url.clone();
        probe.path = "*".into();
        probe.query = None;
        let mut h = Headers::new();
        h.append("Connection", "Upgrade, HTTP2-Settings");
        h.append("Upgrade", "h2c");
        h.append("HTTP2-Settings", settings.as_bytes());
        let o = Out { method: "OPTIONS", url: &probe, absolute: false, headers: &h, extra: &[], proxy_auth: None, expect_continue: false, expect_timeout: cfg.expect_timeout, idle: cfg.read_timeout, close: false };
        let hd = earliest(deadline, cfg.response_timeout.or(cfg.read_timeout).map(|t| Instant::now() + t));
        let head = conn.exchange(&o, &mut Body::Empty, hd, &what)?;
        if head.status != 101 || !head.headers.has_token("upgrade", "h2c") {
            // no h2c here: finish the probe's answer and stay on HTTP/1.1
            if head.framing != Framing::None {
                let mut dec = BodyDecoder::new(head.framing, &crate::h1::limits(cfg.max_head));
                let (mut sink, mut t) = (Vec::new(), None);
                while conn.read_body_vec(&mut dec, &mut sink, &mut t, cfg.read_timeout, deadline, &what)? > 0 || t.is_none() {}
            }
            return Ok(Conn::H1(conn));
        }
        let leftover = conn.take_leftover();
        let proto = crate::h2::H2Proto::upgraded(cfg.h2.clone(), what.clone());
        let m = Mux::new(crate::mux::MuxIo::Tcp(conn.io), Box::new(proto), what).into_arc();
        m.adopt(1, &leftover);
        m.finish(1);
        Ok(Conn::Mux(m))
    }

    #[cfg(feature = "client-h2")]
    fn h2_mux(&self, d: Duplex, what: String) -> Arc<Mux> {
        let proto = crate::h2::H2Proto::new(self.inner.cfg.h2.clone(), what.clone());
        Mux::new(crate::mux::MuxIo::Tcp(d), Box::new(proto), what).into_arc()
    }

    /// Opens an HTTP/1.1 connection outside the pool (WebSocket upgrades, pipelining): TCP,
    /// tunnel, TLS with ALPN http/1.1.
    #[cfg(any(feature = "client-ws", feature = "pipeline"))]
    pub(crate) fn connect_h1_raw(&self, url: &Url, deadline: Option<Instant>) -> Result<H1Conn> {
        let cfg = &self.inner.cfg;
        let proxy = cfg.proxy.as_ref().and_then(|p| p.proxy_for(url)).cloned();
        let what = url.origin();
        let cdl = earliest(deadline, cfg.connect_timeout.map(|t| Instant::now() + t));
        let (host, port) = match &proxy {
            Some(p) => (p.host.as_str(), p.port),
            None => (url.host.as_str(), url.port),
        };
        let tcp = self.dial(host, port, cdl)?;
        if let Some(p) = proxy.as_ref().filter(|p| p.kind != crate::proxy::ProxyKind::Http) {
            socks_connect(&tcp, url, p, cdl)?;
        } else if let Some(p) = &proxy {
            self.tunnel(&tcp, url, p, cdl)?;
        }
        if url.is_secure() {
            #[cfg(feature = "tls")]
            {
                let d = self.tls_connect(tcp, url, 0, deadline, &what)?;
                return Ok(H1Conn::new(d, false, cfg.max_head));
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = tcp;
                return Err(Error::new(ErrorKind::Unsupported, format!("wss needs the `tls` feature of simoom-client: {what}")));
            }
        }
        let d = Duplex::plain(tcp);
        d.set_write_timeout(cfg.write_timeout);
        Ok(H1Conn::new(d, false, cfg.max_head))
    }

    fn h1_request(
        &self,
        mut conn: H1Conn,
        slot: Option<Slot>,
        req: &mut Request,
        proxy: Option<&ProxyAddr>,
        deadline: Option<Instant>,
    ) -> std::result::Result<Response, (Error, bool)> {
        let cfg = &self.inner.cfg;
        let url = &req.url;
        let auth = if conn.absolute { proxy.and_then(|p| p.authorization()) } else { None };
        // client defaults, sent when the request has no such field (write_head checks)
        let basic = url.userinfo.as_ref().map(|u| format!("Basic {}", crate::url::b64(u.as_bytes())));
        let mut extra: [(&str, &[u8]); 3] = [("", b""); 3];
        let mut ne = 0;
        if let Some(ua) = &cfg.user_agent {
            extra[ne] = ("User-Agent", ua.as_bytes());
            ne += 1;
        }
        if cfg.decompress && req.method != "HEAD" {
            if let Some(d) = &self.inner.decoder {
                extra[ne] = ("Accept-Encoding", d.accept_encoding().as_bytes());
                ne += 1;
            }
        }
        if let Some(b) = &basic {
            extra[ne] = ("Authorization", b.as_bytes());
            ne += 1;
        }
        let o = Out {
            method: &req.method,
            url,
            absolute: conn.absolute,
            headers: &req.headers,
            extra: &extra[..ne],
            proxy_auth: auth.as_deref(),
            expect_continue: req.expect_continue,
            expect_timeout: cfg.expect_timeout,
            idle: cfg.read_timeout,
            close: !cfg.keep_alive,
        };
        let head_deadline = earliest(deadline, req.response_timeout.or(cfg.response_timeout).map(|t| Instant::now() + t));
        let head = match conn.exchange(&o, &mut req.body, head_deadline, url) {
            Ok(h) => h,
            Err(e) => {
                let gb = conn.got_bytes;
                conn.io.close();
                drop(slot);
                return Err((e, gb));
            }
        };
        let url = Arc::new(req.url.clone());
        let body = if head.framing == Framing::None || head.upgraded {
            if head.upgraded {
                conn.reusable = false;
            }
            match slot {
                Some(s) if conn.reusable && !conn.has_buffered() => s.put_back(conn),
                _ => conn.io.close(),
            }
            ResponseBody::empty()
        } else {
            let lim = crate::h1::limits(cfg.max_head);
            let dec = BodyDecoder::new(head.framing, &lim);
            ResponseBody::new(BodyInner::H1(Box::new(H1Body { conn: Some(conn), slot, dec, idle: cfg.read_timeout, deadline, what: url.clone(), len_hint: if let Framing::Length(n) = head.framing { Some(n) } else { None } })), cfg.max_body)
        };
        Ok(Response { status: head.status, version: head.version, reason: head.reason, headers: head.headers, url, body })
    }

    /// A request on a shared connection.
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    fn mux_request(&self, m: &Arc<Mux>, req: &mut Request, headers: &Headers, deadline: Option<Instant>) -> Result<Response> {
        let cfg = &self.inner.cfg;
        let url = &req.url;
        let (host, fields) = crate::mux::request_fields(headers, req.body.known_len(), &req.method);
        let authority = host.unwrap_or_else(|| url.host_header());
        let target = url.request_target();
        let head = ReqHead { method: &req.method, scheme: if url.is_secure() { "https" } else { "http" }, authority: &authority, path: &target, fields };
        let end = req.body.is_empty();
        let open_deadline = earliest(deadline, cfg.pool_timeout.map(|t| Instant::now() + t));
        let id = m.open(&head, end, open_deadline)?;
        let mut body = MuxBody { mux: m.clone(), id, idle: cfg.read_timeout, deadline, done: false };
        let wdl = || earliest(deadline, cfg.write_timeout.map(|t| Instant::now() + t));
        // A server may answer and close the stream before the body is all sent (RFC 9113
        // §8.1): stop sending and read the answer.
        let sent = (|| -> Result<()> {
            match &mut req.body {
            Body::Empty => {}
            Body::Bytes(b) => m.write(id, b, true, wdl())?,
            Body::Reader { reader, len } => {
                let mut chunk = vec![0u8; 16 * 1024];
                let mut sent = 0u64;
                loop {
                    let n = reader.read(&mut chunk).map_err(|e| Error::new(ErrorKind::Io(e.kind()), format!("reading the request body: {e}")))?;
                    if n == 0 {
                        if len.is_some_and(|l| l != sent) {
                            return Err(Error::new(ErrorKind::InvalidRequest, "request body shorter than its length"));
                        }
                        m.write(id, &[], true, wdl())?;
                        break;
                    }
                    sent += n as u64;
                    m.write(id, &chunk[..n], false, wdl())?;
                }
            }
            }
            Ok(())
        })();
        match sent {
            Err(e) if matches!(e.kind, ErrorKind::Reset(_)) => {}
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        let head_deadline = earliest(deadline, req.response_timeout.or(cfg.response_timeout).map(|t| Instant::now() + t));
        let kind = if head_deadline.is_some() && head_deadline == deadline { TimeoutKind::Total } else { TimeoutKind::ResponseHead };
        let hd = match (head_deadline, cfg.read_timeout) {
            (Some(h), _) => Some(h),
            (None, Some(r)) => Some(Instant::now() + r),
            (None, None) => None,
        };
        let kind = if head_deadline.is_none() { TimeoutKind::Idle } else { kind };
        let (status, rh) = m.head(id, hd, kind)?;
        let version = m.version();
        let no_body = req.method == "HEAD" || status == 204 || status == 304;
        if no_body {
            body.done = true;
        }
        Ok(Response { status, version, reason: reason_of(status), headers: rh, url: Arc::new(req.url.clone()), body: ResponseBody::new(BodyInner::Mux(Box::new(body)), cfg.max_body) })
    }

    /// Starts the keepalive thread once (HTTP/2 PINGs and idle eviction).
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    fn start_keepalive(&self) {
        let Some(interval) = self.inner.cfg.keepalive_interval else { return };
        let mut started = self.inner.keepalive.lock().unwrap_or_else(|p| p.into_inner());
        if *started {
            return;
        }
        *started = true;
        let weak = Arc::downgrade(&self.inner);
        let tick = interval.max(Duration::from_millis(10));
        let _ = std::thread::Builder::new().name("simoom-client-keepalive".into()).spawn(move || loop {
            std::thread::sleep(tick);
            let Some(inner) = weak.upgrade() else { return };
            for (k, m) in inner.pool.all_mux() {
                if m.is_dead() {
                    inner.pool.remove_mux(&k, &m);
                    m.close();
                    continue;
                }
                if let Some(idle) = m.idle_for() {
                    if idle >= inner.cfg.pool_idle_timeout {
                        inner.pool.remove_mux(&k, &m);
                        m.close();
                    } else if idle >= interval && m.ping(inner.cfg.keepalive_timeout).is_err() {
                        inner.pool.remove_mux(&k, &m);
                        m.close();
                    }
                }
            }
            inner.pool.evict();
        });
    }

    /// Opens a full-duplex call on HTTP/2 or HTTP/3: the request body and the response body
    /// stream at the same time (gRPC-style). HTTP/1.1 origins are refused.
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    pub fn call(&self, method: &str, url: &str, headers: &Headers) -> Result<crate::call::Call> {
        let url = Url::parse(url)?;
        let cfg = &self.inner.cfg;
        let mut mode = cfg.version;
        if mode == HttpVersion::Auto && !url.is_secure() {
            mode = HttpVersion::Http2;
        }
        let mut req = Request { headers: headers.clone(), version: Some(mode), ..Request::new(method, url.clone()) };
        self.run_before_send(&mut req);
        let headers = self.headers_for(&req);
        let m = self.mux_for(&url, mode)?;
        let (host, fields) = crate::mux::request_fields(&headers, None, method);
        let authority = host.unwrap_or_else(|| url.host_header());
        let target = url.request_target();
        let head = ReqHead { method: &req.method, scheme: if url.is_secure() { "https" } else { "http" }, authority: &authority, path: &target, fields };
        let id = m.open(&head, false, cfg.pool_timeout.map(|t| Instant::now() + t))?;
        let mut call = crate::call::Call::new(m, id, cfg.read_timeout, cfg.write_timeout);
        if self.has_interceptors() {
            // interceptors see the response head when the caller asks for it (the body streams,
            // so a retry is not possible)
            let client = self.clone();
            let v = if mode == HttpVersion::Http3 { crate::types::Version::Http3 } else { crate::types::Version::Http2 };
            call.on_head(Box::new(move |status, h| {
                let resp = head_response(status, v, String::new(), h.clone(), &req.url);
                match client.run_on_response(&req, &resp) {
                    crate::hooks::Action::Fail(why) => Err(Error::new(ErrorKind::Protocol, format!("{why}: {}", req.url))),
                    _ => Ok(()),
                }
            }));
        }
        Ok(call)
    }

    /// A shared connection to `url` (opened if needed).
    #[cfg(any(feature = "client-h2", feature = "client-h3"))]
    pub(crate) fn mux_for(&self, url: &Url, mode: HttpVersion) -> Result<Arc<Mux>> {
        let cfg = &self.inner.cfg;
        #[cfg(feature = "client-h3")]
        if mode == HttpVersion::Http3 {
            return self.h3_mux(&url.host, url.port, url, None);
        }
        let proxy: Option<ProxyAddr> = cfg.proxy.as_ref().and_then(|p| p.proxy_for(url)).cloned();
        let key = OriginKey { secure: url.is_secure(), host: url.host.clone(), port: url.port, proxy: proxy.clone(), mode: mode as u8 };
        #[cfg(feature = "client-h2")]
        {
            if let Some(m) = self.inner.pool.mux(&key, true) {
                return Ok(m);
            }
            match self.connect(url, proxy.as_ref(), mode, None)? {
                Conn::Mux(m) => {
                    self.inner.pool.add_mux(key, m.clone());
                    self.start_keepalive();
                    Ok(m)
                }
                Conn::H1(c) => {
                    c.io.close();
                    Err(Error::new(ErrorKind::Unsupported, format!("the server speaks only HTTP/1.1; duplex calls need HTTP/2 or HTTP/3: {url}")))
                }
            }
        }
        #[cfg(not(feature = "client-h2"))]
        {
            let _ = key;
            Err(Error::new(ErrorKind::Unsupported, "duplex calls need HTTP/2 (`client-h2`) or HTTP/3"))
        }
    }

    // ------------------------------------------------------------------ HTTP/3

    #[cfg(feature = "client-h3")]
    fn alt_svc_for(&self, url: &Url) -> Option<(String, u16)> {
        let alt = self.inner.alt.lock().unwrap_or_else(|p| p.into_inner());
        let a = alt.get(&url.origin())?;
        let now = Instant::now();
        if now >= a.expires || a.broken_until.is_some_and(|b| now < b) {
            return None;
        }
        Some((a.host.clone().unwrap_or_else(|| url.host.clone()), a.port))
    }

    #[cfg(feature = "client-h3")]
    fn mark_alt_broken(&self, url: &Url) {
        if let Some(a) = self.inner.alt.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&url.origin()) {
            a.broken_until = Some(Instant::now() + Duration::from_secs(300));
        }
    }

    #[cfg(feature = "client-h3")]
    fn record_alt_svc(&self, r: &Response) {
        let Some(v) = r.headers.get("alt-svc") else { return };
        let mut alt = self.inner.alt.lock().unwrap_or_else(|p| p.into_inner());
        let origin = r.url.origin();
        if v.trim().eq_ignore_ascii_case("clear") {
            alt.remove(&origin);
            return;
        }
        if let Some((host, port, ma)) = parse_alt_svc(v) {
            let broken = alt.get(&origin).and_then(|a| a.broken_until);
            alt.insert(origin, AltSvc { host, port, expires: Instant::now() + ma, broken_until: broken });
        }
    }

    #[cfg(feature = "client-h3")]
    fn h3_mux(&self, host: &str, port: u16, url: &Url, deadline: Option<Instant>) -> Result<Arc<Mux>> {
        let key = OriginKey { secure: true, host: host.to_string(), port, proxy: None, mode: 3 };
        if let Some(m) = self.inner.pool.mux(&key, true) {
            return Ok(m);
        }
        let cfg = &self.inner.cfg;
        let cdl = earliest(deadline, cfg.connect_timeout.map(|t| Instant::now() + t));
        let name = self.inner.tls.opts.server_name.clone().unwrap_or_else(|| url.host.clone());
        let m = crate::h3::connect(self.inner.tls.config(3), host, port, &name, cdl, &url.origin())?.into_arc();
        if cfg.keep_alive {
            self.inner.pool.add_mux(key, m.clone());
            self.start_keepalive();
        }
        Ok(m)
    }

    #[cfg(feature = "client-h3")]
    fn h3_request(&self, req: &mut Request, headers: &Headers, host: &str, port: u16, deadline: Option<Instant>) -> Result<Response> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let m = self.h3_mux(host, port, &req.url, deadline)?;
            match self.mux_request(&m, req, headers, deadline) {
                Err(e) if attempt < 3 && req.body.replayable() && retryable_mux(&e) => continue,
                r => return r,
            }
        }
    }
}

/// Errors worth another attempt: the connection could not be made or was lost.
#[cfg(feature = "retry")]
fn retryable_error(e: &Error) -> bool {
    matches!(e.kind, ErrorKind::Connect | ErrorKind::Closed | ErrorKind::Io(_) | ErrorKind::Reset(_) | ErrorKind::Timeout(TimeoutKind::Connect) | ErrorKind::Timeout(TimeoutKind::Tls))
}

/// Errors after which a request on a shared connection was certainly not processed.
#[cfg(any(feature = "client-h2", feature = "client-h3"))]
fn retryable_mux(e: &Error) -> bool {
    // REFUSED_STREAM (HTTP/2) and H3_REQUEST_REJECTED; a connection going away before the
    // stream was opened.
    matches!(e.kind, ErrorKind::Reset(0x7) | ErrorKind::Reset(0x10b)) || (e.kind == ErrorKind::Closed && e.message.contains("going away"))
}

#[cfg(any(feature = "client-h3", test))]
/// Parses the first `h3` alternative of an `Alt-Svc` value: (host, port, max-age).
pub(crate) fn parse_alt_svc(v: &str) -> Option<(Option<String>, u16, Duration)> {
    for alt in v.split(',') {
        let mut parts = alt.split(';');
        let first = parts.next()?.trim();
        let (proto, auth) = first.split_once('=')?;
        if proto.trim() != "h3" {
            continue;
        }
        let auth = auth.trim().trim_matches('"');
        let (h, p) = auth.rsplit_once(':')?;
        let port: u16 = p.parse().ok()?;
        let host = if h.is_empty() { None } else { Some(h.trim_start_matches('[').trim_end_matches(']').to_string()) };
        let mut ma = Duration::from_secs(86400);
        for p in parts {
            if let Some((k, v)) = p.split_once('=') {
                if k.trim() == "ma" {
                    if let Ok(s) = v.trim().parse::<u64>() {
                        ma = Duration::from_secs(s);
                    }
                }
            }
        }
        return Some((host, port, ma));
    }
    None
}

/// Hands a reader to a decoder and back if the decoder declines.
#[cfg(feature = "compress")]
struct Handoff(Arc<Mutex<Option<Box<dyn std::io::Read + Send>>>>);

#[cfg(feature = "compress")]
impl std::io::Read for Handoff {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match g.as_mut() {
            Some(r) => r.read(buf),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_svc_values() {
        assert_eq!(parse_alt_svc(r#"h3=":443"; ma=3600"#), Some((None, 443, Duration::from_secs(3600))));
        assert_eq!(parse_alt_svc(r#"h3-29=":1", h3="alt.example:8443""#), Some((Some("alt.example".into()), 8443, Duration::from_secs(86400))));
        assert_eq!(parse_alt_svc(r#"h2=":443""#), None);
    }
}

/// A SOCKS5 handshake to `url` through `p` (feature `socks`).
pub(crate) fn socks_connect(tcp: &std::net::TcpStream, url: &Url, p: &ProxyAddr, cdl: Option<Instant>) -> Result<()> {
    #[cfg(feature = "socks")]
    {
        crate::socks::connect(tcp, &url.host, url.port, p, p.kind == crate::proxy::ProxyKind::Socks5h, cdl)
    }
    #[cfg(not(feature = "socks"))]
    {
        let _ = (tcp, cdl);
        Err(Error::new(ErrorKind::Unsupported, format!("SOCKS5 proxy {}:{} needs the `socks` feature of simoom-client: {url}", p.host, p.port)))
    }
}
