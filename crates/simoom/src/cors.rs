//! Cross-origin resource sharing (feature `cors`): [`Cors`] wraps a service, answers
//! preflight requests and adds the `Access-Control-*` headers to actual responses.
//!
//! ```no_run
//! # #[cfg(feature = "cors")] {
//! use simoom::cors::Cors;
//! use simoom::{Outcome, Reply, Request, Server};
//! let app = |_: &mut Request<'_>, r: Reply<'_>| -> Outcome { r.body("hi") };
//! let cors = Cors::new().allow_origin("https://app.example").allow_methods(&["GET", "POST"]).allow_headers(&["content-type"]).max_age(600);
//! Server::builder().listen("127.0.0.1:8080").service(cors.wrap(app)).start().unwrap();
//! # }
//! ```

use crate::service::{Outcome, Service, WatchRef};
use crate::{Reply, Request};

#[derive(Clone, Debug)]
enum Origins {
    Any,
    List(Vec<String>),
}

/// CORS settings. By default no origin is allowed; nothing changes until origins are added.
#[derive(Clone, Debug)]
pub struct Cors {
    origins: Origins,
    methods: Vec<String>,
    headers: Option<Vec<String>>,
    expose: Vec<String>,
    credentials: bool,
    max_age: Option<u32>,
    private_network: bool,
}

impl Default for Cors {
    fn default() -> Self {
        Cors {
            origins: Origins::List(Vec::new()),
            methods: ["GET", "HEAD", "POST"].map(String::from).to_vec(),
            headers: Some(Vec::new()),
            expose: Vec::new(),
            credentials: false,
            max_age: None,
            private_network: false,
        }
    }
}

impl Cors {
    /// No origins, methods GET, HEAD and POST, no extra request headers.
    pub fn new() -> Cors {
        Cors::default()
    }

    /// Allows this origin (`https://app.example`, compared case-insensitively).
    pub fn allow_origin(mut self, origin: &str) -> Self {
        if let Origins::List(l) = &mut self.origins {
            l.push(origin.to_ascii_lowercase());
        }
        self
    }

    /// Allows every origin (`*`, or the request's origin when credentials are allowed).
    pub fn allow_any_origin(mut self) -> Self {
        self.origins = Origins::Any;
        self
    }

    /// The methods a cross-origin request may use.
    pub fn allow_methods(mut self, methods: &[&str]) -> Self {
        self.methods = methods.iter().map(|m| m.to_ascii_uppercase()).collect();
        self
    }

    /// The request headers a cross-origin request may send (beyond the CORS-safelisted ones).
    pub fn allow_headers(mut self, headers: &[&str]) -> Self {
        self.headers = Some(headers.iter().map(|h| h.to_ascii_lowercase()).collect());
        self
    }

    /// Allows whatever headers a preflight asks for.
    pub fn allow_any_header(mut self) -> Self {
        self.headers = None;
        self
    }

    /// Response headers the browser may show to scripts (`Access-Control-Expose-Headers`).
    pub fn expose_headers(mut self, headers: &[&str]) -> Self {
        self.expose = headers.iter().map(|h| h.to_ascii_lowercase()).collect();
        self
    }

    /// Allows cookies and HTTP authentication (`Access-Control-Allow-Credentials: true`).
    pub fn allow_credentials(mut self, on: bool) -> Self {
        self.credentials = on;
        self
    }

    /// How long a browser may cache a preflight result, in seconds.
    pub fn max_age(mut self, secs: u32) -> Self {
        self.max_age = Some(secs);
        self
    }

    /// Answers Private Network Access preflights (`Access-Control-Allow-Private-Network`).
    pub fn allow_private_network(mut self, on: bool) -> Self {
        self.private_network = on;
        self
    }

    /// The service `inner` with CORS in front.
    pub fn wrap<S: Service>(self, inner: S) -> CorsService<S> {
        CorsService { cors: self, inner }
    }

    fn allowed(&self, origin: &[u8]) -> bool {
        match &self.origins {
            Origins::Any => true,
            Origins::List(l) => l.iter().any(|o| o.as_bytes().eq_ignore_ascii_case(origin)),
        }
    }

    /// The `Access-Control-Allow-Origin` value for an allowed origin.
    fn allow_origin_value<'o>(&self, origin: &'o [u8]) -> &'o [u8] {
        if matches!(self.origins, Origins::Any) && !self.credentials {
            b"*"
        } else {
            origin
        }
    }
}

/// A service behind [`Cors`].
#[derive(Debug)]
pub struct CorsService<S> {
    cors: Cors,
    inner: S,
}

impl<S: Service> Service for CorsService<S> {
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        let c = &self.cors;
        let Some(origin) = req.header("origin") else { return self.inner.call(req, reply) };
        // responses depend on Origin unless every origin gets `*`
        let vary = !(matches!(c.origins, Origins::Any) && !c.credentials);
        let reply = if vary { reply.header("vary", "origin") } else { reply };
        if !c.allowed(origin) {
            return self.inner.call(req, reply);
        }
        let reply = reply.header("access-control-allow-origin", c.allow_origin_value(origin));
        let reply = if c.credentials { reply.header("access-control-allow-credentials", "true") } else { reply };
        if req.method() == b"OPTIONS" {
            if let Some(m) = req.header("access-control-request-method") {
                // a preflight
                let method_ok = c.methods.iter().any(|x| x.as_bytes() == m) || matches!(m, b"GET" | b"HEAD" | b"POST");
                let asked = req.header("access-control-request-headers").unwrap_or(b"");
                let asked: Vec<String> = String::from_utf8_lossy(asked).split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()).collect();
                let headers_ok = match &c.headers {
                    None => true,
                    Some(l) => asked.iter().all(|h| l.contains(h) || matches!(h.as_str(), "accept" | "accept-language" | "content-language" | "content-type")),
                };
                if !method_ok || !headers_ok {
                    // no grant: the browser blocks the actual request
                    return reply.status(204).header("vary", "access-control-request-method, access-control-request-headers").empty();
                }
                let mut r = reply.status(204).header("access-control-allow-methods", c.methods.join(", ")).header("vary", "access-control-request-method, access-control-request-headers");
                if !asked.is_empty() {
                    r = r.header("access-control-allow-headers", asked.join(", "));
                }
                if let Some(a) = c.max_age {
                    r = r.header("access-control-max-age", a.to_string());
                }
                if c.private_network && req.header("access-control-request-private-network") == Some(b"true") {
                    r = r.header("access-control-allow-private-network", "true");
                }
                return r.empty();
            }
        }
        let reply = if c.expose.is_empty() { reply } else { reply.header("access-control-expose-headers", c.expose.join(", ")) };
        self.inner.call(req, reply)
    }

    fn watch(&self, req: &Request<'_>) -> Option<WatchRef<'_>> {
        self.inner.watch(req)
    }
}
