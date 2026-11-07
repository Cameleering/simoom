//! [`Router`]: exact paths in a hash map, templates in a segment trie, evaluated on the loop
//! thread. A 404 or 405 never reaches the offload pool.

use crate::reply::Reply;
use crate::request::{Param, Request};
use crate::service::{Outcome, Service};
use crate::util::FastMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

struct RouteEntry {
    method: Option<Box<[u8]>>,
    handler: Arc<dyn Service>,
    names: Vec<Arc<str>>,
    pattern: String,
    stalls: AtomicU32,
    offload: AtomicBool,
    logged: AtomicBool,
}

#[derive(Default)]
struct Node {
    lit: FastMap<Box<[u8]>, Node>,
    param: Option<Box<Node>>,
    /// A `*rest` route list: matches the rest of the path (possibly empty).
    wild: Vec<usize>,
    routes: Vec<usize>,
}

/// Routes requests by method and path.
///
/// - Exact paths (`/health`) are looked up in a hash map.
/// - Templates go into a trie of path segments: `:name` or `{name}` captures one segment,
///   `*name` (last) captures the rest. Literal segments win over parameters, parameters over
///   wildcards.
/// - A path that matches with another method gets `405` with `allow`; no match gets `404`
///   (or the [`Router::fallback`]). `HEAD` falls back to a `GET` route.
/// - Captured values: [`Request::param`]. Paths match as sent (not percent-decoded).
/// - The stall watchdog moves a slow route, alone, to the offload pool.
///
/// ```
/// use simoom::{Router, Request, Reply, Outcome};
/// let router = Router::new()
///     .get("/health", |_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
///     .get("/users/:id", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
///         let id = req.param_str("id").unwrap_or("").to_string();
///         r.body(id)
///     });
/// # let _ = router;
/// ```
pub struct Router {
    exact: FastMap<Box<[u8]>, Vec<usize>>,
    trie: Node,
    routes: Vec<RouteEntry>,
    fallback: Option<Arc<dyn Service>>,
    stalls_before_offload: u32,
}

impl Default for Router {
    fn default() -> Self {
        Router::new()
    }
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.routes.iter().map(|r| (r.method.as_deref().map(String::from_utf8_lossy), &r.pattern))).finish()
    }
}

fn is_template(seg: &[u8]) -> bool {
    seg.first() == Some(&b':') || seg.first() == Some(&b'*') || (seg.first() == Some(&b'{') && seg.last() == Some(&b'}'))
}

impl Router {
    /// An empty router.
    pub fn new() -> Router {
        Router { exact: FastMap::default(), trie: Node::default(), routes: Vec::new(), fallback: None, stalls_before_offload: 3 }
    }

    /// Adds a route for `method` (`"*"` for any) and `path`.
    pub fn route(mut self, method: &str, path: &str, handler: impl Service) -> Router {
        let idx = self.routes.len();
        let method = if method == "*" { None } else { Some(method.as_bytes().to_vec().into_boxed_slice()) };
        let segs: Vec<&[u8]> = path.as_bytes().split(|&b| b == b'/').skip(1).collect();
        let mut names = Vec::new();
        if !segs.iter().any(|s| is_template(s)) {
            self.exact.entry(path.as_bytes().to_vec().into_boxed_slice()).or_default().push(idx);
        } else {
            let mut node = &mut self.trie;
            for (i, s) in segs.iter().enumerate() {
                match s.first() {
                    Some(b'*') => {
                        names.push(Arc::from(std::str::from_utf8(&s[1..]).unwrap_or("")));
                        node.wild.push(idx);
                        let _ = i;
                        break;
                    }
                    Some(b':') | Some(b'{') => {
                        let n = if s[0] == b':' { &s[1..] } else { &s[1..s.len() - 1] };
                        names.push(Arc::from(std::str::from_utf8(n).unwrap_or("")));
                        node = node.param.get_or_insert_with(Box::default);
                    }
                    _ => node = node.lit.entry(s.to_vec().into_boxed_slice()).or_default(),
                }
                if i == segs.len() - 1 {
                    node.routes.push(idx);
                }
            }
        }
        self.routes.push(RouteEntry {
            method,
            handler: Arc::new(handler),
            names,
            pattern: path.to_string(),
            stalls: AtomicU32::new(0),
            offload: AtomicBool::new(false),
            logged: AtomicBool::new(false),
        });
        self
    }

    /// `GET` route.
    pub fn get(self, path: &str, handler: impl Service) -> Router {
        self.route("GET", path, handler)
    }
    /// `POST` route.
    pub fn post(self, path: &str, handler: impl Service) -> Router {
        self.route("POST", path, handler)
    }
    /// `PUT` route.
    pub fn put(self, path: &str, handler: impl Service) -> Router {
        self.route("PUT", path, handler)
    }
    /// `DELETE` route.
    pub fn delete(self, path: &str, handler: impl Service) -> Router {
        self.route("DELETE", path, handler)
    }
    /// `PATCH` route.
    pub fn patch(self, path: &str, handler: impl Service) -> Router {
        self.route("PATCH", path, handler)
    }
    /// A route for any method.
    pub fn any(self, path: &str, handler: impl Service) -> Router {
        self.route("*", path, handler)
    }

    /// Answers requests no route matches (instead of 404).
    pub fn fallback(mut self, handler: impl Service) -> Router {
        self.fallback = Some(Arc::new(handler));
        self
    }

    /// Stalls after which a route moves to the offload pool (default 3; 0 never).
    pub fn stalls_before_offload(mut self, n: u32) -> Router {
        self.stalls_before_offload = n;
        self
    }

    /// Finds the route list for `path`, capturing parameters.
    fn find<'r>(&'r self, path: &[u8], params: &mut Vec<(u32, u32)>) -> Option<&'r [usize]> {
        if let Some(v) = self.exact.get(path) {
            return Some(v);
        }
        if path.first() != Some(&b'/') {
            return None;
        }
        walk(&self.trie, path, 1, params)
    }
}

/// Matches `path[pos..]` (just after a `/`) from `node`.
fn walk<'n>(node: &'n Node, path: &[u8], pos: usize, params: &mut Vec<(u32, u32)>) -> Option<&'n [usize]> {
    let end = path[pos..].iter().position(|&b| b == b'/').map_or(path.len(), |i| pos + i);
    let seg = &path[pos..end];
    let last = end == path.len();
    if let Some(child) = node.lit.get(seg) {
        if last {
            if !child.routes.is_empty() {
                return Some(&child.routes);
            }
        } else if let Some(r) = walk(child, path, end + 1, params) {
            return Some(r);
        }
    }
    if !seg.is_empty() {
        if let Some(child) = node.param.as_deref() {
            params.push((pos as u32, end as u32));
            if last {
                if !child.routes.is_empty() {
                    return Some(&child.routes);
                }
            } else if let Some(r) = walk(child, path, end + 1, params) {
                return Some(r);
            }
            params.pop();
        }
    }
    if !node.wild.is_empty() {
        params.push((pos as u32, path.len() as u32));
        return Some(&node.wild);
    }
    None
}

impl Service for Router {
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        let path = req.path();
        let mut ranges = Vec::new();
        let Some(list) = self.find(path, &mut ranges) else {
            return match &self.fallback {
                Some(f) => f.call(req, reply),
                None => reply.status(404).header("content-type", "text/plain").body_static(b"Not Found"),
            };
        };
        let m = req.method();
        let pick = list
            .iter()
            .copied()
            .find(|&i| self.routes[i].method.as_deref().is_none_or(|x| x == m))
            .or_else(|| if m == b"HEAD" { list.iter().copied().find(|&i| self.routes[i].method.as_deref() == Some(b"GET")) } else { None });
        let Some(i) = pick else {
            let mut allow = Vec::new();
            for &i in list {
                if let Some(x) = &self.routes[i].method {
                    if !allow.is_empty() {
                        allow.extend_from_slice(b", ");
                    }
                    allow.extend_from_slice(x);
                }
            }
            return reply.status(405).header("allow", allow).header("content-type", "text/plain").body_static(b"Method Not Allowed");
        };
        let r = &self.routes[i];
        req.route = i as u32 + 1;
        // Query strings are not part of the path; offsets are into the target, which starts
        // with the path.
        req.params = ranges.iter().zip(&r.names).map(|(&(s, e), n)| -> Param { (n.clone(), s, e) }).collect();
        if r.offload.load(Ordering::Relaxed) {
            return reply.offload_service(req, r.handler.clone());
        }
        r.handler.call(req, reply)
    }

    fn on_stall(&self, req: &Request<'_>) -> bool {
        let Some(r) = (req.route as usize).checked_sub(1).and_then(|i| self.routes.get(i)) else { return false };
        let n = r.stalls.fetch_add(1, Ordering::Relaxed) + 1;
        if !r.logged.swap(true, Ordering::Relaxed) {
            eprintln!("simoom: route {} took longer than the inline budget; slow handlers belong on the offload pool", r.pattern);
        }
        let k = self.stalls_before_offload;
        if k != 0 && n >= k && !r.offload.swap(true, Ordering::Relaxed) {
            eprintln!("simoom: route {} stalled {n} times and now runs on the offload pool", r.pattern);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(_: &mut Request<'_>, r: Reply<'_>) -> Outcome {
        r.empty()
    }

    #[test]
    fn matching_prefers_literals_then_params_then_wildcards() {
        let r = Router::new()
            .get("/", ok)
            .get("/users/me", ok)
            .get("/users/:id", ok)
            .get("/users/:id/posts/{post}", ok)
            .get("/files/*rest", ok)
            .post("/users/:id", ok);
        let mut p = Vec::new();
        assert_eq!(r.find(b"/", &mut p), Some(&[0][..]));
        assert_eq!(r.find(b"/users/me", &mut p), Some(&[1][..]));
        assert!(p.is_empty());
        assert_eq!(r.find(b"/users/42", &mut p), Some(&[2, 5][..]));
        assert_eq!(p, vec![(7, 9)]);
        p.clear();
        assert_eq!(r.find(b"/users/42/posts/7", &mut p), Some(&[3][..]));
        assert_eq!(p, vec![(7, 9), (16, 17)]);
        p.clear();
        assert_eq!(r.find(b"/files/a/b/c", &mut p), Some(&[4][..]));
        assert_eq!(p, vec![(7, 12)]);
        p.clear();
        assert_eq!(r.find(b"/users", &mut p), None);
        assert_eq!(r.find(b"/users/", &mut p), None);
        assert_eq!(r.find(b"/nope", &mut p), None);
    }
}
