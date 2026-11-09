//! The [`Service`] trait and the [`blocking`] adapter.

use crate::reply::Reply;
use crate::request::{OwnedRequest, Request};
use crate::types::Response;
use std::sync::Arc;

/// What [`Service::call`] returns: informational. The server tracks what the [`Reply`] did; a
/// call that neither answered nor deferred gets a 500.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Outcome {
    /// The reply was sent (or will be: [`Reply::stream`], an upgrade).
    Done,
    /// The reply comes later through a [`crate::Responder`].
    Deferred,
}

/// Handles requests. It runs **inline on a loop thread**, so it must not block: answer at once
/// (microseconds), or defer ([`Reply::defer`]), or move the work to the offload pool
/// ([`Reply::offload`], [`blocking`]).
///
/// Panics are caught: the request gets a 500 and its connection closes. A call that uses more
/// CPU than [`crate::Limits::inline_budget`], or blocks, is a stall; after
/// [`crate::Limits::stalls_before_offload`] stalls the route (of a [`crate::Router`]; else the
/// requests with that path) runs on the offload pool until it is fast again.
///
/// Any `Fn(&mut Request<'_>, Reply<'_>) -> Outcome + Send + Sync + 'static` closure is a
/// service:
///
/// ```
/// use simoom::{Outcome, Reply, Request};
/// let hello = |_req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
///     reply.header("content-type", "text/plain").body_static(b"hello")
/// };
/// # fn check(_: impl simoom::Service) {}
/// check(hello);
/// ```
pub trait Service: Send + Sync + 'static {
    /// Answers one request.
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome;

    /// The stall-watchdog state of the route that served `req` (implemented by
    /// [`crate::Router`]); `None` lets the server track the request's path.
    #[doc(hidden)]
    fn watch(&self, req: &Request<'_>) -> Option<WatchRef<'_>> {
        let _ = req;
        None
    }
}

/// The stall-watchdog state of one route ([`Service::watch`]). Opaque.
#[doc(hidden)]
#[derive(Debug)]
pub struct WatchRef<'a> {
    pub(crate) watch: &'a Arc<crate::watchdog::Watch>,
    /// Overrides [`crate::Limits::stalls_before_offload`].
    pub(crate) stalls: Option<u32>,
    pub(crate) name: &'a str,
}

impl<F> Service for F
where
    F: Fn(&mut Request<'_>, Reply<'_>) -> Outcome + Send + Sync + 'static,
{
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        self(req, reply)
    }
}

impl<S: Service + ?Sized> Service for Arc<S> {
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        (**self).call(req, reply)
    }
    fn watch(&self, req: &Request<'_>) -> Option<WatchRef<'_>> {
        (**self).watch(req)
    }
}

/// A service that runs blocking code on the shared, bounded offload pool: the request is
/// copied ([`OwnedRequest`]), `f` runs on a worker thread, and its [`Response`] comes back to
/// the connection. When the pool is full or CoDel reports overload (jobs waiting longer than
/// [`crate::Limits::offload_target`] for a whole interval) the request gets a fast `503` with
/// `Retry-After` instead of queueing.
///
/// ```
/// let svc = simoom::blocking(|req: simoom::OwnedRequest| {
///     simoom::Response::text(format!("you asked for {}", req.path_str()))
/// });
/// # fn check(_: impl simoom::Service) {}
/// check(svc);
/// ```
pub fn blocking<F>(f: F) -> Blocking<F>
where
    F: Fn(OwnedRequest) -> Response + Send + Sync + 'static,
{
    Blocking { f: Arc::new(f) }
}

/// The service returned by [`blocking`].
pub struct Blocking<F> {
    f: Arc<F>,
}

impl<F> std::fmt::Debug for Blocking<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Blocking")
    }
}

impl<F> Service for Blocking<F>
where
    F: Fn(OwnedRequest) -> Response + Send + Sync + 'static,
{
    fn call(&self, req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
        let f = self.f.clone();
        reply.blocking(req, move |r| f(r))
    }
}
