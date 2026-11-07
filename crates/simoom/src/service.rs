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
/// Panics are caught: the request gets a 500 and its connection closes. A call that takes
/// longer than [`crate::Limits::inline_budget`] is counted as a stall; after
/// [`crate::Limits::stalls_before_offload`] stalls the service runs on the offload pool.
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

    /// The stall watchdog saw a call exceed the inline budget. Return `true` if the service
    /// handled it (the [`crate::Router`] moves just that route to the offload pool); the default
    /// returns `false`, and the server counts stalls for the whole service.
    fn on_stall(&self, req: &Request<'_>) -> bool {
        let _ = req;
        false
    }
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
    fn on_stall(&self, req: &Request<'_>) -> bool {
        (**self).on_stall(req)
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
