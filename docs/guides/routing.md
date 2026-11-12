# How do I route requests by path and method in simoom?

> Build a `Router` with `.get`, `.post` and friends; `:name` or `{name}` captures a segment, `*name` the rest, and wrong methods get 405 automatically.

`Router` is a service that picks a handler by method and path. It runs on the loop thread, so a
`404` or `405` costs a hash lookup or a short walk through a tree, never a trip to a pool.

## A router with every kind of route

```rust
use simoom::{Outcome, Reply, Request, Router};

fn router() -> Router {
    Router::new()
        .get("/health", |_: &mut Request<'_>, r: Reply<'_>| r.body_static(b"ok"))
        .get("/users/:id", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let id = req.param_str("id").unwrap_or("");
            r.body(format!("user {id}"))
        })
        .get("/teams/{team}/members/{member}", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let (team, member) = (req.param_str("team").unwrap_or(""), req.param_str("member").unwrap_or(""));
            r.body(format!("{member} of {team}"))
        })
        .get("/files/*path", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            let path = req.param_str("path").unwrap_or("");
            r.body(format!("you asked for {path}"))
        })
        .post("/users", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            r.status(201).body(format!("created from {} bytes", req.body().len()))
        })
        .route("OPTIONS", "/users", |_: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            r.status(204).header("allow", "GET, POST, OPTIONS").empty()
        })
        .any("/echo", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            r.body(String::from_utf8_lossy(req.method()).into_owned())
        })
        .fallback(|req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
            r.status(404).body(format!("nothing at {}", req.path_str()))
        })
}
```

Pass it to `Server::builder().service(router)`.

## Methods

`get`, `post`, `put`, `delete` and `patch` add a route for that method. `route(method, path,
handler)` takes any method name, and `any(path, handler)` (or `route("*", ...)`) matches every
method.

- A path that exists with another method gets **`405 Method Not Allowed`** with an `allow`
  header listing the methods that do exist.
- **`HEAD`** uses the `GET` route when there is no `HEAD` route; the client gets the headers
  without the body.
- A path that matches nothing gets **`404`**, or goes to the `fallback` handler if you set one.

## Path patterns

| pattern | matches | captured |
|---|---|---|
| `/health` | exactly `/health` | nothing |
| `/users/:id` or `/users/{id}` | `/users/42`, not `/users/42/posts` | `id` = `42` |
| `/files/*path` (last segment only) | `/files/a/b.txt`, also `/files/` | `path` = `a/b.txt` |

When several routes could match, literal segments win over parameters, and parameters win over
wildcards. So `/users/me` beats `/users/:id` for the path `/users/me`.

Paths without patterns go into a hash map; the others go into a tree of path segments.

## Captured values are raw

Paths are matched as the client sent them, without percent-decoding, and `param` returns the raw
bytes. Decode them when a value can contain escapes such as `%20`:

```rust
use simoom::{percent_decode, Outcome, Reply, Request, Router};

fn router() -> Router {
    Router::new().get("/search/:term", |req: &mut Request<'_>, r: Reply<'_>| -> Outcome {
        let raw = req.param("term").unwrap_or(b"");
        match percent_decode(raw) {
            Some(term) => r.body(term),
            None => r.status(400).body_static(b"bad escape"),
        }
    })
}
```

## Routes and slow handlers

Any service can be a route handler, including `simoom::blocking(...)` for work that must run on
the offload pool ([Slow work](slow-work.md)). The stall watchdog also works per route: if one
handler keeps blocking its loop thread, that route alone moves to the offload pool and comes back
once it is fast again. `Router::stalls_before_offload(n)` changes how many stalls that takes for
this router (`0` never moves a route).

## Common questions

### Can I nest routers or mount one under a prefix?

Not in 0.1.0. A `Router` matches the whole path, so put every route in one router, or write a
small service that looks at the first path segment and calls one of several routers. Since a
`Router` is a `Service`, `router.call(req, reply)` works from inside your own service.

### How do I add middleware such as logging or authentication?

Wrap the router in your own service that does the work and then calls `router.call(req, reply)`.
For access logs, `Builder::on_complete` is simpler and sees every request, including ones the
parser refuses ([Limits and security](limits-and-security.md)). The `cors` and `auth` features
offer ready-made wrappers ([Services and replies](services-and-replies.md#optional-helpers)).

### Does the router handle trailing slashes?

No: `/users` and `/users/` are different paths. Add both routes if you want both to work.

### Is there a limit on the number of routes?

No fixed one. Exact paths cost one hash lookup however many there are; patterns cost one step per
path segment.
