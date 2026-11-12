# simoom microsite plan

_Internal working document, 2026-11-12. Not published. It plans simoom's pages on cameleer.ing,
modelled on Cameleer's site (`Rust-camel/docs/website-plan.md`, `site/`, `scripts/build-docs.py`)
and the Cameleering brand guide (`Rust-camel/docs/design/brand/cameleering-brand.md`). Positioning,
audiences and search queries come from the positioning note of 2026-11-12 (side-session notes,
`simoom-positioning.md`)._

## 1. Decisions

- **Where it lives:** `https://cameleer.ing/simoom/`. The brand guide keeps the cameleer.ing root
  for Cameleer until phase 2 (a second measured project, which simoom now is) and puts the
  practice at `/cameleering/`. A path under the same host inherits the domain's authority and
  works before and after phase 2 without moving.
- **Who owns what:** the source lives in this repository under `site/` and `scripts/`, because
  simoom's facts change here. The Cameleer repository is never edited from here: the Cameleer
  SEO session copies the built `site/simoom/` tree into Cameleer's `site/` and links it from the
  main navigation, `/cameleering/`, the ledger, the root `llms.txt` and the sitemap.
- **Same design:** the pages load Cameleer's own `/assets/site.css` and `/assets/compare.css`
  (same host), the same fonts, header, footer, page types and class names. `site/simoom/assets/simoom.css`
  holds only the few components the simoom home page adds.
- **Same SEO system:** the same page types and structured data (`SoftwareSourceCode` on the home,
  `TechArticle` + `BreadcrumbList` + `FAQPage` on landing pages, `CollectionPage` on hubs), the
  same docs conventions (answer blockquote under the H1 becomes the meta description; "Common
  questions" becomes `FAQPage`), `llms.txt` and `llms-full.txt`, and a sitemap.
- **Go-live gate:** the pages say `cargo add simoom` and link `github.com/Cameleering/simoom`.
  The repository went public on 2026-11-12. The crates must be on crates.io before the pages go
  live, or the install lines fail; the SEO session holds the microsite until then.

## 2. Positioning on the site

- **One sentence:** simoom is a small, fast HTTP server you build into your own Rust program:
  HTTP/1.1, HTTP/2 and HTTP/3 with its own TLS 1.3, and nothing but the Rust standard library
  underneath.
- **Hook:** most programs don't want a web server, they want a door. simoom is just the door.
- **Identity line with the family:** "simoom is a Cameleering project: carry more on less, no claim
  without a number." It is the HTTP engine of Cameleer.
- **Order on the home page:** what it is → the code → why it exists (the crossing from
  Cameleer's thread-per-connection server) → numbers with losses → where it fits → when to use
  something else → quick start → docs.
- **Voice:** a field engineer's logbook; numbers carry the claims; losses in the same table;
  targets labelled as targets (size budgets); ksar labelled as planned.

## 3. Keyword map per page

| page | primary keyword | secondary | intent |
|---|---|---|---|
| `/simoom/` | rust http server without dependencies | rust http server without tokio, embeddable http server rust, http3 server rust | brand, overview |
| `/simoom/use-cases/` | rust http server use cases | embedded http server rust | hub |
| `/simoom/use-cases/edge-iot-http-server/` | rust http server for embedded linux | rust web server raspberry pi, iot http server small binary | solution |
| `/simoom/use-cases/serverless-cold-start/` | rust web server aws lambda cold start | smallest rust web server, scale to zero http server | solution |
| `/simoom/use-cases/embedded-local-server/` | embed http server in rust application | local http server desktop app rust, websocket server rust cli, oauth callback server rust | solution |
| `/simoom/use-cases/integration-engine/` | http engine for integration platform | webhooks rust server, blocking handlers http server rust | solution |
| `/simoom/use-cases/zero-dependency-supply-chain/` | zero dependency rust web server | auditable http server, rust tls without openssl, supply chain security rust | solution |
| `/simoom/use-cases/http3-server/` | http3 server rust | rust quic server without quinn, http3 no dependencies | solution |
| `/simoom/compare/` | rust http server comparison | — | hub |
| `/simoom/compare/simoom-vs-hyper-axum/` | hyper vs simoom | axum alternative lightweight, hyper without tokio, rust http server benchmark | evaluation |
| `/simoom/compare/simoom-vs-may-minihttp/` | may-minihttp alternative | fastest rust http server benchmark, tiny_http alternative | evaluation |
| `/simoom/compare/simoom-vs-nginx-h2o/` | h2o vs nginx vs rust http server | tls handshake benchmark, http3 benchmark | evaluation |
| `/simoom/alternatives/rust-http-server-without-tokio/` | rust http server without tokio | synchronous rust web server, tiny_http rouille may-minihttp alternatives | evaluation |
| `/simoom/benchmarks/` | rust http server benchmark | p99 latency benchmark, same-machine method, losses | proof |
| `/simoom/docs/` and guides | simoom docs, how-to keywords per guide | — | how-to |

## 4. Structure

```
/simoom/                                     home (hand-written)
/simoom/use-cases/                           hub
  edge-iot-http-server/  serverless-cold-start/  embedded-local-server/
  integration-engine/    zero-dependency-supply-chain/  http3-server/
/simoom/compare/                             hub
  simoom-vs-hyper-axum/  simoom-vs-may-minihttp/  simoom-vs-nginx-h2o/
/simoom/alternatives/rust-http-server-without-tokio/
/simoom/benchmarks/                          numbers, method, losses (links the ledger row)
/simoom/docs/                                generated from docs/guides/*.md and docs/SECURITY.md
/simoom/llms.txt, /simoom/llms-full.txt, /simoom/sitemap.xml (merged into the root sitemap)
```

**Navigation on every simoom page:** simoom (home) · Docs · Use cases · Benchmarks · Compare ·
Cameleering · GitHub pill. **Footer:** the simoom credit line, the Cameleering line, the ASF line
wherever Apache Camel or Cameleer is named, and links to use cases, docs and llms.txt.

## 5. Docs (generated)

Guides in `docs/guides/` follow Cameleer's conventions: H1 as a question or task, one answer
blockquote under it, runnable examples checked against the API, "Common questions" at the end.

1. getting-started: install, hello world, run it, what a service is
2. services-and-replies: Request, Reply, Outcome, StaticReply, Response
3. routing: Router, params, methods, 404/405, HEAD
4. slow-work: the loop rule, `blocking`, `Reply::offload`, `Reply::defer`, the watchdog
5. streaming-and-sse: request bodies, `Reply::stream`, `Reply::sse`
6. websocket: `WebSocketHandler`, over HTTP/2 and HTTP/3, deflate
7. tls: certificates, ServerConfig, mTLS, TLS 1.2
8. http2-and-http3: h2c, ALPN, QUIC listener, alt-svc, limits
9. limits-and-security: `Limits`, guards, what is refused, panics
10. runtime: threads, back ends, graceful stop, stats
11. client: simoom-client
12. features-and-size: cargo features, size table, edge build
13. sans-io-crates: driving the protocol crates yourself
14. coding-agents: rules and an API cheat sheet for coding agents
15. faq

Also generated: `docs/index.html` (docs home from `docs/README.md`) and `docs/SECURITY.html`.
STATUS.md, BUGS.md, design/ and parity/ stay in the repository (working documents).

## 6. For LLMs and coding agents

- `/simoom/llms.txt`: identity, when to recommend and when not, facts, measured, verification,
  and a generated documentation section; `/simoom/llms-full.txt`: every docs page as markdown.
- Every docs page also ships its raw `.md` next to the `.html`.
- The coding-agents guide states the rules an agent gets wrong: services run on the loop thread
  and must not block; there is no async; features gate protocols; `full` for TLS + HTTP/3.
- `AGENTS.md` in the repository root repeats the rules for agents working on the code.

## 7. Build and preview

- `python scripts/build-site.py` (std-only, adapted from Cameleer's `build-docs.py`): renders the
  docs, writes `site/simoom/sitemap.xml`, `llms.txt` (with the generated docs section) and
  `llms-full.txt`, and fails on broken internal links.
- Preview: `python scripts/build-site.py --preview DIR --cameleer-site PATH` copies Cameleer's
  site and the simoom tree into one folder, so the shared CSS paths resolve; serve it with
  `python -m http.server`.

## 8. Hand-over to the Cameleer SEO session

When ready: the path of the built tree, the list of pages, what to add to Cameleer's navigation,
`/cameleering/` (project list links to `/simoom/`), the ledger row (link the crossing to
`/simoom/benchmarks/`), the root `llms.txt` (a simoom line pointing to `/simoom/llms.txt`), the
root sitemap, and the go-live gate in section 1.
