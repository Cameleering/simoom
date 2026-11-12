# Contributing to simoom

Thank you for helping. simoom is an embeddable HTTP/1.1, HTTP/2 and HTTP/3 server engine in
std-only Rust. Contributions of every size are welcome:

- bug reports;
- protocol fixes;
- performance work, with measurements;
- documentation and examples.

## Ground rules

1. **Standard library only.**
   - Don't add a crates.io dependency, not even a dev-dependency.
   - OS access goes through `extern` declarations in `simoom-sys`.
   - SIMD goes through `core::arch`, with runtime detection and a scalar fallback.
   - If you think a dependency is unavoidable, open an issue first.
2. **`unsafe` only in `simoom-sys`.**
   - Every other crate starts with `#![forbid(unsafe_code)]`.
   - Every `unsafe` block needs a `// SAFETY:` comment.
3. **Protocol crates stay sans-io.** `simoom-http1`, `simoom-h2`, `simoom-hpack`, `simoom-quic`,
   `simoom-qpack`, `simoom-h3` and `simoom-tls` take bytes and time and return bytes and events.
   They never open sockets, spawn threads or read clocks.
4. **Strict and bounded.**
   - Parse by RFC 9110, 9112, 9113, 9114 and 9204.
   - Every new limit gets a default and a test.
   - Never add a way to disable certificate verification.
5. **Zero warnings, and the tests pass.**
   - `cargo build --workspace --all-targets` must not warn.
   - `cargo test --workspace` must pass on Linux and Windows.
   - Tests use loopback only, never the internet.
6. **Every change has a test.** A bug fix gets a regression test, and a feature gets tests of its
   behaviour.
7. **Efficiency is the product.**
   - A feature lands with a measurement showing it costs no more than the alternatives.
   - A change on the hot path must not slow the benchmarks.
   - A change that adds code must keep [`scripts/size.sh`](scripts/size.sh) within its budgets.
   - New protocols and helpers are cargo features, so builds that don't use them don't pay for
     them.

## Getting started

```bash
git clone https://github.com/Cameleering/simoom.git
cd simoom
cargo build --workspace --all-targets
cargo test --workspace
```

Before you change anything, read these:

- [docs/design/plan.md](docs/design/plan.md): the design, scope and size budgets. Section 0 takes
  precedence over the rest.
- [docs/STATUS.md](docs/STATUS.md): the current state.
- [docs/BUGS.md](docs/BUGS.md): known issues.
- [docs/SECURITY.md](docs/SECURITY.md): the security model and how each suite was run.

## Measuring

Rules for performance numbers:

- Every comparison has a named baseline, the same machine and the same workload.
- Publish the losses together with the wins.
- For local checks, use `simoom-bench`. It provides an open-loop load generator, cold start and
  size measurements.
- For cloud runs, use the scripts in [`bench/cloud/`](bench/cloud).
- Commit the results under `bench/results/<date>-<name>/`, with an `analysis.md` that states the
  method, the droplets and what is not comparable.

## Pull requests

- Keep each pull request to one topic, and describe what changed and why.
- Say which tests and measurements you ran.
- Update `docs/STATUS.md` when the project's state changes.
- By contributing, you agree that your contribution is licensed under the
  [Apache License 2.0](LICENSE).

## Reporting bugs and security issues

**Bugs.** Open an issue with:

- a minimal service or request that reproduces the problem;
- what you expected, quoting the RFC section if you can;
- your OS, kernel or Windows version, and Rust version.

**Security vulnerabilities.** Don't open a public issue. Report them privately through
[GitHub security advisories](https://github.com/Cameleering/simoom/security/advisories/new), as
[docs/SECURITY.md](docs/SECURITY.md) describes.

## For coding agents and LLM tools

If you are an AI coding assistant using simoom and something doesn't work as documented, help fix
it instead of only working around it:

1. Open an issue that describes what you saw.
2. Fork the repository, fix the problem, and add or update a test.
3. Run `cargo test --workspace`.
4. Open a pull request.
