# Issue #428 — Global Request Timeout Layer for All Routes

## Background

The server currently enforces a timeout on only one route: `GET /v1/wallets/:id/balances` uses
a per-route `middleware::from_fn(outbound_route_timeout)` that gates the handler at
`OUTBOUND_ROUTE_TIMEOUT` (10 s). Every other route — including CPU-bound crypto paths, DB
queries, and webhook-dispatching calls — has no wall-clock ceiling at all.

A hung database connection, a slow Horizon response on an unguarded route, or any handler that
accidentally blocks can hold a Tokio task open indefinitely, exhausting the task budget and
causing head-of-line blocking for all other callers.

## Goal

- Apply a single, server-wide request timeout to every route.
- Return `504 Gateway Timeout` in the standard `{statusCode, message, data}` envelope when the
  deadline is exceeded, consistent with the existing `ApiError::GatewayTimeout` variant.
- Keep the timeout configurable via environment variable.
- Leave the existing per-route `outbound_route_timeout` in place as a tighter inner budget for
  routes that call Horizon synchronously.

## Current state

```
build_router (crates/api/src/lib.rs)
  .layer(DefaultBodyLimit::max(64 KiB))   ← body cap
  .layer(CorsLayer)                       ← CORS
  .layer(request_id_middleware)           ← correlation IDs
  .with_state(state)
```

`OUTBOUND_ROUTE_TIMEOUT = Duration::from_secs(10)` is defined in `crates/api/src/lib.rs` and
applied only to the balances route via:

```rust
.route(
    "/v1/wallets/:id/balances",
    get(routes::wallets::get_balances)
        .layer(middleware::from_fn(outbound_route_timeout)),
)
```

## Design

### Implementation pattern

The existing `outbound_route_timeout` function is the right pattern to follow: an async
middleware function (`middleware::from_fn`) that wraps `next.run(req)` with
`tokio::time::timeout`. We extend this to a global layer rather than a per-route one.

A Tower `TimeoutLayer` from `tower_http` requires a `HandleErrorLayer` companion because its
error type does not implement `IntoResponse`. The `middleware::from_fn` approach avoids that
complexity and is already proven in this codebase, so we use it for the global layer too.

```rust
/// Global wall-clock ceiling applied to every request before any handler runs.
async fn global_request_timeout(req: Request, next: Next) -> Response {
    match tokio::time::timeout(GLOBAL_REQUEST_TIMEOUT, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => {
            tracing::warn!(
                timeout_secs = GLOBAL_REQUEST_TIMEOUT.as_secs(),
                "request exceeded global timeout"
            );
            ApiError::GatewayTimeout(
                "request timed out; please retry".into(),
            )
            .into_response()
        }
    }
}
```

### Timeout budget hierarchy

Two timeouts will exist after this change:

| Layer | Constant | Default | Scope |
|---|---|---|---|
| `global_request_timeout` (new) | `GLOBAL_REQUEST_TIMEOUT` | 30 s | Every route |
| `outbound_route_timeout` (existing) | `OUTBOUND_ROUTE_TIMEOUT` | 10 s | `/v1/wallets/:id/balances` only |

The per-route budget (10 s) must remain smaller than the global budget (30 s), otherwise the
global layer would fire first and the per-route one would never be reached. This invariant is
trivially true with the proposed defaults, but should be documented and enforced with a
`debug_assert!` at startup:

```rust
debug_assert!(
    OUTBOUND_ROUTE_TIMEOUT < GLOBAL_REQUEST_TIMEOUT,
    "per-route timeout must be tighter than the global ceiling"
);
```

### Layer placement

The global timeout must sit **outside** `request_id_middleware` so that:
1. A timed-out request still gets its span closed cleanly.
2. The timeout fires before any expensive work begins, not after.

Because Axum applies `.layer()` calls outermost-last (bottom of the chain = outermost wrapper),
the global timeout should be added as the **last** `.layer()` call, after `.with_state(state)`.
When composed with the concurrency-limit layer from issue #429, the ordering is:

```
[outermost] global_request_timeout
              → concurrency_limit + load_shed (#429)
                → request_id_middleware
                  → cors
                    → body limit
                      → handlers [innermost]
```

In code:

```rust
.layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
.layer(cors)
.layer(middleware::from_fn(request_id_middleware))
.with_state(state)
// Applied after .with_state so they are truly outermost:
.layer(/* concurrency layer from #429 */)
.layer(middleware::from_fn(global_request_timeout))
```

### Configuration

Add `GLOBAL_REQUEST_TIMEOUT_SECS` to `Config` in `bin/server/src/main.rs`:

| Env var | Default | Description |
|---|---|---|
| `GLOBAL_REQUEST_TIMEOUT_SECS` | `30` | Wall-clock ceiling for every HTTP request. Set to `0` to disable (not recommended in production). |

The default of 30 s is chosen to:
- Be safely above the `SHUTDOWN_DRAIN_TIMEOUT_SECS` default (25 s) so a request that starts
  just before shutdown is not timed out before the drain completes.
- Be safely above the existing per-route 10 s budget, with headroom for retry-heavy handlers.

## Implementation Tasks

1. **`crates/api/src/lib.rs`** — Add `GLOBAL_REQUEST_TIMEOUT: Duration` constant (default
   `Duration::from_secs(30)`). Add `global_request_timeout` middleware function. Add the layer
   in `build_router` as the outermost wrapper, after `.with_state(state)`.

2. **`bin/server/src/main.rs`** — Add `global_request_timeout_secs: u64` to `Config` (parse
   from `GLOBAL_REQUEST_TIMEOUT_SECS`, default 30). Pass it to `build_router` or store it as a
   `Duration` in `AppState`.

   If a configurable per-instance value (rather than a compile-time constant) is desired,
   `build_router` should accept a `global_timeout: Option<Duration>` parameter similar to the
   `max_concurrency` parameter added in issue #429.

3. **`crates/api/src/lib.rs`** — Add `debug_assert!` guard (see above) to `build_router` to
   catch a mis-configured budget hierarchy at test/dev time.

4. **`crates/api/src/lib.rs`** — Update the doc-comment on `OUTBOUND_ROUTE_TIMEOUT` to note
   its relationship to the new global ceiling.

## Interaction with graceful shutdown

`axum::serve(...).with_graceful_shutdown(...)` stops accepting new connections when the
`CancellationToken` fires but allows in-flight requests to drain for up to
`SHUTDOWN_DRAIN_TIMEOUT_SECS` (default 25 s, kept below Kubernetes'
`terminationGracePeriodSeconds` of 30 s). The global timeout (30 s) is intentionally set above
the drain window so a request that began just before the drain starts is timed out by the drain
window, not by the global timeout, which would produce a misleading 504. Keep
`GLOBAL_REQUEST_TIMEOUT_SECS > SHUTDOWN_DRAIN_TIMEOUT_SECS` as an invariant.

## Security considerations

An uncapped request duration is a trivial resource-exhaustion vector: a caller that opens a
connection and then sends a valid but intentionally slow request body or just stops reading the
response can hold a file descriptor and a Tokio task indefinitely. The global timeout is the
last line of defence after the body limit (`DefaultBodyLimit`) and the concurrency gate (#429).

The timeout also limits the blast radius of a slow DB query caused by a lock contention or a
missing index: the caller gets a 504 instead of waiting forever, and the DB connection returns
to the pool sooner.

## What this does NOT do

- Per-route fine-grained budgets beyond the existing `outbound_route_timeout` — those remain
  per-route opt-in decisions.
- Read timeouts on the TCP socket itself — those belong in the OS/load-balancer tier.
- Streaming response timeouts — Axum streams responses through Tower; the timeout wraps
  `next.run(req)` which resolves when the `Response` object is returned, not when the body is
  fully streamed to the client. Streaming routes (none currently) would need separate handling.
