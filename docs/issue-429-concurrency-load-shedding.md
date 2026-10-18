# Issue #429 — Concurrency Limit and Load Shedding for the HTTP Server

## Background

The Axum server (`bin/server/src/main.rs`) currently has no upper bound on the number of
requests it will accept and process simultaneously. Under a traffic spike or a slow-upstream
event (e.g., Horizon latency), goroutine-equivalent Tokio tasks accumulate unbounded, memory
pressure rises, and the server degrades globally rather than shedding excess load fast and
staying healthy for requests it can actually service.

The existing middleware stack in `crates/api/src/lib.rs → build_router` already applies:
- `DefaultBodyLimit::max(REQUEST_BODY_LIMIT)` — 64 KiB body cap
- `CorsLayer` — broad CORS
- `middleware::from_fn(request_id_middleware)` — correlation IDs

There is no concurrency gate anywhere in this stack today.

## Goal

- Hard-limit the number of requests being processed concurrently across the entire server.
- Reject (not queue) requests that arrive when the server is at capacity with a fast `503
  Service Unavailable` in the standard `{statusCode, message, data}` envelope.
- Keep the configuration observable and tunable via environment variable.

## Design

### Layer choice

Tower ships a first-party `tower::limit::ConcurrencyLimitLayer` that wraps any `Service` and
tracks in-flight calls with an `Arc<Semaphore>`. When the semaphore is at capacity it returns
`tower::load_shed` errors rather than blocking. We combine it with
`tower::load_shed::LoadShedLayer`, which converts the "at capacity" poll into an immediate
`Overloaded` error rather than back-pressure (back-pressure would block the Tokio task calling
`poll_ready`, which is the wrong behaviour for HTTP).

`ConcurrencyLimitLayer` + `LoadShedLayer` is the idiomatic Tower pair for this.

```
[request in]
  → LoadShedLayer          ← shed immediately when next layer isn't ready
    → ConcurrencyLimitLayer ← gate: at most N in-flight at once
      → existing middleware stack (request_id → CORS → body limit → handlers)
```

### Error mapping

`LoadShedLayer` produces a `BoxError` whose source is `tower::load_shed::error::Overloaded`.
Axum cannot convert that to a `Response` automatically, so we need a `HandleErrorLayer` sitting
outside `LoadShedLayer` that maps the error to a `503` envelope before Axum ever sees it.

```rust
ServiceBuilder::new()
    .layer(HandleErrorLayer::new(handle_overload))
    .layer(LoadShedLayer::new())
    .layer(ConcurrencyLimitLayer::new(max_concurrency))
```

`handle_overload` returns the standard error envelope:

```rust
async fn handle_overload(_err: BoxError) -> Response {
    ApiError::TooManyRequests("server is at capacity; please retry".into()).into_response()
}
```

`ApiError::TooManyRequests` already exists in `crates/api/src/error.rs` and maps to `429`.
`503` is semantically more accurate for load shedding (the server is temporarily overloaded,
not the client sending too many requests), so a new `ApiError::ServiceUnavailable(String)`
variant is preferred. See the implementation tasks below.

### Configuration

Add `MAX_CONCURRENT_REQUESTS` to `Config` in `bin/server/src/main.rs`:

| Env var | Default | Description |
|---|---|---|
| `MAX_CONCURRENT_REQUESTS` | `1024` | Maximum simultaneous in-flight HTTP requests. `0` disables the limit. |

The default of 1 024 is intentionally generous; it is a safety ceiling, not a target operating
point. Operators should tune it based on observed `p99` concurrency under normal load.

### Placement in `build_router`

Because Axum evaluates `.layer()` calls from bottom to top (the last call is the outermost
wrapper), the concurrency gate must be added **after** `.with_state(state)`:

```rust
// crates/api/src/lib.rs — build_router, at the bottom
.layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
.layer(cors)
.layer(middleware::from_fn(request_id_middleware))
.with_state(state)
// Outermost: shed before request_id_middleware so a shed request never enters the span.
// Passed in from AppState or as a plain usize from the caller.
```

`build_router` currently takes `AppState`. The concurrency limit is an operational parameter,
not a domain secret, so it should be passed separately:

```rust
pub fn build_router(state: AppState, max_concurrency: Option<usize>) -> Router
```

`None` means "no limit" (the default during tests and local dev where `MAX_CONCURRENT_REQUESTS`
is not set).

### Where the layer goes relative to request_id_middleware

The concurrency gate sits **outside** `request_id_middleware`. This is intentional: a shed
request should not consume a Tokio span or a UUID allocation. The correlation-ID header in the
`503` response will be absent, which is acceptable — the client can use its own retry logic.

## Implementation Tasks

1. **`crates/api/src/error.rs`** — Add `ApiError::ServiceUnavailable(String)` variant mapping
   to `StatusCode::SERVICE_UNAVAILABLE` (503).

2. **`crates/api/src/lib.rs`** — Add `tower` and `tower-http` (already a dependency) imports
   for `ConcurrencyLimitLayer`, `LoadShedLayer`, `HandleErrorLayer`. Add the layer stack in
   `build_router` behind the `max_concurrency: Option<usize>` parameter. Add a
   `handle_overload` helper returning a `503` envelope.

3. **`bin/server/src/main.rs`** — Add `MAX_CONCURRENT_REQUESTS: usize` field to `Config`
   (parse from env, default `1024`). Pass it to `build_router`.

4. **`crates/api/src/lib.rs`** — Add a constant `DEFAULT_MAX_CONCURRENT_REQUESTS: usize =
   1024` next to `REQUEST_BODY_LIMIT` and `OUTBOUND_ROUTE_TIMEOUT`.

## Cargo dependencies

`tower` (with `limit` and `load-shed` features) is a transitive dependency already present via
`axum`. Confirm it is available with the required features by checking `Cargo.lock` before
adding an explicit dependency entry; if the features are not activated, add:

```toml
# crates/api/Cargo.toml
tower = { version = "0.4", features = ["limit", "load-shed", "util"] }
```

## Observability

The `503` response is returned before `request_id_middleware` runs, so no span is opened.
Log a `tracing::warn!` in `handle_overload` with a `concurrency_limit` field so the shed rate
is visible in structured logs without needing a metrics backend:

```rust
tracing::warn!(concurrency_limit = limit, "request shed: server at capacity");
```

## Security considerations

Load shedding reduces the attack surface of resource-exhaustion DoS: an attacker who floods the
server with slow requests to occupy all workers and deny service to legitimate callers will
instead receive fast `503`s once the semaphore fills. The semaphore is shared across all
routes — there is no per-IP fairness built in here; that is the responsibility of the existing
`RateLimiter` (`crates/api/src/rate_limit.rs`), which operates at the handler level.

## What this does NOT do

- Per-IP or per-wallet concurrency limits — still handled by `RateLimiter`.
- Queue-and-drain (requests are rejected immediately, never parked).
- Adaptive concurrency control (AIMD or similar) — a fixed ceiling is simpler and predictable.
