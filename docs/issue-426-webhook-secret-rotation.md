# Issue #426 — Webhook Secret Rotation with an Overlap Window

## Background

When a merchant rotates a webhook secret — whether as a routine security practice or after a
suspected exposure — there is an unavoidable gap between the moment Octo starts signing with
the new secret and the moment the merchant's server has deployed code that verifies against it.
Any delivery that arrives in that gap will fail HMAC verification and the merchant's endpoint
will return an error.

Today there is no rotation mechanism at all. The only option is to delete the endpoint and
recreate it, which drops all delivery history and causes failures for all in-flight deliveries.

The overlap window solves this: after a rotation Octo continues to accept (for a configurable
grace period) responses that could have been signed by the previous secret, giving the merchant
time to update their verification code without dropping legitimate deliveries.

### Key facts from the current codebase

- `WebhookEndpoint` model (`crates/store/src/models.rs`): fields are `id`, `wallet_id`, `url`,
  `secret`, `active`, `created_at`, `deleted_at`. No `previous_secret`, no rotation timestamp.
- Signing (`crates/webhooks/src/sign.rs`): `sign(secret, body)` → HMAC-SHA256 hex. `verify(secret, body, sig)` uses constant-time comparison via the `subtle` crate. Both primitives exist and are correct.
- Delivery (`crates/webhooks/src/lib.rs`, `deliver_with_retry`): signs **once** before the
  retry loop with the current `ep.secret`. The same signature is reused across all retry
  attempts within one delivery job — this is fine because a job is short-lived (≤ 20 s total
  deadline).
- The `sign::verify` function exists but is currently unused on the server side (Octo only
  sends, it does not receive inbound signed webhooks). It is the correct primitive for any
  future dual-secret acceptance logic.

## Goal

- Add a `POST /v1/wallets/:id/webhooks/:endpoint_id/rotate-secret` endpoint that:
  - Generates a new secret (or accepts a caller-supplied one).
  - Stores the current secret as `previous_secret`.
  - Replaces `secret` with the new one.
  - Records `secret_expires_at` — the time at which `previous_secret` stops being accepted.
- During the overlap window, `WebhookSender` signs with the **new** `secret` only (delivery is
  authoritative; the merchant must migrate to verifying with the new key).
- After `secret_expires_at`, `previous_secret` is ignored and can be cleared.
- The overlap window duration is configurable and defaults to 24 hours.

## Design

### Schema changes

```sql
-- Migration: add rotation fields
ALTER TABLE webhook_endpoints
    ADD COLUMN previous_secret      TEXT,
    ADD COLUMN previous_sealed_secret TEXT,          -- encrypted form (see issue #427)
    ADD COLUMN secret_expires_at    TIMESTAMPTZ;     -- when previous_secret stops being valid
```

`previous_secret` / `previous_sealed_secret` mirror the `secret` / `sealed_secret` split
introduced in issue #427. Both columns are `NULL` when no rotation is in progress or the
overlap window has expired.

`secret_expires_at` is `NULL` when there is no active rotation window.

### `WebhookEndpoint` model

```rust
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub url: String,
    pub secret: String,                          // current secret (plaintext after decrypt)
    pub previous_secret: Option<String>,         // previous secret, valid until secret_expires_at
    pub secret_expires_at: Option<DateTime<Utc>>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}
```

### New route: `POST /v1/wallets/:id/webhooks/:endpoint_id/rotate-secret`

**Auth:** same `authorize_wallet` guard as all other webhook routes.

**Request body:**

```json
{
  "secret": "<optional — if omitted, a new secret is generated>",
  "overlap_seconds": 86400
}
```

`overlap_seconds` defaults to `DEFAULT_ROTATION_OVERLAP_SECS` (86 400 = 24 h). It must be in
the range `[60, 604800]` (1 minute to 7 days); values outside this range return `400`.

**Response (200 OK):**

```json
{
  "statusCode": 200,
  "message": "OK",
  "data": {
    "id": "<endpoint_id>",
    "new_secret": "<new plaintext secret>",
    "previous_secret_expires_at": "<ISO-8601 timestamp>"
  }
}
```

The new secret is returned once so the merchant can update their verification code. The
previous secret is not returned (it was already visible on creation; this response does not
re-expose it).

**Store operation:**

```rust
pub async fn rotate_webhook_secret(
    &self,
    endpoint_id: Uuid,
    new_secret: &str,
    expires_at: DateTime<Utc>,
) -> Result<WebhookEndpoint, StoreError> {
    // Atomically: previous_secret = secret, secret = new_secret, secret_expires_at = expires_at
    sqlx::query_as::<_, WebhookEndpoint>(
        r#"
        UPDATE webhook_endpoints
        SET previous_secret   = secret,
            secret            = $2,
            secret_expires_at = $3
        WHERE id = $1
          AND deleted_at IS NULL
        RETURNING *
        "#,
    )
    .bind(endpoint_id)
    .bind(new_secret)
    .bind(expires_at)
    .fetch_optional(&self.pool)
    .await?
    .ok_or(StoreError::NotFound)
}
```

When issue #427 (encryption at rest) is also implemented, the store method seals both
`new_secret` → `sealed_secret` and the old `secret` → `previous_sealed_secret` before
updating. The `secret` and `previous_secret` columns become legacy-only fallbacks during the
transition.

### Signing during the overlap window

`WebhookSender.deliver_with_retry` signs with `ep.secret` (the new key) only. Octo's outbound
deliveries are always signed with the current key — it is the merchant's server that must be
updated to accept the new key. The overlap window is for the merchant, not for Octo.

No changes are needed to `deliver_with_retry` for the overlap window to work.

### Clearing expired previous secrets (background sweep)

Add a periodic sweep to `bin/server/src/main.rs` alongside the existing stale-sponsorship
reconciler:

```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        match sweep_store.clear_expired_webhook_previous_secrets().await {
            Ok(n) if n > 0 => tracing::info!(count = n, "cleared expired webhook previous secrets"),
            Err(e) => tracing::warn!(error = ?e, "failed to clear expired webhook previous secrets"),
            _ => {}
        }
    }
});
```

Store method:

```rust
pub async fn clear_expired_webhook_previous_secrets(&self) -> Result<u64, StoreError> {
    let result = sqlx::query(
        r#"
        UPDATE webhook_endpoints
        SET previous_secret   = NULL,
            secret_expires_at = NULL
        WHERE secret_expires_at < now()
          AND previous_secret IS NOT NULL
        "#,
    )
    .execute(&self.pool)
    .await?;
    Ok(result.rows_affected())
}
```

The sweep runs hourly; the overlap window minimum (60 s) is much shorter than that, so very
short windows expire in the DB but are only cleared on the next hourly tick. That is fine —
the `secret_expires_at` timestamp is the authoritative guard in any consumer that checks it.

### Audit log

Rotation is a security-relevant event. Call `store.log_audit_event` (or the equivalent) from
the route handler after a successful rotation:

```
action:   "webhook_secret_rotated"
category: "security"
target:   endpoint_id.to_string()
```

This follows the existing audit pattern visible in other routes.

## Overlap window: what it means for the merchant

The merchant's verification code should, during the window, try the new secret first and then
the previous secret if the first fails:

```python
# Pseudocode — merchant side
def verify(body, sig, new_secret, old_secret):
    if hmac_verify(new_secret, body, sig):
        return True
    if old_secret and hmac_verify(old_secret, body, sig):
        return True
    return False
```

Octo signs only with the new key. If a delivery arrives before the merchant has deployed the
new key, the merchant's endpoint will fail to verify with the new key, then succeed with the
old key. After the merchant deploys, both paths pass (new key first). After `secret_expires_at`
the old key should be removed from the merchant's code.

This logic lives entirely on the merchant side; Octo does not expose `previous_secret` over
the API after the rotation call returns.

## Implementation Tasks

1. **`crates/store/migrations/`** — Add migration: `ALTER TABLE webhook_endpoints ADD COLUMN
   previous_secret TEXT, ADD COLUMN previous_sealed_secret TEXT, ADD COLUMN
   secret_expires_at TIMESTAMPTZ`.

2. **`crates/store/src/models.rs`** — Add `previous_secret: Option<String>` and
   `secret_expires_at: Option<DateTime<Utc>>` to `WebhookEndpoint`.

3. **`crates/store/src/lib.rs`** — Add `rotate_webhook_secret` and
   `clear_expired_webhook_previous_secrets` methods.

4. **`crates/api/src/routes/webhooks.rs`** — Add `rotate_secret` handler; add
   `RotateSecretRequest` / `RotateSecretView` structs; register the route in `build_router`.

5. **`crates/api/src/lib.rs`** — Register:
   ```rust
   .route(
       "/v1/wallets/:id/webhooks/:endpoint_id/rotate-secret",
       post(routes::webhooks::rotate_secret),
   )
   ```

6. **`bin/server/src/main.rs`** — Add hourly sweep task calling
   `clear_expired_webhook_previous_secrets`.

7. **`crates/api/src/routes/webhooks.rs`** — Add audit log call in `rotate_secret` handler.

## Constants

Add to `crates/api/src/routes/webhooks.rs` (or a shared webhooks config):

```rust
/// Default overlap window for secret rotation.
pub const DEFAULT_ROTATION_OVERLAP_SECS: u64 = 86_400; // 24 h

/// Allowed range for caller-supplied overlap windows.
pub const MIN_ROTATION_OVERLAP_SECS: u64 = 60;        // 1 min
pub const MAX_ROTATION_OVERLAP_SECS: u64 = 604_800;   // 7 days
```

## Dependency on issue #427

This issue is independent of issue #427 (encrypt at rest) and can be implemented and deployed
first. The rotation endpoint writes the new secret to the `secret` column in plaintext — the
same as the existing `create_webhook_endpoint`. When issue #427 lands, it extends the write
path to also populate `sealed_secret` / `previous_sealed_secret`, and the column fall-back
logic handles the transition transparently.

## Security considerations

- **New secret entropy** — Use the same `generate_secret()` as `create_webhook`: two
  concatenated UUIDv4 hex strings (64 hex chars, 244 bits of entropy). Caller-supplied secrets
  are accepted but not constrained beyond being non-empty; consider enforcing a minimum length
  (e.g., 32 bytes) to prevent weak secrets.
- **Previous secret exposure** — `previous_secret` is never returned in API responses after the
  initial rotation call. It is a transient DB field that exists only to give the merchant's
  server time to redeploy.
- **Replay attack window** — The overlap window is a deliberate trade-off: for its duration, a
  stolen previous secret can still be used to forge a signature that passes the merchant's
  dual-verify code. Keep the window as short as the merchant's deployment cycle allows. The
  7-day maximum is a hard cap.
- **Race condition** — `rotate_webhook_secret` is a single atomic `UPDATE … RETURNING`, so
  concurrent rotation calls on the same endpoint are serialised by Postgres row-level locking.
  The last writer wins; both new secrets will have been returned to their respective callers.
  This is acceptable — if two callers race, both received a valid new secret and the merchant
  needs to use whichever one landed.
- **Audit trail** — Every rotation is recorded in the audit log so suspicious rotation
  frequency is detectable.
