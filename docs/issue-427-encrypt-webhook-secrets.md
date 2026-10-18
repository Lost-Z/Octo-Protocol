# Issue #427 — Encrypt Webhook Endpoint Secrets at Rest

## Background

Webhook endpoint secrets are HMAC-SHA256 keys used to authenticate every outbound delivery from
Octo to a merchant's server. A recipient verifies the `X-Octo-Signature` header against the
received body using their copy of the secret.

Currently the `secret` column of `webhook_endpoints` is a plaintext `TEXT` field written
directly by `store.create_webhook_endpoint(wallet_id, &url, &secret)` and read back with no
transformation by `WebhookSender.deliver_with_retry`. Anyone with read access to the database
— a compromised read replica, a leaked backup, a misconfigured monitoring tool — can obtain
every secret and forge arbitrary webhook deliveries against every registered merchant endpoint.

### Contrast with how API keys are stored

The `ApiKey` model stores only `prefix` (display) and `key_hash` (SHA-256 hex). The raw key is
never persisted. That is not directly applicable to webhook secrets because the raw secret must
be recovered for signing: unlike API keys, which are verified by hashing the inbound value and
comparing against the stored hash, webhook secrets are used as an HMAC key — we must be able
to read the plaintext back to produce a signature.

### Existing encryption infrastructure

`crates/wallet_core` (and the key-sealing layer described in `docs/runbook-migrate-keys.md`)
uses `MASTER_KEY` — a 32-byte AES-256-GCM key provided via environment variable. `AppState`
already holds this key (`master_key: [u8; 32]`) and exposes it to any code with access to
state. The same AES-256-GCM sealing scheme used for HD seeds is the right primitive to reuse
here: it is already audited, already in the codebase, and already supports zero-downtime key
rotation via `MASTER_KEY_NEXT`.

## Goal

- Encrypt webhook secrets at rest using AES-256-GCM under `MASTER_KEY` before writing to the
  DB, and decrypt transparently on read.
- Callers (route handlers, `WebhookSender`) interact with the plaintext secret only — the
  encryption boundary sits entirely inside the `Store`.
- Support zero-downtime key rotation: rows sealed under the old key continue to work while
  `octo-migrate-keys` re-seals them.

## Design

### Sealed representation

The existing wallet-seed sealing scheme (`crates/wallet_core`) produces a versioned, opaque
blob stored as `TEXT` (base64 or hex-encoded). We adopt the same envelope for webhook secrets:

```
sealed_secret = base64( version_byte || nonce_12 || ciphertext || tag_16 )
```

- `version_byte`: scheme version (`0x01` = AES-256-GCM with 12-byte nonce), matching the
  existing `sealed_scheme` convention so `octo-migrate-keys` can handle these rows.
- `nonce_12`: random 12-byte nonce, generated fresh per encryption.
- `ciphertext || tag_16`: AES-256-GCM output over the plaintext secret bytes.

The additional-data (AAD) field should bind the ciphertext to its row: use the endpoint's UUID
as AAD (`aad = endpoint_id.as_bytes()`). This prevents a ciphertext from one row being
transplanted into another row to impersonate a different endpoint's secret.

### Schema change

Add a `sealed_secret` column alongside (not replacing) `secret` during migration. Once all rows
are backfilled and the deployment is confirmed healthy, `secret` can be dropped in a follow-up
migration. This two-step approach avoids a hard cut-over that would break an in-flight
deployment.

```sql
-- Migration: add sealed_secret column
ALTER TABLE webhook_endpoints
    ADD COLUMN sealed_secret TEXT;

-- After backfill is complete (separate migration or runbook step):
-- ALTER TABLE webhook_endpoints DROP COLUMN secret;
```

During the transition window, the read path should prefer `sealed_secret` if present and fall
back to `secret`:

```rust
fn decrypt_secret(row: &WebhookEndpointRow, master_key: &[u8; 32]) -> Result<String, StoreError> {
    if let Some(sealed) = &row.sealed_secret {
        // Decrypt via the existing sealing library.
        octo_wallet_core::unseal(sealed, master_key, row.id.as_bytes())
            .map_err(|_| StoreError::DecryptionFailed)
    } else {
        // Legacy plaintext row, still valid until backfill.
        Ok(row.secret.clone())
    }
}
```

The write path always writes `sealed_secret` (never `secret`) for new rows created after the
migration lands.

### `WebhookEndpoint` model

The model in `crates/store/src/models.rs` currently exposes `secret: String` (the raw
plaintext). After this change:

- `secret` in the model becomes the **decrypted** plaintext, populated by the store layer on
  read — callers never change.
- `sealed_secret: Option<String>` is a raw DB field used only inside the store; it should be
  `pub(crate)` or kept in a separate `WebhookEndpointRow` internal struct that is never exposed
  outside the store crate.

Keeping the public API of `WebhookEndpoint.secret` as plaintext means zero changes to
`WebhookSender`, `routes/webhooks.rs`, or any other consumer.

### Store API changes

`create_webhook_endpoint` receives the plaintext secret from the caller and must encrypt before
inserting:

```rust
pub async fn create_webhook_endpoint(
    &self,
    wallet_id: Uuid,
    url: &str,
    secret: &str,
) -> Result<WebhookEndpoint, StoreError> {
    let sealed = seal_secret(secret, &self.master_key, endpoint_id)?;
    // INSERT sealed_secret = $sealed, secret = '' (or omit if column is nullable).
}
```

The store holds a copy of `master_key: [u8; 32]` (already available via `AppState`; pass it in
at `Store::connect` time or via a `Store::with_master_key` builder, consistent with how
`AppState` exposes it today).

`active_webhook_endpoints`, `get_webhook_endpoint`, and `list_webhooks` all return
`Vec<WebhookEndpoint>` — each row goes through `decrypt_secret` before the `WebhookEndpoint`
struct is constructed.

### Returning the secret in API responses

`list_webhooks` currently returns the full plaintext `secret` in every response. This is a
separate concern from encryption at rest, but worth noting: once encrypted at rest, the
plaintext is still being transmitted over TLS to clients on every list call. The appropriate
long-term posture is to return the secret only on creation (already done) and mask it on
subsequent reads. That change is out of scope for this issue but should follow.

### Key rotation compatibility

The `sealed_scheme` column on `wallets` is how `octo-migrate-keys` identifies which key a row
was sealed under. For webhook secrets, introduce the same field:

```sql
ALTER TABLE webhook_endpoints
    ADD COLUMN sealed_scheme TEXT NOT NULL DEFAULT 'v1';
```

`octo-migrate-keys` iterates over all `wallets` rows today. Extend it to also re-seal
`webhook_endpoints.sealed_secret` rows using the same logic.

## Migration sequence

1. Deploy the migration that adds `sealed_secret` (and `sealed_scheme`) columns.
2. Deploy server code that writes `sealed_secret` for new rows and reads both columns.
3. Run a backfill script (or extend `octo-migrate-keys`) that reads each plaintext `secret`,
   encrypts it, writes to `sealed_secret`.
4. Verify no `sealed_secret IS NULL` rows remain.
5. Deploy a follow-up migration that drops the `secret` column (or makes it a tombstone empty
   string that is no longer read).

Steps 1–4 are safe to roll back. Step 5 is irreversible — take a backup before deploying it.

## Implementation Tasks

1. **`crates/store/migrations/`** — Add migration: `ALTER TABLE webhook_endpoints ADD COLUMN
   sealed_secret TEXT, ADD COLUMN sealed_scheme TEXT NOT NULL DEFAULT 'v1'`.

2. **`crates/store/src/models.rs`** — Add internal `WebhookEndpointRow` struct with the raw DB
   columns including `sealed_secret`. Keep the public `WebhookEndpoint` with a plaintext
   `secret: String`. Alternatively keep the existing struct and add `pub(crate) sealed_secret:
   Option<String>`.

3. **`crates/store/src/lib.rs`** — Add `master_key: [u8; 32]` field to `Store`. Implement
   `seal_secret` and `decrypt_secret` helpers (or call the existing wallet_core sealing
   primitives). Update `create_webhook_endpoint` to encrypt on write; update all read methods
   to decrypt on read.

4. **`crates/store/src/lib.rs` / `bin/server/src/main.rs`** — Thread `master_key` into
   `Store::connect` or add a `Store::with_master_key` builder so the store has access to the
   key without reaching into `AppState`.

5. **`bin/migrate-keys` (or a new backfill script)** — Add a pass over `webhook_endpoints` to
   re-seal plaintext `secret` rows into `sealed_secret`.

## Security considerations

- **AAD binding** — using `endpoint_id` as additional authenticated data means a ciphertext
  moved to a different row will fail to decrypt. This is a cheap defence against database-level
  row swapping.
- **Nonce uniqueness** — AES-256-GCM requires nonces to be unique per (key, message) pair. A
  random 12-byte nonce gives a negligible collision probability for the number of webhook
  endpoints this service will ever have (well below the 2^32 birthday bound).
- **Secret still returned in API responses** — encryption at rest protects against DB read
  access. It does not protect against an authenticated API caller listing their own secrets.
  Masking on list is a recommended follow-up (see above).
- **Backup encryption** — DB backups captured before this change contain plaintext secrets.
  Those backups should be treated as sensitive and rotated (or the secrets they contain
  invalidated) after the migration is confirmed complete.
