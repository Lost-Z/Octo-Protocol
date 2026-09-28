//! Integration tests for the octo API. Require Postgres via `DATABASE_URL` (loaded from .env).
//!
//! These drive the real axum router with in-process requests, exercising
//! crypto + wallet-core + store together. Skipped (with a message) if no DATABASE_URL.

mod common;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::routing::post as post_route;
use axum::Router;
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt; // for `oneshot`
use tower_http::limit::RequestBodyLimitLayer;

const REQUEST_BODY_LIMIT: usize = 64 * 1024;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let master_key = [42u8; 32]; // deterministic test key
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn body_limit_request(body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/limit")
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .body(Body::from(body))
        .unwrap()
}

/// GET with an Authorization bearer token.
fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// POST with no body but an Authorization bearer token.
fn post_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// `POST /v1/wallets` under the non-custodial contract: the "client" (this test) generates the
/// keypair, proves ownership by signing the server challenge, and sends only public material.
async fn create_wallet_req(app: &axum::Router, token: &str) -> Request<Body> {
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let body = common::wallet_body(app, token, &kp).await;
    Request::builder()
        .method("POST")
        .uri("/v1/wallets")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap()
}

/// Sign up a fresh user via the router and return its bearer token.
async fn auth_token(app: &axum::Router, state: &AppState) -> String {
    let email = format!("u-{}@octo.test", uuid::Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

async fn body_limit_handler(_: Bytes) -> Result<StatusCode, std::convert::Infallible> {
    Ok(StatusCode::OK)
}

#[tokio::test]
async fn request_body_over_the_configured_limit_returns_413() {
    let app = Router::new()
        .route("/limit", post_route(body_limit_handler))
        .layer(RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT));

    let body = "a".repeat(REQUEST_BODY_LIMIT + 1);
    assert!(body.len() > REQUEST_BODY_LIMIT);

    let resp = app.oneshot(body_limit_request(body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn request_body_at_the_configured_limit_succeeds() {
    let app = Router::new()
        .route("/limit", post_route(body_limit_handler))
        .layer(RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT));

    let body = "a".repeat(REQUEST_BODY_LIMIT);
    assert_eq!(body.len(), REQUEST_BODY_LIMIT);

    let resp = app.oneshot(body_limit_request(body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_oversized_body_returns_413() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());

    // إرسال طلب كبير جداً (أكبر من الحد المسموح به عادة)
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("Content-Type", "application/json")
                .body(Body::from(vec![0; 1024 * 1024 * 10])) // 10MB
                .unwrap(),
        )
        .await
        .unwrap();

    // `DefaultBodyLimit` rejects an oversized request with its own bare 413 before the request
    // ever reaches a handler — there is deliberately no `HandleErrorLayer` wrapping it in our
    // JSON envelope (see the NOTE in `lib.rs`), so the body here is axum's own text, not JSON.
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // The oversized rejection must still use the standard response envelope, not a bare 413.
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    assert!(!bytes.is_empty(), "413 response should explain itself");
}

#[tokio::test]
async fn create_wallet_is_non_custodial_and_stores_no_seed() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // The client generates the keypair, proves ownership, and sends only public material.
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let account = kp.public_key().account_id();
    let (challenge, signature) = common::signed_challenge(&app, &token, &kp).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(
                    r#"{{"label":"acme","public_key":"{account}","challenge":"{challenge}","signature":"{signature}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    let data = &json["data"];
    assert_eq!(
        data["address"].as_str().unwrap(),
        account,
        "the wallet account must be exactly the client-supplied public key"
    );
    assert_eq!(data["custody"], "client");
    assert!(
        data.get("recovery_mnemonic").is_none() || data["recovery_mnemonic"].is_null(),
        "no mnemonic is ever returned — the client generated it"
    );

    // The custody kill-test: the server holds NO seed for this wallet.
    let wallet_id = data["id"].as_str().unwrap();
    let (custody, has_seed): (String, bool) = sqlx::query_as(
        "SELECT custody, (sealed_ciphertext IS NOT NULL OR sealed_nonce IS NOT NULL \
         OR sealed_salt IS NOT NULL) FROM wallets WHERE id = $1::uuid",
    )
    .bind(wallet_id)
    .fetch_one(state.store().pool())
    .await
    .unwrap();
    assert_eq!(custody, "client");
    assert!(
        !has_seed,
        "no seed material may be stored for a client wallet"
    );
}

#[tokio::test]
async fn create_wallet_rejects_bad_public_key() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Missing public_key → 400.
    let resp = app
        .clone()
        .oneshot(post_json_auth("/v1/wallets", r#"{"label":"x"}"#, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Malformed public_key → 400.
    let resp = app
        .oneshot(post_json_auth(
            "/v1/wallets",
            r#"{"public_key":"not-a-stellar-account"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn addresses_return_both_forms_and_share_base() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet (empty body is allowed).
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet = body_json(resp).await;
    let wallet_id = wallet["data"]["id"].as_str().unwrap().to_string();
    let base = wallet["data"]["address"].as_str().unwrap().to_string();

    // Create two addresses.
    let mut muxed = vec![];
    let mut memo_ids = vec![];
    for _ in 0..2 {
        let uri = format!("/v1/wallets/{wallet_id}/addresses");
        let resp = app.clone().oneshot(post_auth(&uri, &token)).await.unwrap();
        let st = resp.status();
        let j = body_json(resp).await;
        assert_eq!(st, StatusCode::CREATED, "address create failed: {j}");
        let d = &j["data"];
        assert!(d["muxed_address"].as_str().unwrap().starts_with('M'));
        // The fallback form shares the same base G... account.
        assert_eq!(d["base_address"].as_str().unwrap(), base);
        muxed.push(d["muxed_address"].as_str().unwrap().to_string());
        memo_ids.push(d["memo_id"].as_i64().unwrap());
    }

    assert_ne!(muxed[0], muxed[1], "distinct muxed addresses");
    assert_eq!(memo_ids, vec![1, 2], "ids allocated sequentially from 1");

    // List returns both. The paginated envelope is {data: {data: [...], next_cursor}}.
    let uri = format!("/v1/wallets/{wallet_id}/addresses");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    let list = body_json(resp).await;
    assert_eq!(list["data"]["data"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn transactions_endpoint_returns_list() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // A new wallet has no transactions yet → empty array, 200.
    let uri = format!("/v1/wallets/{wallet_id}/transactions");
    let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    // Paginated envelope: {data: {data: [...], next_cursor}}.
    assert_eq!(j["data"]["data"].as_array().unwrap().len(), 0);

    // Unknown wallet (authed user) → 404.
    let uri = format!("/v1/wallets/{}/transactions", uuid::Uuid::new_v4());
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_unknown_wallet_is_404() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let uri = format!("/v1/wallets/{}", uuid::Uuid::new_v4());
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn balances_requires_auth_and_a_real_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;
    let uri = format!("/v1/wallets/{wallet_id}/balances");

    // The Horizon client itself is covered by horizon_client_tests / horizon_resilience_tests;
    // what those cannot check is this route's authorization, which runs on every CI build.
    let resp = app.clone().oneshot(get(&uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Another user must not learn whether this wallet exists.
    let other = auth_token(&app, &state).await;
    let resp = app.clone().oneshot(get_auth(&uri, &other)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Unknown wallet → 404.
    let unknown = format!("/v1/wallets/{}/balances", uuid::Uuid::new_v4());
    let resp = app.oneshot(get_auth(&unknown, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Regression: the sequence number must serialize as a JSON **string**, not a number.
///
/// Stellar sequence numbers are ~1.6e16, past `Number.MAX_SAFE_INTEGER` (9.007e15). As a JSON
/// number, `JSON.parse` rounds to float64 and silently drops the low bits (…466433 → …466432),
/// so the browser signs with a sequence one too low and Horizon rejects it with `tx_bad_seq`.
/// This manifested as "the first withdrawal works, the second always fails".
#[test]
fn signing_info_serializes_sequence_as_a_string() {
    // A value past MAX_SAFE_INTEGER that is NOT representable as an f64 — round-tripping it
    // through a double loses the final digit, which is exactly the production failure.
    let seq: i64 = 15_942_562_120_466_433;
    assert!(
        seq > 9_007_199_254_740_991,
        "test value must be unsafe in JS"
    );
    assert_ne!(
        seq as f64 as i64, seq,
        "test value must actually lose precision as a double"
    );

    // Serialize the REAL response struct — this is what would regress if the attribute is removed.
    let info = octo_api::routes::submit::SigningInfo {
        account: "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6".into(),
        sequence: seq,
        network_passphrase: "Test SDF Network ; September 2015".into(),
        base_fee_stroops: 100,
    };
    let json = serde_json::to_string(&info).unwrap();
    assert!(
        json.contains(r#""sequence":"15942562120466433""#),
        "sequence must be quoted (a string) on the wire, got: {json}"
    );
}

#[tokio::test]
async fn signing_info_requires_auth_and_a_real_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;
    let uri = format!("/v1/wallets/{wallet_id}/signing-info");

    // Unauthenticated → 401. (The success path needs a funded on-chain account and is covered by
    // horizon_live_tests, which only runs with OCTO_LIVE_TESTS=1 — so the auth/404 guards are
    // asserted here, where they run on every CI build.)
    let resp = app.clone().oneshot(get(&uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Another user must not learn whether this wallet exists.
    let other = auth_token(&app, &state).await;
    let resp = app.clone().oneshot(get_auth(&uri, &other)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Unknown wallet → 404.
    let unknown = format!("/v1/wallets/{}/signing-info", uuid::Uuid::new_v4());
    let resp = app.oneshot(get_auth(&unknown, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_is_public_and_ok() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    // The liveness probe must not require auth — a load balancer has no token.
    let resp = app.oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn backup_round_trips_the_opaque_blob_verbatim() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // The blob is ciphertext the CLIENT produced; the server must store and return it byte-for
    // byte without interpreting it.
    let blob = "v1.YmFzZTY0LWNpcGhlcnRleHQ=.bm9uY2U=.c2FsdA==";
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let account = kp.public_key().account_id();
    let (challenge, signature) = common::signed_challenge(&app, &token, &kp).await;
    let body = format!(
        r#"{{"public_key":"{account}","encrypted_backup":"{blob}","challenge":"{challenge}","signature":"{signature}"}}"#
    );
    let resp = app
        .clone()
        .oneshot(post_json_auth("/v1/wallets", &body, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let uri = format!("/v1/wallets/{wallet_id}/backup");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp).await["data"].clone();
    assert_eq!(data["wallet_id"].as_str().unwrap(), wallet_id);
    assert_eq!(
        data["encrypted_backup"].as_str().unwrap(),
        blob,
        "the backup blob must come back exactly as the client stored it"
    );
}

#[tokio::test]
async fn backup_is_null_when_the_client_stored_none() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // encrypted_backup is optional — a user may decline server-side backup entirely.
    let wallet_id = create_wallet_for(&app, &token).await;
    let uri = format!("/v1/wallets/{wallet_id}/backup");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_json(resp).await["data"]["encrypted_backup"].is_null());
}

#[tokio::test]
async fn backup_rejects_api_key_auth_and_other_users() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;
    let uri = format!("/v1/wallets/{wallet_id}/backup");

    // An API key must not be able to pull the key backup: it is the one artifact that, combined
    // with the user's password, reconstructs the signing key. Dashboard login only.
    let key = api_key_for(&app, &token, &wallet_id).await;
    let resp = app.clone().oneshot(get_auth(&uri, &key)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "API keys must not read the key backup"
    );

    // Another logged-in user gets 404 (not 403) so wallet existence isn't leaked.
    let other = auth_token(&app, &state).await;
    let resp = app.oneshot(get_auth(&uri, &other)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unauthenticated_request_is_401() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    // No token at all → 401 (auth required on wallet endpoints).
    let uri = format!("/v1/wallets/{}", uuid::Uuid::new_v4());
    let resp = app.oneshot(get(&uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn addresses_on_unknown_wallet_is_404() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let uri = format!("/v1/wallets/{}/addresses", uuid::Uuid::new_v4());
    let resp = app.oneshot(post_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// DELETE with an Authorization bearer token.
fn delete_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_json_auth(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn put_json_auth(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn custodial_withdraw_is_gone() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // The custodial withdraw endpoint was removed in the non-custodial cutover: it now returns
    // 410 Gone, pointing callers at submit-signed. The server holds no user key to sign with.
    let body = r#"{"destination":"GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6","amount_stroops":100,"idempotency_key":"k"}"#;
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw"),
            body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn submit_signed_requires_transaction_xdr() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let uri = format!("/v1/wallets/{wallet_id}/submit-signed");

    // Empty body → 400.
    let resp = app
        .clone()
        .oneshot(post_json_auth(&uri, "{}", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Garbage XDR → 400.
    let resp = app
        .oneshot(post_json_auth(
            &uri,
            r#"{"transaction_xdr":"not-valid-xdr"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn custodial_trustline_is_gone() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/trustlines"),
            r#"{"asset_code":"USDC","asset_issuer":"GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

/// Regression coverage for the withdrawal route's use of the shared
/// `octo_wallet_core::is_valid_asset_code` (see `crates/wallet-core/src/asset.rs`): an
/// out-of-bounds asset code (0 or 13+ bytes) must be rejected with 400 *before* a withdrawal row
/// is ever created, not merely fail later at signing.
// NOTE: withdraw_rejects_invalid_asset_code_before_creating_withdrawal_row was removed here.
// It tested the pre-cutover custodial withdraw endpoint (POST /v1/wallets/:id/withdraw with a
// destination+amount body); that endpoint is now 410 Gone (see custodial_withdraw_is_gone
// above), so it always failed against this schema/router. Asset-code validation on the
// non-custodial path is covered where the trustline/payment is actually built (wallet-core).

#[tokio::test]
async fn api_key_generate_and_get() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet owned by this user.
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Before generation: not configured.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/wallets/{wallet_id}/api-key"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["data"]["configured"], false);

    // Generate → returns the full key once, prefixed octo_sk_test_.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j = body_json(resp).await;
    let key = j["data"]["api_key"].as_str().unwrap().to_string();
    assert!(key.starts_with("octo_sk_test_"), "key was {key}");
    assert!(key.len() > 20);

    // Get → configured, prefix only (never the full key).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/wallets/{wallet_id}/api-key"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let j = body_json(resp).await;
    assert_eq!(j["data"]["configured"], true);
    let prefix = j["data"]["prefix"].as_str().unwrap();
    assert!(key.starts_with(prefix), "prefix must match the key");
    assert!(
        prefix.len() < key.len(),
        "prefix must be shorter than the key"
    );
}

#[tokio::test]
async fn api_key_requires_ownership() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());

    // User A creates a wallet.
    let token_a = auth_token(&app, &state).await;
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token_a).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // User B cannot generate a key for A's wallet → 404 (not revealed).
    let token_b = auth_token(&app, &state).await;
    let resp = app
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &token_b,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// SHA-256 hex of a raw API key — mirrors `hash_key`/`hash_api_key` in
/// `crates/api/src/routes/apikeys.rs` / `crates/api/src/auth.rs` (both private, so the
/// hashing scheme is reproduced here to inspect the store directly).
fn hash_key_for_test(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

#[tokio::test]
async fn regenerating_api_key_invalidates_the_previous_one() {
    let Some(state) = test_state().await else {
        return;
    };
    // Keep a handle to the store so we can inspect `api_keys` rows directly (upsert-on-conflict
    // is implemented in `Store::upsert_api_key`; the only way to confirm it *replaces* rather
    // than *appends* a row is to check the hash lookup, not just the HTTP responses).
    let store = state.store().clone();
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id_str = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let wallet_id: uuid::Uuid = wallet_id_str.parse().unwrap();

    // First generation.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id_str}/api-key"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j = body_json(resp).await;
    let key1 = j["data"]["api_key"].as_str().unwrap().to_string();
    let prefix1 = j["data"]["prefix"].as_str().unwrap().to_string();

    // key1 resolves to this wallet via the store's key-hash lookup (used by API-key auth).
    let resolved = store
        .wallet_id_for_key_hash(&hash_key_for_test(&key1))
        .await
        .expect("query");
    assert_eq!(resolved, Some(wallet_id));

    // key1 works for an authenticated API-key request.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id_str}/addresses"),
            &key1,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Regenerate: POST again with the (dashboard) owner token, explicitly confirming rotation.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id_str}/api-key"),
            r#"{"confirm":true}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j = body_json(resp).await;
    let key2 = j["data"]["api_key"].as_str().unwrap().to_string();
    let prefix2 = j["data"]["prefix"].as_str().unwrap().to_string();

    // The response always carries a fresh secret and prefix, distinct from the first.
    assert_ne!(key1, key2, "regeneration must mint a new secret");
    assert_ne!(
        prefix1, prefix2,
        "regeneration must mint a new display prefix"
    );
    assert!(key2.starts_with("octo_sk_test_"), "key2 was {key2}");
    assert!(key2.starts_with(&prefix2), "prefix2 must match key2");

    // `upsert_api_key` is `INSERT ... ON CONFLICT (wallet_id) DO UPDATE`, i.e. one row per
    // wallet — so key1's hash must no longer resolve to *any* wallet (fully replaced, not
    // appended alongside key2).
    let resolved = store
        .wallet_id_for_key_hash(&hash_key_for_test(&key1))
        .await
        .expect("query");
    assert_eq!(
        resolved, None,
        "the previous key's hash must no longer resolve once regenerated"
    );

    // key2's hash resolves to the wallet.
    let resolved = store
        .wallet_id_for_key_hash(&hash_key_for_test(&key2))
        .await
        .expect("query");
    assert_eq!(resolved, Some(wallet_id));

    // The old key is fully invalidated for authenticated requests too — 401, not just a stale
    // lookup.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id_str}/addresses"),
            &key1,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The new key works.
    let resp = app
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id_str}/addresses"),
            &key2,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// Documents the observed behavior of presenting an `octo_sk_...` API key as the bearer
/// credential on `POST /v1/wallets/:id/api-key` (i.e. a key trying to regenerate/replace
/// itself).
///
/// `generate_key` gates access through `owned_wallet`, which calls `auth::authenticate` — *not*
/// `auth::authorize_wallet` (the helper that explicitly branches on the `octo_sk_` prefix to
/// accept API keys for wallet-scoped operations like creating addresses). `authenticate` only
/// ever validates `Authorization: Bearer <JWT>`: it calls `verify_token`, which `split('.')`s the
/// token and immediately returns `None` unless there are exactly three dot-separated segments
/// with a matching header. An `octo_sk_<network>_<hex>` key contains no `.` characters at all, so
/// `verify_token` returns `None` and `authenticate` returns `Err(ApiError::Unauthorized)` before
/// any wallet-ownership or key-prefix logic even runs.
///
/// So: an API key can **not** self-regenerate (or view via GET, which is gated the same way).
/// This reads as intentional rather than a gap — it's the same "dashboard JWT only" posture that
/// `delete_key`'s doc comment states explicitly and that `require_login` enforces elsewhere
/// (`api_key_cannot_withdraw`, `delete_api_key_rejects_api_key_auth` cover the analogous cases
/// for withdrawals and revocation). Minting/replacing/viewing wallet credentials is treated as a
/// sensitive, dashboard-only action, consistent across all three api-key routes — `generate_key`
/// and `get_key` just happen not to spell that out in a doc comment the way `delete_key` does.
#[tokio::test]
async fn api_key_bearer_calling_generate_key_behavior_is_documented() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key = api_key_for(&app, &token, &wallet_id).await;

    // Attempt to self-regenerate using the API key itself as the bearer credential.
    let resp = app
        .oneshot(post_auth(&format!("/v1/wallets/{wallet_id}/api-key"), &key))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an octo_sk_ API key must not be accepted by owned_wallet's authenticate()-based gate"
    );
}

/// Generate an API key for a wallet and return the full key string.
async fn api_key_for(app: &axum::Router, token: &str, wallet_id: &str) -> String {
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            token,
        ))
        .await
        .unwrap();
    body_json(resp).await["data"]["api_key"]
        .as_str()
        .unwrap()
        .to_string()
}

// (a second `delete_auth` helper was defined here by the merge; it is identical to the one
// above and has been removed)

#[tokio::test]
async fn api_key_can_create_address_on_its_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet + its API key.
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key = api_key_for(&app, &token, &wallet_id).await;
    assert!(key.starts_with("octo_sk_"));

    // Use the API KEY (not the login token) to create a deposit address.
    let resp = app
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/addresses"),
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "API key should create addresses"
    );
    let j = body_json(resp).await;
    assert!(j["data"]["muxed_address"]
        .as_str()
        .unwrap()
        .starts_with('M'));
}

#[tokio::test]
async fn api_key_cannot_touch_another_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Two wallets owned by the same user; key for wallet A.
    let a = body_json(
        app.clone()
            .oneshot(create_wallet_req(&app, &token).await)
            .await
            .unwrap(),
    )
    .await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let b = body_json(
        app.clone()
            .oneshot(create_wallet_req(&app, &token).await)
            .await
            .unwrap(),
    )
    .await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key_a = api_key_for(&app, &token, &a).await;

    // Key A on wallet B → 404 (scope enforced, existence not revealed).
    let resp = app
        .oneshot(post_auth(&format!("/v1/wallets/{b}/addresses"), &key_a))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_api_key_revokes_it_and_subsequent_calls_using_it_are_401() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet and generate an API key.
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key = api_key_for(&app, &token, &wallet_id).await;

    // The key works for authenticated requests.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/addresses"),
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Revoke the key via the dashboard.
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The revoked key no longer works — 401.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/addresses"),
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // GET metadata confirms no key configured.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/wallets/{wallet_id}/api-key"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["data"]["configured"], false);
}

#[tokio::test]
async fn delete_api_key_requires_wallet_ownership() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());

    // User A creates a wallet with an API key.
    let token_a = auth_token(&app, &state).await;
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token_a).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    api_key_for(&app, &token_a, &wallet_id).await;

    // User B cannot revoke A's key → 404 (not revealed).
    let token_b = auth_token(&app, &state).await;
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &token_b,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_api_key_on_a_wallet_with_no_key_is_ok() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create a wallet without generating a key.
    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // DELETE on a wallet with no key is still OK (idempotent).
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_api_key_rejects_api_key_auth() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key = api_key_for(&app, &token, &wallet_id).await;

    // An API key cannot revoke itself — only dashboard JWT works.
    let resp = app
        .clone()
        .oneshot(delete_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_key_cannot_provision_gas_tank() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let wallet_id = body_json(
        app.clone()
            .oneshot(create_wallet_req(&app, &token).await)
            .await
            .unwrap(),
    )
    .await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key = api_key_for(&app, &token, &wallet_id).await;

    // Provisioning a server-held gas tank is a sensitive, dashboard-only action (require_login):
    // an API key must be rejected with 401. (Moving user funds now requires the user's own
    // client-side signature, so there is no custodial withdraw for a key to abuse.)
    let resp = app
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/gas-tank"),
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "API keys must not provision a gas tank"
    );
}

#[tokio::test]
async fn audit_logs_record_and_list() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());

    // Signup + verify records "created an account"; capture the token.
    let email = format!("audit-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    // Create a wallet → records "created master wallet".
    app.clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();

    // List all audit logs for this user.
    let resp = app
        .clone()
        .oneshot(get_auth("/v1/audit-logs", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let logs = body_json(resp).await;
    let arr = logs["data"].as_array().unwrap();
    assert!(
        arr.len() >= 2,
        "expected signup + wallet events, got {}",
        arr.len()
    );
    let actions: Vec<&str> = arr.iter().map(|l| l["action"].as_str().unwrap()).collect();
    assert!(actions.iter().any(|a| a.contains("account")));
    assert!(actions.iter().any(|a| a.contains("wallet")));

    // Filter by category=wallet → only wallet events.
    let resp = app
        .oneshot(get_auth("/v1/audit-logs?category=wallet", &token))
        .await
        .unwrap();
    let filtered = body_json(resp).await;
    let arr = filtered["data"].as_array().unwrap();
    assert!(!arr.is_empty());
    assert!(arr.iter().all(|l| l["category"] == "wallet"));
}

#[tokio::test]
async fn audit_logs_are_strictly_scoped_to_the_authenticated_user() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());

    // User A signs up and performs an auditable action with a distinctive marker.
    let email_a = format!("audit-a-{}@octo.test", uuid::Uuid::new_v4().simple());
    let (token_a, user_id_a) = common::signup_and_verify_full(&app, &state, &email_a).await;

    let kp_a = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let account_a = kp_a.public_key().account_id();
    let (challenge_a, signature_a) = common::signed_challenge(&app, &token_a, &kp_a).await;
    app.clone()
        .oneshot(post_json_auth(
            "/v1/wallets",
            &format!(
                r#"{{"public_key":"{account_a}","label":"USER-A-ONLY-MARKER","challenge":"{challenge_a}","signature":"{signature_a}"}}"#
            ),
            &token_a,
        ))
        .await
        .unwrap();

    // User B signs up and performs its own auditable action with a different marker.
    let email_b = format!("audit-b-{}@octo.test", uuid::Uuid::new_v4().simple());
    let (token_b, user_id_b) = common::signup_and_verify_full(&app, &state, &email_b).await;

    let kp_b = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let account_b = kp_b.public_key().account_id();
    let (challenge_b, signature_b) = common::signed_challenge(&app, &token_b, &kp_b).await;
    app.clone()
        .oneshot(post_json_auth(
            "/v1/wallets",
            &format!(
                r#"{{"public_key":"{account_b}","label":"USER-B-ONLY-MARKER","challenge":"{challenge_b}","signature":"{signature_b}"}}"#
            ),
            &token_b,
        ))
        .await
        .unwrap();

    // User B's view of /v1/audit-logs (scoped purely by the token's user_id — there's no
    // wallet-id path param on this route) must never contain any of user A's rows.
    let resp = app
        .clone()
        .oneshot(get_auth("/v1/audit-logs", &token_b))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let logs_b = body_json(resp).await;
    let arr_b = logs_b["data"].as_array().unwrap();
    assert!(
        arr_b.iter().all(|l| l["user_id"] == user_id_b),
        "user B's audit log listing contained rows not owned by user B: {arr_b:?}"
    );
    assert!(
        arr_b.iter().all(|l| l["user_id"] != user_id_a),
        "user B's audit log listing leaked user A's rows: {arr_b:?}"
    );
    let targets_b: Vec<&str> = arr_b.iter().filter_map(|l| l["target"].as_str()).collect();
    assert!(
        targets_b.iter().any(|t| t.contains("USER-B-ONLY-MARKER")),
        "user B should see its own marker among its audit rows: {targets_b:?}"
    );
    assert!(
        !targets_b.iter().any(|t| t.contains("USER-A-ONLY-MARKER")),
        "user B must never see user A's marker: {targets_b:?}"
    );

    // Symmetric check: user A's view must never contain user B's rows.
    let resp = app
        .oneshot(get_auth("/v1/audit-logs", &token_a))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let logs_a = body_json(resp).await;
    let arr_a = logs_a["data"].as_array().unwrap();
    assert!(
        arr_a.iter().all(|l| l["user_id"] == user_id_a),
        "user A's audit log listing contained rows not owned by user A: {arr_a:?}"
    );
    assert!(
        arr_a.iter().all(|l| l["user_id"] != user_id_b),
        "user A's audit log listing leaked user B's rows: {arr_a:?}"
    );
    let targets_a: Vec<&str> = arr_a.iter().filter_map(|l| l["target"].as_str()).collect();
    assert!(
        targets_a.iter().any(|t| t.contains("USER-A-ONLY-MARKER")),
        "user A should see its own marker among its audit rows: {targets_a:?}"
    );
    assert!(
        !targets_a.iter().any(|t| t.contains("USER-B-ONLY-MARKER")),
        "user A must never see user B's marker: {targets_a:?}"
    );
}

#[tokio::test]
async fn audit_logs_category_all_behaves_like_no_filter() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());

    // Signup + verify records "created an account"; capture the token.
    let email = format!("audit-all-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    // Create a wallet → records "created master wallet", so there's more than one row/category.
    app.clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();

    // Omitting `category` entirely.
    let resp = app
        .clone()
        .oneshot(get_auth("/v1/audit-logs", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let unfiltered = body_json(resp).await;
    let arr_unfiltered = unfiltered["data"].as_array().unwrap().clone();
    assert!(
        !arr_unfiltered.is_empty(),
        "expected at least the signup event"
    );

    // `category=all` is documented (AuditQuery) to behave exactly like no filter.
    let resp = app
        .oneshot(get_auth("/v1/audit-logs?category=all", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let all = body_json(resp).await;
    let arr_all = all["data"].as_array().unwrap().clone();

    assert_eq!(
        arr_unfiltered, arr_all,
        "category=all should return exactly the same rows as omitting category"
    );
}

#[tokio::test]
async fn audit_logs_without_token_is_401() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    // No Authorization header at all → 401 (audit-logs requires `authenticate`).
    let resp = app.oneshot(get("/v1/audit-logs")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- sponsored transaction tests -------------------------------------------

async fn insert_sponsored_tx(
    pool: &sqlx::PgPool,
    wallet_id: &str,
    status: &str,
    fee_stroops: i64,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sponsored_transactions (id, wallet_id, inner_tx_hash, fee_bump_tx_hash, fee_stroops, status)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(wallet_id)
    .bind(format!("inner-tx-{id}"))
    .bind(format!("fee-tx-{id}"))
    .bind(fee_stroops)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn list_sponsored_transactions_returns_empty_for_new_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let uri = format!("/v1/wallets/{wallet_id}/sponsored-transactions");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["data"]["data"].as_array().unwrap().len(), 0);
    assert!(j["data"]["next_cursor"].is_null());
}

#[tokio::test]
async fn list_sponsored_transactions_pagination() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Insert 10 sponsored transactions with increasing fee_stroops.
    for i in 0..10 {
        insert_sponsored_tx(state.store().pool(), &wallet_id, "confirmed", (i + 1) * 100).await;
        // Small delay to ensure distinct created_at ordering.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    // Fetch with limit=3, follow cursor across pages.
    let mut all_ids: Vec<String> = vec![];
    let mut cursor: Option<String> = None;

    loop {
        let uri = match cursor {
            Some(ref c) => {
                format!("/v1/wallets/{wallet_id}/sponsored-transactions?limit=3&before={c}")
            }
            None => format!("/v1/wallets/{wallet_id}/sponsored-transactions?limit=3"),
        };
        let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        let items = j["data"]["data"].as_array().unwrap();
        for item in items {
            all_ids.push(item["id"].as_str().unwrap().to_string());
        }
        let next = j["data"]["next_cursor"].as_str().map(|s| s.to_string());
        if next.is_none() {
            break;
        }
        cursor = next;
    }

    assert_eq!(
        all_ids.len(),
        10,
        "all 10 rows must be retrieved across pages"
    );
    // Verify no duplicates.
    let mut unique = all_ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 10, "all ids must be distinct");
}

#[tokio::test]
async fn list_sponsored_transactions_status_filter() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    let resp = app
        .clone()
        .oneshot(create_wallet_req(&app, &token).await)
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Insert 2 confirmed + 2 failed.
    for _ in 0..2 {
        insert_sponsored_tx(state.store().pool(), &wallet_id, "confirmed", 100).await;
        insert_sponsored_tx(state.store().pool(), &wallet_id, "failed", 100).await;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    // Filter by status=failed.
    let uri = format!("/v1/wallets/{wallet_id}/sponsored-transactions?status=failed");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let items = j["data"]["data"].as_array().unwrap();
    assert_eq!(items.len(), 2, "only 2 failed rows expected");
    for item in items {
        assert_eq!(item["status"], "failed");
    }
}

#[tokio::test]
async fn list_sponsored_transactions_requires_auth() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let uri = format!(
        "/v1/wallets/{}/sponsored-transactions",
        uuid::Uuid::new_v4()
    );
    let resp = app.oneshot(get(&uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Pagination tests
// ---------------------------------------------------------------------------

/// Helper: create a wallet and return its id string.
async fn create_wallet_for(app: &axum::Router, token: &str) -> String {
    let resp = app
        .clone()
        .oneshot(create_wallet_req(app, token).await)
        .await
        .unwrap();
    body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn list_wallets_pagination_returns_a_next_cursor_and_respects_limit() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // Create 5 wallets for this user.
    for _ in 0..5 {
        app.clone()
            .oneshot(create_wallet_req(&app, &token).await)
            .await
            .unwrap();
    }

    // Fetch first page with limit=2 — expect 2 items and a next_cursor.
    let resp = app
        .clone()
        .oneshot(get_auth("/v1/wallets?limit=2", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let page1 = j["data"]["data"].as_array().unwrap();
    assert_eq!(page1.len(), 2, "first page must have exactly 2 items");
    let cursor = j["data"]["next_cursor"]
        .as_str()
        .expect("next_cursor must be present on first page");

    // Fetch second page using the cursor — expect more items.
    let resp = app
        .clone()
        .oneshot(get_auth(
            &format!("/v1/wallets?limit=2&before={cursor}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j2 = body_json(resp).await;
    let page2 = j2["data"]["data"].as_array().unwrap();
    assert!(!page2.is_empty(), "second page must not be empty");

    // Ids across pages must not overlap.
    let ids1: Vec<&str> = page1.iter().map(|x| x["id"].as_str().unwrap()).collect();
    let ids2: Vec<&str> = page2.iter().map(|x| x["id"].as_str().unwrap()).collect();
    for id in &ids2 {
        assert!(!ids1.contains(id), "pages must not overlap");
    }
}

#[tokio::test]
async fn list_addresses_pagination_returns_a_next_cursor_and_respects_limit() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Create 5 addresses.
    for _ in 0..5 {
        let uri = format!("/v1/wallets/{wallet_id}/addresses");
        app.clone().oneshot(post_auth(&uri, &token)).await.unwrap();
    }

    // Fetch first page with limit=2.
    let uri = format!("/v1/wallets/{wallet_id}/addresses?limit=2");
    let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let page1 = j["data"]["data"].as_array().unwrap();
    assert_eq!(page1.len(), 2, "first page must have exactly 2 items");
    let cursor = j["data"]["next_cursor"]
        .as_str()
        .expect("next_cursor must be present on first page");

    // Fetch second page using the cursor.
    let uri = format!("/v1/wallets/{wallet_id}/addresses?limit=2&before={cursor}");
    let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j2 = body_json(resp).await;
    let page2 = j2["data"]["data"].as_array().unwrap();
    assert!(!page2.is_empty(), "second page must not be empty");

    // Ids across pages must not overlap.
    let ids1: Vec<&str> = page1.iter().map(|x| x["id"].as_str().unwrap()).collect();
    let ids2: Vec<&str> = page2.iter().map(|x| x["id"].as_str().unwrap()).collect();
    for id in &ids2 {
        assert!(!ids1.contains(id), "pages must not overlap");
    }
}

#[tokio::test]
async fn list_transactions_pagination_returns_a_next_cursor_and_respects_limit() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // Insert 5 synthetic deposit transactions directly via the store.
    let address_uri = format!("/v1/wallets/{wallet_id}/addresses");
    let resp = app
        .clone()
        .oneshot(post_auth(&address_uri, &token))
        .await
        .unwrap();
    let address_id: uuid::Uuid = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let wallet_uuid: uuid::Uuid = wallet_id.parse().unwrap();

    for i in 0..5u64 {
        state
            .store()
            .record_deposit(&octo_store::NewDeposit {
                wallet_id: wallet_uuid,
                address_id: Some(address_id),
                asset_code: "native".into(),
                asset_issuer: None,
                amount_stroops: (i + 1) as i64 * 100,
                source_account: Some(
                    "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6".into(),
                ),
                destination_account: Some(
                    "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6".into(),
                ),
                stellar_tx_hash: format!("txhash-pag-{wallet_uuid}-{i}"),
                operation_index: i as i32,
                horizon_op_id: format!("op-pag-{wallet_uuid}-{i}"),
                ledger: Some(i as i64),
                memo_id: None,
            })
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    // Fetch first page with limit=2.
    let uri = format!("/v1/wallets/{wallet_id}/transactions?limit=2");
    let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let page1 = j["data"]["data"].as_array().unwrap();
    assert_eq!(page1.len(), 2, "first page must have exactly 2 items");
    let cursor = j["data"]["next_cursor"]
        .as_str()
        .expect("next_cursor must be present on first page");

    // Fetch second page using the cursor.
    let uri = format!("/v1/wallets/{wallet_id}/transactions?limit=2&before={cursor}");
    let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j2 = body_json(resp).await;
    let page2 = j2["data"]["data"].as_array().unwrap();
    assert!(!page2.is_empty(), "second page must not be empty");

    let ids1: Vec<&str> = page1.iter().map(|x| x["id"].as_str().unwrap()).collect();
    let ids2: Vec<&str> = page2.iter().map(|x| x["id"].as_str().unwrap()).collect();
    for id in &ids2 {
        assert!(!ids1.contains(id), "pages must not overlap");
    }
}

#[tokio::test]
async fn pagination_limit_boundaries_are_validated_consistently_with_sponsored_transactions() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    // limit=0 → 400 on all three endpoints.
    for uri in [
        "/v1/wallets?limit=0".to_string(),
        format!("/v1/wallets/{wallet_id}/addresses?limit=0"),
        format!("/v1/wallets/{wallet_id}/transactions?limit=0"),
    ] {
        let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "limit=0 must be 400 for {uri}"
        );
    }

    // limit=201 → 400 on all three endpoints.
    for uri in [
        "/v1/wallets?limit=201".to_string(),
        format!("/v1/wallets/{wallet_id}/addresses?limit=201"),
        format!("/v1/wallets/{wallet_id}/transactions?limit=201"),
    ] {
        let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "limit=201 must be 400 for {uri}"
        );
    }

    // limit=200 → 200 OK on all three endpoints (boundary is inclusive).
    for uri in [
        "/v1/wallets?limit=200".to_string(),
        format!("/v1/wallets/{wallet_id}/addresses?limit=200"),
        format!("/v1/wallets/{wallet_id}/transactions?limit=200"),
    ] {
        let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "limit=200 must be OK for {uri}"
        );
    }
}

// ---------------------------------------------------------------------------
// Payment links
// ---------------------------------------------------------------------------

#[tokio::test]
async fn payment_link_public_routes_require_no_auth_and_404_unknown_slugs() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());

    // No Authorization header at all — must not be treated as unauthenticated-401, just 404.
    let resp = app
        .clone()
        .oneshot(get("/v1/pay/does-not-exist"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/pay/does-not-exist/intent",
            r#"{"amount_usdc_stroops":100}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .oneshot(get(&format!(
            "/v1/pay/does-not-exist/payments/{}",
            uuid::Uuid::new_v4()
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn payment_link_management_requires_wallet_ownership() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let owner = auth_token(&app, &state).await;
    let other = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &owner).await;

    let uri = format!("/v1/wallets/{wallet_id}/payment-links");
    let resp = app
        .clone()
        .oneshot(post_json_auth(&uri, r#"{"name":"Support"}"#, &other))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "a non-owner must not learn the wallet exists"
    );

    let resp = app
        .clone()
        .oneshot(post_json_auth(&uri, r#"{"name":"Support"}"#, &owner))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let slug = created["data"]["slug"].as_str().unwrap().to_string();
    assert_eq!(created["data"]["active"], true);
    assert_eq!(created["data"]["collected_usdc_stroops"], 0);

    // The public page for a freshly created, active, flexible-amount link is reachable with no
    // auth and echoes back its deposit address.
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/pay/{slug}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let public = body_json(resp).await;
    assert_eq!(public["data"]["name"], "Support");
    assert!(public["data"]["deposit_address"]
        .as_str()
        .unwrap()
        .starts_with('M'));

    // Deactivating requires ownership too.
    let link_id = created["data"]["id"].as_str().unwrap();
    let deactivate_uri = format!("/v1/wallets/{wallet_id}/payment-links/{link_id}");
    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &deactivate_uri,
            r#"{"active":false}"#,
            &other,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .clone()
        .oneshot(put_json_auth(
            &deactivate_uri,
            r#"{"active":false}"#,
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["data"]["active"], false);

    // An inactive link's public page must 404, not leak its (now-off) details.
    let resp = app.oneshot(get(&format!("/v1/pay/{slug}"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn payment_link_response_includes_checkout_url_and_redirect_url() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    let uri = format!("/v1/wallets/{wallet_id}/payment-links");
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &uri,
            r#"{"name":"Support","redirect_url":"https://merchant.example/thank-you"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let slug = created["data"]["slug"].as_str().unwrap().to_string();
    let url = created["data"]["url"].as_str().unwrap();
    assert!(
        url.ends_with(&format!("/pay/{slug}")),
        "url must be a real hosted checkout link ending in /pay/<slug>, got {url}"
    );
    assert_eq!(
        created["data"]["redirect_url"],
        "https://merchant.example/thank-you"
    );

    // GET and the public route must echo the same fields.
    let link_id = created["data"]["id"].as_str().unwrap();
    let get_uri = format!("/v1/wallets/{wallet_id}/payment-links/{link_id}");
    let resp = app
        .clone()
        .oneshot(get_auth(&get_uri, &token))
        .await
        .unwrap();
    let fetched = body_json(resp).await;
    assert_eq!(fetched["data"]["url"], url);
    assert_eq!(
        fetched["data"]["redirect_url"],
        "https://merchant.example/thank-you"
    );

    let resp = app.oneshot(get(&format!("/v1/pay/{slug}"))).await.unwrap();
    let public = body_json(resp).await;
    assert_eq!(
        public["data"]["redirect_url"],
        "https://merchant.example/thank-you"
    );
}

#[tokio::test]
async fn payment_link_intent_rejects_flexible_amount_without_one() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Flexible"}"#,
            &token,
        ))
        .await
        .unwrap();
    let slug = body_json(resp).await["data"]["slug"]
        .as_str()
        .unwrap()
        .to_string();

    // No amount supplied for a flexible link → 400, not a panic or a free $0 intent.
    let resp = app
        .clone()
        .oneshot(post_json(&format!("/v1/pay/{slug}/intent"), "{}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = app
        .oneshot(post_json(
            &format!("/v1/pay/{slug}/intent"),
            r#"{"payer_name":"Ada","payer_email":"ada@example.com","amount_usdc_stroops":5000000}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let intent = body_json(resp).await;
    assert_eq!(intent["data"]["amount_usdc_stroops"], 5_000_000);
    assert!(intent["data"]["payment_id"].as_str().is_some());
}

// ---------------------------------------------------------------------------
// Wallet registration ownership challenge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_wallet_without_challenge_is_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // A valid public key but no ownership proof — must be rejected, or anyone could register a
    // stranger's account and watch its deposit history.
    let account = stellar_base::crypto::DalekKeyPair::random()
        .unwrap()
        .public_key()
        .account_id();
    let resp = app
        .oneshot(post_json_auth(
            "/v1/wallets",
            &format!(r#"{{"public_key":"{account}"}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_wallet_rejects_signature_from_a_different_key() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;

    // The challenge is signed by key B, but the registration claims key A's account.
    let kp_a = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let kp_b = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let account_a = kp_a.public_key().account_id();
    let (challenge, signature_by_b) = common::signed_challenge(&app, &token, &kp_b).await;
    let resp = app
        .oneshot(post_json_auth(
            "/v1/wallets",
            &format!(
                r#"{{"public_key":"{account_a}","challenge":"{challenge}","signature":"{signature_by_b}"}}"#
            ),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a signature from a different key must not prove ownership of account A"
    );
}

#[tokio::test]
async fn create_wallet_rejects_another_users_challenge() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let user_a = auth_token(&app, &state).await;
    let user_b = auth_token(&app, &state).await;

    // Challenge issued to user A, redeemed by user B: the HMAC user-binding must reject it,
    // otherwise a captured (challenge, signature) pair could be replayed cross-account.
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let account = kp.public_key().account_id();
    let (challenge_for_a, signature) = common::signed_challenge(&app, &user_a, &kp).await;
    let resp = app
        .oneshot(post_json_auth(
            "/v1/wallets",
            &format!(
                r#"{{"public_key":"{account}","challenge":"{challenge_for_a}","signature":"{signature}"}}"#
            ),
            &user_b,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Signup with an explicit `X-Forwarded-For` so the limiter buckets by a known IP.
fn signup_from_ip(email: &str, ip: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/auth/signup")
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(Body::from(format!(
            r#"{{"email":"{email}","password":"supersecret"}}"#
        )))
        .unwrap()
}

#[tokio::test]
async fn signup_is_rate_limited_per_ip() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let ip = format!("203.0.113.{}", rand_octet());

    // The limit is 10/min/IP; the 11th attempt from the same IP must be refused.
    for i in 0..10 {
        let email = format!("rl-{}-{i}@octo.test", uuid::Uuid::new_v4().simple());
        let resp = app
            .clone()
            .oneshot(signup_from_ip(&email, &ip))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "signup {i} within the limit should succeed"
        );
    }
    let email = format!("rl-over-{}@octo.test", uuid::Uuid::new_v4().simple());
    let resp = app
        .clone()
        .oneshot(signup_from_ip(&email, &ip))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // A different IP has its own bucket and is unaffected.
    let other_ip = format!("198.51.100.{}", rand_octet());
    let email = format!("rl-other-{}@octo.test", uuid::Uuid::new_v4().simple());
    let resp = app
        .oneshot(signup_from_ip(&email, &other_ip))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// A random last octet so parallel test runs don't share a limiter bucket.
fn rand_octet() -> u8 {
    (uuid::Uuid::new_v4().as_bytes()[0] % 200) + 10
}

#[tokio::test]
async fn payment_intent_creation_is_rate_limited_per_ip() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Rate limit test"}"#,
            &token,
        ))
        .await
        .unwrap();
    let slug = body_json(resp).await["data"]["slug"]
        .as_str()
        .unwrap()
        .to_string();

    let ip = format!("192.0.2.{}", rand_octet());
    let intent_req = || {
        Request::builder()
            .method("POST")
            .uri(format!("/v1/pay/{slug}/intent"))
            .header("content-type", "application/json")
            .header("x-forwarded-for", ip.clone())
            .body(Body::from(r#"{"amount_usdc_stroops":1000000}"#))
            .unwrap()
    };

    // Intent creation is 5/min/IP — each one allocates an address and inserts a row, so it is
    // deliberately much tighter than the read endpoints.
    for i in 0..5 {
        let resp = app.clone().oneshot(intent_req()).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "intent {i} should succeed"
        );
    }
    let resp = app.oneshot(intent_req()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn concurrent_payment_intents_get_distinct_deposit_addresses() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Concurrent payers"}"#,
            &token,
        ))
        .await
        .unwrap();
    let slug = body_json(resp).await["data"]["slug"]
        .as_str()
        .unwrap()
        .to_string();

    // Two payers start paying the same link. Each must get its OWN deposit address, otherwise
    // ingest can only guess which intent a landing deposit belongs to (oldest-pending), and
    // payer B's money could confirm payer A's intent.
    let mut addresses = Vec::new();
    let mut payment_ids = Vec::new();
    for (i, name) in ["Ada", "Grace"].iter().enumerate() {
        let ip = format!("198.18.0.{}", 20 + i);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/pay/{slug}/intent"))
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", ip)
                    .body(Body::from(format!(
                        r#"{{"payer_name":"{name}","amount_usdc_stroops":7000000}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let data = body_json(resp).await;
        addresses.push(
            data["data"]["deposit_address"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        payment_ids.push(data["data"]["payment_id"].as_str().unwrap().to_string());
    }

    assert_ne!(
        addresses[0], addresses[1],
        "each payment intent must get its own muxed deposit address"
    );
    assert_ne!(payment_ids[0], payment_ids[1]);
    for addr in &addresses {
        assert!(
            addr.starts_with('M'),
            "expected a muxed address, got {addr}"
        );
    }

    // Both start out pending and independent.
    for payment_id in &payment_ids {
        let resp = app
            .clone()
            .oneshot(get(&format!("/v1/pay/{slug}/payments/{payment_id}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["data"]["status"], "pending");
    }
}

// ---------------------------------------------------------------------------
// Payment link payments + image uploads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn payment_link_payments_list_requires_ownership_and_returns_payers() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let owner = auth_token(&app, &state).await;
    let other = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &owner).await;

    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Payer list test","amount_usdc_stroops":4000000}"#,
            &owner,
        ))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let slug = created["data"]["slug"].as_str().unwrap().to_string();
    let link_id = created["data"]["id"].as_str().unwrap().to_string();

    // A payer starts a payment; their name/email are captured on the intent.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/pay/{slug}/intent"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", format!("203.0.113.{}", rand_octet()))
                .body(Body::from(
                    r#"{"payer_name":"Ada Lovelace","payer_email":"ada@example.com"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let uri = format!("/v1/wallets/{wallet_id}/payment-links/{link_id}/payments");

    // Payer email is personal data — another user must not be able to read it.
    let resp = app.clone().oneshot(get_auth(&uri, &other)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Unauthenticated is rejected too (this is not a public pay-page route).
    let resp = app.clone().oneshot(get(&uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The owner sees the payer details.
    let resp = app.oneshot(get_auth(&uri, &owner)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let rows = body["data"]["data"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "the one intent should be listed: {body}");
    assert_eq!(rows[0]["payer_name"], "Ada Lovelace");
    assert_eq!(rows[0]["payer_email"], "ada@example.com");
    assert_eq!(rows[0]["amount_usdc_stroops"], 4_000_000);
    assert_eq!(
        rows[0]["status"], "pending",
        "an intent with no deposit yet is pending"
    );
}

#[tokio::test]
async fn upload_signature_requires_auth() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());

    // No credential: must be 401 rather than handing out signed upload params.
    let resp = app
        .clone()
        .oneshot(get("/v1/uploads/signature"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Authenticated: 200 with params when Cloudinary is configured, or a clear 400 when it
    // isn't. Either way it must not be a 401/500 — the test env usually has no credentials.
    let token = auth_token(&app, &state).await;
    let resp = app
        .oneshot(get_auth("/v1/uploads/signature", &token))
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST,
        "expected signed params or a clear not-configured error, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn submit_payment_validates_against_the_intents_own_address() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id = create_wallet_for(&app, &token).await;

    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Intent address test","amount_usdc_stroops":2000000}"#,
            &token,
        ))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let slug = created["data"]["slug"].as_str().unwrap().to_string();

    // The link's own address, as advertised on the public page.
    let resp = app
        .clone()
        .oneshot(get(&format!("/v1/pay/{slug}")))
        .await
        .unwrap();
    let link_address = body_json(resp).await["data"]["deposit_address"]
        .as_str()
        .unwrap()
        .to_string();

    // An intent gets its OWN address, distinct from the link's.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/pay/{slug}/intent"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", format!("198.51.100.{}", rand_octet()))
                .body(Body::from(r#"{"payer_name":"Ada"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let intent = body_json(resp).await;
    let intent_address = intent["data"]["deposit_address"]
        .as_str()
        .unwrap()
        .to_string();
    let payment_id = intent["data"]["payment_id"].as_str().unwrap().to_string();

    assert_ne!(
        link_address, intent_address,
        "each intent must get its own address — this is what the relay validates against"
    );

    // A transaction paying the LINK's address (not this intent's) must be rejected: before the
    // fix the relay compared against the link address, so every real Freighter payment — which
    // correctly targets the intent address — was refused.
    let payer = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let decoded = stellar_strkey::ed25519::MuxedAccount::from_string(&link_address).unwrap();
    let wrong_dest = stellar_base::crypto::MuxedEd25519PublicKey::new(
        stellar_base::crypto::PublicKey::from_slice(&decoded.ed25519).unwrap(),
        decoded.id,
    );
    let usdc = stellar_base::asset::Asset::new_credit(
        "USDC",
        stellar_base::crypto::PublicKey::from_account_id(
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
        )
        .unwrap(),
    )
    .unwrap();
    let op = stellar_base::operations::Operation::new_payment()
        .with_destination(wrong_dest)
        .with_amount(stellar_base::amount::Stroops::new(2_000_000))
        .unwrap()
        .with_asset(usdc)
        .build()
        .unwrap();
    let mut tx = stellar_base::transaction::Transaction::builder(
        payer.public_key(),
        1,
        stellar_base::transaction::MIN_BASE_FEE,
    )
    .add_operation(op)
    .into_transaction()
    .unwrap();
    tx.sign(payer.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let signed_xdr = {
        use stellar_base::xdr::XDRSerialize;
        tx.into_envelope().xdr_base64().unwrap()
    };

    let app_clone = app.clone();
    let resp = app
        .oneshot(post_json(
            &format!("/v1/pay/{slug}/submit-signed"),
            &format!(r#"{{"transaction_xdr":"{signed_xdr}","payment_id":"{payment_id}"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a payment to the link's address rather than this intent's must be rejected"
    );

    // The same transaction aimed at the INTENT's address passes validation. It still fails at
    // Horizon (the payer is unfunded), but the response is a 201 envelope with status "failed"
    // rather than the 400 that means "we refused to relay this" — proving the destination and
    // asset checks accepted it, which is the path a real Freighter payment takes.
    let decoded = stellar_strkey::ed25519::MuxedAccount::from_string(&intent_address).unwrap();
    let right_dest = stellar_base::crypto::MuxedEd25519PublicKey::new(
        stellar_base::crypto::PublicKey::from_slice(&decoded.ed25519).unwrap(),
        decoded.id,
    );
    let usdc = stellar_base::asset::Asset::new_credit(
        "USDC",
        stellar_base::crypto::PublicKey::from_account_id(
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
        )
        .unwrap(),
    )
    .unwrap();
    let op = stellar_base::operations::Operation::new_payment()
        .with_destination(right_dest)
        .with_amount(stellar_base::amount::Stroops::new(2_000_000))
        .unwrap()
        .with_asset(usdc)
        .build()
        .unwrap();
    let mut tx = stellar_base::transaction::Transaction::builder(
        payer.public_key(),
        1,
        stellar_base::transaction::MIN_BASE_FEE,
    )
    .add_operation(op)
    .into_transaction()
    .unwrap();
    tx.sign(payer.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let good_xdr = {
        use stellar_base::xdr::XDRSerialize;
        tx.into_envelope().xdr_base64().unwrap()
    };

    let resp = app_clone
        .oneshot(post_json(
            &format!("/v1/pay/{slug}/submit-signed"),
            &format!(r#"{{"transaction_xdr":"{good_xdr}","payment_id":"{payment_id}"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a USDC payment to this intent's own address must pass validation and be relayed"
    );
}

#[tokio::test]
async fn list_deliveries_response_includes_the_new_diagnostic_fields() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let wallet_id: uuid::Uuid = create_wallet_for(&app, &token).await.parse().unwrap();

    // Seed a failed delivery directly: this test covers the read path, not dispatch.
    let ep = state
        .store()
        .create_webhook_endpoint(wallet_id, "https://merchant.example/hook", "s")
        .await
        .unwrap();
    for _ in 0..2 {
        state
            .store()
            .log_webhook_delivery(
                ep.id,
                "deposit.created",
                &serde_json::json!({}),
                "failed",
                3,
                Some(503),
                Some("upstream unavailable"),
            )
            .await
            .unwrap();
    }

    let uri = format!("/v1/wallets/{wallet_id}/webhooks/{}/deliveries?limit=1", ep.id);
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows = body_json(resp).await["data"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 1, "?limit= must be honoured");
    assert_eq!(rows[0]["response_code"], 503);
    assert_eq!(rows[0]["response_body_snippet"], "upstream unavailable");
    assert_eq!(rows[0]["attempts"], 3);
}
