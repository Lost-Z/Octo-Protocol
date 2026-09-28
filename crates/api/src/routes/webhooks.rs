//! Webhook endpoint registration.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: Option<String>,
    /// Optional shared secret; one is generated if omitted.
    pub secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookView {
    pub id: Uuid,
    pub url: String,
    /// Returned once on creation so the caller can verify signatures.
    pub secret: String,
    pub active: bool,
}

/// `POST /v1/wallets/:id/webhooks`
pub async fn create_webhook(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<WebhookView>>)> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: CreateWebhookRequest = parse_optional(&body)?;
    let url = req
        .url
        .filter(|u| !u.is_empty())
        .ok_or_else(|| ApiError::BadRequest("url is required".into()))?;

    if !octo_webhooks::is_safe_url(&url) {
        return Err(ApiError::BadRequest(
            "url must be a public http(s) endpoint".into(),
        ));
    }

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    // Generate a secret if none supplied.
    let secret = req.secret.unwrap_or_else(generate_secret);

    let ep = state
        .store()
        .create_webhook_endpoint(wallet_id, &url, &secret)
        .await?;

    let view = WebhookView {
        id: ep.id,
        url: ep.url,
        secret: ep.secret,
        active: ep.active,
    };
    let (status, json) = Envelope::created(view);
    Ok((status, json))
}

#[derive(Debug, Deserialize)]
pub struct DeliveriesQuery {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<i64>,
}

/// Generate a random hex secret for HMAC signing.
fn generate_secret() -> String {
    // A v4 UUID (122 bits of randomness) rendered without dashes is a fine webhook secret.
    let a = Uuid::new_v4().simple().to_string();
    let b = Uuid::new_v4().simple().to_string();
    format!("{a}{b}")
}

#[derive(Debug, Serialize)]
pub struct WebhookDeliveryView {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub attempts: i32,
    pub response_code: Option<i32>,
    /// First ≤ 1 KiB of the endpoint's last response body, for self-service diagnosis.
    pub response_body_snippet: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// `DELETE /v1/wallets/:id/webhooks/:endpoint_id` — deactivate an endpoint.
///
/// Deactivates rather than hard-deletes so the delivery history (an audit trail) survives.
/// Returns 404 if the endpoint belongs to a different wallet, so existence is not leaked.
pub async fn delete_webhook(
    State(state): State<AppState>,
    Path((wallet_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    let endpoint = state.store().get_webhook_endpoint(endpoint_id).await?;
    if endpoint.wallet_id != wallet_id {
        return Err(ApiError::NotFound);
    }

    state
        .store()
        .deactivate_webhook_endpoint(endpoint_id)
        .await?;

    Ok(Envelope::ok(serde_json::json!({
        "id": endpoint_id,
        "active": false,
    })))
}

/// `GET /v1/wallets/:id/webhooks`
pub async fn list_webhooks(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<WebhookView>>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    let eps = state.store().active_webhook_endpoints(wallet_id).await?;
    let views: Vec<WebhookView> = eps
        .into_iter()
        .map(|ep| WebhookView {
            id: ep.id,
            url: ep.url,
            secret: ep.secret,
            active: ep.active,
        })
        .collect();

    Ok(Envelope::ok(views))
}

/// `GET /v1/wallets/:id/webhooks/:endpoint_id/deliveries` — an endpoint's delivery history,
/// newest first. `?limit=` (default 50, max 200).
pub async fn list_deliveries(
    State(state): State<AppState>,
    Path((wallet_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Query(q): Query<DeliveriesQuery>,
) -> ApiResult<Json<Envelope<Vec<WebhookDeliveryView>>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    let limit = q.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::BadRequest(
            "limit must be between 1 and 200".into(),
        ));
    }

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    // Confirm the endpoint exists and belongs to the wallet — don't leak whether it exists
    // under a different wallet.
    let endpoint = state.store().get_webhook_endpoint(endpoint_id).await?;
    if endpoint.wallet_id != wallet_id {
        return Err(ApiError::NotFound);
    }

    // Honour the validated `?limit=` (previously ignored in favour of a hardcoded 50).
    let deliveries = state
        .store()
        .list_webhook_deliveries(endpoint_id, limit)
        .await?;

    let views: Vec<WebhookDeliveryView> = deliveries
        .into_iter()
        .map(|d| WebhookDeliveryView {
            id: d.id,
            endpoint_id: d.endpoint_id,
            event_type: d.event_type,
            payload: d.payload,
            status: d.status,
            attempts: d.attempts,
            response_code: d.response_code,
            response_body_snippet: d.response_body_snippet,
            created_at: d.created_at,
            updated_at: d.updated_at,
        })
        .collect();

    Ok(Envelope::ok(views))
}
