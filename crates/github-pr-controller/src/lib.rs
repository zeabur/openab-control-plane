#![forbid(unsafe_code)]

pub mod closing;
pub mod config;
pub mod deciding;
pub mod github;
pub mod ocp;
pub mod planner;
pub mod runtime_events;
pub mod shadow;
pub mod store;
pub mod verdict;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, OriginalUri, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use config::{ComponentReadiness, Config, OperatingMode};
use controller_protocol::audit::{
    AuditActor, AuditCorrelation, AuditCursor, AuditError, AuditEvent, AuditEventQuery,
    AuditOutcome, AuditTarget, AUDIT_EVENT_VERSION, DEFAULT_RETENTION_DAYS,
    EXTENDED_RETENTION_DAYS,
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::{
    audit_timestamp, now_ms, DeliveryAdmission, ProductStore, ReviewFindingQuery,
    RuntimeEventAdmission, ShadowAdmission, WRITE_MAX_ATTEMPTS,
};

#[cfg(test)]
use store::SqliteStore;

type HmacSha256 = Hmac<Sha256>;
const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;
const DELIVERY_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const WRITE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const AUDIT_MAX_TIMESTAMP_SKEW_SECS: u64 = 5 * 60;
/// Writes drained per pass. One closed round queues at most three.
const WRITE_DRAIN_BATCH: i64 = 32;
const AUDIT_SERVICE: &str = "github-pr-controller";

fn controller_audit_event(
    event_key: impl Into<String>,
    kind: &str,
    outcome: AuditOutcome,
    occurred_at: i64,
    correlation: AuditCorrelation,
    detail: Value,
    error: Option<AuditError>,
) -> AuditEvent {
    let event_key = event_key.into();
    let actor = detail.get("actor").and_then(github_actor_from_detail);
    let target = github_target_from_detail(&detail);
    AuditEvent {
        version: AUDIT_EVENT_VERSION,
        event_id: format!("aud:{AUDIT_SERVICE}:{event_key}"),
        event_key,
        occurred_at: audit_timestamp(occurred_at),
        recorded_at: now_ms(),
        service: AUDIT_SERVICE.into(),
        kind: kind.into(),
        outcome,
        caused_by: None,
        correlation,
        actor,
        target,
        detail,
        error,
    }
}

fn github_actor_from_detail(detail: &Value) -> Option<AuditActor> {
    let kind = detail.get("kind")?.as_str()?.to_string();
    Some(AuditActor {
        kind,
        id: detail.get("id").and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_i64().map(|id| id.to_string()))
        }),
        display: detail
            .get("display")
            .and_then(Value::as_str)
            .map(str::to_string),
        association: detail
            .get("association")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Keep only the stable, authenticated sender fields from a verified GitHub
/// webhook. The raw sender object stays in neither the journal nor the detail
/// payload.
fn verified_github_actor(payload: &Value) -> Option<Value> {
    let sender = payload.get("sender")?;
    let id = sender.get("id")?.as_i64()?.to_string();
    let display = sender
        .get("login")
        .and_then(Value::as_str)
        .filter(|login| !login.is_empty())?;
    let association = sender
        .get("author_association")
        .and_then(Value::as_str)
        .or_else(|| payload["comment"]["author_association"].as_str())
        .or_else(|| payload["issue"]["author_association"].as_str())
        .or_else(|| payload["pull_request"]["author_association"].as_str());
    Some(json!({
        "kind": "github_user",
        "id": id,
        "display": display,
        "association": association,
    }))
}

fn github_pr_number(payload: &Value) -> Option<i64> {
    payload["number"]
        .as_i64()
        .or_else(|| payload["issue"]["number"].as_i64())
}

fn github_target_from_detail(detail: &Value) -> Option<AuditTarget> {
    let provider = detail.get("provider").unwrap_or(detail);
    let repository = provider
        .get("repository")
        .or_else(|| provider.get("repo"))
        .and_then(Value::as_str)
        .filter(|repository| !repository.is_empty())?;
    let pr_number = provider
        .get("pr_number")
        .or_else(|| provider.get("pull_request_number"))
        .and_then(Value::as_i64)?;
    let revision = provider
        .get("head_sha")
        .or_else(|| provider.get("sha"))
        .or_else(|| provider.get("revision"))
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(AuditTarget {
        kind: "github_pull_request".into(),
        reference: Some(format!("{repository}#{pr_number}")),
        revision,
    })
}

async fn append_controller_audit(
    store: &dyn ProductStore,
    event: AuditEvent,
) -> anyhow::Result<()> {
    store
        .append_audit_event(&event)
        .await
        .map_err(|error| anyhow::anyhow!("append audit event {}: {error}", event.event_key))?;
    Ok(())
}

pub struct AppState {
    pub config: Config,
    pub store: Option<Arc<dyn ProductStore>>,
    pub store_error: Option<String>,
    pub action_client: Option<Arc<dyn ocp::OcpActionClient>>,
    pub action_client_error: Option<String>,
    pub event_verifier: Option<Arc<runtime_events::RuntimeEventVerifier>>,
    pub event_verifier_error: Option<String>,
    /// Present only when this runtime is allowed to write (external_canary +
    /// the explicit switch). `None` leaves queued writes pending forever,
    /// which is the correct posture until the P7 cutover.
    pub github: Option<Arc<github::GitHubClient>>,
    /// Whether the configured bot handle still matches the App's own slug,
    /// probed once at startup. A rename in GitHub's UI silently kills every
    /// mention command — `@new-name review`, `dismiss`, `reopen` and asks all
    /// stop parsing, with no error in any log — so the mismatch is surfaced
    /// where an operator and the watchdog both already look.
    pub bot_identity: ComponentReadiness,
    /// Handles that count as addressing this bot, most authoritative first:
    /// the App's live slug, then the configured handle as an alias. Plural so
    /// a rename takes effect immediately without invalidating the name already
    /// sitting in older comments on the same thread.
    pub bot_handles: Vec<String>,
}

impl AppState {
    /// The name to PRINT — what a reader should type. Always the live slug
    /// when we know it: advertising the configured name after a rename is how
    /// the system ends up teaching a command that does nothing.
    pub fn bot_name(&self) -> &str {
        self.bot_handles
            .first()
            .map(String::as_str)
            .unwrap_or("bot")
    }
}

/// Resolve which names address this bot, and report how that went.
///
/// The App's slug is authoritative: it is what GitHub renders, what the bot's
/// own comments are signed with, and therefore what a user copies. The
/// configured handle is kept as an alias so a rename does not invalidate the
/// name already in people's fingers and in older comments.
///
/// Probed once at startup — readyz is polled often and this must not spend
/// rate limit. When the probe fails the configured handle stands alone, which
/// is exactly the old behaviour rather than a new failure.
async fn resolve_bot_handles(
    configured: Option<&str>,
    github: Option<&github::GitHubClient>,
) -> (ComponentReadiness, Vec<String>) {
    let configured_vec: Vec<String> = configured.map(str::to_string).into_iter().collect();
    let Some(github) = github else {
        return (
            ComponentReadiness::disabled("no GitHub client; handle unverified"),
            configured_vec,
        );
    };
    match github.app_slug().await {
        Ok(slug) => {
            let matches = configured.is_some_and(|handle| slug.eq_ignore_ascii_case(handle));
            let mut handles = vec![slug.clone()];
            handles.extend(configured_vec.into_iter().filter(|_| !matches));
            let readiness = if matches || configured.is_none() {
                ComponentReadiness::ready(format!("addressed as @{slug}"))
            } else {
                // Informational, not a fault: commands work under both names
                // from here. It still says so, because the configuration is
                // now stale and someone should tidy it.
                ComponentReadiness::ready(format!(
                    "addressed as @{slug} (the App's own name); \
                     GITHUB_CONTROLLER_BOT_HANDLE still says `{}` and is kept as an alias — \
                     update it when convenient",
                    configured.unwrap_or_default()
                ))
            };
            (readiness, handles)
        }
        Err(error) => {
            tracing::warn!(%error, "app slug probe failed; falling back to the configured handle");
            (
                ComponentReadiness::disabled("App slug unavailable; using the configured handle"),
                configured_vec,
            )
        }
    }
}

impl AppState {
    pub async fn from_config(config: Config) -> Self {
        let (store, store_error) = match store::open_product_store(&config.db_path).await {
            Ok(store) => (Some(store), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let (action_client, action_client_error) = if matches!(
            config.mode,
            OperatingMode::ExternalCanary | OperatingMode::External
        ) && config.ocp_action.is_complete()
        {
            match ocp::ReqwestOcpActionClient::new(&config.ocp_action) {
                Ok(client) => (
                    Some(Arc::new(client) as Arc<dyn ocp::OcpActionClient>),
                    None,
                ),
                Err(error) => (None, Some(error.to_string())),
            }
        } else {
            (None, None)
        };
        let (event_verifier, event_verifier_error) = match (
            config.ocp_action.controller_id.as_deref(),
            config.event_signing_secret.as_deref(),
        ) {
            (Some(controller_id), Some(secret))
                if matches!(
                    config.mode,
                    OperatingMode::ExternalCanary | OperatingMode::External
                ) =>
            {
                match runtime_events::RuntimeEventVerifier::new(controller_id, secret) {
                    Ok(verifier) => (Some(Arc::new(verifier)), None),
                    Err(error) => (None, Some(error.to_string())),
                }
            }
            _ => (None, None),
        };
        let github = github::GitHubClient::from_config(&config).map(Arc::new);
        let (bot_identity, bot_handles) =
            resolve_bot_handles(config.bot_handle.as_deref(), github.as_deref()).await;
        Self {
            config,
            store,
            store_error,
            action_client,
            action_client_error,
            event_verifier,
            event_verifier_error,
            github,
            bot_identity,
            bot_handles,
        }
    }

    pub fn with_components(
        config: Config,
        store: impl ProductStore + 'static,
        action_client: Option<Arc<dyn ocp::OcpActionClient>>,
        event_verifier: Option<Arc<runtime_events::RuntimeEventVerifier>>,
    ) -> Self {
        let github = github::GitHubClient::from_config(&config).map(Arc::new);
        let config_handles: Vec<String> = config.bot_handle.clone().into_iter().collect();
        Self {
            config,
            store: Some(Arc::new(store)),
            store_error: None,
            action_client,
            action_client_error: None,
            event_verifier,
            event_verifier_error: None,
            github,
            // Sync constructor: no probe here, so the configured handle stands
            // alone and an unverified name never reads as a mismatch.
            bot_identity: ComponentReadiness::disabled("handle unverified"),
            bot_handles: config_handles,
        }
    }

    #[cfg(test)]
    fn with_store(config: Config, store: SqliteStore) -> Self {
        Self::with_components(config, store, None, None)
    }

    fn product_store_readiness(&self) -> ComponentReadiness {
        if self.store.is_some() {
            ComponentReadiness::ready("controller product store available")
        } else {
            ComponentReadiness::not_ready("controller product store unavailable")
        }
    }

    fn readiness(&self) -> ReadinessReport {
        let ingress = self.config.ingress_readiness();
        let product_store = self.product_store_readiness();
        let github = self.config.github_readiness();
        let ownership = self.config.ownership_readiness();
        let mut ocp = self.config.ocp_readiness();
        if ocp.ready && self.action_client.is_none() {
            ocp = ComponentReadiness::not_ready("scoped OCP action client unavailable");
        }
        let mut runtime_events = self.config.event_readiness();
        if runtime_events.ready && self.event_verifier.is_none() {
            runtime_events = ComponentReadiness::not_ready("runtime-event verifier unavailable");
        }
        let bot_identity = self.bot_identity.clone();
        let ready = ingress.ready
            && product_store.ready
            && (bot_identity.ready || !bot_identity.enabled)
            && (github.ready || !github.enabled)
            && (ownership.ready || !ownership.enabled)
            && (ocp.ready || !ocp.enabled)
            && (runtime_events.ready || !runtime_events.enabled);
        ReadinessReport {
            status: if ready { "ready" } else { "not_ready" },
            mode: self.config.mode.as_str().to_string(),
            components: Components {
                ingress,
                ownership,
                ocp,
                runtime_events,
                github,
                product_store,
                bot_identity,
            },
        }
    }
}

#[derive(Serialize)]
struct ReadinessReport {
    status: &'static str,
    mode: String,
    components: Components,
}

#[derive(Serialize)]
struct Components {
    ingress: ComponentReadiness,
    ownership: ComponentReadiness,
    ocp: ComponentReadiness,
    runtime_events: ComponentReadiness,
    github: ComponentReadiness,
    product_store: ComponentReadiness,
    bot_identity: ComponentReadiness,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/api/v1/github/webhooks", post(handle_webhook))
        .route("/api/v1/shadow/compare", post(handle_shadow_compare))
        .route("/api/v1/shadow/summary", get(shadow_summary))
        .route("/api/v1/openab/events", post(handle_runtime_event))
        .route("/api/v1/audit/events", get(handle_audit_events))
        .route("/api/v1/review/findings", get(handle_review_findings))
        .route(
            "/api/v1/review/waivers",
            get(handle_list_waivers).post(handle_create_waiver),
        )
        .route("/api/v1/review/waivers/:id", patch(handle_update_waiver))
        .route("/api/v1/canary/summary", get(canary_summary))
        .layer(DefaultBodyLimit::max(MAX_WEBHOOK_BODY_BYTES))
        .with_state(state)
}

pub fn spawn_maintenance(state: &Arc<AppState>) {
    let Some(store) = state.store.clone() else {
        return;
    };
    let retention_days = configured_positive_days(
        "GITHUB_CONTROLLER_AUDIT_RETENTION_DAYS",
        DEFAULT_RETENTION_DAYS,
    );
    let extended_retention_days = configured_positive_days(
        "GITHUB_CONTROLLER_AUDIT_EXTENDED_RETENTION_DAYS",
        EXTENDED_RETENTION_DAYS,
    )
    .max(retention_days);
    // Outbox sweep: the event-driven drain only fires when a round closes, so
    // writes stranded by a wedged worker or a restart would otherwise sit
    // forever. The first tick fires immediately — that is the boot replay.
    if let Some(github) = state.github.clone() {
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(WRITE_SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let drained = drain_outbox_batch(&store, &github).await;
                if drained > 0 {
                    tracing::info!(drained, "outbox sweep claimed stranded github writes");
                }
            }
        });
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DELIVERY_PRUNE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match store.prune_completed_deliveries().await {
                Ok(pruned) if pruned > 0 => {
                    tracing::info!(pruned, "pruned expired webhook deliveries")
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "webhook delivery pruning failed"),
            }
            let now = now_ms();
            let before = now.saturating_sub(retention_days.saturating_mul(86_400_000));
            let extended_before =
                now.saturating_sub(extended_retention_days.saturating_mul(86_400_000));
            match store.prune_audit_events(before, extended_before).await {
                Ok(pruned) if pruned > 0 => {
                    let event_key = format!("audit.retention_pruned:{now}:{pruned}");
                    let event = controller_audit_event(
                        event_key,
                        "audit.retention_pruned",
                        AuditOutcome::Succeeded,
                        now,
                        AuditCorrelation::default(),
                        json!({
                            "pruned": pruned,
                            "retention_days": retention_days,
                            "extended_retention_days": extended_retention_days,
                            "before": before,
                            "extended_before": extended_before,
                        }),
                        None,
                    );
                    if let Err(error) = append_controller_audit(store.as_ref(), event).await {
                        tracing::warn!(%error, pruned, "audit retention evidence append failed");
                    } else {
                        tracing::info!(pruned, "pruned expired audit events");
                    }
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "audit retention sweep failed"),
            }
            // The waiver report's log-line half, on the tick that already
            // exists (no new channel): one line an operator's log search
            // finds, only when there is something to say. The endpoint
            // carries the same numbers for the weekly ops report.
            match store.list_review_waivers(None, false, now_unix()).await {
                Ok(waivers) if !waivers.is_empty() => {
                    let report = waiver_report(&waivers, now_unix());
                    tracing::info!(
                        active = report["active"].as_u64().unwrap_or_default(),
                        expiring_within_14d = %report["expiring_within_14d"],
                        renewed_twice_or_more = %report["renewed_twice_or_more"],
                        never_fired = report["never_fired"].as_u64().unwrap_or_default(),
                        "waiver report"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "waiver report read failed"),
            }
        }
    });
}

fn configured_positive_days(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|days: &i64| *days > 0)
        .unwrap_or(default)
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "alive",
        "mode": state.config.mode.as_str(),
        "readiness": state.readiness()
    }))
}

async fn readiness(State(state): State<Arc<AppState>>) -> Response {
    let report = state.readiness();
    let status = if report.status == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report)).into_response()
}

async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(secret) = state.config.webhook_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "webhook_hmac_not_configured"}),
        );
    };
    let signature = header(&headers, "x-hub-signature-256");
    if !verify_signature(secret, &body, signature) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_signature"}),
        );
    }

    let Some(delivery_id) = header(&headers, "x-github-delivery") else {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "missing_delivery_id"}),
        );
    };
    if !valid_delivery_id(delivery_id) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "invalid_delivery_id"}),
        );
    }
    let Some(event_type) = header(&headers, "x-github-event") else {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "missing_event_type"}),
        );
    };
    if !valid_event_type(event_type) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "invalid_event_type"}),
        );
    }
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"ok": false, "error": "invalid_json"}),
            )
        }
    };
    let repository = payload["repository"]["full_name"].as_str();
    if matches!(state.config.mode, OperatingMode::ExternalCanary)
        && repository != state.config.canary_repository.as_deref()
    {
        return response(
            StatusCode::CONFLICT,
            json!({"ok": false, "error": "repository_not_owned"}),
        );
    }
    if state.readiness().status != "ready" {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "controller_not_ready"}),
        );
    }
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };

    let payload_hash = hex::encode(Sha256::digest(&body));
    match store
        .begin_delivery(delivery_id, event_type, repository, &payload_hash)
        .await
    {
        Ok(DeliveryAdmission::New) => {
            if let Err(error) = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("ingress.received:{delivery_id}:{payload_hash}"),
                    "ingress.received",
                    AuditOutcome::Pending,
                    now_unix(),
                    AuditCorrelation {
                        delivery_id: Some(delivery_id.into()),
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({
                        "event_type": event_type,
                        "payload_sha256": payload_hash,
                        "repository": repository,
                        "pr_number": github_pr_number(&payload),
                        "actor": verified_github_actor(&payload),
                    }),
                    None,
                ),
            )
            .await
            {
                tracing::error!(%error, %delivery_id, "ingress journal append failed");
                let result = json!({"ok": false, "error": "audit_store_failed"});
                release_delivery_after_audit_failure(store.as_ref(), delivery_id, &result).await;
                return response(StatusCode::SERVICE_UNAVAILABLE, result);
            }
        }
        Ok(DeliveryAdmission::Duplicate {
            state: delivery_state,
            ..
        }) if delivery_state == "processing" => {
            let _ = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("ingress.duplicate:{delivery_id}:processing"),
                    "ingress.duplicate",
                    AuditOutcome::Ignored,
                    now_unix(),
                    AuditCorrelation {
                        delivery_id: Some(delivery_id.into()),
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({
                        "state": "processing",
                        "repository": repository,
                        "pr_number": github_pr_number(&payload),
                        "actor": verified_github_actor(&payload),
                    }),
                    None,
                ),
            )
            .await;
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "ok": false,
                    "duplicate": true,
                    "error": "delivery_in_progress"
                }),
            );
        }
        Ok(DeliveryAdmission::Duplicate {
            state: delivery_state,
            result,
        }) => {
            let _ = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("ingress.duplicate:{delivery_id}:{delivery_state}"),
                    "ingress.duplicate",
                    AuditOutcome::Ignored,
                    now_unix(),
                    AuditCorrelation {
                        delivery_id: Some(delivery_id.into()),
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({"state": delivery_state}),
                    None,
                ),
            )
            .await;
            return response(
                StatusCode::OK,
                json!({
                    "ok": true,
                    "duplicate": true,
                    "state": delivery_state,
                    "result": result
                }),
            );
        }
        Ok(DeliveryAdmission::Conflict) => {
            let _ = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("ingress.conflict:{delivery_id}:{payload_hash}"),
                    "ingress.conflict",
                    AuditOutcome::Denied,
                    now_unix(),
                    AuditCorrelation {
                        delivery_id: Some(delivery_id.into()),
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({"event_type": event_type}),
                    None,
                ),
            )
            .await;
            return response(
                StatusCode::CONFLICT,
                json!({"ok": false, "error": "delivery_payload_conflict"}),
            );
        }
        Err(error) => {
            tracing::error!(%error, %delivery_id, "delivery admission failed");
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "delivery_store_failed"}),
            );
        }
    }

    // A finding command mutates the ledger and what the pull request already
    // shows; it opens no session, so it never reaches the planner.
    if let Some(command) = planner::parse_finding_command(event_type, &payload, &state.bot_handles)
    {
        let reply = apply_finding_command(&state, &command).await;
        if let Some(github) = state.github.as_ref() {
            if let Err(error) = github
                .create_comment(&command.repository, command.pr_number as i64, &reply)
                .await
            {
                // The author is now waiting on a reply that will not come, so
                // this is louder than a write failure normally would be.
                tracing::error!(%error, repo = %command.repository, pr = command.pr_number, "finding-command reply failed");
            }
        }
        let result = json!({
            "ok": true,
            "planned": false,
            "reason": format!("finding_{}", command.verb),
        });
        if let Err(error) = store.finish_delivery(delivery_id, "handled", &result).await {
            tracing::error!(%error, %delivery_id, "finding-command delivery completion failed");
        }
        return response(StatusCode::OK, result);
    }

    let (durable_state, result) = match candidate_plan(&state, delivery_id, event_type, &payload)
        .await
    {
        Err(reason) => {
            let result = json!({"ok": true, "planned": false, "reason": reason});
            if let Err(error) = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("ingress.ignored:{delivery_id}"),
                    "ingress.ignored",
                    AuditOutcome::Ignored,
                    now_unix(),
                    AuditCorrelation {
                        delivery_id: Some(delivery_id.into()),
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({
                        "event_type": event_type,
                        "reason": reason,
                        "repository": repository,
                        "pr_number": github_pr_number(&payload),
                        "actor": verified_github_actor(&payload),
                    }),
                    None,
                ),
            )
            .await
            {
                tracing::error!(%error, %delivery_id, "ignored ingress journal append failed");
                let result = json!({"ok": false, "error": "audit_store_failed"});
                release_delivery_after_audit_failure(store.as_ref(), delivery_id, &result).await;
                return response(StatusCode::SERVICE_UNAVAILABLE, result);
            }
            ("ignored", result)
        }
        Ok(plan) if matches!(state.config.mode, OperatingMode::PlanOnly) => {
            let result = json!({"ok": true, "planned": true, "plan": plan});
            if let Err(error) = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("ingress.accepted:{delivery_id}"),
                    "ingress.accepted",
                    AuditOutcome::Accepted,
                    now_unix(),
                    AuditCorrelation {
                        delivery_id: Some(delivery_id.into()),
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({
                        "event_type": event_type,
                        "mode": "plan_only",
                        "repository": repository,
                        "pr_number": github_pr_number(&payload),
                        "actor": verified_github_actor(&payload),
                    }),
                    None,
                ),
            )
            .await
            {
                tracing::error!(%error, %delivery_id, "planned ingress journal append failed");
                let result = json!({"ok": false, "error": "audit_store_failed"});
                release_delivery_after_audit_failure(store.as_ref(), delivery_id, &result).await;
                return response(StatusCode::SERVICE_UNAVAILABLE, result);
            }
            ("planned", result)
        }
        Ok(plan) => {
            let action_id = format!("github-delivery-{delivery_id}");
            for (kind, outcome) in [
                ("action.received", AuditOutcome::Pending),
                ("action.accepted", AuditOutcome::Accepted),
            ] {
                if let Err(error) = append_controller_audit(
                    store.as_ref(),
                    controller_audit_event(
                        format!("{kind}:{action_id}"),
                        kind,
                        outcome,
                        now_unix(),
                        AuditCorrelation {
                            delivery_id: Some(delivery_id.into()),
                            controller_id: state.config.ocp_action.controller_id.clone(),
                            action_id: Some(action_id.clone()),
                            scope: state.config.ocp_action.scope.clone(),
                            trigger_ref: Some(plan.trigger_ref.clone()),
                            trigger_fingerprint: plan.trigger_fingerprint.clone(),
                            ..Default::default()
                        },
                        json!({
                            "event_type": event_type,
                            "repository": plan.repository.clone(),
                            "pr_number": plan.pr_number,
                            "actor": verified_github_actor(&payload),
                        }),
                        None,
                    ),
                )
                .await
                {
                    tracing::error!(%error, %delivery_id, "action journal append failed");
                    let result = json!({"ok": false, "error": "audit_store_failed"});
                    let _ = store.release_delivery_for_retry(delivery_id, &result).await;
                    return response(StatusCode::SERVICE_UNAVAILABLE, result);
                }
            }
            let Some(client) = state.action_client.as_ref() else {
                let result = json!({"ok": false, "error": "ocp_action_unavailable"});
                let _ = append_controller_audit(
                    store.as_ref(),
                    controller_audit_event(
                        format!("action.failed:{action_id}"),
                        "action.failed",
                        AuditOutcome::Failed,
                        now_unix(),
                        AuditCorrelation {
                            delivery_id: Some(delivery_id.into()),
                            controller_id: state.config.ocp_action.controller_id.clone(),
                            action_id: Some(action_id.clone()),
                            scope: state.config.ocp_action.scope.clone(),
                            trigger_ref: Some(plan.trigger_ref.clone()),
                            trigger_fingerprint: plan.trigger_fingerprint.clone(),
                            ..Default::default()
                        },
                        json!({"error_code": "ocp_action_unavailable"}),
                        Some(AuditError {
                            class: "ocp_action_unavailable".into(),
                            retryable: true,
                            message: None,
                            status: Some(503),
                        }),
                    ),
                )
                .await;
                let _ = store.release_delivery_for_retry(delivery_id, &result).await;
                return response(StatusCode::SERVICE_UNAVAILABLE, result);
            };
            let mut open_action = plan.open_session_action();
            // ADR 035 P2: the chair — and only the chair — sees the repo's
            // active waivers in its opening input. This side knows the repo
            // natively; no trigger_ref parsing, no hashed-ref blindness (the
            // kernel's version died of exactly that). Council opens only: an
            // ask session is a solo answer, and the block is synthesis
            // instruction — noise there (the kernel's ref parser skipped ask
            // refs by accident of format; this makes it deliberate).
            if plan.mode == "council" {
                let mut context = String::new();
                if let Some(block) = waiver_block_for_repo(store.as_ref(), &plan.repository).await {
                    context.push_str(&block);
                }
                // ADR 038: what the author already answered on THIS pull
                // request. Without it the next round re-raises what was just
                // dealt with, which reads as the tool forgetting — and the
                // chair could read it from the thread anyway, so this only
                // makes an existing channel reliable.
                if let Some(block) =
                    dismissed_block_for_pr(store.as_ref(), &plan.repository, plan.pr_number as i64)
                        .await
                {
                    context.push_str(&block);
                }
                if !context.is_empty() {
                    let fallback = open_action.prompt.clone();
                    open_action
                        .recipient_inputs
                        .entry(plan.chair_bot.clone())
                        .or_insert(fallback)
                        .push_str(&context);
                }
            }
            match client.open_session(action_id.clone(), open_action).await {
                Ok(action_result) => {
                    if let Err(error) = append_controller_audit(
                        store.as_ref(),
                        controller_audit_event(
                            format!("action.completed:{action_id}"),
                            "action.completed",
                            AuditOutcome::Succeeded,
                            now_unix(),
                            AuditCorrelation {
                                delivery_id: Some(delivery_id.into()),
                                controller_id: state.config.ocp_action.controller_id.clone(),
                                action_id: Some(action_id.clone()),
                                scope: state.config.ocp_action.scope.clone(),
                                trigger_ref: Some(plan.trigger_ref.clone()),
                                trigger_fingerprint: plan.trigger_fingerprint.clone(),
                                session_id: opened_session_id(&action_result).map(str::to_string),
                                ..Default::default()
                            },
                            json!({"http_status": 200}),
                            None,
                        ),
                    )
                    .await
                    {
                        tracing::error!(%error, %delivery_id, "completed action journal append failed");
                        let result = json!({"ok": false, "error": "audit_store_failed"});
                        let _ = store.release_delivery_for_retry(delivery_id, &result).await;
                        return response(StatusCode::SERVICE_UNAVAILABLE, result);
                    }
                    // The terminal event will name only this session id. What
                    // it is *about* is provider knowledge the kernel does not
                    // keep, so record it now or the close is unactionable.
                    if let Some(session_id) = opened_session_id(&action_result) {
                        // A comment-triggered round has no webhook sha. Ask
                        // GitHub for the PR's head so the closing status has a
                        // commit to pin to — otherwise an approved re-review
                        // can never overwrite the failure status it answers.
                        // Review rounds only: an /ask session closes with no
                        // verdict trailer, so giving it a sha would turn every
                        // answered question into an `error` status stomping the
                        // last real verdict (council F1, #312).
                        let mut head_sha = plan.head_sha().map(str::to_string);
                        if head_sha.is_none() && plan.reason != "ask" {
                            if let Some(github) = state.github.as_ref() {
                                match github
                                    .pull_head_sha(&plan.repository, plan.pr_number as i64)
                                    .await
                                {
                                    Ok(sha) => head_sha = Some(sha),
                                    Err(error) => tracing::warn!(
                                        %error,
                                        session_id,
                                        "pr head lookup failed; round will close without a status"
                                    ),
                                }
                            }
                        }
                        if let Err(error) = store
                            .record_session_target(
                                session_id,
                                &plan.repository,
                                plan.pr_number as i64,
                                head_sha.as_deref(),
                                Some(plan.reason.as_str()),
                                Some(plan.quorum_n),
                            )
                            .await
                        {
                            tracing::error!(%error, session_id, "session target persistence failed");
                        }
                        // The opening comment is queued HERE, not on the
                        // plane's session.opened event: that event races the
                        // session-target write above and lost in practice
                        // (dev, 2026-08-01) — the action result is the
                        // race-free "session exists" signal. Ask sessions get
                        // no round comment; they answer in their own reply.
                        if plan.reason != "ask" {
                            let round = store
                                .next_round(&plan.repository, plan.pr_number as i64)
                                .await
                                .unwrap_or(1);
                            let payload = json!({
                                "repo": plan.repository,
                                "pr_number": plan.pr_number,
                                "round": round,
                            });
                            if let Err(error) = store
                                .enqueue_write(session_id, closing::KIND_COMMENT_OPEN, &payload)
                                .await
                            {
                                tracing::error!(
                                    %error,
                                    session_id,
                                    "opening-comment enqueue failed"
                                );
                            }
                            spawn_write_drain(&state);
                        }
                    }
                    (
                        "acted",
                        json!({
                            "ok": true,
                            "planned": true,
                            "acted": true,
                            "action_id": action_id,
                            "action_result": action_result,
                            "plan": plan,
                        }),
                    )
                }
                Err(error) => {
                    tracing::warn!(
                        %delivery_id,
                        action_id,
                        error = ?error,
                        "external canary action failed; retaining provider retry path"
                    );
                    let result = json!({"ok": false, "error": error.public_code()});
                    let _ = append_controller_audit(
                        store.as_ref(),
                        controller_audit_event(
                            format!("action.failed:{action_id}"),
                            "action.failed",
                            AuditOutcome::Failed,
                            now_unix(),
                            AuditCorrelation {
                                delivery_id: Some(delivery_id.into()),
                                controller_id: state.config.ocp_action.controller_id.clone(),
                                action_id: Some(action_id.clone()),
                                scope: state.config.ocp_action.scope.clone(),
                                trigger_ref: Some(plan.trigger_ref.clone()),
                                trigger_fingerprint: plan.trigger_fingerprint.clone(),
                                ..Default::default()
                            },
                            json!({"error_code": error.public_code()}),
                            Some(AuditError {
                                class: error.public_code().into(),
                                retryable: true,
                                message: None,
                                status: None,
                            }),
                        ),
                    )
                    .await;
                    if let Err(store_error) =
                        store.release_delivery_for_retry(delivery_id, &result).await
                    {
                        tracing::error!(%store_error, %delivery_id, "retryable delivery persistence failed");
                    }
                    return response(StatusCode::SERVICE_UNAVAILABLE, result);
                }
            }
        }
    };
    if let Err(error) = append_controller_audit(
        store.as_ref(),
        controller_audit_event(
            format!(
                "ingress.{}:{delivery_id}",
                if durable_state == "ignored" {
                    "ignored"
                } else {
                    "accepted"
                }
            ),
            if durable_state == "ignored" {
                "ingress.ignored"
            } else {
                "ingress.accepted"
            },
            if durable_state == "ignored" {
                AuditOutcome::Ignored
            } else {
                AuditOutcome::Accepted
            },
            now_unix(),
            AuditCorrelation {
                delivery_id: Some(delivery_id.into()),
                controller_id: state.config.ocp_action.controller_id.clone(),
                action_id: result["action_id"].as_str().map(str::to_string),
                ..Default::default()
            },
            json!({"state": durable_state}),
            None,
        ),
    )
    .await
    {
        tracing::error!(%error, %delivery_id, "final ingress journal append failed");
        let result = json!({"ok": false, "error": "audit_store_failed"});
        release_delivery_after_audit_failure(store.as_ref(), delivery_id, &result).await;
        return response(StatusCode::SERVICE_UNAVAILABLE, result);
    }
    if let Err(error) = store
        .finish_delivery(delivery_id, durable_state, &result)
        .await
    {
        tracing::error!(%error, %delivery_id, "delivery completion failed");
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "delivery_store_failed"}),
        );
    }

    let status = if matches!(durable_state, "planned" | "acted") {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    response(status, result)
}

async fn handle_runtime_event(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.config.event_readiness().ready {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "runtime_event_receiver_not_configured"}),
        );
    }
    let Some(verifier) = state.event_verifier.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "runtime_event_receiver_not_configured"}),
        );
    };
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    let event = match verifier.verify(
        header(&headers, "x-oab-controller-id"),
        header(&headers, "x-oab-event-id"),
        header(&headers, "x-oab-timestamp"),
        header(&headers, "x-oab-signature"),
        target,
        &body,
        now_unix(),
    ) {
        Ok(event) => event,
        Err(error) => {
            let status = match error {
                runtime_events::VerificationError::InvalidSignature
                | runtime_events::VerificationError::StaleTimestamp => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_REQUEST,
            };
            return response(status, json!({"ok": false, "error": error.public_code()}));
        }
    };
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    let body_hash = hex::encode(Sha256::digest(&body));
    match store.record_runtime_event(&body_hash, &event).await {
        Ok(RuntimeEventAdmission::New) => {
            if let Err(error) = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("runtime_event.received:{}", event.event_id),
                    "runtime_event.received",
                    AuditOutcome::Accepted,
                    event.occurred_at,
                    AuditCorrelation {
                        controller_id: Some(event.controller_id.clone()),
                        session_id: event.session_id.clone(),
                        runtime_event_id: Some(event.event_id.clone()),
                        ..Default::default()
                    },
                    json!({"event_type": event.event_type}),
                    None,
                ),
            )
            .await
            {
                tracing::error!(%error, event_id = event.event_id, "runtime-event journal append failed");
                return response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"ok": false, "error": "audit_store_failed"}),
                );
            }
            tracing::info!(
                event_id = event.event_id,
                event_type = event.event_type,
                session_id = event.session_id,
                "accepted signed runtime event"
            );
            let closed = dispatch_terminal(&state, store, &event).await;
            dispatch_abandoned(&state, store, &event).await;
            response(
                StatusCode::OK,
                json!({"ok": true, "duplicate": false, "closed": closed}),
            )
        }
        Ok(RuntimeEventAdmission::Duplicate) => {
            let _ = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("runtime_event.duplicate:{}:{}", event.event_id, body_hash),
                    "runtime_event.duplicate",
                    AuditOutcome::Ignored,
                    now_unix(),
                    AuditCorrelation {
                        controller_id: Some(event.controller_id.clone()),
                        session_id: event.session_id.clone(),
                        runtime_event_id: Some(event.event_id.clone()),
                        ..Default::default()
                    },
                    json!({"event_type": event.event_type}),
                    None,
                ),
            )
            .await;
            response(StatusCode::OK, json!({"ok": true, "duplicate": true}))
        }
        Ok(RuntimeEventAdmission::Conflict) => {
            let _ = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("runtime_event.conflict:{}:{}", event.event_id, body_hash),
                    "runtime_event.conflict",
                    AuditOutcome::Denied,
                    now_unix(),
                    AuditCorrelation {
                        controller_id: Some(event.controller_id.clone()),
                        session_id: event.session_id.clone(),
                        runtime_event_id: Some(event.event_id.clone()),
                        ..Default::default()
                    },
                    json!({"event_type": event.event_type}),
                    None,
                ),
            )
            .await;
            response(
                StatusCode::CONFLICT,
                json!({"ok": false, "error": "runtime_event_payload_conflict"}),
            )
        }
        Err(error) => {
            tracing::error!(%error, "runtime-event receipt persistence failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "runtime_event_store_failed"}),
            )
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct AuditEventsParams {
    delivery_id: Option<String>,
    controller_id: Option<String>,
    action_id: Option<String>,
    runtime_event_id: Option<String>,
    session_id: Option<String>,
    message_id: Option<String>,
    write_id: Option<String>,
    trigger_ref: Option<String>,
    kind: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn handle_audit_events(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(params): Query<AuditEventsParams>,
) -> Response {
    let Some(secret) = state.config.observer_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "observation_hmac_not_configured"}),
        );
    };
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    if !verify_audit_signature(
        secret,
        target,
        header(&headers, "x-canary-audit-timestamp"),
        header(&headers, "x-canary-audit-signature-256"),
        now_unix(),
    ) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_observation_signature"}),
        );
    }
    let cursor = match params.cursor.as_deref() {
        Some(value) => match AuditCursor::decode(value) {
            Some(cursor) => Some(cursor),
            None => {
                return response(
                    StatusCode::BAD_REQUEST,
                    json!({"ok": false, "error": "invalid_audit_cursor"}),
                )
            }
        },
        None => None,
    };
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    match store
        .audit_events(&AuditEventQuery {
            delivery_id: params.delivery_id,
            controller_id: params.controller_id,
            action_id: params.action_id,
            runtime_event_id: params.runtime_event_id,
            session_id: params.session_id,
            message_id: params.message_id,
            write_id: params.write_id,
            trigger_ref: params.trigger_ref,
            kind: params.kind,
            since: params.since,
            until: params.until,
            cursor,
            limit: params.limit.unwrap_or_default(),
        })
        .await
    {
        Ok(page) => response(
            StatusCode::OK,
            serde_json::to_value(page).unwrap_or_default(),
        ),
        Err(error) => {
            tracing::error!(%error, "audit event query failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "audit_store_failed"}),
            )
        }
    }
}

/// Query params for the findings read. Same names the kernel's
/// `/v1/review/findings` took, so the ops scripts only change host and auth.
#[derive(Debug, serde::Deserialize)]
struct ReviewFindingsParams {
    repo: Option<String>,
    pr: Option<i64>,
    status: Option<String>,
    severity: Option<String>,
    limit: Option<usize>,
}

/// `GET /api/v1/review/findings` — the reporting read for the findings ledger.
///
/// The kernel kept a copy of this ledger, but it can only fill `repo`/`pr` for
/// sessions whose trigger_ref it can parse, which no controller session has;
/// its rows have been NULL there since the cutover (SEI-895). The controller
/// records both from the webhook payload, so this is the copy worth reading.
///
/// Auth is the same signed-observation scheme as the audit read, not a bearer:
/// one credential shape for every operator read on this service.
async fn handle_review_findings(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(params): Query<ReviewFindingsParams>,
) -> Response {
    let Some(secret) = state.config.observer_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "observation_hmac_not_configured"}),
        );
    };
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    if !verify_audit_signature(
        secret,
        target,
        header(&headers, "x-canary-audit-timestamp"),
        header(&headers, "x-canary-audit-signature-256"),
        now_unix(),
    ) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_observation_signature"}),
        );
    }
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    // Clamped, not rejected: a reporting script asking for everything should
    // get a bounded page rather than a 400.
    let limit = params.limit.unwrap_or(100).clamp(1, 5000);
    match store
        .review_findings(&ReviewFindingQuery {
            repo: params.repo,
            pr_number: params.pr,
            status: params.status,
            severity: params.severity,
            limit,
        })
        .await
    {
        Ok(findings) => response(
            StatusCode::OK,
            json!({ "findings": findings, "limit": limit }),
        ),
        Err(error) => {
            tracing::error!(%error, "review findings query failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "findings_store_failed"}),
            )
        }
    }
}

/// v2 operator-write signature: same secret as observation reads, but the
/// canonical payload binds the METHOD and the body hash too —
/// `v2\n{ts}\n{METHOD}\n{target}\n{hex(sha256(body))}` — so a captured GET
/// signature can never be replayed as a write, nor one body as another.
fn verify_operator_write_signature(
    secret: &str,
    method: &str,
    target: &str,
    body: &[u8],
    timestamp_header: Option<&str>,
    signature_header: Option<&str>,
    now_secs: i64,
) -> bool {
    let Some(timestamp) = timestamp_header.and_then(|value| value.parse::<i64>().ok()) else {
        return false;
    };
    if now_secs.abs_diff(timestamp) > AUDIT_MAX_TIMESTAMP_SKEW_SECS {
        return false;
    }
    let canonical = format!(
        "v2\n{timestamp}\n{method}\n{target}\n{}",
        hex::encode(Sha256::digest(body))
    );
    verify_signature(secret, canonical.as_bytes(), signature_header)
}

#[derive(Debug, serde::Deserialize)]
struct ListWaiversParams {
    repo: Option<String>,
    /// Query strings are not JSON booleans (the kernel's lesson): accept
    /// `1`/`true`/`yes`, treat anything else — or absence — as false.
    #[serde(default, deserialize_with = "flag_from_query")]
    all: bool,
}

fn flag_from_query<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(matches!(
        raw.as_deref(),
        Some("1") | Some("true") | Some("yes")
    ))
}

/// `GET /api/v1/review/waivers` — same signed-observation auth as the other
/// operator reads.
async fn handle_list_waivers(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(params): Query<ListWaiversParams>,
) -> Response {
    let Some(secret) = state.config.observer_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "observation_hmac_not_configured"}),
        );
    };
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    if !verify_audit_signature(
        secret,
        target,
        header(&headers, "x-canary-audit-timestamp"),
        header(&headers, "x-canary-audit-signature-256"),
        now_unix(),
    ) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_observation_signature"}),
        );
    }
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    match store
        .list_review_waivers(params.repo.as_deref(), params.all, now_unix())
        .await
    {
        Ok(waivers) => {
            // The report block rides along on every read: the weekly ops
            // report is the consumer the ADRs envisage, and this saves it
            // re-deriving the judgement inputs from raw rows.
            let report = waiver_report(&waivers, now_unix());
            response(
                StatusCode::OK,
                json!({ "waivers": waivers, "report": report }),
            )
        }
        Err(error) => {
            tracing::error!(%error, "waiver list failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "waiver_store_failed"}),
            )
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct CreateWaiverBody {
    repo: String,
    #[serde(default)]
    path_class: Option<String>,
    text: String,
    #[serde(default)]
    origin_pr: Option<String>,
    created_by: String,
    /// Unix SECONDS (controller convention; the kernel's API took ms).
    expires_at: i64,
}

/// `POST /api/v1/review/waivers` — ADR 035 P1, the human gate. Only the
/// operator secret writes waivers; PR content never does.
async fn handle_create_waiver(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(secret) = state.config.operator_write_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "operator_write_secret_not_configured"}),
        );
    };
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    if !verify_operator_write_signature(
        secret,
        "POST",
        target,
        &body,
        header(&headers, "x-canary-audit-timestamp"),
        header(&headers, "x-canary-audit-signature-256"),
        now_unix(),
    ) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_operator_signature"}),
        );
    }
    let Ok(request) = serde_json::from_slice::<CreateWaiverBody>(&body) else {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "invalid_waiver_body"}),
        );
    };
    // The kernel's exact caps, ported with the surface: trimmed before
    // storage (an untrimmed repo would break exact-match scoping) and
    // bounded (this text is injected into the chair's opening input).
    let repo = request.repo.trim();
    let text = request.text.trim();
    let created_by = request.created_by.trim();
    let path_class = request.path_class.as_deref().map(str::trim);
    let origin_pr = request.origin_pr.as_deref().map(str::trim);
    if repo.is_empty() || repo.len() > 200 {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "repo_must_be_1_to_200_bytes"}),
        );
    }
    if text.is_empty() || text.len() > 2000 {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "text_must_be_1_to_2000_bytes"}),
        );
    }
    if created_by.is_empty() || created_by.len() > 100 {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "created_by_must_be_1_to_100_bytes"}),
        );
    }
    if path_class.is_some_and(|v| v.len() > 300) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "path_class_must_be_at_most_300_bytes"}),
        );
    }
    if origin_pr.is_some_and(|v| v.len() > 200) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "origin_pr_must_be_at_most_200_bytes"}),
        );
    }
    if request.expires_at <= now_unix() {
        // The kernel said it best: waivers without expiry are how blindness
        // fossilizes.
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "expires_at_must_be_future"}),
        );
    }
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    match store
        .create_review_waiver(
            repo,
            path_class,
            text,
            origin_pr,
            created_by,
            request.expires_at,
            store::WAIVER_SOURCE_OPERATOR,
        )
        .await
    {
        Ok(waiver) => {
            let _ = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("waiver.created:{}", waiver.id),
                    "waiver.created",
                    AuditOutcome::Succeeded,
                    now_unix(),
                    AuditCorrelation {
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({"waiver_id": waiver.id, "repo": waiver.repo,
                           "created_by": waiver.created_by,
                           "expires_at": waiver.expires_at}),
                    None,
                ),
            )
            .await;
            response(StatusCode::CREATED, json!({ "waiver": waiver }))
        }
        Err(error) => {
            tracing::error!(%error, "waiver create failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "waiver_store_failed"}),
            )
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct UpdateWaiverBody {
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    revoke: bool,
}

/// `PATCH /api/v1/review/waivers/:id` — extend or revoke.
async fn handle_update_waiver(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Path(waiver_id): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(secret) = state.config.operator_write_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "operator_write_secret_not_configured"}),
        );
    };
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    if !verify_operator_write_signature(
        secret,
        "PATCH",
        target,
        &body,
        header(&headers, "x-canary-audit-timestamp"),
        header(&headers, "x-canary-audit-signature-256"),
        now_unix(),
    ) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_operator_signature"}),
        );
    }
    let Ok(request) = serde_json::from_slice::<UpdateWaiverBody>(&body) else {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "invalid_waiver_body"}),
        );
    };
    // The kernel's two PATCH guards, ported with the surface: a patch that
    // changes nothing is a caller bug, and an extension into the past would
    // be a silent revoke wearing the wrong name.
    if request.expires_at.is_none() && !request.revoke {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "empty_patch"}),
        );
    }
    if request.expires_at.is_some_and(|at| at <= now_unix()) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "expires_at_must_be_future"}),
        );
    }
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    match store
        .update_review_waiver(&waiver_id, request.expires_at, request.revoke)
        .await
    {
        Ok(true) => {
            let _ = append_controller_audit(
                store.as_ref(),
                controller_audit_event(
                    format!("waiver.updated:{}:{}", waiver_id, now_unix()),
                    "waiver.updated",
                    AuditOutcome::Succeeded,
                    now_unix(),
                    AuditCorrelation {
                        controller_id: state.config.ocp_action.controller_id.clone(),
                        ..Default::default()
                    },
                    json!({"waiver_id": waiver_id, "revoke": request.revoke,
                           "expires_at": request.expires_at}),
                    None,
                ),
            )
            .await;
            response(StatusCode::OK, json!({"ok": true}))
        }
        Ok(false) => response(
            StatusCode::NOT_FOUND,
            json!({"ok": false, "error": "unknown_waiver"}),
        ),
        Err(error) => {
            tracing::error!(%error, "waiver update failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "waiver_store_failed"}),
            )
        }
    }
}

/// The ACTIVE WAIVERS block for a repo, or None when it has none active.
/// Ported from the kernel (SEI-895): the wording is chair-facing contract —
/// steering references it — so it moves verbatim. Injection happens at the
/// dispatch site below, not in the planner, which stays a pure function for
/// shadow parity.
/// The PR's own author-dismissed findings, for the chair's opening input.
async fn dismissed_block_for_pr(
    store: &dyn store::ProductStore,
    repo: &str,
    pr_number: i64,
) -> Option<String> {
    let query = store::ReviewFindingQuery {
        repo: Some(repo.to_string()),
        pr_number: Some(pr_number),
        status: Some("dismissed".into()),
        severity: None,
        limit: 50,
    };
    match store.review_findings(&query).await {
        Ok(rows) => deciding::dismissed_block(&rows),
        Err(error) => {
            tracing::warn!(%error, repo, pr_number, "dismissed-findings lookup failed; round opens without");
            None
        }
    }
}

/// "Soon" for the waiver report's expiring list. The ADRs name no window;
/// two weeks covers two cycles of the weekly ops report the entries feed, so
/// nothing can lapse between one report an operator skims and the next.
const WAIVER_EXPIRING_SOON_SECS: i64 = 14 * 86_400;

/// The controller half of the ADR 035/038 periodic waiver report.
///
/// The report proper — hit rates, masking detection, intake — is the ops
/// repo's weekly quality loop (ADR 035); this is the smallest summary that
/// serves the two judgements the ADRs put on a clock: "expiry is the
/// classifier" (what lapses soon) and "a waiver renewed twice is a rule
/// wearing a waiver's clothes" (what keeps being renewed). Counts for
/// context, ids where the operator must act.
fn waiver_report(waivers: &[store::ReviewWaiver], now: i64) -> Value {
    let active: Vec<&store::ReviewWaiver> = waivers
        .iter()
        .filter(|waiver| waiver.revoked_at.is_none() && waiver.expires_at > now)
        .collect();
    let expiring_soon: Vec<&str> = active
        .iter()
        .filter(|waiver| waiver.expires_at <= now + WAIVER_EXPIRING_SOON_SECS)
        .map(|waiver| waiver.id.as_str())
        .collect();
    let renewed_twice_or_more: Vec<&str> = active
        .iter()
        .filter(|waiver| waiver.renewal_count >= 2)
        .map(|waiver| waiver.id.as_str())
        .collect();
    let never_fired = active
        .iter()
        .filter(|waiver| waiver.fired_count == 0)
        .count();
    json!({
        "active": active.len(),
        "expiring_within_14d": expiring_soon,
        "never_fired": never_fired,
        // The promotion queue: these belong in the repo's Review Boundaries,
        // and their waivers revoked (ADR 038 point 3).
        "renewed_twice_or_more": renewed_twice_or_more,
    })
}

async fn waiver_block_for_repo(store: &dyn store::ProductStore, repo: &str) -> Option<String> {
    let now = now_unix();
    let waivers = match store.list_review_waivers(Some(repo), false, now).await {
        Ok(waivers) => waivers,
        Err(error) => {
            tracing::warn!(%error, repo, "waiver lookup failed; session opens without");
            return None;
        }
    };
    if waivers.is_empty() {
        return None;
    }
    // Two provenances share the ledger (ADR 038 point 7), so the header
    // labels per entry instead of asserting one source for all: an operator
    // entry is free text recorded via the signed API; an author entry is a
    // waived council finding whose text is the council-authored title —
    // attenuated, not clean, and never the author's prose.
    let mut block = String::from(
        "\n\n===== ACTIVE WAIVERS (ADR 035 / ADR 038) =====\n\
         Accepted trade-offs from the waiver ledger — never shown to \
         reviewers. Each entry names its provenance: recorded by the operator, \
         or `waived by @<login>` — an author-accepted council finding whose \
         text is the council's own title for it, never the author's prose. At \
         synthesis: a finding matching a waiver goes in a `Waived` table row \
         (visible, never an open \u{1F534}/\u{1F7E1}, never blocking), and its entry in \
         the machine findings block carries \
         \"status\":\"waived\",\"waiver_id\":\"<id>\". A finding that only \
         partially matches stays open — when in doubt, it is not waived.\n",
    );
    // Flattened defensively regardless of provenance: one line per waiver,
    // bounded, and no run of '=' can imitate the block delimiters. Author
    // entries carry council-authored words, but the path is verbatim from the
    // diff and the title summarizes author-controlled code.
    let sanitize = |raw: &str, max: usize| {
        let flat = raw
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("=====", "-");
        if flat.chars().count() <= max {
            flat
        } else {
            flat.chars().take(max).collect::<String>() + "…"
        }
    };
    for waiver in &waivers {
        let days_left = (waiver.expires_at - now).max(0) / 86_400;
        let scope = waiver
            .path_class
            .as_deref()
            .map(|p| format!(" [{}]", sanitize(p, 120)))
            .unwrap_or_default();
        if waiver.source == store::WAIVER_SOURCE_AUTHOR {
            block.push_str(&format!(
                "- {}{}: \"{}\" (waived by @{}, expires in {}d)\n",
                waiver.id,
                scope,
                sanitize(&waiver.text, 80),
                sanitize(&waiver.created_by, 40),
                days_left
            ));
        } else {
            block.push_str(&format!(
                "- {}{}: {} (operator, expires in {}d)\n",
                waiver.id,
                scope,
                sanitize(&waiver.text, 2000),
                days_left
            ));
        }
    }
    block.push_str("===== END ACTIVE WAIVERS =====\n");
    Some(block)
}

/// The session id an `open_session` result carries, whether it opened a new
/// session or superseded an older one.
fn opened_session_id(result: &controller_protocol::ActionResultEnvelope) -> Option<&str> {
    match &result.result {
        controller_protocol::ControllerActionResult::SessionOpened { session_id, .. }
        | controller_protocol::ControllerActionResult::Superseded { session_id, .. } => {
            Some(session_id)
        }
        _ => None,
    }
}

/// Turn a normal-close `session.terminal` into a persisted round and queued
/// GitHub writes. Returns false when the event is not ours to act on.
///
/// Deliberately infallible from the caller's side: the event receipt has
/// already been recorded, so a failure here must not make the plane retry the
/// whole delivery — the outbox is what retries.
/// A session that ends without a verdict (superseded by a newer round, or
/// timed out) must not leave its opening post claiming to review forever —
/// rewrite it to say what happened. The opening post itself is queued from
/// the open_session action result in `handle_webhook`, not from here: the
/// plane's session.opened event races the session-target write and loses.
async fn dispatch_abandoned(
    state: &Arc<AppState>,
    store: &Arc<dyn ProductStore>,
    event: &runtime_events::RuntimeEventEnvelope,
) -> bool {
    let timed_out = event.event_type == "session.timeout"
        || (event.event_type == "session.terminal"
            && event.payload["reason"].as_str() == Some("timeout"));
    if !timed_out && event.event_type != "session.superseded" {
        return false;
    }
    let kind = closing::KIND_COMMENT_ABANDON;
    let Some(session_id) = event.session_id.as_deref() else {
        return false;
    };
    let target = match store.session_target(session_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return false,
        Err(error) => {
            tracing::error!(%error, session_id, "session target lookup failed");
            return false;
        }
    };
    // A timeout must be visible even if the opening comment was never posted.
    // Supersede deliberately does not write a status: the replacement round
    // may be reviewing the same SHA.
    if timed_out && target.reason.as_deref() != Some("ask") {
        let mut writes = vec![(
            closing::KIND_COMMENT,
            json!({
                "repo": target.repo,
                "pr_number": target.pr_number,
                "comment_id": Value::Null,
                "body": format!("⚠️ Review Council timed out without a verdict. No formal review was submitted. Re-run the council after reviewer readiness is restored.\n\n{}", closing::round_marker(session_id)),
            }),
        )];
        if let Some(sha) = target
            .head_sha
            .as_deref()
            .and_then(closing::canonical_commit_id)
        {
            writes.push((
                closing::KIND_STATUS,
                json!({
                    "repo": target.repo,
                    "sha": sha,
                    "commit_id": sha,
                    "state": "error",
                    "context": closing::STATUS_CONTEXT,
                    "description": "council error - review timed out",
                }),
            ));
        }
        for (kind, payload) in writes {
            if let Err(error) = store.enqueue_write(session_id, kind, &payload).await {
                tracing::error!(%error, session_id, kind, "timeout write enqueue failed");
            }
        }
    }
    // The tombstone keeps the opening post's marker: the abandon write
    // reconciles (and replays) against the "started" comment it rewrites.
    let marker = closing::open_marker(session_id);
    let payload = serde_json::json!({
        "repo": target.repo,
        "pr_number": target.pr_number,
        "body": format!(
            "<!-- openab-council -->\n\
             Review Council round closed without a verdict — superseded \
             by a newer round or timed out.\n\n{marker}"
        ),
    });
    match store.enqueue_write(session_id, kind, &payload).await {
        Ok(_) => {
            spawn_write_drain(state);
            true
        }
        Err(error) => {
            tracing::error!(%error, session_id, kind, "abandon-comment enqueue failed");
            false
        }
    }
}

async fn dispatch_terminal(
    state: &Arc<AppState>,
    store: &Arc<dyn ProductStore>,
    event: &runtime_events::RuntimeEventEnvelope,
) -> bool {
    if event.event_type != "session.terminal" {
        return false;
    }
    let Some(session_id) = event.session_id.as_deref() else {
        return false;
    };
    let reason = event.payload["reason"].as_str().unwrap_or_default();
    // Timeout and supersede have their own opening-comment tombstone. The
    // reviewer-minimum terminal is different: it must publish an error status
    // while withholding every formal review write.
    if reason != "normal" && reason != "insufficient_valid_reviewers" {
        return false;
    }
    let target = match store.session_target(session_id).await {
        Ok(Some(target)) => target,
        // Not a session this controller opened. The kernel's own plugin owns
        // it; acting would be the two-writer failure invariant #4 forbids.
        Ok(None) => return false,
        Err(error) => {
            tracing::error!(%error, session_id, "session target lookup failed");
            return false;
        }
    };
    let final_messages: Vec<String> = event.payload["final_messages"]
        .as_array()
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let parsed = verdict::parse_final_messages(&final_messages);
    // A follow-up (`@bot <question>`) is an ask session: it posts a plain answer,
    // not a verdict. NULL reason on older rows reads as council, the safe
    // default (SEI-929).
    let is_ask = target.reason.as_deref() == Some("ask");
    if is_ask && reason != "normal" {
        return false;
    }
    // Every round posts its OWN comment (operator decision, 2026-08-01):
    // updating one standing comment in place erased each earlier round's
    // report from the pull request — four rounds of audit trail collapsed
    // into one surviving body. The in-place design (council F3, #305) solved
    // duplicate-comment noise; the round marker plus per-round bodies keep
    // idempotency without destroying history.
    let reported_required = event.payload["required_valid_reviewers"].as_i64();
    let valid_reviewers = event.payload["valid_reviewers"].as_i64();
    let reviewer_gate_passed = is_ask
        || (reason == "normal"
            && target
                .required_valid_reviewers
                .is_some_and(|required| required > 0)
            && reported_required == target.required_valid_reviewers
            && valid_reviewers.is_some_and(|valid| {
                target
                    .required_valid_reviewers
                    .is_some_and(|required| valid >= required)
            }));
    let plan = if reviewer_gate_passed {
        closing::plan_close(&target, &parsed, None, session_id, is_ask)
    } else {
        tracing::warn!(
            session_id,
            reason,
            expected_required = target.required_valid_reviewers,
            reported_required,
            valid_reviewers,
            "terminal reviewer evidence failed closed"
        );
        closing::plan_insufficient_reviewers(
            &target,
            session_id,
            target.required_valid_reviewers,
            valid_reviewers,
        )
    };

    if is_ask {
        // A follow-up answer is not a review: no round, no findings, no status,
        // no verdict. Just the comment. Redelivery is idempotent through the
        // outbox's UNIQUE(session_id, kind), so a re-enqueue is swallowed and we
        // never touch review_rounds (which would inflate round numbers and let
        // the ask comment masquerade as the verdict comment) — SEI-929.
        for (kind, payload) in &plan.writes {
            if let Err(error) = store.enqueue_write(session_id, kind, payload).await {
                tracing::error!(%error, session_id, kind, "ask write enqueue failed");
            }
        }
        tracing::info!(session_id, "ask follow-up answer queued");
        // Post now, not on the next 60 s sweep — the same event-driven drain the
        // council path fires after enqueue (review #395 F2).
        spawn_write_drain(state);
        return true;
    }

    let round = match store
        .record_review_round(&store::ReviewRound {
            repo: target.repo.clone(),
            pr_number: target.pr_number,
            session_id: session_id.to_string(),
            head_sha: plan.head_sha.clone(),
            verified_commit_id: plan.verified_commit_id.clone(),
            integrity_disposition: plan.integrity_disposition.clone(),
            decision: plan.decision.clone(),
            red: plan.red,
            yellow: plan.yellow,
            green: plan.green,
        })
        .await
    {
        Ok(round) => round,
        Err(error) => {
            tracing::error!(%error, session_id, "review round persistence failed");
            return false;
        }
    };
    if !round.first_time {
        // A redelivered terminal event. The round and its writes already exist;
        // re-queueing them would be how a verdict gets posted twice.
        tracing::info!(
            session_id,
            round = round.round,
            "terminal event redelivered"
        );
        return true;
    }
    if let Err(error) = store
        .record_review_findings(
            session_id,
            &target.repo,
            target.pr_number,
            plan.head_sha.as_deref(),
            &plan.findings,
        )
        .await
    {
        tracing::error!(%error, session_id, "findings persistence failed");
    }
    // ADR 035 P2: waived findings bump their waivers' fired counters —
    // repo-scoped, because unlike the kernel this side KNOWS the repo. A
    // foreign id in the block bumps nothing. Guarded by `first_time` above,
    // so a redelivered terminal event cannot double-bump.
    let fired = &plan.fired_waivers;
    if !fired.is_empty() {
        match store.record_waiver_fired(&target.repo, fired).await {
            Ok(bumped) if bumped < fired.len() => tracing::warn!(
                session_id,
                repo = %target.repo,
                named = fired.len(),
                bumped,
                "some waiver ids in the block matched nothing in this repo"
            ),
            Ok(_) => {}
            Err(error) => {
                tracing::error!(%error, session_id, "waiver fired-count update failed");
            }
        }
    }
    for (kind, payload) in &plan.writes {
        if let Err(error) = store.enqueue_write(session_id, kind, payload).await {
            tracing::error!(%error, session_id, kind, "write enqueue failed");
        }
    }
    tracing::info!(
        session_id,
        round = round.round,
        decision = plan.decision,
        writes = plan.writes.len(),
        "queued github writes for closed round"
    );
    spawn_write_drain(state);
    true
}

/// Drain the outbox in the background. Without a write client the rows simply
/// stay pending — which is the whole posture before the P7 cutover: the
/// controller knows exactly what it would post and posts none of it.
fn spawn_write_drain(state: &Arc<AppState>) {
    let (Some(store), Some(github)) = (state.store.clone(), state.github.clone()) else {
        return;
    };
    tokio::spawn(async move {
        drain_outbox_batch(&store, &github).await;
    });
}

/// Claim and deliver one batch of outbox writes. Returns how many writes were
/// claimed, so the periodic sweep can log when it picks up work the
/// event-driven drain missed (wedged worker, restart with pending rows).
async fn drain_outbox_batch(
    store: &Arc<dyn ProductStore>,
    github: &Arc<github::GitHubClient>,
) -> usize {
    {
        let pending = match store.claim_writes(WRITE_DRAIN_BATCH).await {
            Ok(pending) => pending,
            Err(error) => {
                tracing::error!(%error, "outbox read failed");
                return 0;
            }
        };
        let claimed = pending.len();
        for write in pending {
            match perform_write_with_receipt(github, store.as_ref(), &write).await {
                Ok(_) => {
                    if let Err(error) = store.mark_write_done(write.id).await {
                        tracing::error!(%error, id = write.id, "outbox completion failed");
                    }
                }
                Err(error) => {
                    tracing::warn!(id = write.id, kind = write.kind, %error, "github write failed");
                    let retryable = write.attempts + 1 < WRITE_MAX_ATTEMPTS;
                    let error_class = write_error_class(&error);
                    let (audit_kind, audit_outcome) = if retryable {
                        ("github.write.retry_scheduled", AuditOutcome::RetryScheduled)
                    } else {
                        ("github.write.failed", AuditOutcome::Failed)
                    };
                    let _ = append_controller_audit(
                        store.as_ref(),
                        controller_audit_event(
                            format!("{audit_kind}:{}:{}", write.id, write.attempts),
                            audit_kind,
                            audit_outcome,
                            now_unix(),
                            AuditCorrelation {
                                session_id: Some(write.session_id.clone()),
                                write_id: Some(write.id.to_string()),
                                ..Default::default()
                            },
                            json!({
                                "operation": write.kind,
                                "attempt": write.attempts,
                                "retryable": retryable,
                                "error_category": error_class,
                                "provider": {
                                    "repository": write.payload["repo"].as_str(),
                                    "pr_number": write.payload["pr_number"].as_i64(),
                                    "head_sha": write.payload["sha"].as_str(),
                                    "commit_id": write.payload["commit_id"].as_str(),
                                    "event": write.payload["event"].as_str(),
                                },
                            }),
                            Some(AuditError {
                                class: error_class.into(),
                                retryable,
                                message: Some(error.to_string()),
                                status: None,
                            }),
                        ),
                    )
                    .await;
                    if let Err(error) = store.mark_write_failed(write.id, &error.to_string()).await
                    {
                        tracing::error!(%error, id = write.id, "outbox failure record failed");
                    }
                }
            }
        }
        claimed
    }
}

#[cfg(test)]
async fn perform_write(
    github: &github::GitHubClient,
    store: &dyn ProductStore,
    write: &store::PendingWrite,
) -> anyhow::Result<()> {
    perform_write_with_receipt(github, store, write)
        .await
        .map(|_| ())
}

fn write_error_class(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    for (prefix, class) in [
        (
            "unproven_legacy_authority_intent",
            "unproven_legacy_authority_intent",
        ),
        (
            "unverified_round_authority_intent",
            "unverified_round_authority_intent",
        ),
        ("authority_payload_", "authority_payload_invalid"),
        ("authority_commit_mismatch", "authority_commit_mismatch"),
        (
            "authority_status_commit_mismatch",
            "authority_status_commit_mismatch",
        ),
        (
            "github_review_response_mismatch",
            "github_review_response_mismatch",
        ),
        (
            "github_review_reconciliation_conflict",
            "github_review_reconciliation_conflict",
        ),
    ] {
        if message.starts_with(prefix) {
            return class;
        }
    }
    "provider_write_failed"
}

async fn reject_authority_write(
    store: &dyn ProductStore,
    write: &store::PendingWrite,
    category: &str,
    message: &str,
) -> anyhow::Result<()> {
    let detail = json!({
        "operation": write.kind.clone(),
        "attempt": write.attempts,
        "category": category,
        "payload_commit_id": write.payload["commit_id"].as_str(),
        "payload_sha": write.payload["sha"].as_str(),
        "event": write.payload["event"].as_str(),
    });
    append_controller_audit(
        store,
        controller_audit_event(
            format!(
                "github.write.authority_rejected:{}:{}",
                write.id, write.attempts
            ),
            "github.write.authority_rejected",
            AuditOutcome::Failed,
            now_unix(),
            AuditCorrelation {
                session_id: Some(write.session_id.clone()),
                write_id: Some(write.id.to_string()),
                ..Default::default()
            },
            detail,
            Some(AuditError {
                class: category.into(),
                retryable: write.attempts + 1 < WRITE_MAX_ATTEMPTS,
                message: Some(message.into()),
                status: None,
            }),
        ),
    )
    .await?;
    anyhow::bail!("{category}: {message}")
}

async fn enforce_authority_write(
    store: &dyn ProductStore,
    write: &store::PendingWrite,
) -> anyhow::Result<()> {
    let kind = write.kind.as_str();
    let normal_review = kind == closing::KIND_REVIEW;
    let decision_review = kind.starts_with(deciding::KIND_DECISION_REVIEW);
    let normal_status = kind == closing::KIND_STATUS
        && matches!(
            write.payload["state"].as_str(),
            Some("success") | Some("failure")
        );
    let decision_status = kind.starts_with(deciding::KIND_DECISION_STATUS)
        && write.payload["state"].as_str() == Some("success");
    if !normal_review && !decision_review && !normal_status && !decision_status {
        return Ok(());
    }

    let proof = match store.review_round_integrity(&write.session_id).await {
        Ok(proof) => proof,
        Err(error) => {
            return reject_authority_write(
                store,
                write,
                "authority_payload_proof_lookup_failed",
                &format!("round integrity proof lookup failed: {error}"),
            )
            .await
        }
    };
    let Some(proof) = proof else {
        return reject_authority_write(
            store,
            write,
            "unproven_legacy_authority_intent",
            "no explicit verified round proof exists",
        )
        .await;
    };
    if proof.integrity_disposition != "verified" {
        let category = if proof.integrity_disposition == "legacy_unverified" {
            "unproven_legacy_authority_intent"
        } else {
            "unverified_round_authority_intent"
        };
        return reject_authority_write(
            store,
            write,
            category,
            &format!(
                "round integrity disposition is {}",
                proof.integrity_disposition
            ),
        )
        .await;
    }

    let commit_id = match write.payload["commit_id"]
        .as_str()
        .and_then(closing::canonical_commit_id)
    {
        Some(commit_id) => commit_id,
        None => {
            return reject_authority_write(
                store,
                write,
                "authority_payload_missing_or_invalid_commit_id",
                "authority payload carried no full canonical commit_id",
            )
            .await
        }
    };
    if normal_status || decision_status {
        let Some(sha) = write.payload["sha"]
            .as_str()
            .and_then(closing::canonical_commit_id)
        else {
            return reject_authority_write(
                store,
                write,
                "authority_payload_invalid_sha",
                "authority status carried no full canonical sha",
            )
            .await;
        };
        if sha != commit_id {
            return reject_authority_write(
                store,
                write,
                "authority_status_commit_mismatch",
                "authority status sha and commit_id disagree",
            )
            .await;
        }
    }
    if normal_review || decision_review {
        let valid_event = matches!(
            write.payload["event"].as_str(),
            Some("APPROVE") | Some("REQUEST_CHANGES")
        );
        if !valid_event {
            return reject_authority_write(
                store,
                write,
                "authority_payload_invalid_event",
                "authority review carried no supported event",
            )
            .await;
        }
        let marker = if decision_review {
            let deciding_comment = kind.rsplit(':').next().unwrap_or_default();
            deciding::decision_marker(&write.session_id, deciding_comment)
        } else {
            closing::round_marker(&write.session_id)
        };
        if !write.payload["body"]
            .as_str()
            .is_some_and(|body| body.contains(&marker))
        {
            return reject_authority_write(
                store,
                write,
                "authority_payload_missing_marker",
                "authority review body carried no controller-owned marker",
            )
            .await;
        }
    }

    let Some(proof_commit_id) = proof
        .verified_commit_id
        .as_deref()
        .and_then(closing::canonical_commit_id)
    else {
        return reject_authority_write(
            store,
            write,
            "unverified_round_authority_intent",
            "verified round proof carried no full canonical commit_id",
        )
        .await;
    };
    if proof_commit_id != commit_id {
        return reject_authority_write(
            store,
            write,
            "authority_commit_mismatch",
            "authority payload commit_id differs from the verified round proof",
        )
        .await;
    }
    Ok(())
}

async fn perform_write_with_receipt(
    github: &github::GitHubClient,
    store: &dyn ProductStore,
    write: &store::PendingWrite,
) -> anyhow::Result<Value> {
    let payload = &write.payload;
    let request_json = serde_json::to_vec(&write.payload)?;
    let request_sha256 = hex::encode(Sha256::digest(&request_json));
    if write.was_reclaimed {
        append_controller_audit(
            store,
            controller_audit_event(
                format!(
                    "github.write.outcome_unknown:{}:{}",
                    write.id, write.attempts
                ),
                "github.write.outcome_unknown",
                AuditOutcome::OutcomeUnknown,
                now_unix(),
                AuditCorrelation {
                    session_id: Some(write.session_id.clone()),
                    write_id: Some(write.id.to_string()),
                    ..Default::default()
                },
                json!({
                    "operation": write.kind.clone(),
                    "attempt": write.attempts,
                    "reason": "claim_lease_expired_before_completion",
                    "request_sha256": request_sha256.clone(),
                    "expected": {
                        "event": payload["event"].as_str(),
                        "commit_id": payload["commit_id"].as_str().or_else(|| payload["sha"].as_str()),
                    },
                    "provider": {
                        "repository": payload["repo"].as_str(),
                        "pr_number": payload["pr_number"].as_i64(),
                        "head_sha": payload["sha"].as_str().or_else(|| payload["commit_id"].as_str()),
                        "commit_id": payload["commit_id"].as_str(),
                        "event": payload["event"].as_str(),
                    },
                }),
                None,
            ),
        )
        .await?;
    }
    append_controller_audit(
        store,
        controller_audit_event(
            format!("github.write.attempted:{}:{}", write.id, write.attempts),
            "github.write.attempted",
            AuditOutcome::Pending,
            now_unix(),
            AuditCorrelation {
                session_id: Some(write.session_id.clone()),
                write_id: Some(write.id.to_string()),
                ..Default::default()
            },
            json!({
                "operation": write.kind.clone(),
                "attempt": write.attempts,
                "request_sha256": request_sha256.clone(),
                "expected": {
                    "event": payload["event"].as_str(),
                    "commit_id": payload["commit_id"].as_str().or_else(|| payload["sha"].as_str()),
                },
                "provider": {
                    "repository": payload["repo"].as_str(),
                    "pr_number": payload["pr_number"].as_i64(),
                    "head_sha": payload["sha"].as_str().or_else(|| payload["commit_id"].as_str()),
                    "commit_id": payload["commit_id"].as_str(),
                    "event": payload["event"].as_str(),
                },
            }),
            None,
        ),
    )
    .await?;
    enforce_authority_write(store, write).await?;
    let repo = payload["repo"].as_str().unwrap_or_default();
    let receipt = match write.kind.as_str() {
        closing::KIND_COMMENT => {
            let body = payload["body"].as_str().unwrap_or_default();
            match payload["comment_id"].as_i64() {
                Some(comment_id) => {
                    github.update_comment(repo, comment_id, body).await?;
                    json!({"comment_id": comment_id, "reconciled": false})
                }
                None => {
                    let issue = payload["pr_number"].as_i64().unwrap_or_default();
                    // Reconcile before creating: a crash after the create but
                    // before mark-done replays this write once the claim lease
                    // lapses, and a second create is a second comment. The
                    // body carries the round marker, so the earlier success is
                    // findable — adopt it and refresh its body instead.
                    let marker = closing::round_marker(&write.session_id);
                    let (comment_id, reconciled) =
                        match github.find_marked_comment(repo, issue, &marker).await? {
                            Some(existing) => {
                                github.update_comment(repo, existing, body).await?;
                                (existing, true)
                            }
                            None => (github.create_comment(repo, issue, body).await?, false),
                        };
                    // Learned here, used by every later round of this PR.
                    store
                        .set_round_comment_id(&write.session_id, comment_id)
                        .await?;
                    json!({"comment_id": comment_id, "reconciled": reconciled})
                }
            }
        }
        closing::KIND_COMMENT_OPEN => {
            let issue = payload["pr_number"].as_i64().unwrap_or_default();
            let open_marker = closing::open_marker(&write.session_id);
            let verdict_marker = closing::round_marker(&write.session_id);
            let open_exists = github
                .find_marked_comment(repo, issue, &open_marker)
                .await?;
            let verdict_exists = github
                .find_marked_comment(repo, issue, &verdict_marker)
                .await?;
            // Create only if neither of the session's comments exists yet: a
            // replay must not duplicate the "started" post, and a fast close
            // (verdict already up) must not gain a stale "started" after it.
            if open_exists.is_none() && verdict_exists.is_none() {
                let round = payload["round"].as_i64().unwrap_or(1);
                let baseline = github
                    .pull_baseline(repo, issue)
                    .await
                    .unwrap_or_else(|_| "Baseline: unavailable".into());
                let body = format!(
                    "<!-- openab-council -->\n\
                     Review Council started (round {round}).\n\n\
                     {baseline}\n\n\
                     The council is reviewing this pull request; the verdict \
                     will follow as a separate comment when the round \
                     closes.\n\n{open_marker}"
                );
                let comment_id = github.create_comment(repo, issue, &body).await?;
                json!({"comment_id": comment_id, "reconciled": false})
            } else {
                json!({
                    "comment_id": open_exists.or(verdict_exists),
                    "reconciled": true,
                })
            }
        }
        closing::KIND_COMMENT_ABANDON => {
            let issue = payload["pr_number"].as_i64().unwrap_or_default();
            let marker = closing::open_marker(&write.session_id);
            // Update only if the opening post exists — a round that never
            // managed to post "started" gets no tombstone either. The verdict
            // comment lives under a different marker, so this can never touch
            // a verdict.
            let existing = github.find_marked_comment(repo, issue, &marker).await?;
            if let Some(existing) = existing {
                let body = payload["body"].as_str().unwrap_or_default();
                github.update_comment(repo, existing, body).await?;
            }
            json!({"comment_id": existing, "reconciled": existing.is_some()})
        }
        kind if kind.starts_with(deciding::KIND_DECISION_COMMENT) => {
            // A decision's edit of the round's verdict comment. Always a
            // PATCH: the comment provably exists (its id was read from the
            // store), and PATCH is idempotent, so no marker reconcile.
            let comment_id = payload["comment_id"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("decision comment write carried no comment_id"))?;
            let body = payload["body"].as_str().unwrap_or_default();
            github.update_comment(repo, comment_id, body).await?;
            json!({"comment_id": comment_id, "reconciled": false})
        }
        kind if kind == closing::KIND_STATUS
            || kind.starts_with(deciding::KIND_DECISION_STATUS) =>
        {
            let state = match payload["state"].as_str() {
                Some("success") => github::StatusState::Success,
                Some("failure") => github::StatusState::Failure,
                _ => github::StatusState::Error,
            };
            let sha = payload["sha"].as_str().unwrap_or_default();
            let context = payload["context"]
                .as_str()
                .unwrap_or(closing::STATUS_CONTEXT);
            github
                .set_status(
                    repo,
                    sha,
                    state,
                    context,
                    payload["description"].as_str().unwrap_or_default(),
                )
                .await?;
            json!({
                "sha": sha,
                "context": context,
                "state": state.as_str(),
            })
        }
        kind if kind == closing::KIND_REVIEW
            || kind.starts_with(deciding::KIND_DECISION_REVIEW) =>
        {
            let event = match payload["event"].as_str() {
                Some("APPROVE") => github::ReviewEvent::Approve,
                Some("REQUEST_CHANGES") => github::ReviewEvent::RequestChanges,
                other => anyhow::bail!("unknown review event {other:?}"),
            };
            let pr_number = payload["pr_number"].as_i64().unwrap_or_default();
            // Same reconcile as the comment: a replayed submit must find the
            // review it already submitted, not add a second one. A decision's
            // review reconciles on its own marker — the round's marker is
            // already on the REQUEST_CHANGES review this APPROVE supersedes,
            // and matching that one would swallow the unblock as "already
            // sent".
            let marker = if kind.starts_with(deciding::KIND_DECISION_REVIEW) {
                let deciding_comment = kind.rsplit(':').next().unwrap_or_default();
                deciding::decision_marker(&write.session_id, deciding_comment)
            } else {
                closing::round_marker(&write.session_id)
            };
            let commit_id = payload["commit_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("review payload carried no commit_id"))?;
            if let Some(receipt) = github
                .find_marked_review(repo, pr_number, &marker, event, commit_id)
                .await?
            {
                tracing::info!(
                    session_id = write.session_id,
                    "review already on the pull request; reconciled"
                );
                json!({
                    "review_id": receipt.id,
                    "state": receipt.state,
                    "commit_id": receipt.commit_id,
                    "reconciled": true
                })
            } else {
                // The review timeline entry must say where its evidence lives: the
                // comment write ran earlier in this same drain and recorded its
                // id, so link this round's report directly. Absent id (comment
                // write still failing) degrades to the unlinked body.
                let mut body = payload["body"].as_str().unwrap_or_default().to_string();
                if let Ok(Some(comment_id)) = store.round_comment_id(&write.session_id).await {
                    body = body.replace(
                        "Details in the review comment.",
                        &format!(
                            "Full report: https://github.com/{repo}/pull/{pr_number}#issuecomment-{comment_id}"
                        ),
                    );
                }
                let receipt = github
                    .submit_review(repo, pr_number, event, commit_id, &body)
                    .await?;
                json!({
                    "review_id": receipt.id,
                    "state": receipt.state,
                    "commit_id": receipt.commit_id,
                    "reconciled": false
                })
            }
        }
        other => anyhow::bail!("unknown write kind {other}"),
    };
    let reconciled = receipt["reconciled"].as_bool().unwrap_or(false);
    let (kind, outcome) = if reconciled {
        ("github.write.reconciled", AuditOutcome::Reconciled)
    } else {
        ("github.write.succeeded", AuditOutcome::Succeeded)
    };
    append_controller_audit(
        store,
        controller_audit_event(
            format!("{kind}:{}:{}", write.id, write.attempts),
            kind,
            outcome,
            now_unix(),
            AuditCorrelation {
                session_id: Some(write.session_id.clone()),
                write_id: Some(write.id.to_string()),
                ..Default::default()
            },
            json!({
                "operation": write.kind.clone(),
                "attempt": write.attempts,
                "request_sha256": request_sha256,
                "expected": {
                    "event": payload["event"].as_str(),
                    "commit_id": payload["commit_id"].as_str().or_else(|| payload["sha"].as_str()),
                },
                "provider_receipt": receipt.clone(),
                "provider": {
                    "repository": payload["repo"].as_str(),
                    "pr_number": payload["pr_number"].as_i64(),
                    "head_sha": payload["sha"].as_str().or_else(|| payload["commit_id"].as_str()),
                    "commit_id": payload["commit_id"].as_str(),
                    "event": payload["event"].as_str(),
                },
            }),
            None,
        ),
    )
    .await?;
    Ok(receipt)
}

async fn canary_summary(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(secret) = state.config.observer_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "observation_hmac_not_configured"}),
        );
    };
    if !verify_signature(secret, &[], header(&headers, "x-canary-signature-256")) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_observation_signature"}),
        );
    }
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    match store.canary_summary().await {
        Ok(summary) => response(StatusCode::OK, json!({"ok": true, "summary": summary})),
        Err(error) => {
            tracing::error!(%error, "canary summary failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "canary_store_failed"}),
            )
        }
    }
}

async fn handle_shadow_compare(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(secret) = state.config.shadow_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "shadow_hmac_not_configured"}),
        );
    };
    if !verify_signature(secret, &body, header(&headers, "x-shadow-signature-256")) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_shadow_signature"}),
        );
    }
    let request: shadow::ShadowCompareRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"ok": false, "error": "invalid_shadow_request"}),
            )
        }
    };
    if !valid_delivery_id(&request.comparison_id)
        || !valid_delivery_id(&request.delivery_id)
        || !valid_event_type(&request.event_type)
    {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "invalid_shadow_identity"}),
        );
    }

    let controller = match candidate_plan(
        &state,
        &request.delivery_id,
        &request.event_type,
        &request.payload,
    )
    .await
    {
        Ok(plan) => shadow::ParityOutcome::Planned {
            snapshot: Box::new(plan.parity_snapshot()),
        },
        Err(reason) => shadow::ParityOutcome::Ignored {
            reason: reason.into(),
        },
    };
    let repository = request.payload["repository"]["full_name"].as_str();
    let report = shadow::compare(request.comparison_id, request.embedded, Some(controller));
    let request_hash = hex::encode(Sha256::digest(&body));
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    match store
        .record_shadow_comparison(&request_hash, repository, &report)
        .await
    {
        Ok(ShadowAdmission::New) => response(
            StatusCode::OK,
            json!({"ok": true, "duplicate": false, "report": report}),
        ),
        Ok(ShadowAdmission::Duplicate) => response(
            StatusCode::OK,
            json!({"ok": true, "duplicate": true, "report": report}),
        ),
        Ok(ShadowAdmission::Conflict) => response(
            StatusCode::CONFLICT,
            json!({"ok": false, "error": "comparison_payload_conflict"}),
        ),
        Err(error) => {
            tracing::error!(%error, "shadow comparison persistence failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "shadow_store_failed"}),
            )
        }
    }
}

async fn shadow_summary(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(secret) = state.config.shadow_secret.as_deref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "shadow_hmac_not_configured"}),
        );
    };
    if !verify_signature(secret, &[], header(&headers, "x-shadow-signature-256")) {
        return response(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "invalid_shadow_signature"}),
        );
    }
    let Some(store) = state.store.as_ref() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "product_store_unavailable"}),
        );
    };
    match store.shadow_summary().await {
        Ok(summary) => response(StatusCode::OK, json!({"ok": true, "summary": summary})),
        Err(error) => {
            tracing::error!(%error, "shadow summary failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "error": "shadow_store_failed"}),
            )
        }
    }
}

/// The payload said the author is not trusted — but payload
/// `author_association` reflects PUBLIC org membership only (observed on
/// prod, 2026-08-03: a private member of the installation org arrives as
/// CONTRIBUTOR while the same App sees MEMBER over REST). Ask the membership
/// endpoint, which does honor the App's `members: read` grant, before
/// rejecting. Fail closed: no GitHub client (writes off), no login in the
/// payload, or a probe error all leave the author untrusted.
async fn org_membership_fallback(state: &AppState, trigger: &planner::Trigger) -> bool {
    org_member(state, &trigger.repository, trigger.author_login.as_deref()).await
}

/// Trigger-only trust for configured non-org authors (a first-party bot like
/// `nuphos[bot]` that opens PRs). The login is authoritative: the webhook is
/// HMAC-verified, so GitHub — not the sender — sets `user.login`, and `[bot]`
/// logins are reserved for Apps. Grants only "open a review"; it confers no
/// write/merge/finding-dismiss authority, which keep their own live probes.
fn author_allowlisted(state: &AppState, trigger: &planner::Trigger) -> bool {
    trigger
        .author_login
        .as_deref()
        .is_some_and(|login| state.config.trusted_authors.contains(login))
}

/// Live membership probe. The payload's `author_association` renders against
/// PUBLIC org membership only, so a private member arrives as CONTRIBUTOR and
/// would be refused without this (SEI-884).
async fn org_member(state: &AppState, repository: &str, login: Option<&str>) -> bool {
    let Some(github) = state.github.as_ref() else {
        return false;
    };
    let Some(login) = login else {
        return false;
    };
    let Some((org, _)) = repository.split_once('/') else {
        return false;
    };
    match github.is_org_member(org, login).await {
        Ok(member) => member,
        Err(error) => {
            tracing::warn!(%error, org, login, "org membership probe failed; author stays untrusted");
            false
        }
    }
}

/// Apply an author's judgement on a finding (ADR 038).
///
/// Returns the reply body. Every path returns one: a command that is refused,
/// or that matches nothing, or that changes nothing still gets answered —
/// silence is what makes an author conclude the council is broken (ADR 025,
/// SEI-820), and it is the failure mode this whole feature exists to remove.
async fn apply_finding_command(state: &Arc<AppState>, command: &planner::FindingCommand) -> String {
    // Every refusal and every miss ends with the same line: reporting what
    // went wrong without saying what to type leaves the author stuck holding a
    // command they cannot correct.
    let hint = deciding::usage_hint(state.bot_name());
    let Some(store) = state.store.clone() else {
        return deciding::fault(
            "The controller has no product store configured, so findings cannot be judged yet.",
        );
    };
    // Judging a finding can unblock a merge, so the bar is write access to
    // THIS repository, not membership of the org: an org member with read-only
    // access here would otherwise borrow council authority GitHub would refuse
    // them. Fail closed — a probe that errors is not a grant.
    let Some(login) = command.author_login.clone() else {
        return deciding::fault("Could not identify the commenter from this event.");
    };
    let allowed = match state.github.as_ref() {
        Some(github) => github
            .can_write_repo(&command.repository, &login)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(%error, repo = %command.repository, %login, "repo permission probe failed; refusing");
                false
            }),
        None => false,
    };
    if !allowed {
        return format!(
            "Judging a finding can unblock a merge, so it needs write access to \
             `{}` — @{login} does not have it. `/review` still works for anyone who can \
             comment.{hint}",
            command.repository
        );
    }
    if command.reason.is_none() {
        // Both judging verbs require the reason — it is the whole value of
        // the record. Reopen carries none.
        match command.verb.as_str() {
            "dismiss" => {
                return format!(
                    "`dismiss {}` needs a reason — the record is the whole point of trusting \
                     the judgement. Try `dismiss {} <why this is not a defect>`.{hint}",
                    command.stable_id, command.stable_id
                );
            }
            "waive" => {
                return format!(
                    "`waive {}` needs a reason — a waiver is the org accepting a real defect, \
                     and the reason is what future readers of the ledger get. Try `waive {} \
                     <why we accept this defect>`.{hint}",
                    command.stable_id, command.stable_id
                );
            }
            _ => {}
        }
    }
    let Some(github) = state.github.as_ref() else {
        return deciding::fault(
            "No GitHub client is configured, so the head revision cannot be confirmed.",
        );
    };
    let head_sha = match github
        .pull_head_sha(&command.repository, command.pr_number as i64)
        .await
    {
        Ok(sha) => match closing::canonical_commit_id(&sha) {
            Some(canonical) => canonical,
            None => {
                tracing::warn!(repo = %command.repository, head_sha = %sha, "finding command received an invalid live head");
                return deciding::fault("Could not confirm this pull request's head revision.");
            }
        },
        Err(error) => {
            tracing::warn!(%error, repo = %command.repository, "head lookup failed for a finding command");
            return deciding::fault("Could not confirm this pull request's head revision.");
        }
    };
    let query = store::ReviewFindingQuery {
        repo: Some(command.repository.clone()),
        pr_number: Some(command.pr_number as i64),
        status: None,
        severity: None,
        limit: 500,
    };
    let before_rows = match store.review_findings(&query).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, "findings read failed for a finding command");
            return deciding::fault("The findings ledger is unavailable.");
        }
    };
    let before = deciding::open_counts(&before_rows, &head_sha);
    let was_blocking = before.0 > 0 || before.1 > 0;
    let status = match command.verb.as_str() {
        "dismiss" => "dismissed",
        "waive" => "waived",
        _ => "open",
    };
    // Two ways to match nothing, and they need different answers.
    let miss_reply = |before_rows: &[store::ReviewFindingRow]| {
        let on_this_head: Vec<&str> = before_rows
            .iter()
            .filter(|row| row.head_sha.as_deref() == Some(head_sha.as_str()))
            .map(|row| row.stable_id.as_str())
            .collect();
        if on_this_head.contains(&command.stable_id.as_str()) {
            format!(
                "`{}` moved since that round, so nothing was changed — a decision on an \
                 older revision must not unblock code nobody reviewed. The next round will \
                 re-raise whatever still applies.{hint}",
                &head_sha[..head_sha.len().min(8)]
            )
        } else if on_this_head.is_empty() {
            format!(
                "No findings are recorded for `{}` on `{}` yet — a judgement needs a \
                 finding to be about. If no round has run on this revision, \
                 `@{} review` convenes one.{hint}",
                command.repository,
                &head_sha[..head_sha.len().min(8)],
                state.bot_name(),
            )
        } else {
            format!(
                "{} is not a finding on this revision. This round has: {}.{hint}",
                command.stable_id,
                on_this_head.join(", ")
            )
        }
    };
    // `waive` is one transaction — the status flip and the repo-scoped waiver
    // land together or not at all (a stale waive that still minted a waiver
    // would silence rounds on code nobody reviewed). The other verbs touch
    // the finding alone.
    let (decided, waiver) = if command.verb == "waive" {
        // The horizon is severity-aware (ADR 038: red waives are "permitted
        // but conspicuous: a shorter maximum expiry"). Severity comes from
        // the rows just read; a finding those rows do not have gets the short
        // horizon, and in that case the compare-and-swap is about to miss
        // anyway.
        let severity = before_rows
            .iter()
            .find(|row| {
                row.head_sha.as_deref() == Some(head_sha.as_str())
                    && row.stable_id == command.stable_id
            })
            .map(|row| row.severity.as_str())
            .unwrap_or_default();
        match store
            .waive_review_finding(
                &command.repository,
                command.pr_number as i64,
                &command.stable_id,
                &head_sha,
                command.author_login.as_deref().unwrap_or("unknown"),
                command.reason.as_deref().unwrap_or_default(),
                now_unix() + deciding::waive_expiry_secs(severity),
            )
            .await
        {
            Ok(store::WaiveAdmission::Waived(row, waiver)) => (row, Some(waiver)),
            // Council #383 F1: a repeated waive is answered, not repeated —
            // minting again would orphan the first waiver as a permanent,
            // reopen-proof suppression.
            Ok(store::WaiveAdmission::AlreadyWaived(row, existing)) => {
                // The name in force (#375), not the configured one — the
                // retract hint must be a command that actually works.
                let bot = state.bot_name();
                let waiver_state = existing
                    .map(|waiver| {
                        let now = now_unix();
                        if waiver.revoked_at.is_some() {
                            format!(" Its waiver `{}` was revoked.", waiver.id)
                        } else if waiver.expires_at <= now {
                            format!(" Its waiver `{}` has expired.", waiver.id)
                        } else {
                            format!(
                                " Its waiver `{}` is active and expires in {}d.",
                                waiver.id,
                                (waiver.expires_at - now).max(0) / 86_400
                            )
                        }
                    })
                    .unwrap_or_default();
                return format!(
                    "{} is already waived on this revision by @{} — nothing was changed.\
                     {waiver_state} To retract or renew it, `@{bot} reopen {}` first.{hint}",
                    row.stable_id,
                    row.decided_by.as_deref().unwrap_or("?"),
                    row.stable_id,
                );
            }
            Ok(store::WaiveAdmission::NoMatch) => return miss_reply(&before_rows),
            Err(error) => {
                tracing::error!(%error, "finding waive write failed");
                return deciding::fault("The findings ledger refused the write.");
            }
        }
    } else {
        match store
            .decide_review_finding(
                &command.repository,
                command.pr_number as i64,
                &command.stable_id,
                &head_sha,
                status,
                command.author_login.as_deref().unwrap_or("unknown"),
                command.reason.as_deref(),
            )
            .await
        {
            Ok(Some(row)) => (row, None),
            Ok(None) => return miss_reply(&before_rows),
            Err(error) => {
                tracing::error!(%error, "finding decision write failed");
                return deciding::fault("The findings ledger refused the write.");
            }
        }
    };
    // Reopening a waived finding must also revoke the waiver it minted, or
    // the finding would come back while the repo-wide suppression stayed live
    // — an undo that does not undo.
    let mut revoked_waiver: Option<String> = None;
    let mut revoke_failed = false;
    if command.verb == "reopen" {
        if let Some(waiver_id) = decided.waiver_id.as_deref() {
            match store.update_review_waiver(waiver_id, None, true).await {
                Ok(_) => revoked_waiver = Some(waiver_id.to_string()),
                Err(error) => {
                    revoke_failed = true;
                    tracing::error!(%error, waiver_id, "waiver revoke failed on reopen");
                }
            }
        }
    }

    // A failed re-read must not be answered with pre-decision counts: the
    // ledger already holds the judgement, so stale rows would tell the author
    // they are still blocked by the very finding they just dismissed (F4).
    let after_rows = match store.review_findings(&query).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(%error, "findings re-read failed after a decision");
            return format!(
                "{} is recorded as {status}, but the ledger could not be re-read, so the \
                 verdict was not recomputed. Comment again to retry — the judgement is \
                 already saved.",
                command.stable_id
            );
        }
    };
    let approval_authorized = match store.review_round_integrity(&decided.session_id).await {
        Ok(Some(proof)) if proof.integrity_disposition == "verified" => proof
            .verified_commit_id
            .as_deref()
            .and_then(closing::canonical_commit_id)
            .is_some_and(|commit_id| commit_id == head_sha),
        Ok(Some(proof)) => {
            tracing::info!(
                session_id = %decided.session_id,
                disposition = %proof.integrity_disposition,
                "withholding decision approval from an unverified round"
            );
            false
        }
        Ok(None) => {
            tracing::info!(session_id = %decided.session_id, "withholding decision approval without a round proof");
            false
        }
        Err(error) => {
            tracing::warn!(%error, session_id = %decided.session_id, "round proof lookup failed; withholding decision approval");
            false
        }
    };
    // A waive moves the finding to a visible `Waived` section on the round's
    // own verdict comment (ADR 038 point 4) — read the live body, upsert the
    // section, PATCH it back. Every step degrades to "reply carries the news"
    // rather than blocking the decision: the ledger already holds the truth.
    // Dismiss keeps v1's posture — the verdict comment stays the record of
    // what the council said that round.
    let verdict_comment = if command.verb == "waive" {
        match store.round_comment_id(&decided.session_id).await {
            Ok(Some(comment_id)) => {
                match github
                    .issue_comment_body(&command.repository, comment_id)
                    .await
                {
                    Ok(body) => {
                        let expiries: std::collections::BTreeMap<String, i64> = store
                            .list_review_waivers(Some(&command.repository), false, now_unix())
                            .await
                            .map(|waivers| {
                                waivers
                                    .into_iter()
                                    .map(|waiver| (waiver.id, waiver.expires_at))
                                    .collect()
                            })
                            .unwrap_or_default();
                        deciding::waived_section(&after_rows, &head_sha, &expiries, now_unix()).map(
                            |section| {
                                (comment_id, deciding::upsert_waived_section(&body, &section))
                            },
                        )
                    }
                    Err(error) => {
                        tracing::warn!(%error, comment_id, "verdict comment read failed; waive proceeds without the section");
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(%error, "round comment lookup failed; waive proceeds without the section");
                None
            }
        }
    } else {
        None
    };
    let outcome = deciding::plan_decision(
        &command.repository,
        command.pr_number as i64,
        &head_sha,
        &after_rows,
        was_blocking,
        approval_authorized,
        verdict_comment,
        &decided.session_id,
        command.comment_id,
    );
    // A write that does not enqueue must never be reported as done: that is the
    // exact shape of the bug this path was born with — the reply said approved
    // while the outbox had silently ignored the row.
    let mut all_queued = true;
    for (kind, payload) in &outcome.writes {
        match store
            .enqueue_write(&decided.session_id, kind, payload)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                all_queued = false;
                tracing::error!(kind, session_id = %decided.session_id, "decision write collided with an existing outbox row");
            }
            Err(error) => {
                all_queued = false;
                tracing::error!(%error, kind, "decision write enqueue failed");
            }
        }
    }
    let _ = append_controller_audit(
        store.as_ref(),
        controller_audit_event(
            format!("finding.{status}:{}:{}", decided.id, command.comment_id),
            match status {
                "dismissed" => "finding.dismissed",
                "waived" => "finding.waived",
                _ => "finding.reopened",
            },
            AuditOutcome::Succeeded,
            now_unix(),
            AuditCorrelation {
                session_id: Some(decided.session_id.clone()),
                controller_id: state.config.ocp_action.controller_id.clone(),
                ..Default::default()
            },
            json!({
                "repository": command.repository,
                "pr_number": command.pr_number,
                "finding": command.stable_id,
                "head_sha": head_sha,
                "reason": command.reason,
                "counts_before": {"red": before.0, "yellow": before.1},
                "counts_after": {"red": outcome.red, "yellow": outcome.yellow},
                "decision": outcome.decision,
                "unblocked": outcome.unblocked,
                // The actor is the point of the record, not a detail of it.
                "actor": command.author_login,
                "waiver_id": waiver.as_ref().map(|waiver| waiver.id.clone()),
                "revoked_waiver_id": revoked_waiver,
            }),
            None,
        ),
    )
    .await;
    // The minted waiver gets the same `waiver.created` event the operator
    // path writes — and, per ADR 038 point 6, this one carries the audit
    // ACTOR, not just a created_by inside the detail payload.
    if let Some(waiver) = waiver.as_ref() {
        let _ = append_controller_audit(
            store.as_ref(),
            controller_audit_event(
                format!("waiver.created:{}", waiver.id),
                "waiver.created",
                AuditOutcome::Succeeded,
                now_unix(),
                AuditCorrelation {
                    session_id: Some(decided.session_id.clone()),
                    controller_id: state.config.ocp_action.controller_id.clone(),
                    ..Default::default()
                },
                json!({"waiver_id": waiver.id, "repo": waiver.repo,
                "created_by": waiver.created_by,
                "expires_at": waiver.expires_at,
                "source": waiver.source,
                "finding": command.stable_id,
                "actor": {
                    "kind": "github_user",
                    "display": command.author_login,
                }}),
                None,
            ),
        )
        .await;
    }
    if !outcome.writes.is_empty() {
        spawn_write_drain(state);
    }
    let mut reply = deciding::reply_body(
        &command.verb,
        &decided,
        before,
        &outcome,
        command.author_login.as_deref().unwrap_or("unknown"),
        state.bot_name(),
        waiver.as_ref(),
    );
    if let Some(waiver_id) = revoked_waiver.as_deref() {
        reply.push_str(&format!(
            "\nThe linked waiver `{waiver_id}` was revoked — future rounds will weigh this \
             finding again.\n"
        ));
    }
    if revoke_failed {
        reply.push_str(
            "\n⚠️ The finding is reopened, but its linked waiver could not be revoked — future \
             rounds may still treat it as accepted. This is a controller fault, not yours; \
             `reopen` again to retry.\n",
        );
    }
    if !all_queued {
        reply.push_str(
            "\n⚠️ The judgement is recorded, but at least one update to this pull request \
             could not be queued — the status and review may still show the old verdict. \
             This is a controller fault, not yours.\n",
        );
    }
    reply
}

async fn candidate_plan(
    state: &AppState,
    delivery_id: &str,
    event_type: &str,
    payload: &Value,
) -> Result<planner::SessionPlan, &'static str> {
    let Some(mut trigger) = planner::parse_trigger(event_type, payload, &state.bot_handles) else {
        return Err("not_a_trigger");
    };
    if !state.config.allowed_repos.is_empty()
        && !state.config.allowed_repos.contains(&trigger.repository)
    {
        return Err("repo_not_allowed");
    }
    // Allowlist first so a configured bot skips the network probe entirely.
    if !trigger.author_trusted
        && !author_allowlisted(state, &trigger)
        && !org_membership_fallback(state, &trigger).await
    {
        return Err("author_not_trusted");
    }
    // #326: a plain `/review` (no notes, not from-scratch, not an ask) is an
    // idempotent "make sure a round runs on the current head" — but its
    // comment-id fingerprint is unique by construction, so it always
    // superseded (killed) an in-flight round on the same code, and the two
    // deaths compounded: the predecessor's agent sessions were still busy, so
    // the successor's prompts bounced too. Resolve it to the head sha so the
    // kernel dedupes into the running round instead. Notes and from-scratch
    // keep the comment fingerprint: those are deliberate restarts. Runs after
    // the allowlist and trust gates: no outbound lookup on behalf of a repo
    // or commenter this controller would refuse anyway.
    if trigger.reason == "/review"
        && trigger.question.is_none()
        && !trigger.review_from_scratch
        && trigger
            .review_notes
            .as_deref()
            .is_none_or(|notes| notes.trim().is_empty())
    {
        if let Some(github) = state.github.as_ref() {
            match github
                .pull_head_sha(&trigger.repository, trigger.pr_number as i64)
                .await
            {
                Ok(sha) => trigger.trigger_fingerprint = Some(format!("sha:{sha}")),
                Err(error) => tracing::warn!(
                    %error,
                    repo = trigger.repository,
                    pr = trigger.pr_number,
                    "head sha lookup for /review failed; keeping comment fingerprint"
                ),
            }
        }
    }
    // The round number is ours to know: `review_rounds` counts what this
    // controller actually closed on this pull request.
    let round = match state.store.as_ref() {
        Some(store) => match store
            .next_round(&trigger.repository, trigger.pr_number as i64)
            .await
        {
            Ok(round) => round,
            Err(error) => {
                tracing::warn!(%error, "round lookup failed; assuming round 1");
                1
            }
        },
        None => 1,
    };
    Ok(planner::build_plan_for_round(
        delivery_id,
        trigger,
        &state.config.roster,
        state.config.council_preset.as_deref(),
        &state.config.review_mode,
        round,
        // The chair renders this into the verdict footer, so it must be the
        // name in force: advertising the configured one after a rename is how
        // the system ends up teaching a command that does nothing.
        Some(state.bot_name()),
    ))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .filter(|value| !value.is_empty())
}

fn valid_delivery_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_event_type(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

pub fn verify_signature(secret: &str, body: &[u8], signature_header: Option<&str>) -> bool {
    let Some(signature) = signature_header.and_then(|value| value.strip_prefix("sha256=")) else {
        return false;
    };
    let Ok(expected) = hex::decode(signature) else {
        return false;
    };
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

fn verify_audit_signature(
    secret: &str,
    target: &str,
    timestamp_header: Option<&str>,
    signature_header: Option<&str>,
    now_secs: i64,
) -> bool {
    let Some(timestamp) = timestamp_header.and_then(|value| value.parse::<i64>().ok()) else {
        return false;
    };
    if now_secs.abs_diff(timestamp) > AUDIT_MAX_TIMESTAMP_SKEW_SECS {
        return false;
    }
    let canonical = audit_signature_payload(timestamp, target);
    verify_signature(secret, canonical.as_bytes(), signature_header)
}

fn audit_signature_payload(timestamp: i64, target: &str) -> String {
    format!("v1\n{timestamp}\nGET\n{target}")
}

async fn release_delivery_after_audit_failure(
    store: &dyn ProductStore,
    delivery_id: &str,
    result: &Value,
) {
    if let Err(error) = store.release_delivery_for_retry(delivery_id, result).await {
        tracing::error!(%error, %delivery_id, "audit failure delivery release failed");
    }
}

fn response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

#[cfg(test)]
mod tests {
    const COMMIT_ID: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER_COMMIT_ID: &str = "fedcba9876543210fedcba9876543210fedcba98";
    const COMMIT_FINGERPRINT: &str = "sha:0123456789abcdef0123456789abcdef01234567";
    const OTHER_COMMIT_FINGERPRINT: &str = "sha:fedcba9876543210fedcba9876543210fedcba98";

    #[tokio::test]
    async fn a_renamed_app_is_answered_to_under_both_names() {
        // Live case 2026-08-07: the dev App was renamed to `openab-council`
        // while the controller still had `zeabur-council`. Nothing errored —
        // `@openab-council review` simply did nothing. The App's own slug is
        // authoritative now, and the configured name survives as an alias so
        // the rename does not invalidate what is already in the thread.
        let (readiness, handles) = resolve_bot_handles(Some("zeabur-council"), None).await;
        assert!(
            !readiness.enabled,
            "no client to ask: unverified, not a fault"
        );
        assert_eq!(handles, vec!["zeabur-council".to_string()]);

        // The matcher takes either name, and neither matches a stranger.
        let both = vec!["openab-council".to_string(), "zeabur-council".to_string()];
        for comment in [
            "@openab-council review",
            "@zeabur-council review",
            "@OpenAB-Council review",
        ] {
            assert!(
                planner::parse_trigger("issue_comment", &comment_fixture(comment), &both).is_some(),
                "{comment}"
            );
        }
        assert!(planner::parse_trigger(
            "issue_comment",
            &comment_fixture("@someone-else review"),
            &both
        )
        .is_none());
    }

    fn comment_fixture(body: &str) -> serde_json::Value {
        json!({
            "action": "created",
            "repository": {"full_name": "example/repo"},
            "issue": {"number": 1, "pull_request": {"url": "https://api.github.com/x"}},
            "comment": {"id": 1, "body": body, "author_association": "MEMBER",
                        "user": {"login": "someone", "type": "User"}}
        })
    }

    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use controller_protocol::{ActionResultEnvelope, ControllerActionResult, OpenSessionAction};
    use http_body_util::BodyExt;
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::Mutex;
    use tower::ServiceExt;

    type ActionCalls = Arc<Mutex<Vec<(String, OpenSessionAction)>>>;

    #[test]
    fn audit_signature_is_bound_to_the_exact_query_target() {
        let target = "/api/v1/audit/events?session_id=ses_1&limit=500";
        let timestamp = 1_000;
        let mut mac = HmacSha256::new_from_slice(b"observer-secret").unwrap();
        mac.update(audit_signature_payload(timestamp, target).as_bytes());
        let header = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_audit_signature(
            "observer-secret",
            target,
            Some("1000"),
            Some(&header),
            1_001,
        ));
        assert!(!verify_audit_signature(
            "observer-secret",
            "/api/v1/audit/events?session_id=ses_2&limit=500",
            Some("1000"),
            Some(&header),
            1_001,
        ));
        assert!(!verify_audit_signature(
            "observer-secret",
            target,
            Some("1000"),
            Some(&header),
            2_000,
        ));
    }

    #[tokio::test]
    async fn audit_failure_release_reopens_delivery_for_retry() {
        let store = SqliteStore::memory().unwrap();
        assert_eq!(
            store
                .begin_delivery("delivery-audit-failure", "pull_request", None, "hash")
                .unwrap(),
            DeliveryAdmission::New
        );
        let result = json!({"ok": false, "error": "audit_store_failed"});
        release_delivery_after_audit_failure(&store, "delivery-audit-failure", &result).await;
        assert_eq!(
            store
                .begin_delivery("delivery-audit-failure", "pull_request", None, "hash")
                .unwrap(),
            DeliveryAdmission::New
        );
    }

    #[test]
    fn provider_audit_context_normalizes_actor_and_pull_request_target() {
        let event = controller_audit_event(
            "action.accepted:test",
            "action.accepted",
            AuditOutcome::Accepted,
            1_000,
            AuditCorrelation::default(),
            json!({
                "actor": {
                    "kind": "github_user",
                    "id": "42",
                    "display": "octocat",
                    "association": "MEMBER"
                },
                "repository": "example/repo",
                "pr_number": 7,
                "head_sha": "0123456789abcdef0123456789abcdef01234567"
            }),
            None,
        );
        assert_eq!(event.actor.unwrap().id.as_deref(), Some("42"));
        let target = event.target.unwrap();
        assert_eq!(target.kind, "github_pull_request");
        assert_eq!(target.reference.as_deref(), Some("example/repo#7"));
        assert_eq!(
            target.revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
    }

    struct RecordingActionClient {
        calls: ActionCalls,
        failures: Mutex<VecDeque<bool>>,
    }

    impl RecordingActionClient {
        fn new(failures: impl IntoIterator<Item = bool>) -> (Self, ActionCalls) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    calls: calls.clone(),
                    failures: Mutex::new(failures.into_iter().collect()),
                },
                calls,
            )
        }
    }

    impl ocp::OcpActionClient for RecordingActionClient {
        fn open_session(&self, action_id: String, action: OpenSessionAction) -> ocp::ActionFuture {
            self.calls
                .lock()
                .unwrap()
                .push((action_id.clone(), action.clone()));
            let fail = self.failures.lock().unwrap().pop_front().unwrap_or(false);
            Box::pin(async move {
                if fail {
                    return Err(ocp::ActionFailure::Unavailable);
                }
                let result =
                    if action.trigger_fingerprint.as_deref() == Some(OTHER_COMMIT_FINGERPRINT) {
                        ControllerActionResult::Superseded {
                            session_id: "ses_2".into(),
                            old_id: "ses_1".into(),
                        }
                    } else {
                        ControllerActionResult::SessionOpened {
                            session_id: "ses_1".into(),
                            deduped: false,
                        }
                    };
                Ok(ActionResultEnvelope {
                    version: controller_protocol::CURRENT_VERSION,
                    action_id,
                    result,
                })
            })
        }
    }

    fn test_config() -> Config {
        Config {
            addr: "127.0.0.1:0".into(),
            db_path: ":memory:".into(),
            mode: OperatingMode::PlanOnly,
            webhook_secret: Some("fixture-secret".into()),
            shadow_secret: Some("shadow-secret".into()),
            observer_secret: None,
            operator_write_secret: None,
            canary_repository: None,
            allowed_repos: BTreeSet::from(["example/repo".into()]),
            trusted_authors: BTreeSet::new(),
            bot_handle: Some("fixture-council".into()),
            roster: vec!["chair".into(), "rev1".into(), "rev2".into()],
            council_preset: None,
            review_mode: "approve".into(),
            ocp_action: config::OcpActionConfig {
                base_url: None,
                action_token: None,
                scope: None,
                controller_id: None,
            },
            event_signing_secret: None,
            github_app: config::GitHubAppConfig {
                app_id: None,
                installation_id: None,
                private_key: None,
            },
            enable_writes: false,
            github_api_base: "https://api.github.com".into(),
        }
    }

    fn external_config(event_secret: &[u8]) -> Config {
        let mut config = test_config();
        config.mode = OperatingMode::ExternalCanary;
        config.canary_repository = Some("example/repo".into());
        config.ocp_action = config::OcpActionConfig {
            base_url: Some("https://ocp.example.test".into()),
            action_token: Some("fixture-action-token".into()),
            scope: Some("tenant:dev/resource:canary".into()),
            controller_id: Some("github-canary".into()),
        };
        config.event_signing_secret = Some(URL_SAFE_NO_PAD.encode(event_secret));
        config.observer_secret = Some("observer-secret".into());
        config
    }

    #[tokio::test]
    async fn external_mode_actually_wires_up_and_reaches_ready() {
        // Council F1 on #315: config-level readiness said external was live
        // while the AppState constructors still gated on ExternalCanary, so
        // the mode could never build an action client or event verifier. This
        // exercises the real wiring end to end.
        let mut config = external_config(b"0123456789abcdef0123456789abcdef");
        config.mode = OperatingMode::External;
        config.canary_repository = None;
        config.github_app = config::GitHubAppConfig {
            app_id: Some("4235962".into()),
            installation_id: Some("144934354".into()),
            private_key: Some("not-a-pem-but-present".into()),
        };
        config.enable_writes = true;
        let state = AppState::from_config(config).await;
        assert!(state.action_client.is_some(), "action client must exist");
        assert!(state.event_verifier.is_some(), "event verifier must exist");
        assert!(state.github.is_some(), "write client must exist");
        let readiness = state.readiness();
        assert_eq!(readiness.status, "ready", "external mode must reach ready");
    }

    #[tokio::test]
    async fn legacy_authority_writes_are_parked_before_provider_send() {
        let concrete_store = Arc::new(SqliteStore::memory().unwrap());
        let store: Arc<dyn ProductStore> = concrete_store.clone();
        let mut config = Config::from_values(|_| None);
        config.mode = OperatingMode::ExternalCanary;
        config.enable_writes = true;
        config.canary_repository = Some("example/repo".into());
        config.github_api_base = "http://127.0.0.1:1".into();
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let github = Arc::new(
            github::GitHubClient::from_config(&config).expect("writes enabled builds a client"),
        );
        github.seed_test_token("ghs_test");

        let writes = vec![
            (
                "legacy_review",
                closing::KIND_REVIEW,
                json!({
                    "repo": "example/repo",
                    "pr_number": 7,
                    "event": "APPROVE",
                    "body": format!("legacy\n\n{}", closing::round_marker("legacy_review"))
                }),
            ),
            (
                "legacy_success",
                closing::KIND_STATUS,
                json!({
                    "repo": "example/repo",
                    "sha": COMMIT_ID,
                    "state": "success",
                    "context": closing::STATUS_CONTEXT,
                    "description": "legacy"
                }),
            ),
            (
                "legacy_failure",
                closing::KIND_STATUS,
                json!({
                    "repo": "example/repo",
                    "sha": COMMIT_ID,
                    "state": "failure",
                    "context": closing::STATUS_CONTEXT,
                    "description": "legacy"
                }),
            ),
        ];
        for (session_id, kind, payload) in &writes {
            concrete_store
                .record_review_round(&store::ReviewRound {
                    repo: "example/repo".into(),
                    pr_number: 7,
                    session_id: (*session_id).into(),
                    head_sha: Some(COMMIT_ID.into()),
                    verified_commit_id: None,
                    integrity_disposition: "legacy_unverified".into(),
                    decision: "approve".into(),
                    red: 0,
                    yellow: 0,
                    green: 1,
                })
                .unwrap();
            concrete_store
                .enqueue_write(session_id, kind, payload)
                .unwrap();
        }

        for _ in 0..WRITE_MAX_ATTEMPTS {
            assert_eq!(drain_outbox_batch(&store, &github).await, writes.len());
        }
        assert_eq!(concrete_store.pending_writes(10).unwrap().len(), 0);
        let rejected = concrete_store
            .audit_events(&AuditEventQuery {
                kind: Some("github.write.authority_rejected".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            rejected.events.len(),
            writes.len() * WRITE_MAX_ATTEMPTS as usize
        );
        assert!(rejected.events.iter().all(|event| {
            event
                .event
                .error
                .as_ref()
                .is_some_and(|error| error.class == "unproven_legacy_authority_intent")
        }));
    }

    fn signed_request(delivery: &str, body: &'static str) -> Request<Body> {
        let mut mac = HmacSha256::new_from_slice(b"fixture-secret").unwrap();
        mac.update(body.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        Request::post("/api/v1/github/webhooks")
            .header("x-github-event", "pull_request")
            .header("x-github-delivery", delivery)
            .header("x-hub-signature-256", signature)
            .body(Body::from(body))
            .unwrap()
    }

    fn signed_owned_request(delivery: &str, event: &str, body: String) -> Request<Body> {
        let mut mac = HmacSha256::new_from_slice(b"fixture-secret").unwrap();
        mac.update(body.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        Request::post("/api/v1/github/webhooks")
            .header("x-github-event", event)
            .header("x-github-delivery", delivery)
            .header("x-hub-signature-256", signature)
            .body(Body::from(body))
            .unwrap()
    }

    fn signed_shadow_request(request: &shadow::ShadowCompareRequest) -> Request<Body> {
        let body = serde_json::to_vec(request).unwrap();
        let mut mac = HmacSha256::new_from_slice(b"shadow-secret").unwrap();
        mac.update(&body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        Request::post("/api/v1/shadow/compare")
            .header("x-shadow-signature-256", signature)
            .body(Body::from(body))
            .unwrap()
    }

    fn signed_shadow_summary_request() -> Request<Body> {
        let mut mac = HmacSha256::new_from_slice(b"shadow-secret").unwrap();
        mac.update(&[]);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        Request::get("/api/v1/shadow/summary")
            .header("x-shadow-signature-256", signature)
            .body(Body::empty())
            .unwrap()
    }

    fn signed_runtime_event_request(
        secret: &[u8],
        event_id: &str,
        target: &str,
        body: String,
    ) -> Request<Body> {
        let timestamp = now_unix();
        let body_hash = hex::encode(Sha256::digest(body.as_bytes()));
        let canonical =
            format!("v1\ngithub-canary\n{event_id}\n{timestamp}\nPOST\n{target}\n{body_hash}");
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(canonical.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        Request::post(target)
            .header("x-oab-controller-id", "github-canary")
            .header("x-oab-event-id", event_id)
            .header("x-oab-timestamp", timestamp)
            .header("x-oab-signature", signature)
            .body(Body::from(body))
            .unwrap()
    }

    fn signed_canary_summary_request() -> Request<Body> {
        let mut mac = HmacSha256::new_from_slice(b"observer-secret").unwrap();
        mac.update(&[]);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        Request::get("/api/v1/canary/summary")
            .header("x-canary-signature-256", signature)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn readiness_reports_disabled_external_clients() {
        let state = Arc::new(AppState::with_store(
            test_config(),
            SqliteStore::memory().unwrap(),
        ));
        let response = router(state)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["mode"], "plan_only");
        assert_eq!(body["components"]["ocp"]["enabled"], false);
        assert_eq!(body["components"]["github"]["enabled"], false);
    }

    #[tokio::test]
    async fn findings_read_is_signed_filtered_and_shaped_like_the_kernel_route() {
        let store = SqliteStore::memory().unwrap();
        store
            .record_review_findings(
                "ses_read_1",
                "example/repo",
                7,
                Some(COMMIT_ID),
                &[
                    store::ReviewFinding {
                        stable_id: "F1".into(),
                        severity: "red".into(),
                        status: "open".into(),
                        title: "first".into(),
                        path: Some("src/a.rs".into()),
                        line: Some(12),
                        raised_by: Some("rev1".into()),
                        angle: Some("correctness".into()),
                    },
                    store::ReviewFinding {
                        stable_id: "F2".into(),
                        severity: "green".into(),
                        status: "resolved".into(),
                        title: "second".into(),
                        path: None,
                        line: None,
                        raised_by: Some("rev2".into()),
                        angle: None,
                    },
                ],
            )
            .unwrap();
        store
            .record_review_findings(
                "ses_read_2",
                "other/repo",
                9,
                None,
                &[store::ReviewFinding {
                    stable_id: "F1".into(),
                    severity: "red".into(),
                    status: "open".into(),
                    title: "elsewhere".into(),
                    path: None,
                    line: None,
                    raised_by: None,
                    angle: None,
                }],
            )
            .unwrap();

        let mut config = test_config();
        config.observer_secret = Some("observer-secret".into());
        let state = Arc::new(AppState {
            config,
            store: Some(Arc::new(store)),
            store_error: None,
            action_client: None,
            action_client_error: None,
            event_verifier: None,
            event_verifier_error: None,
            github: None,
            bot_identity: ComponentReadiness::disabled("handle unverified"),
            bot_handles: vec!["bot".into()],
        });

        let signed = |target: &str| {
            let timestamp = now_unix();
            let mut mac = HmacSha256::new_from_slice(b"observer-secret").unwrap();
            mac.update(audit_signature_payload(timestamp, target).as_bytes());
            Request::get(target)
                .header("x-canary-audit-timestamp", timestamp.to_string())
                .header(
                    "x-canary-audit-signature-256",
                    format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
                )
                .body(Body::empty())
                .unwrap()
        };
        let read = |request: Request<Body>| async {
            let response = router(state.clone()).oneshot(request).await.unwrap();
            let status = response.status();
            let body: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            (status, body)
        };

        // Unfiltered: newest first, and the identity columns the kernel's copy
        // cannot fill for controller sessions are populated here.
        let (status, body) = read(signed("/api/v1/review/findings?limit=10")).await;
        assert_eq!(status, StatusCode::OK);
        let rows = body["findings"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["title"], "elsewhere");
        let f1 = rows.iter().find(|r| r["title"] == "first").unwrap();
        assert_eq!(f1["repo"], "example/repo");
        assert_eq!(f1["pr_number"], 7);
        assert_eq!(f1["head_sha"], COMMIT_ID);
        assert_eq!(f1["session_id"], "ses_read_1");
        assert_eq!(f1["stable_id"], "F1");
        assert_eq!(f1["severity"], "red");
        assert_eq!(f1["status"], "open");
        assert_eq!(f1["path"], "src/a.rs");
        assert_eq!(f1["line"], 12);
        assert_eq!(f1["raised_by"], "rev1");
        assert_eq!(f1["angle"], "correctness");
        assert!(f1["created_at"].is_number());

        // The filter `review-escapes.py` needs, and the one it gets nothing
        // from on the kernel's copy today.
        let (_, body) = read(signed("/api/v1/review/findings?repo=example/repo&limit=10")).await;
        assert_eq!(body["findings"].as_array().unwrap().len(), 2);
        let (_, body) = read(signed(
            "/api/v1/review/findings?repo=example/repo&status=open&limit=10",
        ))
        .await;
        assert_eq!(body["findings"].as_array().unwrap().len(), 1);
        let (_, body) = read(signed("/api/v1/review/findings?severity=red&limit=10")).await;
        assert_eq!(body["findings"].as_array().unwrap().len(), 2);
        let (_, body) = read(signed("/api/v1/review/findings?pr=9&limit=10")).await;
        assert_eq!(body["findings"].as_array().unwrap().len(), 1);

        // Bounded rather than rejected, and the bound is reported back.
        let (_, body) = read(signed("/api/v1/review/findings?limit=99999")).await;
        assert_eq!(body["limit"], 5000);

        // A signature bound to a different query cannot be replayed onto this
        // one — the same property the audit read has.
        let wrong = {
            let timestamp = now_unix();
            let mut mac = HmacSha256::new_from_slice(b"observer-secret").unwrap();
            mac.update(
                audit_signature_payload(timestamp, "/api/v1/review/findings?repo=other/repo")
                    .as_bytes(),
            );
            Request::get("/api/v1/review/findings?repo=example/repo")
                .header("x-canary-audit-timestamp", timestamp.to_string())
                .header(
                    "x-canary-audit-signature-256",
                    format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
                )
                .body(Body::empty())
                .unwrap()
        };
        let (status, _) = read(wrong).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = read(
            Request::get("/api/v1/review/findings")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unsigned reads are refused");
    }

    #[tokio::test]
    async fn waived_findings_reach_the_plan_and_bump_repo_scoped_counters() {
        let store = SqliteStore::memory().unwrap();
        let own = store
            .create_review_waiver(
                "example/repo",
                None,
                "accepted eval",
                None,
                "op",
                now_unix() + 86_400,
                store::WAIVER_SOURCE_OPERATOR,
            )
            .await
            .unwrap();
        let foreign = store
            .create_review_waiver(
                "other/repo",
                None,
                "elsewhere",
                None,
                "op",
                now_unix() + 86_400,
                store::WAIVER_SOURCE_OPERATOR,
            )
            .await
            .unwrap();

        // The chair's block: one waived finding naming the own-repo waiver and
        // one naming the foreign repo's — the second must bump nothing.
        let body = format!(
            "<!-- openab-council -->\nReviewed at {COMMIT_ID}\nreport\n<!-- openab-findings\n{{\"head_sha\":\"{COMMIT_ID}\",\"findings\":[\
             {{\"id\":\"F1\",\"severity\":\"yellow\",\"status\":\"waived\",\
              \"title\":\"waived one\",\"waiver_id\":\"{}\"}},\
             {{\"id\":\"F2\",\"severity\":\"yellow\",\"status\":\"waived\",\
              \"title\":\"cross-repo attempt\",\"waiver_id\":\"{}\"}}]}}\n-->\n\
             [[verdict:approve r=0 y=0 g=1]] [done]",
            own.id, foreign.id
        );
        let parsed = verdict::parse_final_messages(&[body]);
        assert!(
            parsed.findings.is_some(),
            "a waived status must not reject the block — it did before SEI-895"
        );
        let target = store::SessionTarget {
            repo: "example/repo".into(),
            pr_number: 7,
            head_sha: Some(COMMIT_ID.into()),
            reason: None,
            required_valid_reviewers: Some(2),
        };
        let plan = closing::plan_close(&target, &parsed, None, "ses_waiver_test", false);
        assert_eq!(plan.fired_waivers.len(), 2);
        assert_eq!(
            plan.findings
                .iter()
                .filter(|f| f.status == "waived")
                .count(),
            2
        );

        let bumped = store
            .record_waiver_fired("example/repo", &plan.fired_waivers)
            .await
            .unwrap();
        assert_eq!(bumped, 1, "only the own-repo waiver fires");
        let own_after = store
            .list_review_waivers(Some("example/repo"), true, now_unix())
            .await
            .unwrap();
        assert_eq!(own_after[0].fired_count, 1);
        assert!(own_after[0].last_fired_at.is_some());
        let foreign_after = store
            .list_review_waivers(Some("other/repo"), true, now_unix())
            .await
            .unwrap();
        assert_eq!(
            foreign_after[0].fired_count, 0,
            "a chair cannot bump another repo's ledger — restored from the kernel"
        );
    }

    #[tokio::test]
    async fn open_dispatch_appends_active_waivers_to_the_chair_alone() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let event_secret = vec![8; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let (client, calls) = RecordingActionClient::new([false]);
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            Some(Arc::new(client)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();
        let live = store
            .create_review_waiver(
                "example/repo",
                Some("src/**"),
                "flaky ===== timing\nassertions accepted",
                Some("example/repo#1"),
                "op",
                now_unix() + 3 * 86_400,
                store::WAIVER_SOURCE_OPERATOR,
            )
            .await
            .unwrap();
        // An author-waived finding's entry (ADR 038): council-authored title,
        // labeled with who accepted it — never the author's prose.
        store
            .record_review_findings(
                "ses_authored",
                "example/repo",
                9,
                Some(COMMIT_ID),
                &[store::ReviewFinding {
                    stable_id: "F1".into(),
                    severity: "red".into(),
                    status: "open".into(),
                    title: "Forged sentinel bypasses safeDiagnostic".into(),
                    path: Some("src/lib/agent/cost.rs".into()),
                    line: None,
                    raised_by: None,
                    angle: None,
                }],
            )
            .await
            .unwrap();
        let store::WaiveAdmission::Waived(_, authored) = store
            .waive_review_finding(
                "example/repo",
                9,
                "F1",
                COMMIT_ID,
                "yuaanlin",
                "we accept this for eval traffic",
                now_unix() + 83 * 86_400,
            )
            .await
            .unwrap()
        else {
            panic!("an open finding on the right head must waive");
        };
        // Inactive ones must not appear: one expired, one revoked.
        let expired = store
            .create_review_waiver(
                "example/repo",
                None,
                "expired",
                None,
                "op",
                now_unix() + 1,
                store::WAIVER_SOURCE_OPERATOR,
            )
            .await
            .unwrap();
        store
            .update_review_waiver(&expired.id, Some(now_unix() - 1), false)
            .await
            .unwrap();
        let revoked = store
            .create_review_waiver(
                "example/repo",
                None,
                "revoked",
                None,
                "op",
                now_unix() + 86_400,
                store::WAIVER_SOURCE_OPERATOR,
            )
            .await
            .unwrap();
        store
            .update_review_waiver(&revoked.id, None, true)
            .await
            .unwrap();

        let response = router(state)
            .oneshot(signed_owned_request(
                "waiver-delivery-1",
                "pull_request",
                BODY.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let action = &calls[0].1;
        let chair = action.chair_bot.clone().unwrap();
        let chair_input = action.recipient_inputs.get(&chair).unwrap();
        assert!(chair_input.contains("===== ACTIVE WAIVERS"));
        assert!(chair_input.contains(&live.id));
        assert!(
            chair_input.contains("flaky - timing assertions accepted"),
            "text flattened and delimiter runs defanged: {chair_input}"
        );
        assert!(chair_input.contains("[src/**]"));
        // Provenance is labeled per entry (ADR 038 point 7): the operator's
        // words as operator, the author's acceptance under the council's own
        // title with the accepting login — and never the author's prose.
        assert!(
            chair_input.contains("(operator, expires in"),
            "operator provenance labeled: {chair_input}"
        );
        assert!(chair_input.contains(&authored.id));
        assert!(
            chair_input.contains(
                "\"Forged sentinel bypasses safeDiagnostic\" (waived by @yuaanlin, expires in"
            ),
            "author provenance carries the council-authored title: {chair_input}"
        );
        assert!(
            !chair_input.contains("we accept this for eval traffic"),
            "the author's prose must never reach the chair: {chair_input}"
        );
        assert!(!chair_input.contains(&expired.id), "expired never injected");
        assert!(!chair_input.contains(&revoked.id), "revoked never injected");
        for (bot, input) in action.recipient_inputs.iter().filter(|(b, _)| **b != chair) {
            assert!(
                !input.contains("ACTIVE WAIVERS"),
                "reviewer {bot} must never see the waiver ledger"
            );
        }
    }

    #[tokio::test]
    async fn a_waive_unblocks_and_rewrites_all_three_artifacts() {
        // ADR 038 v2 end to end: `@bot waive F1 <reason>` flips the last
        // blocker to waived, mints the repo-scoped waiver, and rewrites what
        // the pull request shows — the verdict comment gains a visible Waived
        // section, the status goes green, and a new APPROVE review supersedes
        // the REQUEST_CHANGES that actually holds the merge.
        use axum::extract::Path as AxPath;
        use axum::routing::{get as axum_get, post as axum_post};

        #[derive(Clone, Default)]
        struct Recorded {
            patched: Arc<std::sync::Mutex<Vec<(i64, String)>>>,
            statuses: Arc<std::sync::Mutex<Vec<Value>>>,
            reviews: Arc<std::sync::Mutex<Vec<Value>>>,
        }
        let gh = Recorded::default();
        let round_marker = closing::round_marker("ses_w");
        let app = Router::new()
            .route(
                "/repos/:o/:n/collaborators/:login/permission",
                axum_get(|| async { Json(json!({"permission": "write"})) }),
            )
            .route(
                "/repos/:o/:n/pulls/7",
                axum_get(|| async { Json(json!({"head": {"sha": COMMIT_ID}})) }),
            )
            .route(
                "/repos/:o/:n/issues/comments/:id",
                axum_get({
                    let marker = round_marker.clone();
                    move || {
                        let marker = marker.clone();
                        async move { Json(json!({"body": format!("council report\n\n{marker}")})) }
                    }
                })
                .patch({
                    let gh = gh.clone();
                    move |AxPath((_, _, id)): AxPath<(String, String, i64)>,
                          Json(body): Json<Value>| {
                        let gh = gh.clone();
                        async move {
                            gh.patched
                                .lock()
                                .unwrap()
                                .push((id, body["body"].as_str().unwrap_or_default().into()));
                            Json(json!({"id": id}))
                        }
                    }
                }),
            )
            .route(
                "/repos/:o/:n/statuses/:sha",
                axum_post({
                    let gh = gh.clone();
                    move |Json(body): Json<Value>| {
                        let gh = gh.clone();
                        async move {
                            gh.statuses.lock().unwrap().push(body);
                            Json(json!({"id": 1}))
                        }
                    }
                }),
            )
            .route(
                "/repos/:o/:n/pulls/7/reviews",
                axum_get({
                    // The round's own REQUEST_CHANGES review is already on the
                    // pull request, carrying the round marker. The decision's
                    // APPROVE must not reconcile onto it and conclude
                    // "already sent" — that would swallow the unblock.
                    let marker = round_marker.clone();
                    move || {
                        let marker = marker.clone();
                        async move {
                            Json(json!([{
                                "id": 901,
                                "body": format!("blocked\n\n{marker}"),
                                "state": "CHANGES_REQUESTED",
                                "commit_id": COMMIT_ID,
                                "user": {"login": "fixture-council[bot]"}
                            }]))
                        }
                    }
                })
                .post({
                    let gh = gh.clone();
                    move |Json(body): Json<Value>| {
                        let gh = gh.clone();
                        async move {
                            gh.reviews.lock().unwrap().push(body);
                            Json(json!({
                                "id": 2000,
                                "state": "APPROVED",
                                "commit_id": COMMIT_ID
                            }))
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = Config::from_values(|_| None);
        config.mode = OperatingMode::ExternalCanary;
        config.enable_writes = true;
        config.canary_repository = Some("example/repo".into());
        config.github_api_base = format!("http://{addr}");
        config.bot_handle = Some("fixture-council".into());
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            None,
            None,
        ));
        state.github.as_ref().unwrap().seed_test_token("ghs_test");
        let store = state.store.clone().unwrap();
        store
            .record_review_round(&store::ReviewRound {
                repo: "example/repo".into(),
                pr_number: 7,
                session_id: "ses_w".into(),
                head_sha: Some(COMMIT_ID.into()),
                verified_commit_id: Some(COMMIT_ID.into()),
                integrity_disposition: "verified".into(),
                decision: "request_changes".into(),
                red: 1,
                yellow: 0,
                green: 1,
            })
            .await
            .unwrap();
        store.set_round_comment_id("ses_w", 4242).await.unwrap();
        store
            .record_review_findings(
                "ses_w",
                "example/repo",
                7,
                Some(COMMIT_ID),
                &[
                    store::ReviewFinding {
                        stable_id: "F1".into(),
                        severity: "red".into(),
                        status: "open".into(),
                        title: "Forged sentinel bypasses safeDiagnostic".into(),
                        path: Some("src/lib/agent/cost.rs".into()),
                        line: Some(42),
                        raised_by: Some("rev-codex".into()),
                        angle: Some("security".into()),
                    },
                    store::ReviewFinding {
                        stable_id: "F2".into(),
                        severity: "green".into(),
                        status: "open".into(),
                        title: "fine".into(),
                        path: None,
                        line: None,
                        raised_by: None,
                        angle: None,
                    },
                ],
            )
            .await
            .unwrap();

        // A reasonless waive is refused with the exact command to type — the
        // waiver ledger must gain no row from it.
        let mut command = planner::FindingCommand {
            repository: "example/repo".into(),
            pr_number: 7,
            verb: "waive".into(),
            stable_id: "F1".into(),
            reason: None,
            comment_id: 555,
            author_trusted: true,
            author_login: Some("author1".into()),
        };
        let refusal = apply_finding_command(&state, &command).await;
        assert!(refusal.contains("`waive F1` needs a reason"), "{refusal}");
        assert!(refusal.contains("waive F1 <why we accept this defect>"));
        assert!(store
            .list_review_waivers(Some("example/repo"), true, now_unix())
            .await
            .unwrap()
            .is_empty());

        command.reason = Some("eval traffic only, capped upstream".into());
        let reply = apply_finding_command(&state, &command).await;
        assert!(reply.contains("F1 waived"), "{reply}");
        assert!(reply.contains("repo-wide"), "{reply}");
        assert!(reply.contains("🔴1 🟡0 → 🔴0 🟡0"), "{reply}");
        assert!(reply.contains("APPROVE review"), "{reply}");
        assert!(
            !reply.contains("controller fault"),
            "every write must enqueue: {reply}"
        );
        // F1 is 🔴, so the waiver is minted with the short horizon and the
        // reply says why it is short.
        assert!(
            reply.contains("shorter horizon") && reply.contains("conspicuous"),
            "a red waive must explain its horizon: {reply}"
        );
        let waivers = store
            .list_review_waivers(Some("example/repo"), false, now_unix())
            .await
            .unwrap();
        assert_eq!(waivers.len(), 1);
        assert_eq!(waivers[0].source, store::WAIVER_SOURCE_AUTHOR);
        let horizon = waivers[0].expires_at - waivers[0].created_at;
        assert!(
            horizon <= deciding::WAIVE_RED_EXPIRY_SECS
                && horizon > deciding::WAIVE_RED_EXPIRY_SECS - 60,
            "a red finding's waiver gets the 30d horizon, got {horizon}s"
        );
        assert!(reply.contains(&waivers[0].id), "the reply names the waiver");

        // The outbox drains to the fake GitHub; wait for it to empty.
        for _ in 0..200 {
            if store.pending_writes(10).await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(store.pending_writes(10).await.unwrap().is_empty());

        let patched = gh.patched.lock().unwrap();
        assert_eq!(patched.len(), 1, "the verdict comment was edited in place");
        assert_eq!(patched[0].0, 4242);
        assert!(patched[0].1.contains(&round_marker), "the marker survives");
        assert!(patched[0].1.contains("**Waived**"));
        assert!(patched[0]
            .1
            .contains("F1 🔴 Forged sentinel bypasses safeDiagnostic"));
        assert!(patched[0].1.contains("waived by @author1"));
        let statuses = gh.statuses.lock().unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["state"], "success");
        let reviews = gh.reviews.lock().unwrap();
        assert_eq!(
            reviews.len(),
            1,
            "the APPROVE must not reconcile onto the round's own REQUEST_CHANGES"
        );
        assert_eq!(reviews[0]["event"], "APPROVE");
        assert!(reviews[0]["body"]
            .as_str()
            .unwrap()
            .contains(&deciding::decision_marker("ses_w", "555")));
    }

    #[tokio::test]
    async fn reopening_a_waived_finding_revokes_its_waiver() {
        // An undo that does not undo would be worse than none: the finding
        // would come back while the repo-wide suppression stayed live, and
        // every future round would waive it again.
        use axum::routing::get as axum_get;

        let app = Router::new()
            .route(
                "/repos/:o/:n/collaborators/:login/permission",
                axum_get(|| async { Json(json!({"permission": "maintain"})) }),
            )
            .route(
                "/repos/:o/:n/pulls/7",
                axum_get(|| async { Json(json!({"head": {"sha": COMMIT_ID}})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = Config::from_values(|_| None);
        config.mode = OperatingMode::ExternalCanary;
        config.enable_writes = true;
        config.canary_repository = Some("example/repo".into());
        config.github_api_base = format!("http://{addr}");
        config.bot_handle = Some("fixture-council".into());
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            None,
            None,
        ));
        state.github.as_ref().unwrap().seed_test_token("ghs_test");
        let store = state.store.clone().unwrap();
        store
            .record_review_findings(
                "ses_w",
                "example/repo",
                7,
                Some(COMMIT_ID),
                &[store::ReviewFinding {
                    stable_id: "F1".into(),
                    severity: "red".into(),
                    status: "open".into(),
                    title: "title".into(),
                    path: None,
                    line: None,
                    raised_by: None,
                    angle: None,
                }],
            )
            .await
            .unwrap();
        let store::WaiveAdmission::Waived(_, waiver) = store
            .waive_review_finding(
                "example/repo",
                7,
                "F1",
                COMMIT_ID,
                "author1",
                "accepted",
                now_unix() + 86_400,
            )
            .await
            .unwrap()
        else {
            panic!("an open finding on the right head must waive");
        };

        // Council #383 F1 regression, first half: repeating the waive answers
        // "already waived" and mints nothing — no second waiver to orphan.
        let repeat = apply_finding_command(
            &state,
            &planner::FindingCommand {
                repository: "example/repo".into(),
                pr_number: 7,
                verb: "waive".into(),
                stable_id: "F1".into(),
                reason: Some("again".into()),
                comment_id: 557,
                author_trusted: true,
                author_login: Some("author2".into()),
            },
        )
        .await;
        assert!(
            repeat.contains("already waived on this revision by @author1"),
            "{repeat}"
        );
        assert!(repeat.contains(&waiver.id), "{repeat}");
        assert!(repeat.contains("reopen F1"), "{repeat}");
        let all = store
            .list_review_waivers(Some("example/repo"), true, now_unix())
            .await
            .unwrap();
        assert_eq!(all.len(), 1, "no second waiver row exists");

        let command = planner::FindingCommand {
            repository: "example/repo".into(),
            pr_number: 7,
            verb: "reopen".into(),
            stable_id: "F1".into(),
            reason: None,
            comment_id: 556,
            author_trusted: true,
            author_login: Some("author1".into()),
        };
        let reply = apply_finding_command(&state, &command).await;
        assert!(reply.contains("F1 reopened"), "{reply}");
        assert!(
            reply.contains(&waiver.id) && reply.contains("revoked"),
            "the reply says the waiver went with it: {reply}"
        );
        assert!(
            store
                .list_review_waivers(Some("example/repo"), false, now_unix())
                .await
                .unwrap()
                .is_empty(),
            "the waiver must not stay live after the reopen"
        );
    }

    #[tokio::test]
    async fn waiver_crud_requires_the_v2_write_signature() {
        let mut config = test_config();
        config.observer_secret = Some("observer-secret".into());
        config.operator_write_secret = Some("operator-write-secret".into());
        let state = Arc::new(AppState {
            config,
            store: Some(Arc::new(SqliteStore::memory().unwrap())),
            store_error: None,
            action_client: None,
            action_client_error: None,
            event_verifier: None,
            event_verifier_error: None,
            github: None,
            bot_identity: ComponentReadiness::disabled("handle unverified"),
            bot_handles: vec!["bot".into()],
        });

        let sign_write = |method: &str, target: &str, body: &[u8]| {
            let ts = now_unix();
            let canonical = format!(
                "v2\n{ts}\n{method}\n{target}\n{}",
                hex::encode(Sha256::digest(body))
            );
            let mut mac = HmacSha256::new_from_slice(b"operator-write-secret").unwrap();
            mac.update(canonical.as_bytes());
            (
                ts.to_string(),
                format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
            )
        };
        let call = |request: Request<Body>| {
            let state = state.clone();
            async move {
                let response = router(state).oneshot(request).await.unwrap();
                let status = response.status();
                let body: Value = serde_json::from_slice(
                    &response.into_body().collect().await.unwrap().to_bytes(),
                )
                .unwrap();
                (status, body)
            }
        };

        let body = serde_json::to_vec(&json!({
            "repo": "example/repo", "text": "ok trade-off",
            "created_by": "op", "expires_at": now_unix() + 86_400,
        }))
        .unwrap();

        // A v1 GET-style signature over the same target must not authorize a write.
        let ts = now_unix();
        let mut mac = HmacSha256::new_from_slice(b"observer-secret").unwrap();
        mac.update(audit_signature_payload(ts, "/api/v1/review/waivers").as_bytes());
        let v1_sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        let (status, _) = call(
            Request::post("/api/v1/review/waivers")
                .header("x-canary-audit-timestamp", ts.to_string())
                .header("x-canary-audit-signature-256", v1_sig)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "read signature cannot write");

        // A v2-shaped signature made with the OBSERVATION secret must also be
        // refused: reads and writes are separate credentials, the boundary
        // the kernel kept and round 1 of this PR's review flagged.
        let ts = now_unix();
        let canonical = format!(
            "v2\n{ts}\nPOST\n/api/v1/review/waivers\n{}",
            hex::encode(Sha256::digest(&body))
        );
        let mut mac = HmacSha256::new_from_slice(b"observer-secret").unwrap();
        mac.update(canonical.as_bytes());
        let observer_v2 = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        let (status, _) = call(
            Request::post("/api/v1/review/waivers")
                .header("x-canary-audit-timestamp", ts.to_string())
                .header("x-canary-audit-signature-256", observer_v2)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the observation secret must not authorize writes"
        );

        let (ts, sig) = sign_write("POST", "/api/v1/review/waivers", &body);
        let (status, created) = call(
            Request::post("/api/v1/review/waivers")
                .header("x-canary-audit-timestamp", ts)
                .header("x-canary-audit-signature-256", sig)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["waiver"]["id"].as_str().unwrap().to_string();
        assert!(id.starts_with("wvr_"));

        // A signature over one body must not authorize another.
        let tampered = serde_json::to_vec(&json!({
            "repo": "example/repo", "text": "different",
            "created_by": "op", "expires_at": now_unix() + 86_400,
        }))
        .unwrap();
        let (ts, sig) = sign_write("POST", "/api/v1/review/waivers", &body);
        let (status, _) = call(
            Request::post("/api/v1/review/waivers")
                .header("x-canary-audit-timestamp", ts)
                .header("x-canary-audit-signature-256", sig)
                .body(Body::from(tampered))
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "body is bound by the signature"
        );

        // The kernel's PATCH guards: an empty patch and a past expiry 400.
        let empty = serde_json::to_vec(&json!({})).unwrap();
        let target = format!("/api/v1/review/waivers/{id}");
        let (ts, sig) = sign_write("PATCH", &target, &empty);
        let (status, _) = call(
            Request::patch(&target)
                .header("x-canary-audit-timestamp", ts)
                .header("x-canary-audit-signature-256", sig)
                .body(Body::from(empty))
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "empty patch is a caller bug"
        );
        let past = serde_json::to_vec(&json!({"expires_at": now_unix() - 60})).unwrap();
        let (ts, sig) = sign_write("PATCH", &target, &past);
        let (status, _) = call(
            Request::patch(&target)
                .header("x-canary-audit-timestamp", ts)
                .header("x-canary-audit-signature-256", sig)
                .body(Body::from(past))
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a past expiry is a silent revoke wearing the wrong name"
        );

        // Revoke, then confirm the active list is empty but --all still sees it.
        let patch_body = serde_json::to_vec(&json!({"revoke": true})).unwrap();
        let (ts, sig) = sign_write("PATCH", &target, &patch_body);
        let (status, _) = call(
            Request::patch(&target)
                .header("x-canary-audit-timestamp", ts)
                .header("x-canary-audit-signature-256", sig)
                .body(Body::from(patch_body))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let signed_get = |target: &str| {
            let ts = now_unix();
            let mut mac = HmacSha256::new_from_slice(b"observer-secret").unwrap();
            mac.update(audit_signature_payload(ts, target).as_bytes());
            Request::get(target)
                .header("x-canary-audit-timestamp", ts.to_string())
                .header(
                    "x-canary-audit-signature-256",
                    format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
                )
                .body(Body::empty())
                .unwrap()
        };
        let (status, body) = call(signed_get("/api/v1/review/waivers?repo=example/repo")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["waivers"].as_array().unwrap().len(),
            0,
            "revoked is inactive"
        );
        // Both spellings of the flag work — query strings are not JSON
        // booleans, and waiver-candidates.py sends `all=1`.
        let (_, body) = call(signed_get(
            "/api/v1/review/waivers?repo=example/repo&all=true",
        ))
        .await;
        assert_eq!(body["waivers"].as_array().unwrap().len(), 1);
        assert!(body["waivers"][0]["revoked_at"].is_number());
        let (_, body) = call(signed_get("/api/v1/review/waivers?repo=example/repo&all=1")).await;
        assert_eq!(body["waivers"].as_array().unwrap().len(), 1);

        // The report block rides on every read, and renewals are visible per
        // row — the controller half of the ADR 035/038 periodic report.
        let store = state.store.clone().unwrap();
        let live = store
            .create_review_waiver(
                "example/repo",
                None,
                "expiring soon and twice renewed",
                None,
                "op",
                now_unix() + 3 * 86_400,
                store::WAIVER_SOURCE_OPERATOR,
            )
            .await
            .unwrap();
        for days in [5i64, 7] {
            store
                .update_review_waiver(&live.id, Some(now_unix() + days * 86_400), false)
                .await
                .unwrap();
        }
        let (_, body) = call(signed_get("/api/v1/review/waivers?repo=example/repo")).await;
        assert_eq!(body["waivers"].as_array().unwrap().len(), 1);
        assert_eq!(body["waivers"][0]["renewal_count"], 2);
        let report = &body["report"];
        assert_eq!(report["active"], 1, "the revoked row stays out: {report}");
        assert_eq!(report["expiring_within_14d"], json!([live.id]));
        assert_eq!(
            report["renewed_twice_or_more"],
            json!([live.id]),
            "the promotion queue names its candidates: {report}"
        );
        assert_eq!(report["never_fired"], 1);
    }

    #[test]
    fn the_waiver_report_serves_the_two_clocked_judgements() {
        // "Expiry is the classifier" and "renewed twice is a rule" are the
        // judgements the ADRs put on a clock; the report is the smallest
        // summary that serves them. Revoked and expired rows are out of every
        // number — they are history, not exposure.
        let now = 1_000_000_000;
        let mk =
            |id: &str, expires_at: i64, renewal_count: i64, fired_count: i64| store::ReviewWaiver {
                id: id.into(),
                repo: "example/repo".into(),
                path_class: None,
                text: "t".into(),
                origin_pr: None,
                created_by: "op".into(),
                created_at: now - 86_400,
                expires_at,
                revoked_at: None,
                fired_count,
                last_fired_at: None,
                source: store::WAIVER_SOURCE_OPERATOR.into(),
                renewal_count,
            };
        let mut revoked = mk("wvr_revoked", now + 90 * 86_400, 5, 0);
        revoked.revoked_at = Some(now - 10);
        let expired = mk("wvr_expired", now - 10, 2, 0);
        let waivers = vec![
            mk("wvr_far", now + 90 * 86_400, 0, 3),
            mk("wvr_soon", now + 3 * 86_400, 0, 0),
            mk("wvr_rule", now + 90 * 86_400, 2, 1),
            revoked,
            expired,
        ];
        let report = waiver_report(&waivers, now);
        assert_eq!(report["active"], 3);
        assert_eq!(report["expiring_within_14d"], json!(["wvr_soon"]));
        assert_eq!(report["renewed_twice_or_more"], json!(["wvr_rule"]));
        assert_eq!(report["never_fired"], 1, "wvr_soon alone: {report}");
    }

    #[tokio::test]
    async fn readiness_does_not_disclose_product_store_errors() {
        let state = Arc::new(AppState {
            config: test_config(),
            store: None,
            store_error: Some("unable to open /private/secret/controller.db".into()),
            action_client: None,
            action_client_error: None,
            event_verifier: None,
            event_verifier_error: None,
            github: None,
            bot_identity: ComponentReadiness::disabled("handle unverified"),
            bot_handles: vec!["bot".into()],
        });
        let response = router(state)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("controller product store unavailable"));
        assert!(!body.contains("/private/secret"));
    }

    #[tokio::test]
    async fn plan_only_readiness_rejects_github_write_credentials() {
        let mut config = test_config();
        config.github_app.app_id = Some("1".into());
        config.github_app.installation_id = Some("2".into());
        config.github_app.private_key = Some("private".into());
        let state = Arc::new(AppState::with_store(config, SqliteStore::memory().unwrap()));
        let response = router(state)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn canary_readiness_needs_the_write_switch_alongside_credentials() {
        // Credentials without the switch is now the *loud* failure — before P4
        // any credential at all was rejected, so this is the one case whose
        // meaning changed and it must stay a 503 rather than become ready.
        let event_secret = vec![9; 32];
        let mut config = external_config(&event_secret);
        config.github_app.app_id = Some("1".into());
        config.github_app.installation_id = Some("2".into());
        config.github_app.private_key = Some("private".into());
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let state = Arc::new(AppState::with_components(
            config.clone(),
            SqliteStore::memory().unwrap(),
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let response = router(state)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // With the switch on, the same deployment is ready and the write client
        // can be built — the two gates cannot drift apart.
        config.enable_writes = true;
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let state = Arc::new(AppState::with_components(
            config.clone(),
            SqliteStore::memory().unwrap(),
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let response = router(state)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(github::GitHubClient::from_config(&config).is_some());
    }

    #[tokio::test]
    async fn a_supersede_rewrites_the_round_comment_and_session_opened_queues_nothing() {
        let event_secret = vec![7; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let store = SqliteStore::memory().unwrap();
        store
            .record_session_target("ses_1", "example/repo", 7, Some(COMMIT_ID), None, Some(2))
            .unwrap();
        let state = Arc::new(AppState::with_components(
            config,
            store,
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();
        let app = router(state.clone());

        let opened = json!({
            "version": "1",
            "event_id": "cev_open_1",
            "controller_id": "github-canary",
            "event_type": "session.opened",
            "session_id": "ses_1",
            "occurred_at": 1_000,
            "payload": {"trigger_ref": "github:pr/example/repo#7"}
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(signed_runtime_event_request(
                &event_secret,
                "cev_open_1",
                "/api/v1/openab/events?version=1",
                opened,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // session.opened queues nothing: it races the session-target write,
        // so the opening comment is queued from the open_session action
        // result instead (see handle_webhook).
        assert_eq!(store.pending_writes(10).await.unwrap().len(), 0);

        // A supersede queues the rewrite that retires the "started" post —
        // marked with the session's own marker, so it can never touch another
        // round's verdict.
        let superseded = json!({
            "version": "1",
            "event_id": "cev_sup_1",
            "controller_id": "github-canary",
            "event_type": "session.superseded",
            "session_id": "ses_1",
            "occurred_at": 2_000,
            "payload": {"reason": "superseded"}
        })
        .to_string();
        let response = app
            .oneshot(signed_runtime_event_request(
                &event_secret,
                "cev_sup_1",
                "/api/v1/openab/events?version=1",
                superseded,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let pending = store.pending_writes(10).await.unwrap();
        let abandon = pending
            .iter()
            .find(|w| w.kind == closing::KIND_COMMENT_ABANDON)
            .expect("abandon write queued");
        let body = abandon.payload["body"].as_str().unwrap();
        assert!(body.contains("without a verdict"));
        assert!(body.contains(&closing::open_marker("ses_1")));
    }

    #[tokio::test]
    async fn timeout_without_opening_comment_posts_error_once_and_never_a_review() {
        let secret = vec![7; 32];
        let config = external_config(&secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let store = SqliteStore::memory().unwrap();
        store
            .record_session_target(
                "ses_timeout",
                "example/repo",
                7,
                Some(COMMIT_ID),
                None,
                Some(2),
            )
            .unwrap();
        let state = Arc::new(AppState::with_components(
            config,
            store,
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();
        let app = router(state);
        for (index, event_type) in ["session.timeout", "session.terminal", "session.timeout"]
            .iter()
            .enumerate()
        {
            let id = format!("timeout_{index}");
            let body = json!({
                "version":"1", "event_id":id, "controller_id":"github-canary",
                "event_type":event_type, "session_id":"ses_timeout", "occurred_at":1000,
                "payload":{"reason":"timeout"}
            })
            .to_string();
            let response = app
                .clone()
                .oneshot(signed_runtime_event_request(
                    &secret,
                    &id,
                    "/api/v1/openab/events?version=1",
                    body,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let writes = store.pending_writes(10).await.unwrap();
        assert_eq!(writes.len(), 3);
        assert!(!writes.iter().any(|w| w.kind == closing::KIND_REVIEW));
        let status = writes
            .iter()
            .find(|w| w.kind == closing::KIND_STATUS)
            .unwrap();
        assert_eq!(status.payload["state"], "error");
        assert_eq!(status.payload["sha"], COMMIT_ID);
        let comment = writes
            .iter()
            .find(|w| w.kind == closing::KIND_COMMENT)
            .unwrap();
        assert!(comment.payload["body"]
            .as_str()
            .unwrap()
            .contains("timed out"));
    }

    #[tokio::test]
    async fn timeout_enqueue_failure_does_not_skip_remaining_writes() {
        for failed_kind in [closing::KIND_COMMENT, closing::KIND_STATUS] {
            let uri = "file:timeout_enqueue_failure?mode=memory&cache=shared";
            let store = SqliteStore::open(uri).unwrap();
            let connection = rusqlite::Connection::open(uri).unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TRIGGER fail_timeout_write BEFORE INSERT ON github_writes
                 WHEN NEW.kind = '{failed_kind}'
                 BEGIN SELECT RAISE(FAIL, 'injected enqueue failure'); END;"
                ))
                .unwrap();
            store
                .record_session_target(
                    "ses_timeout_failure",
                    "example/repo",
                    7,
                    Some(COMMIT_ID),
                    None,
                    Some(2),
                )
                .unwrap();
            let state = Arc::new(AppState::with_components(
                external_config(&[7; 32]),
                store,
                None,
                None,
            ));
            let store = state.store.as_ref().unwrap();
            let event = serde_json::from_value(json!({
                "version":"1", "event_id":"timeout_failure", "controller_id":"github-canary",
                "event_type":"session.timeout", "session_id":"ses_timeout_failure",
                "occurred_at":1000, "payload":{"reason":"timeout"}
            }))
            .unwrap();
            assert!(dispatch_abandoned(&state, store, &event).await);
            let writes = store.pending_writes(10).await.unwrap();
            assert_eq!(writes.len(), 2);
            assert!(writes
                .iter()
                .any(|w| w.kind == closing::KIND_COMMENT_ABANDON));
            assert!(!writes.iter().any(|w| w.kind == failed_kind));
        }
    }

    #[tokio::test]
    async fn a_closed_round_becomes_persisted_state_and_queued_writes() {
        let event_secret = vec![7; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let store = SqliteStore::memory().unwrap();
        store
            .record_session_target("ses_1", "example/repo", 7, Some(COMMIT_ID), None, Some(2))
            .unwrap();
        let state = Arc::new(AppState::with_components(
            config,
            store,
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();
        let app = router(state.clone());

        let body = json!({
            "version": "1",
            "event_id": "cev_close_1",
            "controller_id": "github-canary",
            "event_type": "session.terminal",
            "session_id": "ses_1",
            "occurred_at": 1_000,
            "payload": {
                "reason": "normal",
                "required_valid_reviewers": 2,
                "valid_reviewers": 2,
                "final_messages": [
                    format!(
                        "<!-- openab-council -->\nReviewed at {COMMIT_ID}\n## Verdict\n\nprose\n<!-- openab-findings\n{{\"head_sha\":\"{COMMIT_ID}\",\"findings\":[{{\"id\":\"F1\",\"severity\":\"yellow\",\"title\":\"races on close\"}}]}}\n-->\n[[verdict:request_changes r=0 y=1 g=2]] [done]"
                    )
                ]
            }
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(signed_runtime_event_request(
                &event_secret,
                "cev_close_1",
                "/api/v1/openab/events?version=1",
                body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(value["closed"], true);

        // The round landed with the verdict the chair's counts imply, and the
        // authority payloads carry the verified opened target.
        let pending = store.pending_writes(10).await.unwrap();
        assert_eq!(
            pending.iter().map(|w| w.kind.as_str()).collect::<Vec<_>>(),
            ["comment", "status", "review"]
        );
        let status = pending.iter().find(|w| w.kind == "status").unwrap();
        assert_eq!(
            status.payload["sha"], COMMIT_ID,
            "the status is pinned to the webhook sha, not the chair's claim"
        );
        assert_eq!(status.payload["state"], "failure");
        let review = pending.iter().find(|w| w.kind == "review").unwrap();
        assert_eq!(review.payload["event"], "REQUEST_CHANGES");
        assert_eq!(review.payload["commit_id"], COMMIT_ID);
        assert_eq!(status.payload["commit_id"], COMMIT_ID);
        assert_eq!(
            store
                .review_round_integrity("ses_1")
                .await
                .unwrap()
                .unwrap(),
            store::ReviewRoundIntegrity {
                verified_commit_id: Some(COMMIT_ID.into()),
                integrity_disposition: "verified".into(),
            }
        );

        // Nothing was sent: no write client in this configuration. That is the
        // pre-cutover posture — the controller knows what it would post.
        assert!(state.github.is_none());

        // At-least-once redelivery must not queue a second verdict. A fresh
        // event id, the same session — exactly what a retry after a lost
        // acknowledgement looks like.
        let redelivery = body.replace("cev_close_1", "cev_close_2");
        let response = app
            .oneshot(signed_runtime_event_request(
                &event_secret,
                "cev_close_2",
                "/api/v1/openab/events?version=1",
                redelivery,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(store.pending_writes(10).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_started_post_skips_when_the_verdict_already_landed() {
        // Fast close: the verdict comment can beat the queued "started" write
        // out of the outbox. The open write must then do nothing — a fresh
        // "started" after the verdict reads as a phantom extra round.
        use axum::routing::{get as axum_get, post as axum_post};

        #[derive(Clone, Default)]
        struct Github {
            comments: Arc<std::sync::Mutex<Vec<(i64, String, String)>>>,
        }
        let gh = Github::default();
        let app = Router::new()
            .route(
                "/app/installations/:id/access_tokens",
                axum_post(|| async { Json(json!({"token": "ghs_test"})) }),
            )
            .route(
                "/repos/:o/:n/issues/:num/comments",
                axum_get({
                    let gh = gh.clone();
                    move || {
                        let gh = gh.clone();
                        async move {
                            let list: Vec<Value> = gh
                                .comments
                                .lock()
                                .unwrap()
                                .iter()
                                .rev()
                                .map(|(id, body, login)| {
                                    json!({"id": id, "body": body, "user": {"login": login}})
                                })
                                .collect();
                            Json(Value::Array(list))
                        }
                    }
                })
                .post({
                    let gh = gh.clone();
                    move |Json(body): Json<Value>| {
                        let gh = gh.clone();
                        async move {
                            let mut comments = gh.comments.lock().unwrap();
                            let id = 1000 + comments.len() as i64;
                            comments.push((
                                id,
                                body["body"].as_str().unwrap_or_default().into(),
                                "fixture-council[bot]".into(),
                            ));
                            Json(json!({"id": id}))
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = Config::from_values(|_| None);
        config.mode = OperatingMode::ExternalCanary;
        config.enable_writes = true;
        config.canary_repository = Some("example/repo".into());
        config.github_api_base = format!("http://{addr}");
        config.bot_handle = Some("fixture-council".into());
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let client =
            github::GitHubClient::from_config(&config).expect("writes enabled builds a client");
        client.seed_test_token("ghs_test");
        let store = SqliteStore::memory().unwrap();

        // The fast close already put the verdict up.
        gh.comments.lock().unwrap().push((
            900,
            format!("verdict body\n\n{}", closing::round_marker("ses_1")),
            "fixture-council[bot]".into(),
        ));
        let open_payload = |ses: &str| json!({"repo": "example/repo", "pr_number": 7, "round": 1, "session_id": ses});
        store
            .enqueue_write("ses_1", closing::KIND_COMMENT_OPEN, &open_payload("ses_1"))
            .unwrap();
        // Control: a session with no verdict up still posts its "started"
        // (pull_baseline has no route here, so it falls back — the skip in
        // ses_1 must come from the marker check, not general failure).
        store
            .enqueue_write("ses_2", closing::KIND_COMMENT_OPEN, &open_payload("ses_2"))
            .unwrap();
        for write in store.claim_writes(10).unwrap() {
            perform_write(&client, &store, &write).await.unwrap();
        }
        {
            let comments = gh.comments.lock().unwrap();
            assert_eq!(comments.len(), 2, "verdict + ses_2's started, no more");
            assert!(
                comments[1].1.contains(&closing::open_marker("ses_2")),
                "the surviving create is ses_2's opening post"
            );
        }

        // Replaying the opens (crash before mark-done) adds nothing: ses_1
        // still sees its verdict, ses_2 reconciles on its open marker.
        std::thread::sleep(std::time::Duration::from_millis(5));
        for write in store.claim_writes_for_test_after_lease(10).unwrap() {
            perform_write(&client, &store, &write).await.unwrap();
            store.mark_write_done(write.id).unwrap();
        }
        assert_eq!(gh.comments.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn stranded_outbox_writes_drain_through_the_sweep_entry_point() {
        // #341 defect 2: rows queued before a restart were never replayed,
        // because only round-close events kicked a drain. The maintenance
        // sweep now calls drain_outbox_batch on an interval whose first tick
        // fires at boot; this drives that entry point against a store that
        // already holds pending writes and nothing else to trigger them.
        use axum::routing::{get as axum_get, post as axum_post};

        #[derive(Clone, Default)]
        struct Github {
            comments: Arc<std::sync::Mutex<Vec<(i64, String, String)>>>,
        }
        let gh = Github::default();
        let app = Router::new()
            .route(
                "/app/installations/:id/access_tokens",
                axum_post(|| async { Json(json!({"token": "ghs_test"})) }),
            )
            .route(
                "/repos/:o/:n/issues/:num/comments",
                axum_get({
                    let gh = gh.clone();
                    move || {
                        let gh = gh.clone();
                        async move {
                            let list: Vec<Value> = gh
                                .comments
                                .lock()
                                .unwrap()
                                .iter()
                                .rev()
                                .map(|(id, body, login)| {
                                    json!({"id": id, "body": body, "user": {"login": login}})
                                })
                                .collect();
                            Json(Value::Array(list))
                        }
                    }
                })
                .post({
                    let gh = gh.clone();
                    move |Json(body): Json<Value>| {
                        let gh = gh.clone();
                        async move {
                            let mut comments = gh.comments.lock().unwrap();
                            let id = 1000 + comments.len() as i64;
                            comments.push((
                                id,
                                body["body"].as_str().unwrap_or_default().into(),
                                "fixture-council[bot]".into(),
                            ));
                            Json(json!({"id": id}))
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = Config::from_values(|_| None);
        config.mode = OperatingMode::ExternalCanary;
        config.enable_writes = true;
        config.canary_repository = Some("example/repo".into());
        config.github_api_base = format!("http://{addr}");
        config.bot_handle = Some("fixture-council".into());
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let client =
            github::GitHubClient::from_config(&config).expect("writes enabled builds a client");
        client.seed_test_token("ghs_test");

        let store = SqliteStore::memory().unwrap();
        let open_payload = |ses: &str| json!({"repo": "example/repo", "pr_number": 7, "round": 1, "session_id": ses});
        store
            .enqueue_write("ses_1", closing::KIND_COMMENT_OPEN, &open_payload("ses_1"))
            .unwrap();
        store
            .enqueue_write("ses_2", closing::KIND_COMMENT_OPEN, &open_payload("ses_2"))
            .unwrap();

        let store: Arc<dyn ProductStore> = Arc::new(store);
        let github = Arc::new(client);
        assert_eq!(
            drain_outbox_batch(&store, &github).await,
            2,
            "the sweep claims both stranded writes"
        );
        assert_eq!(gh.comments.lock().unwrap().len(), 2, "both delivered");
        assert!(
            store.pending_writes(10).await.unwrap().is_empty(),
            "delivered writes are marked done, not re-claimable"
        );
        assert_eq!(
            drain_outbox_batch(&store, &github).await,
            0,
            "an empty outbox makes the next sweep tick a no-op"
        );
    }

    #[tokio::test]
    async fn a_private_org_member_passes_trust_via_the_membership_probe() {
        // Webhook payloads render `author_association` against PUBLIC org
        // membership only: a private member arrives as CONTRIBUTOR. The
        // membership endpoint honors the App's `members: read` grant, so the
        // controller must ask it before rejecting — and stay closed when the
        // probe says no or cannot run at all.
        use axum::routing::{get as axum_get, post as axum_post};

        let app =
            Router::new()
                .route(
                    "/app/installations/:id/access_tokens",
                    axum_post(|| async { Json(json!({"token": "ghs_test"})) }),
                )
                .route(
                    "/orgs/:org/members/:login",
                    axum_get(
                        |axum::extract::Path((org, login)): axum::extract::Path<(
                            String,
                            String,
                        )>| async move {
                            if org == "example" && login == "private-member" {
                                StatusCode::NO_CONTENT
                            } else {
                                StatusCode::NOT_FOUND
                            }
                        },
                    ),
                );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = test_config();
        config.mode = OperatingMode::ExternalCanary;
        config.enable_writes = true;
        config.canary_repository = Some("example/repo".into());
        config.github_api_base = format!("http://{addr}");
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let client =
            github::GitHubClient::from_config(&config).expect("writes enabled builds a client");
        client.seed_test_token("ghs_test");
        let state = AppState {
            config,
            store: None,
            store_error: None,
            action_client: None,
            action_client_error: None,
            event_verifier: None,
            event_verifier_error: None,
            github: Some(Arc::new(client)),
            bot_identity: ComponentReadiness::disabled("handle unverified"),
            bot_handles: vec!["bot".into()],
        };

        let payload = |login: &str| {
            json!({
                "action": "synchronize",
                "repository": {"full_name": "example/repo"},
                "pull_request": {
                    "author_association": "CONTRIBUTOR",
                    "number": 7,
                    "draft": false,
                    "head": {"sha": COMMIT_ID},
                    "labels": [],
                    "user": {"login": login}
                }
            })
        };

        let plan = candidate_plan(&state, "d1", "pull_request", &payload("private-member"))
            .await
            .expect("the probe's 204 makes the author trusted");
        assert_eq!(plan.repository, "example/repo");

        let denied = candidate_plan(&state, "d2", "pull_request", &payload("stranger")).await;
        assert_eq!(denied.unwrap_err(), "author_not_trusted");

        // No GitHub client (writes off) means no probe — fail closed, exactly
        // the pre-fallback behavior.
        let closed = AppState {
            config: test_config(),
            store: None,
            store_error: None,
            action_client: None,
            action_client_error: None,
            event_verifier: None,
            event_verifier_error: None,
            github: None,
            bot_identity: ComponentReadiness::disabled("handle unverified"),
            bot_handles: vec!["bot".into()],
        };
        let denied =
            candidate_plan(&closed, "d3", "pull_request", &payload("private-member")).await;
        assert_eq!(denied.unwrap_err(), "author_not_trusted");
    }

    #[tokio::test]
    async fn an_allowlisted_bot_author_triggers_without_org_membership() {
        // A first-party bot (nuphos[bot]) opens PRs with author_association
        // NONE and is not an org member, so the standing gate refuses it. The
        // GITHUB_CONTROLLER_TRUSTED_AUTHORS allowlist trusts its exact login to
        // TRIGGER — and does so with no GitHub client (writes off), proving the
        // allowlist short-circuits before the membership probe.
        let mut config = test_config();
        config.trusted_authors = ["nuphos[bot]".to_string()].into_iter().collect();
        let state = AppState {
            config,
            store: None,
            store_error: None,
            action_client: None,
            action_client_error: None,
            event_verifier: None,
            event_verifier_error: None,
            github: None,
            bot_identity: ComponentReadiness::disabled("handle unverified"),
            bot_handles: vec!["bot".into()],
        };

        let payload = |login: &str| {
            json!({
                "action": "opened",
                "repository": {"full_name": "example/repo"},
                "pull_request": {
                    "author_association": "NONE",
                    "number": 9,
                    "draft": false,
                    "head": {"sha": OTHER_COMMIT_ID},
                    "labels": [],
                    "user": {"login": login}
                }
            })
        };

        let plan = candidate_plan(&state, "d1", "pull_request", &payload("nuphos[bot]"))
            .await
            .expect("an allowlisted author triggers with no probe");
        assert_eq!(plan.repository, "example/repo");

        // A login not on the list still fails closed, probe or no probe.
        let denied = candidate_plan(&state, "d2", "pull_request", &payload("other[bot]")).await;
        assert_eq!(denied.unwrap_err(), "author_not_trusted");
    }

    #[tokio::test]
    async fn a_replayed_write_reconciles_instead_of_posting_twice() {
        // Council F5 on #305, the P7 gate: a crash between sending and marking
        // done replays the write after the claim lease lapses, and neither a
        // comment nor a review is idempotent. The reconcile must find the
        // earlier success by its round marker and not post again.
        use axum::extract::Path as AxPath;
        use axum::routing::{get as axum_get, post as axum_post};

        #[derive(Clone, Default)]
        struct Github {
            comments: Arc<std::sync::Mutex<Vec<(i64, String, String)>>>,
            reviews: Arc<std::sync::Mutex<Vec<(i64, String, String)>>>,
        }
        let gh = Github::default();
        let app = Router::new()
            .route(
                "/app/installations/:id/access_tokens",
                axum_post(|| async { Json(json!({"token": "ghs_test"})) }),
            )
            .route(
                "/repos/:o/:n/issues/:num/comments",
                axum_get({
                    let gh = gh.clone();
                    move || {
                        let gh = gh.clone();
                        async move {
                            let list: Vec<Value> = gh
                                .comments
                                .lock()
                                .unwrap()
                                .iter()
                                .rev() // newest first, like the real API sorted desc
                                .map(|(id, body, login)| {
                                    json!({"id": id, "body": body, "user": {"login": login}})
                                })
                                .collect();
                            Json(Value::Array(list))
                        }
                    }
                })
                .post({
                    let gh = gh.clone();
                    move |Json(body): Json<Value>| {
                        let gh = gh.clone();
                        async move {
                            let mut comments = gh.comments.lock().unwrap();
                            let id = 1000 + comments.len() as i64;
                            comments.push((
                                id,
                                body["body"].as_str().unwrap_or_default().into(),
                                "fixture-council[bot]".into(),
                            ));
                            Json(json!({"id": id}))
                        }
                    }
                }),
            )
            .route(
                "/repos/:o/:n/issues/comments/:id",
                axum::routing::patch(
                    |AxPath((_, _, id)): AxPath<(String, String, i64)>| async move {
                        Json(json!({"id": id}))
                    },
                ),
            )
            .route(
                "/repos/:o/:n/statuses/:sha",
                axum_post(|| async { Json(json!({"id": 1})) }),
            )
            .route(
                "/repos/:o/:n/pulls/:num/reviews",
                axum_get({
                    let gh = gh.clone();
                    move || {
                        let gh = gh.clone();
                        async move {
                            let list: Vec<Value> = gh
                                .reviews
                                .lock()
                                .unwrap()
                                .iter()
                                .rev()
                                .map(|(id, body, login)| {
                                    json!({
                                        "id": id,
                                        "body": body,
                                        "state": "CHANGES_REQUESTED",
                                        "commit_id": COMMIT_ID,
                                        "user": {"login": login}
                                    })
                                })
                                .collect();
                            Json(Value::Array(list))
                        }
                    }
                })
                .post({
                    let gh = gh.clone();
                    move |Json(body): Json<Value>| {
                        let gh = gh.clone();
                        async move {
                            let mut reviews = gh.reviews.lock().unwrap();
                            let id = 2000 + reviews.len() as i64;
                            reviews.push((
                                id,
                                body["body"].as_str().unwrap_or_default().into(),
                                "fixture-council[bot]".into(),
                            ));
                            Json(json!({
                                "id": id,
                                "state": "CHANGES_REQUESTED",
                                "commit_id": body["commit_id"]
                            }))
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = Config::from_values(|_| None);
        config.mode = OperatingMode::ExternalCanary;
        config.enable_writes = true;
        config.canary_repository = Some("example/repo".into());
        config.github_api_base = format!("http://{addr}");
        config.bot_handle = Some("fixture-council".into());
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let client =
            github::GitHubClient::from_config(&config).expect("writes enabled builds a client");
        client.seed_test_token("ghs_test");
        let store = SqliteStore::memory().unwrap();
        store
            .record_review_round(&store::ReviewRound {
                repo: "example/repo".into(),
                pr_number: 7,
                session_id: "ses_1".into(),
                head_sha: Some(COMMIT_ID.into()),
                verified_commit_id: Some(COMMIT_ID.into()),
                integrity_disposition: "verified".into(),
                decision: "request_changes".into(),
                red: 1,
                yellow: 0,
                green: 0,
            })
            .unwrap();

        // The round's writes, as dispatch would queue them.
        let marker = closing::round_marker("ses_1");
        // A hostile participant has already planted decoys carrying the same
        // marker — the id is public the moment any council comment exists.
        // Neither may be adopted: the comment is not PATCHable by us, and the
        // decoy review must not suppress the real one (council F1, #307).
        gh.comments.lock().unwrap().push((
            900,
            format!(
                "decoy

{marker}"
            ),
            "attacker".into(),
        ));
        gh.reviews.lock().unwrap().push((
            901,
            format!(
                "decoy

{marker}"
            ),
            "attacker".into(),
        ));
        store
            .enqueue_write(
                "ses_1",
                closing::KIND_COMMENT,
                &json!({"repo": "example/repo", "pr_number": 7, "comment_id": null,
                        "body": format!("verdict body\n\n{marker}")}),
            )
            .unwrap();
        store
            .enqueue_write(
                "ses_1",
                closing::KIND_REVIEW,
                &json!({"repo": "example/repo", "pr_number": 7, "event": "REQUEST_CHANGES",
                        "commit_id": COMMIT_ID,
                        "body": format!("blocked\n\n{marker}")}),
            )
            .unwrap();

        // First drain pass: both writes go out.
        for write in store.claim_writes(10).unwrap() {
            perform_write(&client, &store, &write).await.unwrap();
            // Deliberately NOT marking done — this is the crash. The rows keep
            // their claim; GitHub has the comment and the review.
        }
        assert_eq!(
            gh.comments.lock().unwrap().len(),
            2,
            "decoy + the real comment: the create ignored the attacker's marker"
        );
        assert_eq!(gh.reviews.lock().unwrap().len(), 2);

        // The lease lapses and another drain claims the same rows. Without the
        // reconcile this second pass double-posts.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let replayed = store.claim_writes_for_test_after_lease(10).unwrap();
        assert_eq!(replayed.len(), 2, "the crash left both rows claimable");
        for write in &replayed {
            perform_write(&client, &store, write).await.unwrap();
            store.mark_write_done(write.id).unwrap();
        }
        assert_eq!(
            gh.comments.lock().unwrap().len(),
            2,
            "the replayed create adopted OUR marked comment, not the decoy"
        );
        assert_eq!(
            gh.reviews.lock().unwrap().len(),
            2,
            "the replayed submit found OUR marked review, not the decoy"
        );
        // And the adopted comment id is now the round's anchor.
        assert_eq!(
            store.last_comment_id("example/repo", 7).unwrap(),
            Some(1001),
            "the verified round stores OUR adopted comment as its anchor"
        );
    }

    #[tokio::test]
    async fn with_writes_enabled_the_outbox_drains_to_real_requests() {
        // The end the whole workstream is for: a closed round becomes a
        // comment, a status, and a formal review actually sent over HTTP.
        use axum::extract::Path;
        use axum::routing::post as axum_post;

        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorder = seen.clone();
        let fake = Router::new()
            .route(
                "/app/installations/:id/access_tokens",
                axum_post(|| async { Json(json!({"token": "ghs_test"})) }),
            )
            .route(
                "/repos/:owner/:name/issues/:number/comments",
                // The reconcile GETs before the create POSTs; nothing exists
                // yet, so the listing is empty.
                axum::routing::get(|| async { Json(json!([])) }).post({
                    let seen = seen.clone();
                    move |Json(body): Json<Value>| {
                        let seen = seen.clone();
                        async move {
                            seen.lock().unwrap().push(format!(
                                "comment:{}",
                                body["body"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .lines()
                                    .next()
                                    .unwrap_or_default()
                            ));
                            Json(json!({"id": 4242}))
                        }
                    }
                }),
            )
            .route(
                "/repos/:owner/:name/statuses/:sha",
                axum_post({
                    let seen = seen.clone();
                    move |Path((_, _, sha)): Path<(String, String, String)>,
                          Json(body): Json<Value>| {
                        let seen = seen.clone();
                        async move {
                            seen.lock().unwrap().push(format!(
                                "status:{sha}:{}",
                                body["state"].as_str().unwrap_or_default()
                            ));
                            Json(json!({"id": 1}))
                        }
                    }
                }),
            )
            .route(
                "/repos/:owner/:name/pulls/:number/reviews",
                axum::routing::get(|| async { Json(json!([])) }).post({
                    let seen = recorder;
                    move |Json(body): Json<Value>| {
                        let seen = seen.clone();
                        async move {
                            let event = body["event"].as_str().unwrap_or_default().to_string();
                            seen.lock().unwrap().push(format!("review:{event}"));
                            Json(json!({
                                "id": 77,
                                "state": "CHANGES_REQUESTED",
                                "commit_id": body["commit_id"]
                            }))
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, fake).await;
        });

        let event_secret = vec![7; 32];
        let mut config = external_config(&event_secret);
        config.enable_writes = true;
        config.github_api_base = format!("http://{addr}");
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused-the-token-is-seeded".into()),
        };
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let store = SqliteStore::memory().unwrap();
        store
            .record_session_target("ses_1", "example/repo", 7, Some(COMMIT_ID), None, Some(2))
            .unwrap();
        let state = Arc::new(AppState::with_components(
            config,
            store,
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        state
            .github
            .as_ref()
            .expect("writes enabled builds a client")
            .seed_test_token("ghs_test");
        let store = state.store.clone().unwrap();

        let body = json!({
            "version": "1",
            "event_id": "cev_drain_1",
            "controller_id": "github-canary",
            "event_type": "session.terminal",
            "session_id": "ses_1",
            "occurred_at": 1_000,
            "payload": {
                "reason": "normal",
                "required_valid_reviewers": 2,
                "valid_reviewers": 2,
                "final_messages": [format!(
                    "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n## Verdict\n\nblocked\n<!-- openab-findings\n{{\"head_sha\":\"{COMMIT_ID}\",\"findings\":[]}}\n-->\n[[verdict:request_changes r=1 y=0 g=0]] [done]"
                )]
            }
        })
        .to_string();
        let response = router(state.clone())
            .oneshot(signed_runtime_event_request(
                &event_secret,
                "cev_drain_1",
                "/api/v1/openab/events?version=1",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The drain is spawned; wait for the outbox to empty.
        for _ in 0..100 {
            if store.pending_writes(10).await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            store.pending_writes(10).await.unwrap().is_empty(),
            "every queued write should have been sent"
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                "comment:<!-- openab-council -->".to_string(),
                format!("status:{COMMIT_ID}:failure"),
                "review:REQUEST_CHANGES".to_string()
            ]
        );
        // The comment id came back from GitHub and is now the upsert anchor
        // for the next round of this pull request.
        assert_eq!(
            store.last_comment_id("example/repo", 7).await.unwrap(),
            Some(4242)
        );
    }

    #[tokio::test]
    async fn approve_is_impossible_below_the_recorded_reviewer_minimum() {
        let event_secret = vec![7; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let store = SqliteStore::memory().unwrap();
        store
            .record_session_target(
                "ses_short",
                "example/repo",
                7,
                Some(COMMIT_ID),
                None,
                Some(2),
            )
            .unwrap();
        let state = Arc::new(AppState::with_components(
            config,
            store,
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();

        let body = json!({
            "version": "1",
            "event_id": "cev_short",
            "controller_id": "github-canary",
            "event_type": "session.terminal",
            "session_id": "ses_short",
            "occurred_at": 1_000,
            "payload": {
                "reason": "normal",
                "required_valid_reviewers": 2,
                "valid_reviewers": 1,
                "final_messages": [
                    "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\nLGTM\n[[verdict:approve r=0 y=0 g=2]] [done]"
                ]
            }
        })
        .to_string();
        let response = router(state)
            .oneshot(signed_runtime_event_request(
                &event_secret,
                "cev_short",
                "/api/v1/openab/events?version=1",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let pending = store.pending_writes(10).await.unwrap();
        assert_eq!(
            pending
                .iter()
                .map(|write| write.kind.as_str())
                .collect::<Vec<_>>(),
            ["comment", "status"]
        );
        assert_eq!(pending[1].payload["state"], "error");
        assert!(pending.iter().all(|write| write.kind != "review"));
        assert!(pending[0].payload["body"]
            .as_str()
            .unwrap()
            .contains("failed closed"));
    }

    #[tokio::test]
    async fn terminal_events_we_do_not_own_or_cannot_act_on_are_left_alone() {
        let event_secret = vec![7; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let store = SqliteStore::memory().unwrap();
        store
            .record_session_target(
                "ses_ours",
                "example/repo",
                7,
                Some(COMMIT_ID),
                None,
                Some(2),
            )
            .unwrap();
        let state = Arc::new(AppState::with_components(
            config,
            store,
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();
        let app = router(state);

        let cases = [
            // A session the embedded plugin owns — acting would be the
            // two-writer failure invariant #4 forbids.
            ("cev_a", "ses_theirs", "normal"),
            // Timeout and supersede have no result to report; a review
            // submitted on a guess is worse than silence.
            ("cev_c", "ses_ours", "superseded"),
        ];
        for (event_id, session_id, reason) in cases {
            let body = json!({
                "version": "1",
                "event_id": event_id,
                "controller_id": "github-canary",
                "event_type": "session.terminal",
                "session_id": session_id,
                "occurred_at": 1_000,
                "payload": {
                    "reason": reason,
                    "final_messages": ["done [[verdict:approve r=0 y=0 g=1]] [done]"]
                }
            })
            .to_string();
            let response = app
                .clone()
                .oneshot(signed_runtime_event_request(
                    &event_secret,
                    event_id,
                    "/api/v1/openab/events?version=1",
                    body,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let value: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(value["closed"], false, "{reason} on {session_id}");
        }
        assert!(store.pending_writes(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_ask_terminal_queues_only_a_plain_answer_comment() {
        // SEI-929 end to end: a follow-up (reason "ask") closes into exactly one
        // comment carrying the settled answer — no status, no review, no verdict
        // warning, and no raw transcript.
        let event_secret = vec![7; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let store = SqliteStore::memory().unwrap();
        store
            .record_session_target(
                "ses_ask",
                "example/repo",
                7,
                Some(COMMIT_ID),
                Some("ask"),
                Some(0),
            )
            .unwrap();
        let state = Arc::new(AppState::with_components(
            config,
            store,
            Some(Arc::new(RecordingActionClient::new([]).0)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();
        let app = router(state);

        let answer = "Regarding F1: buildRegions is keyed by request region, so cgk1 is correct.";
        let body = json!({
            "version": "1",
            "event_id": "cev_ask",
            "controller_id": "github-canary",
            "event_type": "session.terminal",
            "session_id": "ses_ask",
            "occurred_at": 1_000,
            "payload": {
                "reason": "normal",
                // The kind of noisy final the Kiro CLI produces; only the answer
                // line should survive into the comment.
                "final_messages": [format!("{answer}\n[done]")]
            }
        })
        .to_string();
        let response = app
            .clone()
            .oneshot(signed_runtime_event_request(
                &event_secret,
                "cev_ask",
                "/api/v1/openab/events?version=1",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let writes = store.pending_writes(10).await.unwrap();
        assert_eq!(writes.len(), 1, "ask must queue exactly one write");
        assert_eq!(writes[0].kind, closing::KIND_COMMENT);
        let comment = writes[0].payload["body"].as_str().unwrap();
        assert!(comment.contains(answer), "answer missing: {comment}");
        assert!(
            !comment.contains("[done]"),
            "machine tail leaked: {comment}"
        );
        assert!(
            !comment.contains("parseable verdict"),
            "ask must not warn about a missing verdict: {comment}"
        );
    }

    #[tokio::test]
    async fn signed_shadow_comparison_records_exact_fixture_parity() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let state = Arc::new(AppState::with_store(
            test_config(),
            SqliteStore::memory().unwrap(),
        ));
        let payload: Value = serde_json::from_str(BODY).unwrap();
        let embedded = shadow::ParityOutcome::Planned {
            snapshot: Box::new(
                candidate_plan(&state, "delivery-shadow", "pull_request", &payload)
                    .await
                    .unwrap()
                    .parity_snapshot(),
            ),
        };
        let request = shadow::ShadowCompareRequest {
            comparison_id: "comparison-1".into(),
            delivery_id: "delivery-shadow".into(),
            event_type: "pull_request".into(),
            payload,
            embedded: Some(embedded),
        };
        let app = router(state);
        let response = app
            .clone()
            .oneshot(signed_shadow_request(&request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["report"]["exact_match"], true);
        assert_eq!(body["report"]["promotion_blocked"], false);

        let duplicate = app
            .clone()
            .oneshot(signed_shadow_request(&request))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        let duplicate: Value =
            serde_json::from_slice(&duplicate.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(duplicate["duplicate"], true);

        let mut conflicting = request;
        let shadow::ParityOutcome::Planned { snapshot } = conflicting.embedded.as_mut().unwrap()
        else {
            unreachable!();
        };
        snapshot.open_session.prompt = "drift".into();
        let conflict = app
            .clone()
            .oneshot(signed_shadow_request(&conflicting))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let unauthorized = app
            .clone()
            .oneshot(
                Request::get("/api/v1/shadow/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);

        let response = app.oneshot(signed_shadow_summary_request()).await.unwrap();
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["summary"]["total"], 1);
        assert_eq!(body["summary"]["exact_matches"], 1);
    }

    #[tokio::test]
    async fn signed_fixture_produces_a_plan_and_dedupes_delivery() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let state = Arc::new(AppState::with_store(
            test_config(),
            SqliteStore::memory().unwrap(),
        ));
        let app = router(state);
        let first = app
            .clone()
            .oneshot(signed_request("delivery-1", BODY))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let body: Value =
            serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["plan"]["source_delivery_id"], "delivery-1");
        assert_eq!(body["plan"]["proposed_writes"].as_array().unwrap().len(), 3);

        let duplicate = app
            .oneshot(signed_request("delivery-1", BODY))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&duplicate.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["duplicate"], true);
        assert_eq!(body["state"], "planned");
    }

    #[tokio::test]
    async fn external_canary_acts_once_per_delivery_and_supersedes_by_fingerprint() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let event_secret = vec![8; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let (client, calls) = RecordingActionClient::new([false, false]);
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            Some(Arc::new(client)),
            Some(Arc::new(verifier)),
        ));
        let store = state.store.clone().unwrap();
        let app = router(state);

        let first = app
            .clone()
            .oneshot(signed_owned_request(
                "canary-delivery-1",
                "pull_request",
                BODY.into(),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let first: Value =
            serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(first["action_result"]["result"]["type"], "session_opened");

        // Opening the session queued the round comment — from the action
        // result, race-free, before any runtime event arrives.
        let pending = store.pending_writes(10).await.unwrap();
        let open = pending
            .iter()
            .find(|w| w.kind == closing::KIND_COMMENT_OPEN)
            .expect("opening comment queued");
        assert_eq!(open.payload["round"], 1);

        let duplicate = app
            .clone()
            .oneshot(signed_owned_request(
                "canary-delivery-1",
                "pull_request",
                BODY.into(),
            ))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        assert_eq!(calls.lock().unwrap().len(), 1);

        let mut synchronize: Value = serde_json::from_str(BODY).unwrap();
        synchronize["action"] = json!("synchronize");
        synchronize["pull_request"]["head"]["sha"] = json!(OTHER_COMMIT_ID);
        let superseded = app
            .oneshot(signed_owned_request(
                "canary-delivery-2",
                "pull_request",
                synchronize.to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(superseded.status(), StatusCode::ACCEPTED);
        let superseded: Value =
            serde_json::from_slice(&superseded.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(superseded["action_result"]["result"]["type"], "superseded");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "github-delivery-canary-delivery-1");
        assert_eq!(
            calls[1].1.trigger_fingerprint.as_deref(),
            Some(OTHER_COMMIT_FINGERPRINT)
        );
    }

    #[tokio::test]
    async fn a_plain_review_comment_adopts_the_head_sha_fingerprint() {
        // #326: push + `/review` seconds apart opened two same-code sessions
        // that superseded each other to a double death, because the comment's
        // `cmd:<id>` fingerprint is unique by construction. A plain re-review
        // resolves to the current head sha so the kernel dedupes into the
        // running round; a mention review carrying notes keeps the comment
        // fingerprint (a deliberate restart).
        use axum::routing::{get as axum_get, post as axum_post};
        let gh_app = Router::new()
            .route(
                "/app/installations/:id/access_tokens",
                axum_post(|| async { Json(json!({"token": "ghs_test"})) }),
            )
            .route(
                "/repos/:o/:n/pulls/:num",
                axum_get(|| async { Json(json!({"head": {"sha": COMMIT_ID}})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, gh_app).await;
        });

        let event_secret = vec![8; 32];
        let mut config = external_config(&event_secret);
        config.enable_writes = true;
        config.github_api_base = format!("http://{addr}");
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let (client, calls) = RecordingActionClient::new([false, false]);
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            Some(Arc::new(client)),
            Some(Arc::new(verifier)),
        ));
        state
            .github
            .as_ref()
            .expect("writes enabled builds a client")
            .seed_test_token("ghs_test");
        let app = router(state);

        const REVIEW: &str =
            include_str!("../../../tests/fixtures/github/issue_comment_review.json");
        let response = app
            .clone()
            .oneshot(signed_owned_request(
                "plain-review-1",
                "issue_comment",
                REVIEW.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        const MENTION: &str =
            include_str!("../../../tests/fixtures/github/issue_comment_mention_review.json");
        let response = app
            .clone()
            .oneshot(signed_owned_request(
                "mention-review-1",
                "issue_comment",
                MENTION.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // A bare mention ("@bot review", no notes) is also a plain re-review.
        let mut bare: Value = serde_json::from_str(MENTION).unwrap();
        bare["comment"]["body"] = json!("@fixture-council review");
        bare["comment"]["id"] = json!(7004);
        let response = app
            .clone()
            .oneshot(signed_owned_request(
                "bare-mention-1",
                "issue_comment",
                bare.to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 3);
            assert_eq!(
                calls[0].1.trigger_fingerprint.as_deref(),
                Some(COMMIT_FINGERPRINT),
                "plain /review resolves to the current head sha"
            );
            assert_eq!(
                calls[1].1.trigger_fingerprint.as_deref(),
                Some("cmd:7003"),
                "a mention review with notes keeps its comment fingerprint"
            );
            assert_eq!(
                calls[2].1.trigger_fingerprint.as_deref(),
                Some(COMMIT_FINGERPRINT),
                "a bare mention review also resolves to the head sha"
            );
        }
    }

    #[tokio::test]
    async fn a_failed_head_sha_lookup_falls_back_to_the_comment_fingerprint() {
        // #326 F2: the sha resolution is an optimization, not a gate — a
        // GitHub hiccup must degrade to the old cmd:<id> behavior, not drop
        // the trigger.
        use axum::routing::post as axum_post;
        // Token mints fine; the pulls route does not exist → lookup fails.
        let gh_app = Router::new().route(
            "/app/installations/:id/access_tokens",
            axum_post(|| async { Json(json!({"token": "ghs_test"})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, gh_app).await;
        });

        let event_secret = vec![8; 32];
        let mut config = external_config(&event_secret);
        config.enable_writes = true;
        config.github_api_base = format!("http://{addr}");
        config.github_app = config::GitHubAppConfig {
            app_id: Some("1".into()),
            installation_id: Some("2".into()),
            private_key: Some("unused".into()),
        };
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let (client, calls) = RecordingActionClient::new([false]);
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            Some(Arc::new(client)),
            Some(Arc::new(verifier)),
        ));
        state
            .github
            .as_ref()
            .expect("writes enabled builds a client")
            .seed_test_token("ghs_test");

        const REVIEW: &str =
            include_str!("../../../tests/fixtures/github/issue_comment_review.json");
        let response = router(state)
            .oneshot(signed_owned_request(
                "plain-review-fallback",
                "issue_comment",
                REVIEW.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1.trigger_fingerprint.as_deref(),
            Some("cmd:7001"),
            "lookup failure keeps the comment fingerprint"
        );
    }

    #[tokio::test]
    async fn external_canary_rejects_an_unowned_repository_before_action_dispatch() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let event_secret = vec![8; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let (client, calls) = RecordingActionClient::new([]);
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            Some(Arc::new(client)),
            Some(Arc::new(verifier)),
        ));
        let mut payload: Value = serde_json::from_str(BODY).unwrap();
        payload["repository"]["full_name"] = json!("other/repo");

        let response = router(state)
            .oneshot(signed_owned_request(
                "wrong-repository",
                "pull_request",
                payload.to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn signed_runtime_events_are_deduped_and_visible_as_aggregates_only() {
        let event_secret = vec![8; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let (client, _) = RecordingActionClient::new([]);
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            Some(Arc::new(client)),
            Some(Arc::new(verifier)),
        ));
        let app = router(state);
        let target = "/api/v1/openab/events?version=1";
        let event_id = "cev-timeout-1";
        let body = json!({
            "version": "1",
            "event_id": event_id,
            "controller_id": "github-canary",
            "event_type": "session.timeout",
            "session_id": "ses-canary-1",
            "occurred_at": now_unix() * 1000,
            "payload": {"reason": "timeout", "private_detail": "must-not-persist"}
        })
        .to_string();

        let accepted = app
            .clone()
            .oneshot(signed_runtime_event_request(
                &event_secret,
                event_id,
                target,
                body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let accepted: Value =
            serde_json::from_slice(&accepted.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(accepted["duplicate"], false);

        let duplicate = app
            .clone()
            .oneshot(signed_runtime_event_request(
                &event_secret,
                event_id,
                target,
                body,
            ))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        let duplicate: Value =
            serde_json::from_slice(&duplicate.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(duplicate["duplicate"], true);

        let conflicting_body = json!({
            "version": "1",
            "event_id": event_id,
            "controller_id": "github-canary",
            "event_type": "action.failed",
            "session_id": "ses-canary-1",
            "occurred_at": now_unix() * 1000,
            "payload": {"reason": "changed"}
        })
        .to_string();
        let conflict = app
            .clone()
            .oneshot(signed_runtime_event_request(
                &event_secret,
                event_id,
                target,
                conflicting_body,
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let unauthorized = app
            .clone()
            .oneshot(
                Request::get("/api/v1/canary/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);
        let summary = app.oneshot(signed_canary_summary_request()).await.unwrap();
        assert_eq!(summary.status(), StatusCode::OK);
        let summary: Value =
            serde_json::from_slice(&summary.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(summary["summary"]["runtime_events"], 1);
        assert_eq!(
            summary["summary"]["runtime_event_types"]["session.timeout"],
            1
        );
        assert!(summary.to_string().find("private_detail").is_none());
    }

    #[tokio::test]
    async fn external_canary_outage_retries_same_action_id_without_embedded_fallback() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let event_secret = vec![8; 32];
        let config = external_config(&event_secret);
        let verifier = runtime_events::RuntimeEventVerifier::new(
            "github-canary",
            config.event_signing_secret.as_deref().unwrap(),
        )
        .unwrap();
        let (client, calls) = RecordingActionClient::new([true, false]);
        let state = Arc::new(AppState::with_components(
            config,
            SqliteStore::memory().unwrap(),
            Some(Arc::new(client)),
            Some(Arc::new(verifier)),
        ));
        let app = router(state);

        let outage = app
            .clone()
            .oneshot(signed_owned_request(
                "retry-delivery",
                "pull_request",
                BODY.into(),
            ))
            .await
            .unwrap();
        assert_eq!(outage.status(), StatusCode::SERVICE_UNAVAILABLE);

        let recovered = app
            .oneshot(signed_owned_request(
                "retry-delivery",
                "pull_request",
                BODY.into(),
            ))
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::ACCEPTED);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, calls[1].0);
    }

    #[tokio::test]
    async fn in_progress_duplicate_returns_retryable_status() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let state = Arc::new(AppState::with_store(
            test_config(),
            SqliteStore::memory().unwrap(),
        ));
        let payload_hash = hex::encode(Sha256::digest(BODY.as_bytes()));
        state
            .store
            .as_ref()
            .unwrap()
            .begin_delivery(
                "delivery-processing",
                "pull_request",
                Some("example/repo"),
                &payload_hash,
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(signed_request("delivery-processing", BODY))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"], "delivery_in_progress");
    }

    #[tokio::test]
    async fn rejects_invalid_hmac_before_touching_store() {
        const BODY: &str = include_str!("../../../tests/fixtures/github/pull_request_opened.json");
        let state = Arc::new(AppState::with_store(
            test_config(),
            SqliteStore::memory().unwrap(),
        ));
        let request = Request::post("/api/v1/github/webhooks")
            .header("x-github-event", "pull_request")
            .header("x-github-delivery", "delivery-invalid")
            .header("x-hub-signature-256", "sha256=00")
            .body(Body::from(BODY))
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn delivery_and_event_headers_are_bounded() {
        assert!(valid_delivery_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!valid_delivery_id("bad/delivery"));
        assert!(!valid_delivery_id(&"a".repeat(129)));
        assert!(valid_event_type("pull_request_review"));
        assert!(!valid_event_type("Pull-Request"));
    }
}
