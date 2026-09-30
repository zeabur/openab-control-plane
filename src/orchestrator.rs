//! Orchestration (design §13): the deterministic referee. The plane owns the
//! lifecycle, client-trigger fanout, and quorum; the chair bot is the only LLM
//! judgment.

use crate::coordinator::{self, Action, Coordinator, Ctx};
use crate::protocol::{Content, GatewayReply, GatewayResponse, SenderInfo, RESPONSE_SCHEMA};
use crate::routing;
use crate::session::DONE_EMOJI;
use crate::state::AppState;
use crate::store::{
    BotHealthTransition, Message, OpeningInput, RosterAddOutcome, Session, SessionState,
};
use anyhow::Result;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug)]
pub enum PostClientMessageError {
    UnknownSession(String),
    ReopenRefused(String),
    Internal(anyhow::Error),
}

impl std::fmt::Display for PostClientMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostClientMessageError::UnknownSession(message)
            | PostClientMessageError::ReopenRefused(message) => f.write_str(message),
            PostClientMessageError::Internal(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PostClientMessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PostClientMessageError::UnknownSession(_)
            | PostClientMessageError::ReopenRefused(_) => None,
            PostClientMessageError::Internal(err) => Some(err.as_ref()),
        }
    }
}

impl From<anyhow::Error> for PostClientMessageError {
    fn from(err: anyhow::Error) -> Self {
        PostClientMessageError::Internal(err)
    }
}

type PostClientMessageResult<T> = std::result::Result<T, PostClientMessageError>;

/// The edit/reaction target message id. A stock OAB gateway adapter carries it
/// in `reply_to` (it sets `quote_message_id: None` except for explicit
/// reply-quotes — see openab-core gateway.rs edit_message/add_reaction). Prefer
/// reply_to; fall back to quote_message_id for clients that use it instead.
fn target_msg(reply: &GatewayReply) -> Option<&str> {
    Some(reply.reply_to.as_str())
        .filter(|s| !s.is_empty())
        .or(reply.quote_message_id.as_deref())
}

fn bot_sender(id: &str, name: &str) -> SenderInfo {
    SenderInfo {
        id: id.into(),
        name: name.into(),
        display_name: name.into(),
        is_bot: true,
    }
}

/// Client posts the opening intent. Stores it, moves open→deliberating, fans the
/// trigger to the roster, and mentions only the coordinator-selected starters.
pub fn post_client_message(
    state: &Arc<AppState>,
    session_id: &str,
    content: &str,
) -> PostClientMessageResult<Message> {
    let Some(session) = state.store.session(session_id)? else {
        return Err(PostClientMessageError::UnknownSession(format!(
            "unknown session {session_id}"
        )));
    };
    let cur = SessionState::from_db_str(&session.state);
    if matches!(cur, SessionState::Closed | SessionState::Aborted) {
        let reopen = dispatch_coordinator(state, &session)?
            .map(|coord| coord.reopen_on_client_message())
            .unwrap_or(false);
        if !reopen {
            return Err(PostClientMessageError::ReopenRefused(format!(
                "session {} is closed; mode '{}' does not reopen on client messages - open a fresh session",
                session.id, session.mode
            )));
        }
    }
    let msg = state
        .store
        .add_message(session_id, None, "client", None, None, content, None)?;
    match cur {
        SessionState::Open => {
            state.store.advance_state(
                session_id,
                SessionState::Open,
                SessionState::Deliberating,
            )?;
        }
        SessionState::Closed | SessionState::Aborted => {
            // ADR 028: reopening starts a new turn — the previous close's
            // result identity is cleared in the same guarded UPDATE; the next
            // close records its own turn's span.
            state.store.reopen_session(session_id, cur)?;
        }
        SessionState::Deliberating | SessionState::Quorum => {}
    }

    let sender = SenderInfo {
        id: "client".into(),
        name: "client".into(),
        display_name: "client".into(),
        is_bot: false,
    };
    let roster = state.store.roster(session_id)?;
    let thread = state.store.thread_for_session(session_id)?;
    // Who is prompted to act now is a coordinator decision: PR councils mention
    // reviewers first, solo mentions the lone bot, and pipeline mentions stage 0.
    // A9: Pre-thread, an unmentioned stock bot drops the trigger at the group
    // mention gate. The non-starter chair receives it in-thread once the topic
    // exists; other future non-starter trigger delivery needs a named
    // Coordinator hook, not blanket re-fanout.
    // A stock OAB bot in a group gates on @mention before a thread exists
    // (gateway.rs is_responder); bot_username == the plane's bot name (served in
    // /bot-config), so a recipient's own name matches its gate.
    let Some(coord) = dispatch_coordinator(state, &session)? else {
        return Ok(msg);
    };
    let starters = coord.starters(&roster, session.chair_bot.as_deref());
    let cx = OrchCtx {
        state,
        session: &session,
        roster: roster.clone(),
    };
    for target in routing::fanout_targets(&roster, None) {
        let tname = state
            .store
            .bot(&target)?
            .map(|b| b.name)
            .unwrap_or_default();
        let mentions = if starters.contains(&target) {
            vec![tname.clone()]
        } else {
            vec![]
        };
        state.deliver_event(
            &target,
            session_id,
            thread.as_deref(),
            sender.clone(),
            Content::text(coord.recipient_trigger_text(&cx, &target, content)),
            mentions,
            &msg.id,
        );
    }
    state.emit_north(
        "message",
        session_id,
        json!({ "message_id": msg.id, "author": "client", "content": content }),
    );
    Ok(msg)
}

/// Deliver audience-scoped opening inputs that were committed atomically with
/// their session. The durable message rows are the source of truth; outbox
/// enqueue and live flush remain the existing post-commit delivery mechanism.
pub fn deliver_opening_inputs(state: &Arc<AppState>, session_id: &str) -> Result<()> {
    let Some(session) = state.store.session(session_id)? else {
        anyhow::bail!("unknown session {session_id}");
    };
    let Some(coord) = dispatch_coordinator(state, &session)? else {
        return Ok(());
    };
    let roster = state.store.roster(session_id)?;
    let starters = coord.starters(&roster, session.chair_bot.as_deref());
    let thread = state.store.thread_for_session(session_id)?;
    let sender = SenderInfo {
        id: "client".into(),
        name: "client".into(),
        display_name: "client".into(),
        is_bot: false,
    };

    for message in state.store.messages(session_id)? {
        if message.author_kind != "client" || message.author_id.is_some() {
            continue;
        }
        let Some(target) = message.audience.as_deref() else {
            continue;
        };
        let name = state
            .store
            .bot(target)?
            .map(|bot| bot.name)
            .unwrap_or_default();
        let mentions = starters
            .iter()
            .any(|starter| starter == target)
            .then_some(vec![name])
            .unwrap_or_default();
        state.deliver_event(
            target,
            session_id,
            thread.as_deref(),
            sender.clone(),
            Content::text(&message.content),
            mentions,
            &message.id,
        );
        state.emit_north(
            "message",
            session_id,
            json!({
                "message_id": message.id,
                "author": "client",
                "audience": target,
                "content": message.content,
            }),
        );
    }
    Ok(())
}

/// Controller-requested terminal transition. Authorization is enforced by the
/// action interpreter; this function owns the same CAS, outbox cleanup, token
/// revoke, north event, and close-webhook effects as other terminal paths.
pub fn close_session_by_controller(
    state: &Arc<AppState>,
    session_id: &str,
    reason: &str,
) -> Result<bool> {
    if state.store.session(session_id)?.is_none() {
        anyhow::bail!("unknown session {session_id}");
    }
    if !state
        .store
        .close_if_active(session_id, "session.terminal", reason, None)?
    {
        return Ok(false);
    }
    purge_session_outbox_after_close(state, session_id);
    state.emit_north(
        "state",
        session_id,
        json!({ "state": "closed", "reason": reason }),
    );
    fire_close_webhook(state, session_id, "", reason);
    Ok(true)
}

/// Persist a controller status as a status audit row and surface it to north
/// subscribers. It is deliberately not delivered to bots or mapped to a
/// provider side effect.
pub fn emit_controller_status(
    state: &Arc<AppState>,
    session_id: &str,
    target: &str,
    body: &str,
) -> Result<Message> {
    if state.store.session(session_id)?.is_none() {
        anyhow::bail!("unknown session {session_id}");
    }
    let message =
        state
            .store
            .add_message(session_id, None, "status", None, Some(target), body, None)?;
    state.emit_north(
        "controller_status",
        session_id,
        json!({
            "status_id": message.id,
            "target": target,
            "body": body,
        }),
    );
    Ok(message)
}

/// A *settled* bot turn: non-empty and not the "…" streaming placeholder. The
/// single predicate shared by `latest_settled` (verdict selection) and
/// `settled_result_span` (ADR 028 result identity) — the recorded result must
/// never disagree with the verdict about which message settled. ASCII "..."
/// counts as settled content, matching `latest_settled` since v1.
fn is_settled_content(text: &str) -> bool {
    let t = text.trim();
    !t.is_empty() && t != "…"
}

/// A bot's last *settled* (non-stub) message content. Standalone twin of
/// `OrchCtx::latest_settled` for the watchdog, which builds no `OrchCtx`.
fn chair_latest_settled(state: &Arc<AppState>, session_id: &str, bot: &str) -> Option<String> {
    state
        .store
        .messages(session_id)
        .ok()?
        .into_iter()
        .rfind(|m| m.author_id.as_deref() == Some(bot) && is_settled_content(&m.content))
        .map(|m| m.content)
}

/// Liveness guarantee (design: "what OCP actually guarantees"). Force a stuck
/// session to a terminal verdict. A silent reviewer otherwise hangs
/// `QuorumCouncil` forever (quorum never reached), and a dead bot can't run its
/// own fallback — so only the plane can guarantee termination. Mode-agnostic:
/// closes with the reviews already in the thread, naming absentees in the
/// verdict. CAS once-only — returns true iff this call performed the close (a
/// normal close racing in wins and this becomes a no-op).
pub fn force_close_timeout(
    state: &Arc<AppState>,
    session_id: &str,
    stale_before: i64,
) -> Result<bool> {
    if !state
        .store
        .close_if_active(session_id, "session.timeout", "timeout", Some(stale_before))?
    {
        return Ok(false); // already terminal
    }
    purge_session_outbox_after_close(state, session_id);
    let session = state.store.session(session_id)?;
    let roster = state.store.roster(session_id)?;
    let done: std::collections::HashSet<String> =
        state.store.done_voters(session_id)?.into_iter().collect();
    let absent: Vec<String> = roster
        .iter()
        .filter(|bot| !done.contains(bot.as_str()))
        .cloned()
        .collect();
    let note = format!(
        "TIMEOUT: session closed by watchdog — {}/{} signaled done.{}",
        done.len(),
        roster.len(),
        if absent.is_empty() {
            String::new()
        } else {
            format!(" Absent: {}.", absent.join(", "))
        },
    );
    // If the chair already synthesized a verdict (the live #1187 case: produced
    // but never cleanly closed), surface it — don't bury it under the timeout note.
    let chair_final = session
        .as_ref()
        .and_then(|s| s.chair_bot.clone())
        .and_then(|chair| chair_latest_settled(state, session_id, &chair));
    let verdict = match chair_final {
        Some(v) => format!("{note}\n\n{v}"),
        None => format!("{note} (No verdict synthesized; reviews are in the thread.)"),
    };
    state.emit_north(
        "timeout",
        session_id,
        json!({
            "reason": "timeout",
            "done": done.len(),
            "total": roster.len(),
            "absent": absent,
            "trigger_ref": session.as_ref().and_then(|s| s.trigger_ref.clone()),
            "verdict": verdict.clone(),
        }),
    );
    state.emit_north(
        "verdict",
        session_id,
        json!({ "text": verdict.clone(), "reason": "timeout" }),
    );
    state.emit_north("state", session_id, json!({ "state": "closed" }));
    fire_close_webhook(state, session_id, &verdict, "timeout");
    tracing::warn!("watchdog force-closed stale session {session_id}");
    Ok(true)
}

/// Resolve the coordinator for a persisted session row. Unknown mode →
/// error log + north `dispatch_error` + force-close reason:"unknown_mode"
/// (CAS-idempotent; no-op if already terminal), and None — refusal, never
/// silent quorum adoption. Unreachable in a correctly built binary (new
/// opens validate via controller); insurance against registry refactors.
fn dispatch_coordinator(
    state: &Arc<AppState>,
    session: &Session,
) -> Result<Option<Box<dyn Coordinator>>> {
    if let Some(coord) = coordinator::lookup(&session.mode) {
        return Ok(Some(coord));
    }

    tracing::error!(
        session_id = %session.id,
        mode = %session.mode,
        "unknown persisted coordinator mode; force-closing session"
    );
    state.emit_north(
        "dispatch_error",
        &session.id,
        json!({ "mode": session.mode.clone(), "reason": "unknown_mode" }),
    );
    if state
        .store
        .close_if_active(&session.id, "session.terminal", "unknown_mode", None)?
    {
        purge_session_outbox_after_close(state, &session.id);
        state.emit_north(
            "state",
            &session.id,
            json!({ "state": "closed", "reason": "unknown_mode" }),
        );
        fire_close_webhook(state, &session.id, "", "unknown_mode");
    }
    Ok(None)
}

fn purge_session_outbox_after_close(state: &Arc<AppState>, session_id: &str) {
    // Post-close drop used to hold only on the ledger (`deliver_event` gate). Purging
    // the durable queue makes it hold at the bot's eyes too. Reopened sessions post
    // fresh messages with fresh ids, so they do not depend on these stale frames.
    if let Err(e) = state.store.purge_outbox_for_session(session_id) {
        tracing::warn!("purge outbox for closed session {session_id} failed: {e}");
    }
}

/// Post-commit cleanup for a session closed by `create_session_superseding`.
/// The close+open itself is atomic in the store; these effects are deliberately
/// after-commit and at-least-once. Crash window: if the process dies here, stale
/// outbox rows wait for the terminal-outbox sweep, and `reason:"superseded"`
/// events/webhooks are lost because there is no redrive in the pre-P3 plane.
pub fn handle_superseded_session(state: &Arc<AppState>, session_id: &str) {
    purge_session_outbox_after_close(state, session_id);
    state.emit_north(
        "state",
        session_id,
        json!({ "state": "closed", "reason": "superseded" }),
    );
    fire_close_webhook(state, session_id, "", "superseded");
}

/// Liveness policy (A3): a roster member disconnected past the grace window is
/// flipped to `unreachable`, then replaced from the inventory (connected, healthy,
/// same-role spare). With no spare, a reviewer that hasn't voted is trimmed and
/// the quorum shrunk so the session still converges on the survivors; the chair
/// is replace-only (never trimmed — the watchdog stays the chair backstop). Runs
/// from the background sweep in `main`; grace must exceed the OAB reconnect
/// backoff (1–30s) so a plane restart doesn't trim the whole roster.
pub fn sweep_liveness(state: &Arc<AppState>, grace_ms: i64) -> Result<()> {
    let now = crate::store::now_ms();
    for session_id in state.store.active_sessions_before(now + 1)? {
        let Some(session) = state.store.session(&session_id)? else {
            continue;
        };
        let done: std::collections::HashSet<String> =
            state.store.done_voters(&session_id)?.into_iter().collect();
        for bot_id in state.store.roster(&session_id)? {
            let Some(inv) = state.store.bot_inventory(&bot_id)? else {
                continue;
            };
            if state.is_connected(&bot_id) {
                continue;
            }
            // Never-connected bots have no last_seen — age them from session open.
            let seen = inv.last_seen_ms.unwrap_or(session.created_at);
            if now - seen < grace_ms {
                continue;
            }
            let is_chair = session.chair_bot.as_deref() == Some(bot_id.as_str());
            if !is_chair && done.contains(&bot_id) {
                continue; // vote already recorded; the chair has its findings
            }
            if replace_unreachable(state, &session_id, &inv, is_chair)? {
                continue;
            }
            if is_chair {
                tracing::warn!(
                    "liveness: chair {bot_id} unreachable in {session_id}, no chair-capable spare"
                );
                continue;
            }
            trim_reviewer(state, &session_id, &bot_id)?;
        }
    }
    Ok(())
}

/// Flip a dead bot's inventory health to `unreachable` (idempotent). The WS
/// connect path flips it back to `ok` on reconnect.
fn mark_unreachable(state: &Arc<AppState>, inv: &crate::store::BotInventory) {
    if inv.health == "unreachable" {
        return;
    }
    let patch = crate::store::BotMetadataPatch {
        health: Some("unreachable".into()),
        ..Default::default()
    };
    if let Err(e) = state.store.update_bot_metadata(&inv.id, &patch) {
        tracing::warn!("liveness: health flip for {} failed: {e}", inv.id);
    }
    state.emit_north(
        "bot_health",
        "-",
        json!({ "bot": inv.id, "health": "unreachable" }),
    );
}

fn replace_unreachable(
    state: &Arc<AppState>,
    session_id: &str,
    inv: &crate::store::BotInventory,
    is_chair: bool,
) -> Result<bool> {
    if state.is_connected(&inv.id) {
        return Ok(true);
    }
    mark_unreachable(state, inv);
    let Some(spare) = find_spare(state, session_id, inv, is_chair)? else {
        return Ok(false);
    };
    match replace_roster_bot(state, session_id, &inv.id, &spare)? {
        Replacement::Replaced => {
            tracing::info!("liveness: replaced {} with {spare} in {session_id}", inv.id);
        }
        other => tracing::warn!(
            "liveness: replace {}→{spare} in {session_id} rejected: {other:?}",
            inv.id
        ),
    }
    Ok(true)
}

/// A connected, enabled, healthy inventory bot of the required role that is not
/// already in the session roster. First match wins.
fn find_spare(
    state: &Arc<AppState>,
    session_id: &str,
    dead: &crate::store::BotInventory,
    chair: bool,
) -> Result<Option<String>> {
    let roster = state.store.roster(session_id)?;
    let want_role = if chair { "chair" } else { dead.role.as_str() };
    Ok(state
        .store
        .list_bots()?
        .into_iter()
        .find(|b| {
            state.is_connected(&b.id)
                && b.enabled
                && b.health == "ok"
                && b.role == want_role
                && !roster.iter().any(|r| r == &b.id)
        })
        .map(|b| b.id))
}

/// Drop a dead reviewer from the roster, shrink the quorum to the surviving
/// reviewer count, and re-run the coordinator — the shrunk quorum may make the
/// already-recorded done-count sufficient, in which case the chair is prompted
/// to synthesize now instead of waiting for the watchdog.
fn trim_reviewer(state: &Arc<AppState>, session_id: &str, bot_id: &str) -> Result<()> {
    // Narrow the check→trim race (council review on #68): a bot that reconnected
    // since the sweep's connected check keeps its seat.
    if state.is_connected(bot_id) {
        return Ok(());
    }
    trim_reviewer_body(state, session_id, bot_id, "unreachable")
}

/// Report-delivery keeps liveness's capacity-preserving preference — use a
/// connected same-role spare when one is available — but unlike liveness it
/// must never shrink the roster. A reviewer that is merely slow still holds a
/// seat the fixed `quorum_n` needs; removing it turned nuphos#1231 round 1 into
/// an `insufficient_valid_reviewers` fail-close 9 minutes before the report
/// actually arrived. Without a spare the reviewer keeps its seat and the round
/// waits — the watchdog is the only backstop for one that never delivers.
fn replace_reviewer_if_spare(state: &Arc<AppState>, session_id: &str, bot_id: &str) -> Result<()> {
    if let Some(inv) = state.store.bot_inventory(bot_id)? {
        if let Some(spare) = find_spare(state, session_id, &inv, false)? {
            match replace_roster_bot(state, session_id, bot_id, &spare)? {
                Replacement::Replaced => {
                    tracing::info!(
                        "report-delivery: replaced {bot_id} with {spare} in {session_id}"
                    );
                    return Ok(());
                }
                other => tracing::warn!(
                    "report-delivery: replace {bot_id}→{spare} in {session_id} rejected: {other:?}"
                ),
            }
        }
    }
    tracing::warn!(
        "report-delivery: {bot_id} has not delivered a report in {session_id} and no spare is \
         available; keeping its roster seat so a late report can still close the round"
    );
    Ok(())
}

/// Remove a reviewer, shrink the quorum, and re-run the coordinator's roster
/// change hook. There is intentionally no connectivity guard here: the
/// liveness caller owns that race check, while the report-delivery action must
/// also be able to remove a connected but non-delivering reviewer.
fn trim_reviewer_body(
    state: &Arc<AppState>,
    session_id: &str,
    bot_id: &str,
    reason: &str,
) -> Result<()> {
    if !state.store.remove_session_bot(session_id, bot_id)? {
        return Ok(());
    }
    state
        .store
        .purge_outbox_for_session_bot(session_id, bot_id)?;
    let Some(session) = state.store.session(session_id)? else {
        return Ok(());
    };
    let roster = state.store.roster(session_id)?;
    let reviewers = crate::session::reviewers(&roster, session.chair_bot.as_deref()).len() as i64;
    // An external controller opened a formal review with an immutable reviewer
    // minimum. Availability handling may replace a failed slot, but it may not
    // silently redefine the evidence needed for a GitHub verdict. PR 0 has no
    // in-flight standby yet, so loss below the minimum closes fail-closed.
    let fixed_review_contract = session
        .trigger_ref
        .as_deref()
        .is_some_and(|trigger| trigger.starts_with("controller:"))
        && session.quorum_n > 0;
    if fixed_review_contract && reviewers < session.quorum_n {
        close_session_by_controller(state, session_id, "insufficient_valid_reviewers")?;
        state.emit_north(
            "insufficient_valid_reviewers",
            session_id,
            json!({
                "last_trimmed": bot_id,
                "reason": reason,
                "required_valid_reviewers": session.quorum_n,
                "remaining_reviewers": reviewers,
            }),
        );
        tracing::warn!(
            "reviewer minimum lost on {session_id} ({reviewers}/{}); session fail-closed",
            session.quorum_n
        );
        return Ok(());
    }
    // Trimming the LAST reviewer must not leave quorum_n = 0: `0 >= 0` is
    // trivially a quorum, so the very next roster-change evaluation would
    // convene the chair to synthesize from nothing — the failure class
    // SEI-873 exists to prevent, reached at the roster-exhaustion edge
    // (confirmed as a red by the council on the sibling #349 review).
    // Fail-close instead; the controller ignores non-normal terminals, so
    // no verdict is fabricated on either side.
    if reviewers == 0 {
        // The standard close helper carries ALL terminal side effects —
        // outbox purge (log-and-continue), provider token revocation, the
        // generic state:closed north event and the ADR 012 close webhook
        // (council F1–F4 on this PR: a hand-rolled close path missed every
        // one of them; the red was tokens outliving their round).
        close_session_by_controller(state, session_id, "roster_exhausted")?;
        state.emit_north(
            "roster_exhausted",
            session_id,
            json!({ "last_trimmed": bot_id, "reason": reason }),
        );
        tracing::warn!("roster exhausted on {session_id} ({reason}); session fail-closed");
        return Ok(());
    }
    let quorum_n = session.quorum_n.min(reviewers);
    if quorum_n != session.quorum_n {
        state.store.set_session_quorum(session_id, quorum_n)?;
    }
    state.emit_north(
        "roster_drop",
        session_id,
        json!({ "bot": bot_id, "reason": reason, "quorum_n": quorum_n }),
    );
    tracing::info!("trimmed {bot_id} from {session_id}, quorum now {quorum_n}");
    let Some(session) = state.store.session(session_id)? else {
        return Ok(());
    };
    let cx = OrchCtx {
        state,
        session: &session,
        roster: state.store.roster(session_id)?,
    };
    let Some(coord) = dispatch_coordinator(state, &session)? else {
        return Ok(());
    };
    let actions = coord.on_roster_change(&cx);
    run_actions(state, &session, actions)
}

/// Trimmed non-empty lines outside triple-backtick fenced blocks. An unclosed
/// fence drops everything after the opening fence, fail-closed.
pub(crate) fn unfenced_lines(text: &str) -> Vec<&str> {
    text.split("```")
        .step_by(2)
        .flat_map(str::lines)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// Build the ADR 012 `session.closed` webhook payload. Pure — unit-tested.
fn close_webhook_payload(
    session: Option<&Session>,
    session_id: &str,
    roster: &[String],
    verdict: &str,
    reason: &str,
) -> serde_json::Value {
    json!({
        "event": "session.closed",
        "session_id": session_id,
        "trigger_ref": session.and_then(|s| s.trigger_ref.clone()),
        "mode": session.map(|s| s.mode.clone()),
        "verdict": verdict,
        "reason": reason,
        "roster": roster,
        // ADR 013: structured verdict (all null on timeout / missing trailer).
        "decision": session.and_then(|s| s.decision.clone()),
        "findings_red": session.and_then(|s| s.findings_red),
        "findings_yellow": session.and_then(|s| s.findings_yellow),
        "findings_green": session.and_then(|s| s.findings_green),
        "ts": crate::store::now_ms(),
    })
}

/// ADR 012: fire-and-forget POST to `OABCP_SESSION_CLOSE_WEBHOOK` after a
/// session closes. Best-effort by design — a failure logs a warning; no retry,
/// no queue (the verdict already lives on the PR and in the store). No-op when
/// the env var is unset.
fn fire_close_webhook(state: &Arc<AppState>, session_id: &str, verdict: &str, reason: &str) {
    let Some(url) = state.close_webhook_url.clone() else {
        return;
    };
    let session = state.store.session(session_id).ok().flatten();
    let roster = state.store.roster(session_id).unwrap_or_default();
    let payload = close_webhook_payload(session.as_ref(), session_id, &roster, verdict, reason);
    let session_id = session_id.to_string();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        match client.post(&url).json(&payload).send().await {
            Ok(resp) if !resp.status().is_success() => {
                tracing::warn!("close webhook for {session_id} returned {}", resp.status());
            }
            Err(e) => tracing::warn!("close webhook for {session_id} failed: {e}"),
            _ => {}
        }
    });
}

/// Reconstruct the sender of a stored message (for history backfill).
fn sender_for(state: &AppState, m: &Message) -> SenderInfo {
    match m.author_kind.as_str() {
        "bot" => {
            let id = m.author_id.as_deref().unwrap_or("");
            let name = state
                .store
                .bot(id)
                .ok()
                .flatten()
                .map(|b| b.name)
                .unwrap_or_default();
            bot_sender(id, &name)
        }
        "system" => SenderInfo {
            id: "system".into(),
            name: "system".into(),
            display_name: "system".into(),
            is_bot: false,
        },
        _ => SenderInfo {
            id: "client".into(),
            name: "client".into(),
            display_name: "client".into(),
            is_bot: false,
        },
    }
}

/// Outcome of an admission decision (membership plane, ADR 001). The plane
/// guarantees a session roster stays bounded and valid; every add — north-driven
/// today, bot-recruited later — passes through this one gate.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Added,
    AlreadyMember,
    Rejected(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
pub enum BatchAdmission {
    Added {
        added: Vec<String>,
        already_members: Vec<String>,
    },
    Rejected(&'static str),
}

/// Outcome of a dynamic one-for-one roster replacement.
#[derive(Debug, PartialEq, Eq)]
pub enum Replacement {
    Replaced,
    Noop,
    Rejected(&'static str),
}

/// Pure admission policy → unit-tested; `add_to_roster` supplies the live values.
/// `Added` is provisional approval — the caller still performs the insert+backfill.
fn admit(known: bool, already_member: bool, roster_len: usize, max: usize) -> Admission {
    if already_member {
        Admission::AlreadyMember // idempotent re-add, even at capacity
    } else if !known {
        Admission::Rejected("unknown bot") // never registered → would hang the roster
    } else if roster_len >= max {
        Admission::Rejected("roster full") // bounded growth
    } else {
        Admission::Added
    }
}

/// Max session roster size (admission quota). ponytail: env read per add — adds
/// are rare mid-session events; default 16, bump via `OABCP_MAX_ROSTER`.
fn max_roster() -> usize {
    std::env::var("OABCP_MAX_ROSTER")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(16)
}

/// Max distinct recruit directives accepted per session. This bounds the
/// unknown-target provision signal surface; repeats are handled separately.
fn recruit_session_cap() -> usize {
    std::env::var("OABCP_RECRUIT_SESSION_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(5)
}

/// Max distinct intent-carrying messages per bot per session (ADR 039).
/// Bounds the controller event volume a single looping bot can generate
/// without letting it exhaust the other roster members' budgets.
fn intent_session_cap() -> usize {
    std::env::var("OABCP_INTENT_SESSION_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(32)
}

/// Max history frames replayed to a late/replacement bot. `0` disables the cap.
/// A joiner must not cost O(full history) agent turns; the opening client
/// trigger is pinned because it carries the task.
fn backfill_max() -> Option<usize> {
    let max = std::env::var("OABCP_BACKFILL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    (max > 0).then_some(max)
}

/// Add a bot to a session mid-flight and backfill the conversation so far,
/// through the admission gate. The history is replayed via the durable outbox
/// (same as live delivery), so it arrives in order whether the bot is online now
/// or connects later. `/bot-config` pins OAB to per-thread processing so this
/// burst is one context turn instead of one agent turn per message. Errors only
/// on an unknown session; rejection/idempotency are reported via `Admission`.
pub fn add_to_roster(state: &Arc<AppState>, session_id: &str, bot_id: &str) -> Result<Admission> {
    if state.store.session(session_id)?.is_none() {
        anyhow::bail!("unknown session {session_id}");
    }
    let roster = state.store.roster(session_id)?;
    let decision = admit(
        state.store.bot(bot_id)?.is_some(),
        roster.iter().any(|b| b == bot_id),
        roster.len(),
        max_roster(),
    );
    if decision != Admission::Added {
        return Ok(decision);
    }
    // approved → insert + backfill. add_session_bot stays the authoritative guard
    // (false on a concurrent double-add → already a member, skip the backfill).
    if !state.store.add_session_bot(session_id, bot_id)? {
        return Ok(Admission::AlreadyMember);
    }
    backfill_bot(state, session_id, bot_id)?;
    state.emit_north("roster_add", session_id, json!({ "bot": bot_id }));
    Ok(Admission::Added)
}

/// Add a controller-supplied batch atomically at the membership layer, then
/// backfill every newly added bot through the normal durable delivery path.
/// All ids are validated before mutation, so an unknown bot cannot leave a
/// partially updated roster.
pub fn add_to_roster_batch(
    state: &Arc<AppState>,
    session_id: &str,
    bot_ids: &[String],
    opening_inputs: &[OpeningInput],
) -> Result<BatchAdmission> {
    let Some(session) = state.store.session(session_id)? else {
        anyhow::bail!("unknown session {session_id}");
    };
    if matches!(
        SessionState::from_db_str(&session.state),
        SessionState::Closed | SessionState::Aborted
    ) {
        return Ok(BatchAdmission::Rejected("terminal session"));
    }
    for bot_id in bot_ids {
        if state.store.bot(bot_id)?.is_none() {
            return Ok(BatchAdmission::Rejected("unknown bot"));
        }
    }

    let outcome = state.store.add_session_bots_if_capacity(
        session_id,
        bot_ids,
        max_roster(),
        opening_inputs,
    )?;
    let RosterAddOutcome::Added {
        added,
        already_members,
    } = outcome
    else {
        return Ok(BatchAdmission::Rejected("roster full"));
    };
    for bot_id in &added {
        backfill_bot(state, session_id, bot_id)?;
        state.emit_north("roster_add", session_id, json!({ "bot": bot_id }));
    }
    Ok(BatchAdmission::Added {
        added,
        already_members,
    })
}

/// Replace one session roster member with another without changing roster size.
/// The new bot is backfilled with the session history, while pending frames for the
/// removed bot in this session are purged so an offline bot can't rejoin later and
/// keep working on a task it no longer owns.
pub fn replace_roster_bot(
    state: &Arc<AppState>,
    session_id: &str,
    old_bot_id: &str,
    new_bot_id: &str,
) -> Result<Replacement> {
    if old_bot_id == new_bot_id {
        return Ok(Replacement::Noop);
    }
    let Some(session) = state.store.session(session_id)? else {
        anyhow::bail!("unknown session {session_id}");
    };
    if matches!(
        SessionState::from_db_str(&session.state),
        SessionState::Closed | SessionState::Aborted
    ) {
        return Ok(Replacement::Rejected("terminal session"));
    }

    let roster = state.store.roster(session_id)?;
    if !roster.iter().any(|b| b == old_bot_id) {
        return Ok(Replacement::Rejected("old bot not in roster"));
    }
    if roster.iter().any(|b| b == new_bot_id) {
        return Ok(Replacement::Rejected("replacement already in roster"));
    }
    let Some(old_bot) = state.store.bot(old_bot_id)? else {
        return Ok(Replacement::Rejected("old bot not registered"));
    };
    let Some(new_bot) = state.store.bot(new_bot_id)? else {
        return Ok(Replacement::Rejected("unknown replacement bot"));
    };
    let replacing_chair = session.chair_bot.as_deref() == Some(old_bot_id);
    if replacing_chair && new_bot.role != "chair" {
        return Ok(Replacement::Rejected("replacement is not chair-capable"));
    }
    if !replacing_chair && new_bot.role != old_bot.role {
        return Ok(Replacement::Rejected("replacement role mismatch"));
    }

    if !state
        .store
        .replace_session_bot(session_id, old_bot_id, new_bot_id)?
    {
        return Ok(Replacement::Rejected("old bot not in roster"));
    }
    if replacing_chair {
        state.store.set_session_chair(session_id, new_bot_id)?;
    }
    state
        .store
        .purge_outbox_for_session_bot(session_id, old_bot_id)?;
    if replacing_chair {
        backfill_bot_with_audience_alias(state, session_id, new_bot_id, Some(old_bot_id))?;
    } else {
        backfill_bot(state, session_id, new_bot_id)?;
    }
    state.emit_north(
        "roster_replace",
        session_id,
        json!({ "old_bot": old_bot_id, "new_bot": new_bot_id, "chair": replacing_chair }),
    );
    Ok(Replacement::Replaced)
}

fn backfill_bot(state: &Arc<AppState>, session_id: &str, bot_id: &str) -> Result<()> {
    backfill_bot_with_audience_alias(state, session_id, bot_id, None)
}

fn backfill_bot_with_audience_alias(
    state: &Arc<AppState>,
    session_id: &str,
    bot_id: &str,
    audience_alias: Option<&str>,
) -> Result<()> {
    let Some(session) = state.store.session(session_id)? else {
        anyhow::bail!("unknown session {session_id}");
    };
    let thread = state.store.thread_for_session(session_id)?;
    let mut eligible = vec![];
    for m in state.store.messages(session_id)? {
        if m.author_kind == "status" {
            continue; // operator audit is never bot conversation context
        }
        if m.author_id.as_deref() == Some(bot_id) {
            continue; // don't echo the joiner's own messages
        }
        if let Some(audience) = m.audience.as_deref() {
            let owns_audience =
                audience == bot_id || audience_alias.is_some_and(|alias| audience == alias);
            if !owns_audience {
                continue;
            }
        }
        eligible.push(m);
    }

    let selected = match backfill_max() {
        Some(cap) if eligible.len() > cap => {
            let trigger = eligible.iter().find(|m| m.author_kind == "client").cloned();
            let mut selected = vec![];
            if let Some(trigger) = trigger {
                selected.push(trigger.clone());
                let mut recent: Vec<_> = eligible
                    .iter()
                    .rev()
                    .filter(|m| m.id != trigger.id)
                    .take(cap.saturating_sub(1))
                    .cloned()
                    .collect();
                recent.reverse();
                selected.extend(recent);
            } else {
                selected = eligible.iter().rev().take(cap).cloned().collect();
                selected.reverse();
            }
            tracing::warn!(
                session_id,
                bot_id,
                skipped = eligible.len().saturating_sub(selected.len()),
                cap,
                "backfill capped"
            );
            selected
        }
        _ => eligible,
    };

    let Some(coord) = dispatch_coordinator(state, &session)? else {
        return Ok(());
    };
    let cx = OrchCtx {
        state,
        session: &session,
        roster: state.store.roster(session_id)?,
    };
    for m in selected {
        let content = if m.author_kind == "client" {
            coord.recipient_trigger_text(&cx, bot_id, &m.content)
        } else {
            m.content.clone()
        };
        state.deliver_event(
            bot_id,
            session_id,
            thread.as_deref(),
            sender_for(state, &m),
            Content::text(content),
            vec![],
            &m.id,
        );
    }
    Ok(())
}

/// Extract a self-recruit target from an own-line, unfenced
/// `[[recruit:<bot_id>]]` directive. A text convention (like OAB's
/// `[[reply_to:]]`), so no new gateway wire type.
fn parse_recruit(text: &str) -> Option<&str> {
    for line in unfenced_lines(text) {
        let Some(inner) = line
            .strip_prefix("[[recruit:")
            .and_then(|rest| rest.strip_suffix("]]"))
        else {
            continue;
        };
        let id = inner.trim();
        if !id.is_empty() {
            return Some(id);
        }
    }
    None
}

/// Authz: who may recruit. v1 = the session chair only (the coordination
/// authority); a reviewer can't unilaterally expand the panel. One place to widen
/// later (role/allow-list) without touching call sites.
fn may_recruit(session: &Session, bot_id: &str) -> bool {
    session.chair_bot.as_deref() == Some(bot_id)
}

/// Which north event an authorized recruit produces (`None` = silent no-op).
/// inc3 seam: an `unknown bot` rejection becomes a `provision_requested` signal —
/// the cue for an *external* fleet provisioner to spin up that pod, register it,
/// and add it (OCP never calls the infra API; see `docs/provisioner.md`). A
/// `roster full` rejection stays a plain rejection.
fn recruit_event(admission: &Admission) -> Option<&'static str> {
    match admission {
        Admission::Added => Some("recruit"),
        Admission::AlreadyMember => None,
        Admission::Rejected("unknown bot") => Some("provision_requested"),
        Admission::Rejected(_) => Some("recruit_rejected"),
    }
}

/// Self-recruitment (membership plane inc2/inc3, ADR 001): a bot asks to add a
/// member by embedding `[[recruit:<bot_id>]]` in a normal message. Authorized
/// requests route through the *same* admission gate (`add_to_roster`) — so quota +
/// registered-bot still hold; a bot can't bypass them by asking. No new wire type.
/// A recruit of an unregistered bot emits `provision_requested` for an external
/// provisioner rather than failing silently (inc3).
fn maybe_recruit(state: &Arc<AppState>, session: &Session, bot_id: &str, text: &str) -> Result<()> {
    let Some(target) = parse_recruit(text) else {
        return Ok(());
    };
    if !may_recruit(session, bot_id) {
        tracing::warn!(
            "bot {bot_id} not authorized to recruit in session {}",
            session.id
        );
        state.emit_north(
            "recruit_denied",
            &session.id,
            json!({ "by": bot_id, "target": target }),
        );
        return Ok(());
    }
    let target = target.to_string();
    let cap = recruit_session_cap();
    {
        let mut seen = state.recruit_seen.lock().unwrap();
        let session_seen = seen.entry(session.id.clone()).or_default();
        if session_seen.contains(&target) {
            return Ok(());
        }
        if session_seen.len() >= cap {
            tracing::warn!(
                "recruit rate limit reached in session {} for target {target}",
                session.id
            );
            state.emit_north(
                "recruit_rejected",
                &session.id,
                json!({ "by": bot_id, "target": target, "reason": "rate_limited" }),
            );
            return Ok(());
        }
        session_seen.insert(target.clone());
    }
    let outcome = add_to_roster(state, &session.id, &target)?;
    if let Some(event) = recruit_event(&outcome) {
        state.emit_north(
            event,
            &session.id,
            json!({ "by": bot_id, "target": target }),
        );
        if event == "provision_requested" {
            tracing::info!(
                "provision requested for '{target}' by {bot_id} in session {}",
                session.id
            );
        }
    }
    Ok(())
}

/// Extract a bot intent from an own-line, unfenced `[[intent:<verb> <args>]]`
/// directive (ADR 039). Verb is the first whitespace-separated token; the
/// argument tail stays raw — the kernel transports intents, the consuming
/// controller owns the grammar. Same text convention as `[[recruit:]]`.
fn parse_intent(text: &str) -> Option<(&str, &str)> {
    for line in unfenced_lines(text) {
        let Some(inner) = line
            .strip_prefix("[[intent:")
            .and_then(|rest| rest.strip_suffix("]]"))
        else {
            continue;
        };
        let inner = inner.trim();
        let (verb, args) = match inner.split_once(char::is_whitespace) {
            Some((v, a)) => (v, a.trim()),
            None => (inner, ""),
        };
        if !verb.is_empty() {
            return Some((verb, args));
        }
    }
    None
}

/// Bot-initiated intent (ADR 039): a roster bot may embed
/// `[[intent:<verb> <args>]]` in a normal message. The mechanism never acts on
/// it — it emits north for observability and enqueues a grant-gated
/// `session.intent` controller event; policy (a coordinator or an external
/// controller) decides what, if anything, happens. Any roster member may emit
/// one (`handle_reply` already proved membership); finer authorization is
/// policy, not mechanism.
fn maybe_intent(
    state: &Arc<AppState>,
    session: &Session,
    bot_id: &str,
    message_id: &str,
    text: &str,
) -> Result<()> {
    let Some((verb, args)) = parse_intent(text) else {
        return Ok(());
    };
    let cap = intent_session_cap();
    {
        let mut seen = state.intent_seen.lock().unwrap();
        // Per-bot budget (PR 381 F1): a shared session-wide set would let one
        // looping bot starve every other member's intent channel.
        let bot_seen = seen
            .entry(session.id.clone())
            .or_default()
            .entry(bot_id.to_string())
            .or_default();
        if bot_seen.contains(message_id) {
            return Ok(()); // a streamed edit re-delivers the same final message
        }
        if bot_seen.len() >= cap {
            tracing::warn!(
                "intent rate limit reached in session {} (bot {bot_id})",
                session.id
            );
            state.emit_north(
                "intent_rejected",
                &session.id,
                json!({ "by": bot_id, "verb": verb, "reason": "rate_limited" }),
            );
            return Ok(());
        }
        bot_seen.insert(message_id.to_string());
    }
    state.emit_north(
        "intent",
        &session.id,
        json!({ "by": bot_id, "message_id": message_id, "verb": verb, "args": args }),
    );
    state.store.enqueue_session_intent(
        &session.id,
        message_id,
        json!({ "message_id": message_id, "bot_id": bot_id, "verb": verb, "args": args }),
    )
}

/// Dispatch a bot's GatewayReply (the south handler core).
pub fn handle_reply(state: &Arc<AppState>, bot_id: &str, reply: GatewayReply) -> Result<()> {
    let session_id = reply.channel.id.clone();
    let session = match state.store.session(&session_id)? {
        Some(s) => s,
        None => {
            tracing::warn!("reply for unknown session {session_id}");
            return Ok(());
        }
    };
    // Roster authorization (plane-level isolation). The /ws token proves *who*
    // the bot is; this proves it *belongs to this session*. Without it any valid
    // bot could act in any session. This is orthogonal to OAB's own bot-side
    // `allow_*` filters (which decide what a bot responds to) — both layers apply.
    if !state.store.roster(&session_id)?.iter().any(|b| b == bot_id) {
        tracing::warn!("bot {bot_id} not in roster of session {session_id}; dropping reply");
        return Ok(());
    }
    let bot = state.store.bot(bot_id)?;
    let bot_name = bot.as_ref().map(|b| b.name.clone()).unwrap_or_default();

    // Once closed, the transcript is frozen: drop new sends/topics (a bot
    // whose turn was already in flight at close time would otherwise append a
    // post-verdict message, often a "…" stub) and reject edits/deletes — the
    // recorded result span is on disk (ADR 028) and its text must stay
    // immutable. Council bot configs use send-once delivery, so the settled
    // content arrives before OCP can interpret its [done] signal and close the
    // session. A late edit is stale delivery, not a continuation of the turn.
    // Reactions stay harmless (delivery is already gated in deliver_event).
    let closed = matches!(
        SessionState::from_db_str(&session.state),
        SessionState::Closed | SessionState::Aborted
    );
    match reply.command.as_deref() {
        None if closed => {}
        Some("create_topic") if closed => {}
        Some("edit_message") if closed => {
            tracing::warn!("edit_message from {bot_id} on closed session {session_id} rejected");
        }
        Some("delete_message") if closed => {
            tracing::warn!("delete_message from {bot_id} on closed session {session_id} rejected");
        }
        None => on_send(state, &session, bot_id, &bot_name, &reply)?,
        Some("create_topic") => on_create_topic(state, &session, bot_id, &reply)?,
        Some("add_reaction") => on_reaction(state, &session, bot_id, &reply, true)?,
        Some("remove_reaction") => on_reaction(state, &session, bot_id, &reply, false)?,
        Some("edit_message") => on_edit(state, &session, bot_id, &reply)?,
        Some("delete_message") => {} // no-op for the council; audit keeps history
        Some(other) => tracing::warn!("unknown command {other}"),
    }
    Ok(())
}

/// Consecutive error frames before a bot flips to `degraded` (ADR 023 Phase 1).
/// Env-overridable so an operator can tighten/loosen without a rebuild; the ADR
/// default is 3.
fn health_error_threshold() -> i64 {
    std::env::var("OABCP_HEALTH_ERROR_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(3)
}

/// Recognize a bot turn that carried an agent error instead of model output
/// (ADR 023 Phase 1). The bot gateway wraps a JSON-RPC failure (kiro-cli / codex
/// ACP) into the message frame verbatim, so the plane — blind to it until now —
/// matches the signature in the content. The `-32603` internal-error code is the
/// unambiguous signal: it surfaced for BOTH failure modes in the 2026-07-13
/// incident (kiro quota, codex token revoke) and is vanishingly unlikely in real
/// model prose. ponytail: text-matching until a frame-level `is_error` flag is
/// added at the gateway (ADR 023 build-order §6).
pub fn is_agent_error_frame(content: &str) -> bool {
    crate::turn_failure::classify_legacy_turn_failure(content).is_some()
}

/// A streaming stub — the empty / "…" placeholder a bot sends first, filled in
/// later via `edit_message`. Not a settled turn, so it is not health-accounted
/// (the final content lands through `on_edit`).
fn is_streaming_stub(text: &str) -> bool {
    let t = text.trim();
    t.is_empty() || t == "…" || t == "..."
}

/// Passive agent-liveness accounting for a settled bot turn (ADR 023 Phase 1):
/// classify the frame, drive `bots.health`, and WARN exactly once on crossing.
/// Called from BOTH `on_send` (complete frames) and `on_edit` (the settled
/// content of a streamed turn) — council F1: streamed bots (kiro/codex) deliver
/// their final content via edit, so an on_send-only hook meant a streamed bot
/// could never recover from `degraded` and streamed error frames never counted.
/// The stub-skip keeps partial edits from being accounted; the content reset is
/// idempotent, so re-accounting a settled edit is safe.
fn account_bot_health(state: &Arc<AppState>, session_id: &str, bot_id: &str, text: &str) {
    if is_streaming_stub(text) {
        return; // partial stub — wait for the settled content
    }
    // Shared execution capacity is not evidence that this bot's provider is
    // unhealthy. Reject the report without triggering provider failover or
    // treating the busy frame as a successful recovery.
    if crate::turn_failure::classify_legacy_turn_failure(text)
        == Some(crate::turn_failure::LegacyTurnFailureKind::LocalCapacity)
    {
        return;
    }
    let threshold = health_error_threshold();
    let is_error = is_agent_error_frame(text);
    match state.store.record_bot_frame(bot_id, is_error, threshold) {
        Ok(BotHealthTransition::Degraded) => {
            let bot_name = state.store.bot(bot_id).ok().flatten().map(|b| b.name);
            // The one alert path (ADR 023 Decision 2): existing log-based alerting
            // is the delivery — no new notification system. connected != healthy.
            tracing::warn!(
                bot = bot_id,
                bot_name,
                session = session_id,
                "bot degraded: {threshold} consecutive agent error frames \
                 (connected but not producing output)"
            );
            // Phase 4: route around the degraded bot by promoting a healthy
            // standby of the same role (Decision 5). Bounded + alert-on-none.
            attempt_failover(state, bot_id);
        }
        Ok(BotHealthTransition::Recovered) => {
            tracing::info!(bot = bot_id, "bot recovered: agent producing output again");
        }
        Ok(BotHealthTransition::None) => {}
        Err(e) => tracing::warn!(bot = bot_id, "health accounting failed: {e}"),
    }
}

/// Whether a `degraded` bot is *automatically* routed around (ADR 023 Phase 4).
/// Default off: the WARN alert still fires, but the roster swap is opt-in per lane
/// (`OABCP_AUTO_FAILOVER=1`). This honors Decision 5's "first cut may surface as a
/// one-click alert before going fully automatic" and the dev-before-prod deploy
/// gate — enable in dev, prove no thrash, then prod.
fn auto_failover_enabled() -> bool {
    matches!(
        std::env::var("OABCP_AUTO_FAILOVER").ok().as_deref(),
        Some("1") | Some("true")
    )
}

/// Pick a promotable standby for a degraded rostered bot (ADR 023 Decision 5):
/// a **same-role** bot that is enabled, `connected`, `health == ok`, and not
/// already in `roster`. A quota/token outage is provider-specific, so a standby
/// on a *different* provider is preferred; a same-provider healthy standby is a
/// last resort (returned only if no cross-provider one exists). Same-role keeps
/// the roster valid by construction — a chair's standby is itself `role=chair`,
/// so it lands at slot 0 as a chair; a reviewer's standby stays a reviewer.
fn pick_healthy_standby(
    state: &Arc<AppState>,
    role: &str,
    degraded_provider: Option<&str>,
    roster: &[String],
) -> Option<String> {
    let bots = state.store.list_bots().ok()?;
    let mut same_provider_fallback: Option<String> = None;
    for b in bots {
        let promotable = b.role == role
            && b.enabled
            && b.health == "ok"
            && !roster.contains(&b.id)
            && state.is_connected(&b.id);
        if !promotable {
            continue;
        }
        // Prefer a different provider; stash a same-provider candidate as a last
        // resort (better than leaving the council without this role).
        if b.provider.as_deref() != degraded_provider || degraded_provider.is_none() {
            return Some(b.id);
        }
        same_provider_fallback.get_or_insert(b.id);
    }
    same_provider_fallback
}

/// Route around a bot that just crossed to `degraded` (ADR 023 Phase 4) by
/// swapping it out of the **standing** roster for a healthy same-role standby, so
/// the next convene uses the good bot. This restores council *capacity*; it does
/// not rescue the in-flight session (the watchdog closes that, and the WARN has
/// already alerted a human). Bounded: it swaps in one currently-healthy standby;
/// the just-degraded bot stays `health=degraded` so it can't be re-selected, and
/// with no standby it is alert-only — no thrash.
fn attempt_failover(state: &Arc<AppState>, degraded_bot_id: &str) {
    // Serialize the whole read-modify-write (council F7): two bots degrading on
    // concurrent reply tasks would otherwise each read the same roster snapshot
    // and the later `set_standing_roster` would clobber the earlier swap. The
    // roster is (re-)read below *inside* this lock, so each swap sees the prior
    // one. Cheap — failover is rare — and the path is fully synchronous.
    // Recover from poison (guards `()`; see controller_action_lock note): a
    // panicked prior holder must not brick all future failovers until restart.
    let _swap = state
        .failover_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok((roster, _)) = crate::plugins::council::runtime_council_roster(state) else {
        return;
    };
    // Only route around a bot that is actually in the standing roster — an
    // off-roster bot (e.g. a solo-session participant) has nothing to swap.
    if !roster.contains(&degraded_bot_id.to_string()) {
        return;
    }
    let provider = state
        .store
        .bot_inventory(degraded_bot_id)
        .ok()
        .flatten()
        .and_then(|b| b.provider);
    let role = if roster.first().map(String::as_str) == Some(degraded_bot_id) {
        "chair"
    } else {
        "reviewer"
    };

    let Some(standby) = pick_healthy_standby(state, role, provider.as_deref(), &roster) else {
        tracing::warn!(
            bot = degraded_bot_id,
            role,
            "no healthy {role} standby to fail over to — alert only (provision a \
             blue-green standby: #227 for the chair)"
        );
        return;
    };

    if !auto_failover_enabled() {
        // Surface the actionable one-click (Decision 5) without mutating prod.
        tracing::warn!(
            bot = degraded_bot_id,
            standby,
            role,
            "healthy {role} standby available — auto-failover disabled; promote \
             manually via PUT /v1/council/roster or set OABCP_AUTO_FAILOVER=1"
        );
        return;
    }

    let new_roster: Vec<String> = roster
        .iter()
        .map(|b| {
            if b == degraded_bot_id {
                standby.clone()
            } else {
                b.clone()
            }
        })
        .collect();
    match state.store.set_standing_roster(&new_roster) {
        Ok(()) => {
            tracing::warn!(
                degraded = degraded_bot_id,
                promoted = standby,
                role,
                "auto-failover: promoted healthy {role} standby into the standing roster"
            );
            state.emit_north(
                "failover",
                "-",
                json!({
                    "degraded": degraded_bot_id,
                    "promoted": standby,
                    "role": role,
                    "roster": new_roster,
                }),
            );
        }
        Err(e) => tracing::warn!(
            bot = degraded_bot_id,
            "auto-failover roster swap failed: {e}"
        ),
    }
}

fn on_send(
    state: &Arc<AppState>,
    session: &Session,
    bot_id: &str,
    bot_name: &str,
    reply: &GatewayReply,
) -> Result<()> {
    let thread = reply
        .channel
        .thread_id
        .clone()
        .or(state.store.thread_for_session(&session.id)?);
    let msg = state.store.add_message(
        &session.id,
        thread.as_deref(),
        "bot",
        Some(bot_id),
        None,
        &reply.content.text,
        reply.quote_message_id.as_deref(),
    )?;
    // Passive health accounting (ADR 023 Phase 1): a `-32603` error frame arrives
    // here as a complete (non-streamed) send, so this is where the broken-agent
    // signal — invisible to the plane until now — is finally read.
    account_bot_health(state, &session.id, bot_id, &reply.content.text);
    state.emit_north(
        "message",
        &session.id,
        json!({ "message_id": msg.id, "author": bot_name, "content": reply.content.text }),
    );
    ack(state, bot_id, reply, None, Some(&msg.id));
    // A bot may embed `[[recruit:<id>]]` to add a member (chair-only, via the
    // admission gate). Parsed from the same message — no extra wire command.
    maybe_recruit(state, session, bot_id, &reply.content.text)?;
    // A bot may embed `[[intent:<verb> …]]` (ADR 039) — emitted, never acted on.
    maybe_intent(state, session, bot_id, &msg.id, &reply.content.text)?;
    // A done-signal posted as a complete (non-streamed) message is caught here;
    // a streamed one is caught in `on_edit` when the final content lands.
    check_text_done(state, session, bot_id, &msg.id, &reply.content.text)?;
    Ok(())
}

fn on_create_topic(
    state: &Arc<AppState>,
    session: &Session,
    bot_id: &str,
    reply: &GatewayReply,
) -> Result<()> {
    let had_thread = state.store.thread_for_session(&session.id)?.is_some();
    let thread_id = state
        .store
        .upsert_thread(&session.id, reply.quote_message_id.as_deref())?;
    if !had_thread {
        redeliver_trigger_to_non_starter_chair(state, session)?;
    }
    state.emit_north("thread", &session.id, json!({ "thread_id": thread_id }));
    ack(state, bot_id, reply, Some(&thread_id), None);
    Ok(())
}

fn redeliver_trigger_to_non_starter_chair(state: &Arc<AppState>, session: &Session) -> Result<()> {
    let Some(chair) = session.chair_bot.as_deref() else {
        return Ok(());
    };
    let roster = state.store.roster(&session.id)?;
    let Some(coord) = dispatch_coordinator(state, session)? else {
        return Ok(());
    };
    let starters = coord.starters(&roster, Some(chair));
    if starters.iter().any(|bot| bot == chair) {
        return Ok(());
    }
    let messages = state.store.messages(&session.id)?;
    let trigger = messages
        .iter()
        .find(|message| {
            message.author_kind == "client" && message.audience.as_deref() == Some(chair)
        })
        .or_else(|| {
            messages
                .iter()
                .find(|message| message.author_kind == "client" && message.audience.is_none())
        });
    let Some(trigger) = trigger else {
        return Ok(());
    };

    // A9: pre-thread, an unmentioned stock bot drops the opening trigger at the
    // group mention gate. Once the topic exists, re-deliver only to the
    // non-starter chair as a new audience-scoped system row/message_id; A2 keeps
    // the original outbox idem_key after ack. Chair done from this prompt is
    // inert before Quorum, and chair votes never count toward reviewer quorum.
    let cx = OrchCtx {
        state,
        session,
        roster,
    };
    deliver_system_prompt(
        state,
        session,
        chair,
        &coord.recipient_trigger_text(&cx, chair, &trigger.content),
    )
}

fn on_reaction(
    state: &Arc<AppState>,
    session: &Session,
    bot_id: &str,
    reply: &GatewayReply,
    add: bool,
) -> Result<()> {
    let emoji = &reply.content.text;
    let target = target_msg(reply).map(String::from);
    let target_msg = target
        .as_deref()
        .map(|target| state.store.message(target))
        .transpose()?
        .flatten();
    let Some(target_msg) = target_msg.filter(|m| m.session_id == session.id) else {
        tracing::warn!(
            "bot {bot_id} sent reaction {emoji} with unresolvable target {:?} in {}",
            target,
            session.id
        );
        state.emit_north(
            "reaction_rejected",
            &session.id,
            json!({
                "bot": bot_id,
                "emoji": emoji,
                "target": target,
                "reason": "unresolvable_target",
            }),
        );
        ack(state, bot_id, reply, None, None);
        return Ok(());
    };
    if add {
        state.store.add_reaction(&target_msg.id, bot_id, emoji)?;
    } else if emoji == DONE_EMOJI {
        tracing::info!(
            "ignoring remove_reaction {emoji} from {bot_id} in {}; done-votes are monotonic",
            session.id
        );
    } else {
        state.store.remove_reaction(&target_msg.id, bot_id, emoji)?;
    }
    state.emit_north(
        "reaction",
        &session.id,
        json!({ "bot": bot_id, "emoji": emoji, "add": add }),
    );
    ack(state, bot_id, reply, None, None);

    if add && emoji == DONE_EMOJI && matches!(target_msg.author_kind.as_str(), "client" | "system")
    {
        let Some(coord) = dispatch_coordinator(state, session)? else {
            return Ok(());
        };
        let cx = OrchCtx {
            state,
            session,
            roster: state.store.roster(&session.id)?,
        };
        if coord.reaction_counts_as_done(&cx, bot_id) {
            run_done(state, session, bot_id)?;
        }
    }
    Ok(())
}

/// Run the active coordinator's done-handling for `bot` and execute the actions.
/// Shared by the 🆗-reaction path and the text done-signal path.
fn run_done(state: &Arc<AppState>, session: &Session, bot_id: &str) -> Result<()> {
    let Some(coord) = dispatch_coordinator(state, session)? else {
        return Ok(());
    };
    let cx = OrchCtx {
        state,
        session,
        roster: state.store.roster(&session.id)?,
    };
    let rerequest_attempts = reviewer_rerequest_attempts(state, &session.id, bot_id);
    let actions = coord.on_done_with_reviewer_rerequest_attempts(&cx, bot_id, rerequest_attempts);
    run_actions(state, session, actions)
}

/// Count this reviewer's report re-request prompts from the durable transcript.
/// The stable prefix is the attempt log; no schema or coordinator context field
/// is needed.
fn reviewer_rerequest_attempts(state: &Arc<AppState>, session_id: &str, bot: &str) -> i64 {
    state
        .store
        .messages(session_id)
        .map(|msgs| {
            msgs.iter()
                .filter(|m| {
                    m.author_kind == "system"
                        && m.audience.as_deref() == Some(bot)
                        && m.content
                            .starts_with(coordinator::REVIEWER_REREQUEST_PREFIX)
                })
                .count() as i64
        })
        .unwrap_or(0)
}

/// Real agents often signal completion in message *text* (`[done]`, or a bare
/// 🆗) rather than via the gateway `add_reaction` the quorum path counts — this
/// is what stalled the live `openabdev/openab#1187` council. Recognize the text
/// form too. Conservative on purpose: a trailing `[done]` or a message that is
/// only 🆗 — not any 🆗 in passing (real bots use 🆗 as an ack mid-thread).
fn is_done_signal(text: &str) -> bool {
    let t = text.trim();
    t == DONE_EMOJI || t.ends_with("[done]")
}

/// If `text` is a done-signal, register a synthetic 🆗 (so the quorum count sees
/// it) and run the coordinator — the text-path equivalent of an `add_reaction`.
/// Checked on both send and edit: with `streaming=true` the final content (with
/// the `[done]`) lands via `edit_message`, not the initial stub. Idempotent —
/// `add_reaction` is INSERT OR IGNORE and the close/transition CAS guard re-runs.
fn check_text_done(
    state: &Arc<AppState>,
    session: &Session,
    bot_id: &str,
    msg_id: &str,
    text: &str,
) -> Result<()> {
    if is_done_signal(text) {
        let Some(coord) = dispatch_coordinator(state, session)? else {
            return Ok(());
        };
        let cx = OrchCtx {
            state,
            session,
            roster: state.store.roster(&session.id)?,
        };
        if !coord.accepts_text_done(&cx, bot_id, text) {
            tracing::warn!(
                "done-signal from {bot_id} rejected by {} policy in {}",
                session.mode,
                session.id
            );
            return Ok(());
        }
        state.store.add_reaction(msg_id, bot_id, DONE_EMOJI)?;
        run_done(state, session, bot_id)?;
    }
    Ok(())
}

/// Read-only view the Coordinator decides from; backed by the store.
struct OrchCtx<'a> {
    state: &'a AppState,
    session: &'a Session,
    roster: Vec<String>,
}

impl Ctx for OrchCtx<'_> {
    fn session_id(&self) -> &str {
        &self.session.id
    }
    fn roster(&self) -> &[String] {
        &self.roster
    }
    fn chair(&self) -> Option<&str> {
        self.session.chair_bot.as_deref()
    }
    fn quorum_n(&self) -> i64 {
        self.session.quorum_n
    }
    fn done_voters(&self) -> Vec<String> {
        self.state
            .store
            .done_voters(&self.session.id)
            .unwrap_or_default()
    }
    /// `bot`'s last non-stub message (skips empty / "…" streaming stubs).
    fn latest_settled(&self, bot: &str) -> Option<String> {
        self.state
            .store
            .messages(&self.session.id)
            .ok()?
            .into_iter()
            .rfind(|m| m.author_id.as_deref() == Some(bot) && is_settled_content(&m.content))
            .map(|m| m.content)
    }
    fn state(&self) -> SessionState {
        SessionState::from_db_str(&self.session.state)
    }
    fn trigger_ref(&self) -> Option<&str> {
        self.session.trigger_ref.as_deref()
    }
    /// The transcript is the attempt log: every synthesis prompt (initial and
    /// retries) is a system message starting with the quorum-prompt prefix.
    fn synthesis_attempts(&self) -> i64 {
        self.state
            .store
            .messages(&self.session.id)
            .map(|msgs| {
                msgs.iter()
                    .filter(|m| {
                        m.author_kind == "system" && m.content.starts_with("Quorum reached.")
                    })
                    .count() as i64
            })
            .unwrap_or(0)
    }
    /// Chair-capable pool: registered bots with the chair role that are
    /// enabled and healthy, sorted for deterministic rotation. Where only one
    /// chair is registered (today's lanes) this is just the current chair.
    fn chair_candidates(&self) -> Vec<String> {
        self.state
            .store
            .list_bots()
            .map(|bots| {
                let mut ids: Vec<String> = bots
                    .into_iter()
                    .filter(|b| {
                        // Rotating to an ABSENT bot would strand the synthesis
                        // prompt in its outbox until the watchdog times the
                        // round out — slower than today's failure. The
                        // just-failed chair stays eligible (it spoke seconds
                        // ago), and the rotation fallback re-prompts it when
                        // nobody else is reachable.
                        b.role == "chair"
                            && b.enabled
                            && b.health == "ok"
                            && self.state.is_connected(&b.id)
                    })
                    .map(|b| b.id)
                    .collect();
                ids.sort();
                ids
            })
            .unwrap_or_else(|_| {
                self.chair()
                    .map(|c| vec![c.to_string()])
                    .unwrap_or_default()
            })
    }
}

/// The settled result span of `author` (ADR 028): walk back from the author's
/// last settled message (`is_settled_content`, the same predicate as
/// `latest_settled`), collecting contiguous settled messages by the same
/// author. `system` rows are transparent (a coordination prompt between
/// chunks must not truncate an artifact). A `client` row BREAKS the run — a
/// client message starts a new turn, so a reopened session's later close
/// records only the later answer, never both. So does any row from a
/// DIFFERENT bot: that is the rule's accepted ceiling under interleaved
/// multi-bot chatter, fixed only by bot-declared spans (ADR 028 Decision 4).
/// Returns message ids oldest→newest; empty when the author has no settled
/// message. `messages` must be in store order (created_at ASC), as
/// `Store::messages` returns them.
fn settled_result_span(messages: &[Message], author: &str) -> Vec<String> {
    let is_author = |m: &Message| m.author_kind == "bot" && m.author_id.as_deref() == Some(author);
    let Some(last) = messages
        .iter()
        .rposition(|m| is_author(m) && is_settled_content(&m.content))
    else {
        return vec![];
    };
    let mut ids = vec![messages[last].id.clone()];
    for m in messages[..last].iter().rev() {
        if matches!(m.author_kind.as_str(), "system" | "status") {
            continue;
        }
        if !is_author(m) {
            break;
        }
        if is_settled_content(&m.content) {
            ids.push(m.id.clone());
        }
    }
    ids.reverse();
    ids
}

/// Execute the coordinator's actions. `Transition`/`Close` are CAS-guarded (fire
/// only from their `from` state); a `Prompt` right after a failed `Transition` is
/// suppressed, so the synthesizer is prompted exactly once — on the call that
/// actually enters the new state. The plane emits results and closes; it never
/// acts on the verdict (side-effects are the app's job — design: OCP doesn't own
/// PR logic).
fn run_actions(state: &Arc<AppState>, session: &Session, actions: Vec<Action>) -> Result<()> {
    let mut transition_failed = false;
    for action in actions {
        match action {
            Action::Relay { from, to } => {
                transition_failed = false;
                relay_settled(state, session, &from, &to)?;
            }
            Action::Prompt { to, content } => {
                if transition_failed {
                    continue; // its transition didn't happen — don't prompt
                }
                deliver_system_prompt(state, session, &to, &content)?;
            }
            Action::ReassignChair { to } => {
                // #344: hand the seat over. Membership first (delivery needs
                // it), then the chair column; the session stays in Quorum.
                transition_failed = false;
                let outgoing = session.chair_bot.clone();
                state.store.add_session_bot(&session.id, &to)?;
                state.store.set_session_chair(&session.id, &to)?;
                // The newcomer received none of the session's earlier fanout,
                // and the reviewers' relayed finals carry the findings but not
                // the AUTHORITY: repo, PR number, side-effect instructions all
                // live in the opening chair task (council F1 on the fix PR).
                // Hand the outgoing chair's task over verbatim — it is already
                // recipient-rewritten for the chair ROLE, so no re-derivation.
                let messages = state.store.messages(&session.id)?;
                let chair_task = messages
                    .iter()
                    .find(|m| {
                        m.author_kind == "client" && m.audience.as_deref() == outgoing.as_deref()
                    })
                    .or_else(|| {
                        messages
                            .iter()
                            .find(|m| m.author_kind == "client" && m.audience.is_none())
                    });
                if let Some(task) = chair_task {
                    deliver_system_prompt(state, session, &to, &task.content)?;
                }
                state.emit_north("chair_reassigned", &session.id, json!({ "chair": to }));
            }
            Action::ReplaceReviewerIfSpare { bot } => {
                transition_failed = false;
                replace_reviewer_if_spare(state, &session.id, &bot)?;
            }
            Action::Transition { from, to } => {
                let to_str = to.as_str();
                let ok = state.store.advance_state(&session.id, from, to)?;
                transition_failed = !ok;
                if ok {
                    state.emit_north("state", &session.id, json!({ "state": to_str }));
                }
            }
            Action::Close {
                from,
                author,
                verdict,
            } => {
                transition_failed = false;
                // ADR 013: the chair's structured verdict, parsed from the
                // closing text. Computed BEFORE the close CAS so it lands in
                // the same transaction (the close webhook re-reads the row).
                let roster = state.store.roster(&session.id)?;
                let cx = OrchCtx {
                    state,
                    session,
                    roster,
                };
                let structured_verdict = if let Some(coord) = coordinator::lookup(&session.mode) {
                    coord.structured_verdict(&cx, &verdict)
                } else {
                    None
                };
                // ADR 028: the settled result span that produced `verdict`,
                // also computed up front for the same atomic landing. Normal
                // close only; the timeout path never guesses a result.
                let messages = state.store.messages(&session.id)?;
                let span = settled_result_span(&messages, &author);
                let ids_json = (!span.is_empty())
                    .then(|| serde_json::to_string(&span).expect("Vec<String> serializes to JSON"));
                // The span bodies ride the terminal event (ADR 031:159) so an
                // external controller can parse verdict + findings from the
                // same text the kernel parses. Empty span → the closing text.
                let final_messages: Vec<String> = if span.is_empty() {
                    vec![verdict.clone()]
                } else {
                    messages
                        .iter()
                        .filter(|m| span.contains(&m.id))
                        .map(|m| m.content.clone())
                        .collect()
                };
                let reviewer_completion = coordinator::reviewer_completion(&cx, false);
                // One transaction: close CAS + verdict columns + result
                // identity. On error nothing landed — the session stays open
                // and the watchdog timeout path remains the termination
                // backstop; a normal close is never visible without its result.
                let closed = match state.store.close_session_with_result(
                    &session.id,
                    from,
                    structured_verdict.as_ref().map(|t| t.decision.as_str()),
                    structured_verdict.as_ref().and_then(|t| t.red),
                    structured_verdict.as_ref().and_then(|t| t.yellow),
                    structured_verdict.as_ref().and_then(|t| t.green),
                    ids_json.as_ref().map(|_| author.as_str()),
                    ids_json.as_deref(),
                    &final_messages,
                    reviewer_completion,
                ) {
                    Ok(won) => won,
                    Err(e) => {
                        tracing::warn!(
                            "atomic close for {} failed; session stays open for the watchdog: {e}",
                            session.id
                        );
                        return Err(e);
                    }
                };
                if closed {
                    purge_session_outbox_after_close(state, &session.id);
                    // The chair's findings block is no longer the kernel's to
                    // read: the ledger AND the ADR 035 waiver counters live on
                    // the controller, which parses its own join of the
                    // terminal event's final_messages (SEI-895).
                    state.emit_north(
                        "verdict",
                        &session.id,
                        json!({
                            "text": verdict.clone(),
                            "decision": structured_verdict.as_ref().map(|t| t.decision.clone()),
                            "findings_red": structured_verdict.as_ref().and_then(|t| t.red),
                            "findings_yellow": structured_verdict.as_ref().and_then(|t| t.yellow),
                            "findings_green": structured_verdict.as_ref().and_then(|t| t.green),
                        }),
                    );
                    state.emit_north("state", &session.id, json!({ "state": "closed" }));
                    fire_close_webhook(state, &session.id, &verdict, "normal");
                }
            }
        }
    }
    Ok(())
}

/// Deliver `from`'s settled final to `to`, in-thread (no mention needed — OAB
/// bypasses @mention gating inside a thread). Skips if `from` has no settled
/// message (streaming stubs were already filtered out by `latest_settled`).
fn relay_settled(state: &Arc<AppState>, session: &Session, from: &str, to: &str) -> Result<()> {
    let msgs = state.store.messages(&session.id)?;
    let Some(msg) = msgs
        .into_iter()
        .rfind(|m| m.author_id.as_deref() == Some(from) && is_settled_content(&m.content))
    else {
        return Ok(());
    };
    let bname = state.store.bot(from)?.map(|b| b.name).unwrap_or_default();
    let thread = state.store.thread_for_session(&session.id)?;
    state.deliver_event(
        to,
        &session.id,
        thread.as_deref(),
        bot_sender(from, &bname),
        Content::text(&msg.content),
        vec![],
        &msg.id,
    );
    Ok(())
}

/// Deliver a system message to `to` (e.g. the synthesizer prompt).
fn deliver_system_prompt(
    state: &Arc<AppState>,
    session: &Session,
    to: &str,
    content: &str,
) -> Result<()> {
    let to_name = state.store.bot(to)?.map(|b| b.name).unwrap_or_default();
    let thread = state.store.thread_for_session(&session.id)?;
    let msg = state.store.add_message(
        &session.id,
        thread.as_deref(),
        "system",
        None,
        Some(to),
        content,
        None,
    )?;
    state.deliver_event(
        to,
        &session.id,
        thread.as_deref(),
        SenderInfo {
            id: "system".into(),
            name: "system".into(),
            display_name: "system".into(),
            is_bot: false,
        },
        Content::text(content),
        vec![to_name],
        &msg.id,
    );
    state.emit_north(
        "message",
        &session.id,
        json!({ "message_id": msg.id, "author": "system", "content": content }),
    );
    Ok(())
}

fn on_edit(
    state: &Arc<AppState>,
    session: &Session,
    bot_id: &str,
    reply: &GatewayReply,
) -> Result<()> {
    if let Some(target) = target_msg(reply) {
        state.store.edit_message(target, &reply.content.text)?;
        state.emit_north(
            "message_edit",
            &session.id,
            json!({ "message_id": target, "content": reply.content.text }),
        );
        ack(state, bot_id, reply, None, Some(target));
        // Health-account the settled edit content (council F1): a streamed bot's
        // final turn lands here, so this is where a streamed error is counted and,
        // crucially, where a streamed content frame lets a degraded bot recover.
        account_bot_health(state, &session.id, bot_id, &reply.content.text);
        // A streamed recruit directive lands via edit_message when the final
        // content replaces the stub. The per-session seen set absorbs repeats.
        maybe_recruit(state, session, bot_id, &reply.content.text)?;
        // Same for a streamed `[[intent:…]]` (ADR 039); seen-set absorbs repeats.
        maybe_intent(state, session, bot_id, target, &reply.content.text)?;
        // a streamed done-signal arrives here (the stub had no `[done]` yet)
        check_text_done(state, session, bot_id, target, &reply.content.text)?;
    }
    Ok(())
}

// --- ack helpers (only when the reply carried a request_id, §2 streaming) ---

fn ack(
    state: &AppState,
    bot_id: &str,
    reply: &GatewayReply,
    thread_id: Option<&str>,
    message_id: Option<&str>,
) {
    let Some(req) = &reply.request_id else { return };
    let resp = GatewayResponse {
        schema: RESPONSE_SCHEMA.into(),
        request_id: req.clone(),
        success: true,
        thread_id: thread_id.map(String::from),
        message_id: message_id.map(String::from),
        error: None,
    };
    state.send_to_bot(bot_id, serde_json::to_string(&resp).unwrap());
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test fixtures: gateway reply builders, outbox frame readers, and a
    //! local close-webhook listener — used by orchestrator tests and the plugin
    //! test modules (same crate).
    use crate::protocol::{Content, GatewayReply, ReplyChannel};
    use crate::store::{SqliteStore, Store};
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    pub async fn spawn_close_webhook_listener(
    ) -> (String, mpsc::UnboundedReceiver<serde_json::Value>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let app = Router::new()
            .route("/", post(capture_close_webhook))
            .with_state(tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), rx)
    }

    pub async fn capture_close_webhook(
        State(tx): State<mpsc::UnboundedSender<serde_json::Value>>,
        body: Bytes,
    ) -> StatusCode {
        let value = serde_json::from_slice(&body).unwrap();
        tx.send(value).unwrap();
        StatusCode::NO_CONTENT
    }

    pub fn msg_reply(session: &str, text: &str) -> GatewayReply {
        GatewayReply {
            schema: String::new(),
            reply_to: String::new(),
            platform: String::new(),
            channel: ReplyChannel {
                id: session.into(),
                thread_id: None,
            },
            content: Content::text(text),
            command: None,
            request_id: None,
            quote_message_id: None,
        }
    }

    pub fn reaction_reply(session: &str, target: &str, emoji: &str) -> GatewayReply {
        GatewayReply {
            schema: String::new(),
            reply_to: target.into(),
            platform: String::new(),
            channel: ReplyChannel {
                id: session.into(),
                thread_id: None,
            },
            content: Content::text(emoji),
            command: Some("add_reaction".into()),
            request_id: None,
            quote_message_id: None,
        }
    }

    pub fn pending_frames_for_session(
        store: &SqliteStore,
        bot_id: &str,
        session_id: &str,
    ) -> usize {
        store
            .pending_outbox(bot_id)
            .unwrap()
            .into_iter()
            .filter(|(_, frame)| {
                serde_json::from_str::<serde_json::Value>(frame)
                    .ok()
                    .and_then(|v| v["channel"]["id"].as_str().map(str::to_string))
                    .as_deref()
                    == Some(session_id)
            })
            .count()
    }

    pub fn pending_frame_values(store: &SqliteStore, bot_id: &str) -> Vec<serde_json::Value> {
        store
            .pending_outbox(bot_id)
            .unwrap()
            .into_iter()
            .map(|(_, frame)| serde_json::from_str(&frame).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {

    /// Roster exhaustion edge (council red on the #349 sibling review):
    /// trimming the last reviewer must fail-close the session — never leave
    /// quorum_n = 0, where `0 >= 0` convenes the chair to synthesize from
    /// nothing.
    #[test]
    fn an_undelivering_last_reviewer_keeps_its_seat_instead_of_fail_closing() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                Some("controller:test:solo"),
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        // Blank-vote past exhaustion (no spare registered): re-requests, then
        // nothing. The seat must survive — a reviewer whose report is merely
        // late still holds the seat `quorum_n` needs, and removing it turned
        // nuphos#1231 round 1 into an `insufficient_valid_reviewers` fail-close
        // 9 minutes before the report actually arrived.
        for _ in 0..4 {
            handle_reply(&state, &rev.id, msg_reply(&session.id, "ok [done]")).unwrap();
        }
        let after = store.session(&session.id).unwrap().unwrap();
        assert_eq!(
            SessionState::from_db_str(&after.state),
            SessionState::Deliberating,
            "an undelivered report must not fail-close the round"
        );
        assert!(after.decision.is_none(), "no verdict is fabricated");
        assert!(
            store.roster(&session.id).unwrap().contains(&rev.id),
            "the reviewer keeps its seat so a late report can still close the round"
        );
        assert!(
            !store
                .messages(&session.id)
                .unwrap()
                .iter()
                .any(|m| m.author_kind == "system" && m.content.starts_with("Quorum reached.")),
            "the chair must never be convened without a delivered report"
        );
    }

    /// PR #348 regression: the chair rotation pool must exclude registered
    /// chair-role bots that have no live gateway connection — rotating to an
    /// absent bot strands the synthesis prompt in its outbox until the
    /// watchdog times the round out. This drives the REAL
    /// OrchCtx::chair_candidates() → AppState::is_connected() wiring (the
    /// coordinator tests hand-set their candidate lists and cannot catch it).
    #[test]
    fn chair_candidates_exclude_disconnected_pool_members() {
        use crate::coordinator::Ctx as _;
        let store = std::sync::Arc::new(crate::store::SqliteStore::open(":memory:").unwrap());
        let state = crate::state::AppState::new(store.clone());
        store
            .seed_bot("chair", "Chair", "chair", "h1", "t1")
            .unwrap();
        store
            .seed_bot("chair-claude", "Standby", "chair", "h2", "t2")
            .unwrap();
        store
            .seed_bot("rev-a", "Rev", "reviewer", "h3", "t3")
            .unwrap();
        let session = store
            .create_session("t", None, 1, Some("chair"), &["chair".into()], "council")
            .unwrap();
        let cx = OrchCtx {
            state: &state,
            session: &session,
            roster: vec!["chair".into()],
        };
        // Nobody connected: the pool is empty (requeue_synthesis then falls
        // back to re-prompting the failed chair rather than reassigning).
        assert!(cx.chair_candidates().is_empty());

        // Only the live chair counts; the registered-but-absent standby and
        // the reviewer never enter the pool.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let generation = state.register_conn("chair", tx);
        assert_eq!(cx.chair_candidates(), vec!["chair".to_string()]);

        // The standby joins the pool the moment it actually connects…
        let (tx2, _rx2) = tokio::sync::mpsc::unbounded_channel();
        let gen2 = state.register_conn("chair-claude", tx2);
        assert_eq!(
            cx.chair_candidates(),
            vec!["chair".to_string(), "chair-claude".to_string()]
        );

        // …and leaves it the moment it drops.
        state.unregister_conn("chair-claude", gen2);
        assert_eq!(cx.chair_candidates(), vec!["chair".to_string()]);
        state.unregister_conn("chair", generation);
        assert!(cx.chair_candidates().is_empty());
    }

    use super::test_support::*;
    use super::*;
    use crate::protocol::ReplyChannel;
    use crate::state::AppState;
    use crate::store::{SqliteStore, Store};
    use std::collections::HashMap;
    use tokio::sync::mpsc;

    static BACKFILL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn agent_error_frame_recognized_but_prose_is_not() {
        // The unambiguous JSON-RPC signal — both incident failure modes surfaced it.
        assert!(is_agent_error_frame(
            r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal Error"}}"#
        ));
        assert!(is_agent_error_frame("Internal error"));
        assert!(is_agent_error_frame("  -32603  "));
        // Not errors: real review prose (even mentioning the phrase in passing),
        // empty/stub frames.
        assert!(!is_agent_error_frame(""));
        assert!(!is_agent_error_frame("…"));
        assert!(!is_agent_error_frame(
            "LGTM. One nit: guard the internal error path so a downstream 500 \
             doesn't leak a stack trace to the client — otherwise this looks solid \
             and I'm approving once that's addressed. Nice test coverage overall."
        ));
        // Council F2: long review prose that DISCUSSES -32603 is not an error frame
        // — the code must be error-shaped (short, or carrying jsonrpc/`"code"`),
        // not merely present in a paragraph. Otherwise a reviewer false-degrades
        // and (with Phase 4) triggers a roster swap.
        assert!(!is_agent_error_frame(
            "On the reconnect path the agent can surface a JSON-RPC -32603 to the \
             gateway; we should classify that as an error frame rather than storing \
             it as review content, because right now it counts toward the reviewer \
             quorum and silently degrades the verdict to noise. Worth a follow-up."
        ));
        // ...but a genuine JSON-RPC error object still trips even if longer, via the
        // structural signal.
        assert!(is_agent_error_frame(
            "gateway wrapped agent failure: \
             {\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32603,\"message\":\
             \"Internal Error: upstream provider returned quota_exceeded for the \
             configured API key; the agent could not produce any model output\"}}"
        ));
    }

    #[test]
    fn streaming_stub_is_not_health_accounted() {
        assert!(is_streaming_stub(""));
        assert!(is_streaming_stub("  "));
        assert!(is_streaming_stub("…"));
        assert!(is_streaming_stub("..."));
        assert!(!is_streaming_stub("real content"));
    }

    /// Store-ordered message row for span tests (only the fields the rule reads).
    fn span_msg(id: &str, author_kind: &str, author_id: Option<&str>, content: &str) -> Message {
        Message {
            id: id.into(),
            session_id: "ses_1".into(),
            thread_id: None,
            author_kind: author_kind.into(),
            author_id: author_id.map(str::to_string),
            audience: None,
            content: content.into(),
            reply_to: None,
            created_at: 0,
        }
    }

    #[test]
    fn span_single_message_degrades_to_latest_settled() {
        let msgs = vec![
            span_msg("m1", "client", None, "question"),
            span_msg("m2", "bot", Some("a"), "answer"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m2"]);
    }

    #[test]
    fn span_collects_a_chunked_run_oldest_to_newest() {
        let msgs = vec![
            span_msg("m1", "client", None, "question"),
            span_msg("m2", "bot", Some("a"), "chunk 1"),
            span_msg("m3", "bot", Some("a"), "chunk 2"),
            span_msg("m4", "bot", Some("a"), "chunk 3"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m2", "m3", "m4"]);
    }

    #[test]
    fn span_breaks_at_an_intervening_foreign_bot_row() {
        let msgs = vec![
            span_msg("m1", "bot", Some("a"), "earlier turn"),
            span_msg("m2", "bot", Some("b"), "other bot"),
            span_msg("m3", "bot", Some("a"), "chunk 1"),
            span_msg("m4", "bot", Some("a"), "chunk 2"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m3", "m4"]);
    }

    #[test]
    fn span_skips_stubs_without_breaking_the_run() {
        let msgs = vec![
            span_msg("m1", "bot", Some("a"), "chunk 1"),
            span_msg("m2", "bot", Some("a"), "…"),
            span_msg("m3", "bot", Some("a"), "chunk 2"),
            // trailing stub: the walk starts from the last SETTLED message
            span_msg("m4", "bot", Some("a"), ""),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m1", "m3"]);
    }

    /// ASCII "..." is settled content — the span uses the SAME predicate as
    /// `latest_settled`, so the recorded result can never disagree with the
    /// verdict about which message settled.
    #[test]
    fn span_treats_ascii_ellipsis_as_settled_like_latest_settled() {
        let msgs = vec![
            span_msg("m1", "bot", Some("a"), "..."),
            span_msg("m2", "bot", Some("a"), "final"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m1", "m2"]);
        assert!(is_settled_content("..."));
        assert!(!is_settled_content("…"));
    }

    #[test]
    fn span_tolerates_system_interleave() {
        let msgs = vec![
            span_msg("m1", "bot", Some("a"), "chunk 1"),
            span_msg("m2", "system", None, "coordination prompt"),
            span_msg("m3", "bot", Some("a"), "chunk 2"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m1", "m3"]);
    }

    #[test]
    fn span_tolerates_controller_status_audit_interleave() {
        let msgs = vec![
            span_msg("m1", "bot", Some("a"), "chunk 1"),
            span_msg("m2", "status", None, "waiting for evidence"),
            span_msg("m3", "bot", Some("a"), "chunk 2"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m1", "m3"]);
    }

    /// A client row BREAKS the run: it starts a new turn. The forum-reopen
    /// shape (Q1, A1, follow-up, A2) must record only the second answer —
    /// never [A1, A2].
    #[test]
    fn span_breaks_at_a_client_row_forum_reopen_shape() {
        let msgs = vec![
            span_msg("m1", "client", None, "first question"),
            span_msg("m2", "bot", Some("a"), "first answer"),
            span_msg("m3", "client", None, "follow-up question"),
            span_msg("m4", "bot", Some("a"), "second answer"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m4"]);
    }

    /// The walk-back ANCHOR is the author's LAST settled message: a foreign
    /// bot row trailing after it must not shift or empty the span.
    #[test]
    fn span_anchor_survives_a_trailing_foreign_bot_row() {
        let msgs = vec![
            span_msg("m1", "bot", Some("a"), "chunk 1"),
            span_msg("m2", "bot", Some("a"), "chunk 2"),
            span_msg("m3", "bot", Some("b"), "late reviewer note"),
        ];
        assert_eq!(settled_result_span(&msgs, "a"), vec!["m1", "m2"]);
    }

    #[test]
    fn span_is_empty_without_a_settled_message() {
        assert!(settled_result_span(&[], "a").is_empty());
        let only_stubs = vec![
            span_msg("m1", "client", None, "question"),
            span_msg("m2", "bot", Some("a"), "…"),
        ];
        assert!(settled_result_span(&only_stubs, "a").is_empty());
    }

    #[test]
    fn health_threshold_env_override() {
        let _guard = BACKFILL_ENV_LOCK.lock().unwrap();
        std::env::remove_var("OABCP_HEALTH_ERROR_THRESHOLD");
        assert_eq!(health_error_threshold(), 3);
        std::env::set_var("OABCP_HEALTH_ERROR_THRESHOLD", "5");
        assert_eq!(health_error_threshold(), 5);
        // Junk / sub-1 values fall back to the default rather than disabling it.
        std::env::set_var("OABCP_HEALTH_ERROR_THRESHOLD", "0");
        assert_eq!(health_error_threshold(), 3);
        std::env::set_var("OABCP_HEALTH_ERROR_THRESHOLD", "nope");
        assert_eq!(health_error_threshold(), 3);
        std::env::remove_var("OABCP_HEALTH_ERROR_THRESHOLD");
    }

    #[test]
    fn close_webhook_payload_shape() {
        let mut s = test_session(Some("chair"), "council");
        s.trigger_ref = Some("github:pr/o/r#1".into());
        let roster = vec!["chair".to_string(), "rev1".to_string()];
        let p = close_webhook_payload(Some(&s), &s.id, &roster, "LGTM", "normal");
        assert_eq!(p["event"], "session.closed");
        assert_eq!(p["session_id"], "ses_1");
        assert_eq!(p["trigger_ref"], "github:pr/o/r#1");
        assert_eq!(p["mode"], "council");
        assert_eq!(p["verdict"], "LGTM");
        assert_eq!(p["reason"], "normal");
        assert_eq!(p["roster"], serde_json::json!(["chair", "rev1"]));
        assert!(p["ts"].as_i64().unwrap() > 0);
        // Session lookup failed → fields null, payload still well-formed.
        let p = close_webhook_payload(None, "ses_x", &[], "v", "timeout");
        assert!(p["trigger_ref"].is_null());
        assert!(p["mode"].is_null());
    }

    #[tokio::test]
    async fn persisted_unknown_mode_force_closes_without_quorum_dispatch() {
        let (webhook_url, mut webhook_rx) = spawn_close_webhook_listener().await;
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new_with_options(
            store.clone(),
            None,
            None,
            "http://control-plane.zeabur.internal:8090".to_string(),
            Some(webhook_url),
        );
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "legacy",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "bogus_mode",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        let trigger = store
            .add_message(&session.id, None, "client", None, None, "review this", None)
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "bot",
                Some(&rev.id),
                None,
                "reviewer finding",
                None,
            )
            .unwrap();
        let mut north = state.north_tx.subscribe();

        handle_reply(
            &state,
            &rev.id,
            reaction_reply(&session.id, &trigger.id, DONE_EMOJI),
        )
        .unwrap();

        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Closed,
        );
        assert_eq!(
            pending_frames_for_session(&store, &chair.id, &session.id),
            0
        );
        assert_eq!(pending_frames_for_session(&store, &rev.id, &session.id), 0);
        assert!(
            store
                .messages(&session.id)
                .unwrap()
                .iter()
                .all(|m| m.author_kind != "system"),
            "unknown mode must not deliver the quorum chair prompt",
        );

        let mut saw_dispatch_error = false;
        let mut saw_unknown_mode_close = false;
        let mut saw_quorum = false;
        while let Ok(raw) = north.try_recv() {
            let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
            match event["type"].as_str() {
                Some("dispatch_error") => {
                    saw_dispatch_error = true;
                    assert_eq!(event["payload"]["mode"], "bogus_mode");
                    assert_eq!(event["payload"]["reason"], "unknown_mode");
                }
                Some("state") if event["payload"]["state"] == "closed" => {
                    saw_unknown_mode_close = event["payload"]["reason"] == "unknown_mode";
                }
                Some("state") if event["payload"]["state"] == "quorum" => {
                    saw_quorum = true;
                }
                _ => {}
            }
        }
        assert!(saw_dispatch_error, "unknown mode must emit dispatch_error");
        assert!(
            saw_unknown_mode_close,
            "unknown mode close must surface reason"
        );
        assert!(!saw_quorum, "unknown mode must not silently adopt quorum");

        let payload = tokio::time::timeout(std::time::Duration::from_secs(5), webhook_rx.recv())
            .await
            .expect("timed out waiting for close webhook")
            .expect("close webhook listener stopped");
        assert_eq!(payload["reason"], "unknown_mode");
        assert_eq!(payload["mode"], "bogus_mode");
    }

    fn test_session(chair: Option<&str>, mode: &str) -> Session {
        Session {
            id: "ses_1".into(),
            title: "t".into(),
            state: "deliberating".into(),
            trigger_ref: None,
            trigger_fingerprint: None,
            quorum_n: 1,
            chair_bot: chair.map(str::to_string),
            created_at: 0,
            closed_at: None,
            mode: mode.into(),
            decision: None,
            findings_red: None,
            findings_yellow: None,
            findings_green: None,
            result_author_id: None,
            result_message_ids: None,
        }
    }

    fn edit_reply(session: &str, target: &str, text: &str) -> GatewayReply {
        GatewayReply {
            schema: String::new(),
            reply_to: target.into(),
            platform: String::new(),
            channel: ReplyChannel {
                id: session.into(),
                thread_id: None,
            },
            content: Content::text(text),
            command: Some("edit_message".into()),
            request_id: None,
            quote_message_id: None,
        }
    }

    fn create_topic_reply(session: &str, root_message: &str) -> GatewayReply {
        GatewayReply {
            schema: String::new(),
            reply_to: String::new(),
            platform: String::new(),
            channel: ReplyChannel {
                id: session.into(),
                thread_id: None,
            },
            content: Content::text(""),
            command: Some("create_topic".into()),
            request_id: None,
            quote_message_id: Some(root_message.into()),
        }
    }

    fn remove_reaction_reply(session: &str, target: &str, emoji: &str) -> GatewayReply {
        let mut reply = reaction_reply(session, target, emoji);
        reply.command = Some("remove_reaction".into());
        reply
    }

    type TestConns = HashMap<String, (u64, mpsc::UnboundedReceiver<String>)>;

    fn connect_bot(state: &Arc<AppState>, conns: &mut TestConns, bot_id: &str) {
        let (tx, rx) = mpsc::unbounded_channel();
        let gen = state.register_conn(bot_id, tx);
        conns.insert(bot_id.to_string(), (gen, rx));
    }

    fn disconnect_bot(
        state: &Arc<AppState>,
        store: &Arc<SqliteStore>,
        conns: &mut TestConns,
        bot_id: &str,
    ) {
        let (gen, _rx) = conns
            .remove(bot_id)
            .unwrap_or_else(|| panic!("{bot_id} was not connected"));
        assert!(state.unregister_conn(bot_id, gen));
        store.touch_last_seen(bot_id).unwrap();
    }

    /// chair + rev1 + rev2 (quorum 2, review_council), all connected, Deliberating.
    fn liveness_setup() -> (
        Arc<AppState>,
        Arc<SqliteStore>,
        crate::store::Session,
        String, // chair id
        String, // rev1 id
        String, // rev2 id
        TestConns,
    ) {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev1 = store.register_bot("rev1", "reviewer", "h2", "t2").unwrap();
        let rev2 = store.register_bot("rev2", "reviewer", "h3", "t3").unwrap();
        let mut conns = TestConns::new();
        for id in [&chair.id, &rev1.id, &rev2.id] {
            connect_bot(&state, &mut conns, id);
        }
        let session = store
            .create_session(
                "t",
                None,
                2,
                Some(&chair.id),
                &[chair.id.clone(), rev1.id.clone(), rev2.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        (state, store, session, chair.id, rev1.id, rev2.id, conns)
    }

    fn pending_message_frames(
        store: &SqliteStore,
        bot_id: &str,
        message_id: &str,
    ) -> Vec<serde_json::Value> {
        store
            .pending_outbox(bot_id)
            .unwrap()
            .into_iter()
            .filter_map(|(_, frame)| serde_json::from_str::<serde_json::Value>(&frame).ok())
            .filter(|v| v["message_id"] == message_id)
            .collect()
    }

    fn pending_text_frames(
        store: &SqliteStore,
        bot_id: &str,
        text: &str,
    ) -> Vec<serde_json::Value> {
        store
            .pending_outbox(bot_id)
            .unwrap()
            .into_iter()
            .filter_map(|(_, frame)| serde_json::from_str::<serde_json::Value>(&frame).ok())
            .filter(|v| v["content"]["text"].as_str() == Some(text))
            .collect()
    }

    #[test]
    fn service_busy_neither_degrades_nor_recovers_provider_health() {
        let (state, store, session, chair, _rev1, _rev2, _conns) = liveness_setup();
        let busy = "⚠️ Service Busy All agent sessions are in use, please try again shortly.";
        for _ in 0..5 {
            handle_reply(&state, &chair, msg_reply(&session.id, busy)).unwrap();
        }
        assert_eq!(store.bot_inventory(&chair).unwrap().unwrap().health, "ok");
        store.record_bot_frame(&chair, true, 1).unwrap();
        handle_reply(&state, &chair, msg_reply(&session.id, busy)).unwrap();
        assert_eq!(
            store.bot_inventory(&chair).unwrap().unwrap().health,
            "degraded"
        );
    }

    #[test]
    fn error_frames_through_handle_reply_degrade_then_recover_the_bot() {
        // End-to-end wiring (ADR 023 Phase 1): a bot posting `-32603` error frames
        // via the real reply path crosses to `degraded`, and a later content frame
        // recovers it — proving `on_send` actually drives health, not just the store.
        let (state, store, session, chair, _rev1, _rev2, _conns) = liveness_setup();
        let health = |s: &SqliteStore| s.bot_inventory(&chair).unwrap().unwrap().health;
        let err = r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal Error"}}"#;

        handle_reply(&state, &chair, msg_reply(&session.id, err)).unwrap();
        handle_reply(&state, &chair, msg_reply(&session.id, err)).unwrap();
        assert_eq!(health(&store), "ok"); // 2 < threshold 3
        handle_reply(&state, &chair, msg_reply(&session.id, err)).unwrap();
        assert_eq!(health(&store), "degraded"); // 3rd crosses

        // A real content frame is observed recovery.
        handle_reply(
            &state,
            &chair,
            msg_reply(&session.id, "Looks correct; approving."),
        )
        .unwrap();
        assert_eq!(health(&store), "ok");
    }

    #[test]
    fn streamed_content_via_on_edit_recovers_a_degraded_bot() {
        // Council F1: streamed bots (kiro/codex) deliver their final content via
        // `edit_message`, not `on_send`. Before the fix a degraded streamed bot
        // could never recover because `on_edit` didn't health-account. This proves
        // the settled edit content now drives recovery.
        let (state, store, session, chair, _rev1, _rev2, _conns) = liveness_setup();
        let health = |s: &SqliteStore| s.bot_inventory(&chair).unwrap().unwrap().health;
        let err = r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal Error"}}"#;

        for _ in 0..3 {
            handle_reply(&state, &chair, msg_reply(&session.id, err)).unwrap();
        }
        assert_eq!(health(&store), "degraded");

        // The bot streams its next turn: a "…" stub (skipped), then the settled
        // content lands via edit_message.
        handle_reply(&state, &chair, msg_reply(&session.id, "…")).unwrap();
        assert_eq!(health(&store), "degraded", "the stub must not recover");
        let stub = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .rfind(|m| m.author_id.as_deref() == Some(chair.as_str()))
            .unwrap();
        handle_reply(
            &state,
            &chair,
            edit_reply(&session.id, &stub.id, "Reviewed the diff — looks correct."),
        )
        .unwrap();
        assert_eq!(
            health(&store),
            "ok",
            "settled edit content recovers the bot"
        );
    }

    fn set_provider(store: &SqliteStore, id: &str, provider: &str) {
        store
            .update_bot_metadata(
                id,
                &crate::store::BotMetadataPatch {
                    provider: Some(Some(provider.to_string())),
                    ..Default::default()
                },
            )
            .unwrap();
    }

    #[test]
    fn chair_degraded_auto_failover_promotes_standby() {
        // Phase 4 end-to-end: the chair crossing to `degraded` promotes a healthy,
        // connected, off-roster standby chair into the standing roster's slot 0.
        let _g = BACKFILL_ENV_LOCK.lock().unwrap();
        std::env::set_var("OABCP_AUTO_FAILOVER", "1");
        let (state, store, session, chair, rev1, rev2, mut conns) = liveness_setup();
        store
            .set_standing_roster(&[chair.clone(), rev1.clone(), rev2.clone()])
            .unwrap();
        let standby = store.register_bot("chair2", "chair", "h9", "t9").unwrap();
        connect_bot(&state, &mut conns, &standby.id);

        let err = r#"{"code":-32603,"message":"Internal Error"}"#;
        for _ in 0..3 {
            handle_reply(&state, &chair, msg_reply(&session.id, err)).unwrap();
        }

        let (roster, source) = crate::plugins::council::runtime_council_roster(&state).unwrap();
        assert_eq!(source, "override");
        assert_eq!(
            roster.first().unwrap(),
            &standby.id,
            "healthy standby promoted into the chair slot"
        );
        assert!(!roster.contains(&chair), "degraded chair routed out");
        std::env::remove_var("OABCP_AUTO_FAILOVER");
    }

    #[test]
    fn sequential_failovers_compose_without_clobbering() {
        // Council F7: each swap must build on the previous roster, not a stale
        // snapshot. Degrade two different reviewers in turn; the second swap must
        // see the first's result, so the final roster carries BOTH standbys and
        // neither degraded bot. (The failover_lock makes this hold under
        // concurrency too; here we prove the re-read-and-compose behavior.)
        let _g = BACKFILL_ENV_LOCK.lock().unwrap();
        std::env::set_var("OABCP_AUTO_FAILOVER", "1");
        let (state, store, session, chair, rev1, rev2, mut conns) = liveness_setup();
        store
            .set_standing_roster(&[chair.clone(), rev1.clone(), rev2.clone()])
            .unwrap();
        let sb1 = store.register_bot("rev1b", "reviewer", "h8", "t8").unwrap();
        let sb2 = store.register_bot("rev2b", "reviewer", "h9", "t9").unwrap();
        connect_bot(&state, &mut conns, &sb1.id);
        connect_bot(&state, &mut conns, &sb2.id);

        let err = "-32603";
        for _ in 0..3 {
            handle_reply(&state, &rev1, msg_reply(&session.id, err)).unwrap();
        }
        for _ in 0..3 {
            handle_reply(&state, &rev2, msg_reply(&session.id, err)).unwrap();
        }

        let (roster, _) = crate::plugins::council::runtime_council_roster(&state).unwrap();
        assert_eq!(roster.first().unwrap(), &chair, "chair untouched");
        assert!(
            roster.contains(&sb1.id) && roster.contains(&sb2.id),
            "both swaps kept"
        );
        assert!(
            !roster.contains(&rev1) && !roster.contains(&rev2),
            "neither degraded reviewer left in-roster"
        );
        std::env::remove_var("OABCP_AUTO_FAILOVER");
    }

    #[test]
    fn chair_degraded_with_no_standby_is_alert_only() {
        let _g = BACKFILL_ENV_LOCK.lock().unwrap();
        std::env::set_var("OABCP_AUTO_FAILOVER", "1");
        let (state, store, session, chair, rev1, rev2, _conns) = liveness_setup();
        store
            .set_standing_roster(&[chair.clone(), rev1.clone(), rev2.clone()])
            .unwrap();

        for _ in 0..3 {
            handle_reply(&state, &chair, msg_reply(&session.id, "-32603")).unwrap();
        }

        let (roster, _) = crate::plugins::council::runtime_council_roster(&state).unwrap();
        assert_eq!(roster.first().unwrap(), &chair, "no standby → chair stays");
        assert_eq!(
            store.bot_inventory(&chair).unwrap().unwrap().health,
            "degraded"
        );
        std::env::remove_var("OABCP_AUTO_FAILOVER");
    }

    #[test]
    fn auto_failover_disabled_keeps_roster_even_with_standby() {
        let _g = BACKFILL_ENV_LOCK.lock().unwrap();
        std::env::remove_var("OABCP_AUTO_FAILOVER"); // default off
        let (state, store, session, chair, rev1, rev2, mut conns) = liveness_setup();
        store
            .set_standing_roster(&[chair.clone(), rev1.clone(), rev2.clone()])
            .unwrap();
        let standby = store.register_bot("chair2", "chair", "h9", "t9").unwrap();
        connect_bot(&state, &mut conns, &standby.id);

        for _ in 0..3 {
            handle_reply(&state, &chair, msg_reply(&session.id, "-32603")).unwrap();
        }

        let (roster, _) = crate::plugins::council::runtime_council_roster(&state).unwrap();
        assert_eq!(roster.first().unwrap(), &chair, "disabled → no auto-swap");
        assert!(!roster.contains(&standby.id));
    }

    #[test]
    fn standby_selection_prefers_different_provider_then_falls_back() {
        let (state, store, _session, chair, rev1, rev2, mut conns) = liveness_setup();
        let roster = vec![chair, rev1, rev2];
        let same = store
            .register_bot("chair-kiro2", "chair", "h8", "t8")
            .unwrap();
        let diff = store
            .register_bot("chair-claude", "chair", "h9", "t9")
            .unwrap();
        connect_bot(&state, &mut conns, &same.id);
        connect_bot(&state, &mut conns, &diff.id);
        set_provider(&store, &same.id, "kiro");
        set_provider(&store, &diff.id, "claude");

        // Degraded provider is kiro → the cross-provider (claude) standby wins.
        assert_eq!(
            pick_healthy_standby(&state, "chair", Some("kiro"), &roster).as_deref(),
            Some(diff.id.as_str())
        );
        // Degrade the cross-provider standby → fall back to the same-provider one
        // rather than leaving the role empty.
        store.record_bot_frame(&diff.id, true, 1).unwrap();
        assert_eq!(
            pick_healthy_standby(&state, "chair", Some("kiro"), &roster).as_deref(),
            Some(same.id.as_str())
        );
        // Degrade that too → no promotable standby remains.
        store.record_bot_frame(&same.id, true, 1).unwrap();
        assert_eq!(
            pick_healthy_standby(&state, "chair", Some("kiro"), &roster),
            None
        );
    }

    #[test]
    fn bot_send_is_stored_and_emitted_north_but_never_fanned() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev1 = store.register_bot("rev1", "reviewer", "h2", "t2").unwrap();
        let rev2 = store.register_bot("rev2", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                2,
                Some(&chair.id),
                &[chair.id.clone(), rev1.id.clone(), rev2.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        let mut north = state.north_tx.subscribe();

        handle_reply(&state, &rev1.id, msg_reply(&session.id, "review body")).unwrap();

        let msg = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .find(|m| {
                m.author_id.as_deref() == Some(rev1.id.as_str()) && m.content == "review body"
            })
            .expect("bot send should be stored");
        assert!(
            pending_message_frames(&store, &chair.id, &msg.id).is_empty(),
            "chair must not receive implicit bot-message fanout"
        );
        assert!(
            pending_message_frames(&store, &rev2.id, &msg.id).is_empty(),
            "peer reviewer must not receive implicit bot-message fanout"
        );

        let raw = north.try_recv().expect("north message event");
        let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(event["type"], "message");
        assert_eq!(event["payload"]["message_id"], msg.id);
        assert_eq!(event["payload"]["content"], "review body");
    }

    #[test]
    fn session_reset_placeholder_reaches_no_peer() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev1 = store.register_bot("rev1", "reviewer", "h2", "t2").unwrap();
        let rev2 = store.register_bot("rev2", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                2,
                Some(&chair.id),
                &[chair.id.clone(), rev1.id.clone(), rev2.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        let placeholder = "⚠️ _Session expired, starting fresh..._\n\n…";

        handle_reply(&state, &rev1.id, msg_reply(&session.id, placeholder)).unwrap();

        let msg = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .find(|m| m.author_id.as_deref() == Some(rev1.id.as_str()) && m.content == placeholder)
            .expect("placeholder should still be stored");
        assert!(pending_message_frames(&store, &chair.id, &msg.id).is_empty());
        assert!(pending_message_frames(&store, &rev2.id, &msg.id).is_empty());
    }

    #[test]
    fn reviewer_done_relays_settled_final_to_chair_once() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();

        handle_reply(
            &state,
            &rev.id,
            msg_reply(&session.id, "reviewer settled final [done]"),
        )
        .unwrap();

        let msg = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .find(|m| m.author_id.as_deref() == Some(rev.id.as_str()))
            .unwrap();
        let relayed = pending_message_frames(&store, &chair.id, &msg.id);
        assert_eq!(relayed.len(), 1);
        assert_eq!(
            relayed[0]["content"]["text"],
            "reviewer settled final [done]"
        );
    }

    #[test]
    fn pipeline_stage_done_relays_output_and_prompt_to_next_stage() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let s0 = store.register_bot("s0", "reviewer", "h0", "t0").unwrap();
        let s1 = store.register_bot("s1", "reviewer", "h1", "t1").unwrap();
        let s2 = store.register_bot("s2", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                0,
                None,
                &[s0.id.clone(), s1.id.clone(), s2.id.clone()],
                "pipeline",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();

        handle_reply(
            &state,
            &s0.id,
            msg_reply(&session.id, "stage 0 output [done]"),
        )
        .unwrap();

        let msg = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .find(|m| m.author_id.as_deref() == Some(s0.id.as_str()))
            .unwrap();
        let output_to_s1 = pending_message_frames(&store, &s1.id, &msg.id);
        assert_eq!(output_to_s1.len(), 1);
        assert_eq!(output_to_s1[0]["content"]["text"], "stage 0 output [done]");
        assert!(
            !pending_text_frames(
                &store,
                &s1.id,
                "Your turn — continue the review, building on the prior stage's output above.",
            )
            .is_empty(),
            "next stage should also receive the handoff prompt"
        );
        assert!(
            pending_message_frames(&store, &s2.id, &msg.id).is_empty(),
            "later pipeline stages must not receive implicit bot-message fanout"
        );
    }

    #[test]
    fn liveness_trims_dead_reviewer_shrinks_quorum_and_reevaluates() {
        let (state, store, session, _chair, rev1, rev2, mut conns) = liveness_setup();
        // rev1 votes; quorum 2 not reached → still deliberating
        handle_reply(
            &state,
            &rev1,
            msg_reply(
                &session.id,
                "Findings: the changed path is covered and has no blocking issue. [[review:complete]] [done]",
            ),
        )
        .unwrap();
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Deliberating,
        );
        // rev2 dies (no spare registered)
        disconnect_bot(&state, &store, &mut conns, &rev2);
        sweep_liveness(&state, 0).unwrap();

        let roster = store.roster(&session.id).unwrap();
        assert!(!roster.contains(&rev2), "dead reviewer must be trimmed");
        let s = store.session(&session.id).unwrap().unwrap();
        assert_eq!(s.quorum_n, 1, "quorum must shrink to surviving reviewers");
        assert_eq!(
            SessionState::from_db_str(&s.state),
            SessionState::Quorum,
            "trim must re-evaluate quorum and prompt the chair",
        );
        assert_eq!(
            store.bot_inventory(&rev2).unwrap().unwrap().health,
            "unreachable",
        );
    }

    #[test]
    fn controller_review_never_shrinks_its_required_reviewer_minimum() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev1 = store.register_bot("rev1", "reviewer", "h2", "t2").unwrap();
        let rev2 = store.register_bot("rev2", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "controller review",
                Some("controller:github-prod:test"),
                2,
                Some(&chair.id),
                &[chair.id.clone(), rev1.id.clone(), rev2.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();

        // `"unreachable"` is the only reason that still reaches this path: the
        // report-delivery caller keeps the seat instead of trimming, so a
        // controller review can now only fall below its minimum by losing a bot.
        trim_reviewer_body(&state, &session.id, &rev2.id, "unreachable").unwrap();

        let current = store.session(&session.id).unwrap().unwrap();
        assert_eq!(current.quorum_n, 2, "the opening minimum is immutable");
        assert_eq!(
            SessionState::from_db_str(&current.state),
            SessionState::Closed,
            "falling below the minimum must fail closed"
        );
        assert!(current.decision.is_none());
        assert_eq!(store.roster(&session.id).unwrap(), vec![chair.id, rev1.id]);
    }

    #[test]
    fn production_subscription_failure_never_counts_as_report_or_quorum() {
        let frame = include_str!("../tests/fixtures/claude-subscription-disabled.txt").trim_end();
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev_claude = store
            .register_bot("rev-claude", "reviewer", "h2", "t2")
            .unwrap();
        let rev_codex = store
            .register_bot("rev-codex", "reviewer", "h3", "t3")
            .unwrap();
        let session = store
            .create_session(
                "controller review",
                Some("controller:github-prod:subscription-disabled"),
                2,
                Some(&chair.id),
                &[
                    chair.id.clone(),
                    rev_claude.id.clone(),
                    rev_codex.id.clone(),
                ],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        let opening = post_client_message(&state, &session.id, "review this change").unwrap();

        for attempt in 0..3 {
            handle_reply(&state, &rev_claude.id, msg_reply(&session.id, frame)).unwrap();
            handle_reply(
                &state,
                &rev_claude.id,
                reaction_reply(&session.id, &opening.id, DONE_EMOJI),
            )
            .unwrap();

            let current = store.session(&session.id).unwrap().unwrap();
            if attempt < 2 {
                assert_eq!(
                    SessionState::from_db_str(&current.state),
                    SessionState::Deliberating,
                    "an error reaction is not reviewer quorum"
                );
            }
        }

        let current = store.session(&session.id).unwrap().unwrap();
        assert_eq!(current.quorum_n, 2, "the reviewer minimum is immutable");
        // The seat is not taken away, so the round stays open and the watchdog
        // is the backstop. What matters is that the failed frame buys nothing:
        // no quorum, no verdict, and nothing relayed to the chair.
        assert_eq!(
            SessionState::from_db_str(&current.state),
            SessionState::Deliberating
        );
        assert!(current.decision.is_none(), "no verdict may be fabricated");
        assert!(
            store.roster(&session.id).unwrap().contains(&rev_claude.id),
            "a failing reviewer keeps its seat; quorum simply stays unmet"
        );
        assert!(
            store
                .messages(&session.id)
                .unwrap()
                .iter()
                .all(|message| message.audience.as_deref() != Some(chair.id.as_str())),
            "the failed frame must never be relayed as a reviewer report"
        );
    }

    #[test]
    fn connected_blank_reviewer_retries_then_keeps_its_seat_through_real_store() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let reviewer = store
            .register_bot("reviewer", "reviewer", "h2", "t2")
            .unwrap();
        let session = store
            .create_session(
                "controller round",
                Some("controller:test:blank-report"),
                1,
                Some(&chair.id),
                &[chair.id.clone(), reviewer.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        state.register_conn(&reviewer.id, tx);
        for _ in 0..3 {
            handle_reply(&state, &reviewer.id, msg_reply(&session.id, "PONG [done]")).unwrap();
        }

        let roster = store.roster(&session.id).unwrap();
        assert_eq!(
            roster,
            vec![chair.id.clone(), reviewer.id.clone()],
            "the seat survives an exhausted retry budget"
        );
        let current = store.session(&session.id).unwrap().unwrap();
        // The round stays open instead of fail-closing. Quorum is still
        // unreachable — `counted_done_voters` refuses a reviewer without a
        // delivered report, so the chair is not convened against nothing
        // (council red on the #349 sibling review) — but a late report can
        // still arrive and close the round, and the watchdog is the backstop.
        assert_eq!(
            SessionState::from_db_str(&current.state),
            SessionState::Deliberating,
            "an exhausted retry budget must not fail-close the session"
        );
        assert!(current.decision.is_none(), "no verdict is fabricated");
        let messages = store.messages(&session.id).unwrap();
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    message.author_kind == "system"
                        && message.audience.as_deref() == Some(reviewer.id.as_str())
                        && message
                            .content
                            .starts_with(crate::coordinator::REVIEWER_REREQUEST_PREFIX)
                })
                .count(),
            2,
            "the retry budget is per reviewer and transcript-backed",
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    message.author_kind == "system"
                        && message.audience.as_deref() == Some(chair.id.as_str())
                        && message.content.starts_with("Quorum reached.")
                })
                .count(),
            0,
            "the chair must never be convened without a delivered report",
        );
    }

    #[test]
    fn echo_then_real_report_reaches_quorum_via_handle_reply() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let reviewer = store
            .register_bot("reviewer", "reviewer", "h2", "t2")
            .unwrap();
        let session = store
            .create_session(
                "review round",
                Some("controller:pr/example/repo#349"),
                1,
                Some(&chair.id),
                &[chair.id.clone(), reviewer.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();

        handle_reply(&state, &reviewer.id, msg_reply(&session.id, "PONG [done]")).unwrap();
        let after_echo = store.session(&session.id).unwrap().unwrap();
        assert_eq!(
            SessionState::from_db_str(&after_echo.state),
            SessionState::Deliberating
        );
        assert_eq!(
            store
                .messages(&session.id)
                .unwrap()
                .iter()
                .filter(|message| {
                    message.author_kind == "system"
                        && message.audience.as_deref() == Some(reviewer.id.as_str())
                        && message
                            .content
                            .starts_with(crate::coordinator::REVIEWER_REREQUEST_PREFIX)
                })
                .count(),
            1
        );

        handle_reply(
            &state,
            &reviewer.id,
            msg_reply(
                &session.id,
                "Finding: the retry path loses the request id; preserve it before dispatch. [[review:complete]] [done]",
            ),
        )
        .unwrap();
        let after_report = store.session(&session.id).unwrap().unwrap();
        assert_eq!(
            SessionState::from_db_str(&after_report.state),
            SessionState::Quorum
        );
        assert_eq!(store.done_voters(&session.id).unwrap(), vec![reviewer.id]);
        assert!(
            store.messages(&session.id).unwrap().iter().any(|message| {
                message.author_kind == "system"
                    && message.audience.as_deref() == Some(chair.id.as_str())
                    && message.content.starts_with("Quorum reached.")
            }),
            "a valid replacement report must proceed to the chair"
        );
    }

    #[test]
    fn exhausted_blank_reviewer_prefers_a_connected_spare() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let reviewer = store
            .register_bot("reviewer", "reviewer", "h2", "t2")
            .unwrap();
        let spare = store.register_bot("spare", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "review round",
                Some("controller:test:spare"),
                1,
                Some(&chair.id),
                &[chair.id.clone(), reviewer.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        state.register_conn(&spare.id, tx);
        for _ in 0..3 {
            handle_reply(&state, &reviewer.id, msg_reply(&session.id, "PONG [done]")).unwrap();
        }

        let roster = store.roster(&session.id).unwrap();
        assert!(roster.contains(&spare.id));
        assert!(!roster.contains(&reviewer.id));
        assert_eq!(roster.len(), 2, "replacement preserves reviewer capacity");
        let current = store.session(&session.id).unwrap().unwrap();
        assert_eq!(current.quorum_n, 1);
        assert_eq!(
            SessionState::from_db_str(&current.state),
            SessionState::Deliberating
        );
    }

    #[test]
    fn peer_ack_reaction_does_not_advance_quorum() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev1 = store.register_bot("rev1", "reviewer", "h2", "t2").unwrap();
        let rev2 = store.register_bot("rev2", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                2,
                Some(&chair.id),
                &[chair.id.clone(), rev1.id.clone(), rev2.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        let trigger = store
            .add_message(&session.id, None, "client", None, None, "review this", None)
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "bot",
                Some(&rev1.id),
                None,
                "Findings from reviewer one: the peer path is safe and covered. [done]",
                None,
            )
            .unwrap();
        let rev2_msg = store
            .add_message(
                &session.id,
                None,
                "bot",
                Some(&rev2.id),
                None,
                "Findings from reviewer two: the peer path is safe and covered. [done]",
                None,
            )
            .unwrap();

        handle_reply(
            &state,
            &rev1.id,
            reaction_reply(&session.id, &rev2_msg.id, DONE_EMOJI),
        )
        .unwrap();
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Deliberating,
        );
        assert!(
            store.pending_outbox(&chair.id).unwrap().is_empty(),
            "peer ack must not relay a reviewer's settled message to the chair",
        );
        assert!(store.done_voters(&session.id).unwrap().is_empty());

        handle_reply(
            &state,
            &rev1.id,
            reaction_reply(&session.id, &trigger.id, DONE_EMOJI),
        )
        .unwrap();
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Deliberating,
        );
        handle_reply(
            &state,
            &rev2.id,
            reaction_reply(&session.id, &trigger.id, DONE_EMOJI),
        )
        .unwrap();
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Quorum,
        );
    }

    #[test]
    fn done_vote_is_monotonic_under_remove_reaction() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        let trigger = store
            .add_message(&session.id, None, "client", None, None, "review this", None)
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "bot",
                Some(&rev.id),
                None,
                "Findings: the requested path is covered and safe. [done]",
                None,
            )
            .unwrap();

        handle_reply(
            &state,
            &rev.id,
            reaction_reply(&session.id, &trigger.id, DONE_EMOJI),
        )
        .unwrap();
        assert_eq!(
            store.done_voters(&session.id).unwrap(),
            vec![rev.id.clone()]
        );
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Quorum,
        );

        handle_reply(
            &state,
            &rev.id,
            remove_reaction_reply(&session.id, &trigger.id, DONE_EMOJI),
        )
        .unwrap();
        assert_eq!(
            store.done_voters(&session.id).unwrap(),
            vec![rev.id.clone()]
        );
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Quorum,
        );
    }

    #[test]
    fn unresolvable_reaction_target_is_rejected() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let rev = store.register_bot("rev", "reviewer", "h1", "t1").unwrap();
        let session = store
            .create_session("t", None, 1, None, std::slice::from_ref(&rev.id), "council")
            .unwrap();
        let other_session = store
            .create_session("other", None, 1, None, &[], "council")
            .unwrap();
        let other_msg = store
            .add_message(
                &other_session.id,
                None,
                "client",
                None,
                None,
                "other trigger",
                None,
            )
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        state.register_conn(&rev.id, tx);
        let mut north = state.north_tx.subscribe();

        for (request_id, target) in [
            ("empty-target", ""),
            ("unknown-target", "msg_missing"),
            ("other-session-target", other_msg.id.as_str()),
        ] {
            let mut reply = reaction_reply(&session.id, target, DONE_EMOJI);
            reply.request_id = Some(request_id.to_string());
            handle_reply(&state, &rev.id, reply).unwrap();

            let raw = rx.try_recv().unwrap();
            let ack: GatewayResponse = serde_json::from_str(&raw).unwrap();
            assert!(ack.success);
            assert_eq!(ack.request_id, request_id);

            let raw = north.try_recv().unwrap();
            let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(event["type"], "reaction_rejected");
            assert_eq!(event["payload"]["bot"], rev.id);
            assert_eq!(event["payload"]["emoji"], DONE_EMOJI);
            assert_eq!(event["payload"]["reason"], "unresolvable_target");
        }
        assert!(store.reactions(&session.id).unwrap().is_empty());
        assert!(store.reactions(&other_session.id).unwrap().is_empty());
    }

    #[test]
    fn liveness_replaces_dead_reviewer_when_spare_exists() {
        let (state, store, session, _chair, _rev1, rev2, mut conns) = liveness_setup();
        let rev3 = store.register_bot("rev3", "reviewer", "h4", "t4").unwrap();
        connect_bot(&state, &mut conns, &rev3.id);

        disconnect_bot(&state, &store, &mut conns, &rev2);
        sweep_liveness(&state, 0).unwrap();

        let roster = store.roster(&session.id).unwrap();
        assert!(!roster.contains(&rev2));
        assert!(roster.contains(&rev3.id), "spare must take the dead seat");
        let s = store.session(&session.id).unwrap().unwrap();
        assert_eq!(s.quorum_n, 2, "replacement keeps the quorum intact");
        assert_eq!(
            SessionState::from_db_str(&s.state),
            SessionState::Deliberating,
        );
    }

    #[test]
    fn liveness_replace_rechecks_connection_before_acting() {
        let (state, store, session, chair, rev1, rev2, mut conns) = liveness_setup();
        let rev3 = store.register_bot("rev3", "reviewer", "h4", "t4").unwrap();
        connect_bot(&state, &mut conns, &rev3.id);
        disconnect_bot(&state, &store, &mut conns, &rev2);
        let inv = store.bot_inventory(&rev2).unwrap().unwrap();
        connect_bot(&state, &mut conns, &rev2);
        let mut north = state.north_tx.subscribe();

        assert!(
            replace_unreachable(&state, &session.id, &inv, false).unwrap(),
            "a reconnect race is handled by keeping the original roster seat",
        );

        let roster = store.roster(&session.id).unwrap();
        assert!(roster.contains(&chair));
        assert!(roster.contains(&rev1));
        assert!(roster.contains(&rev2), "reconnected bot keeps its seat");
        assert!(
            !roster.contains(&rev3.id),
            "spare must not replace a reconnected bot",
        );
        assert_eq!(
            store.bot_inventory(&rev2).unwrap().unwrap().health,
            "ok",
            "reconnected bot must not be marked unreachable",
        );
        assert!(
            north.try_recv().is_err(),
            "no roster_replace or bot_health event should be emitted",
        );
    }

    #[test]
    fn liveness_leaves_done_reviewer_and_live_bots_alone() {
        let (state, store, session, _chair, rev1, rev2, mut conns) = liveness_setup();
        // rev1 votes then dies — its vote is recorded, leave the seat alone
        handle_reply(&state, &rev1, msg_reply(&session.id, "findings [done]")).unwrap();
        disconnect_bot(&state, &store, &mut conns, &rev1);
        sweep_liveness(&state, 0).unwrap();

        let roster = store.roster(&session.id).unwrap();
        assert!(roster.contains(&rev1), "voted reviewer must not be trimmed");
        assert!(
            roster.contains(&rev2),
            "connected reviewer must not be trimmed"
        );
        assert_eq!(store.session(&session.id).unwrap().unwrap().quorum_n, 2);
    }

    #[test]
    fn liveness_trim_rechecks_connection_before_dropping() {
        let (state, store, session, _chair, _rev1, rev2, _conns) = liveness_setup();
        // rev2 is connected again by the time the trim runs (check→trim race)
        trim_reviewer(&state, &session.id, &rev2).unwrap();
        assert!(
            store.roster(&session.id).unwrap().contains(&rev2),
            "a reconnected bot must keep its seat",
        );
        assert_eq!(store.session(&session.id).unwrap().unwrap().quorum_n, 2);
    }

    #[test]
    fn liveness_respects_grace_window() {
        let (state, store, session, _chair, _rev1, rev2, mut conns) = liveness_setup();
        disconnect_bot(&state, &store, &mut conns, &rev2); // last_seen = now
        sweep_liveness(&state, 60_000).unwrap();
        assert!(
            store.roster(&session.id).unwrap().contains(&rev2),
            "a bot inside the grace window must not be touched",
        );
    }

    #[test]
    fn relay_settled_twice_delivers_logical_message_once() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let from = store.register_bot("from", "reviewer", "h1", "t1").unwrap();
        let to = store.register_bot("to", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                None,
                &[from.id.clone(), to.id.clone()],
                "council",
            )
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "bot",
                Some(&from.id),
                None,
                "settled final [done]",
                None,
            )
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        state.register_conn(&to.id, tx);

        relay_settled(&state, &session, &from.id, &to.id).unwrap();
        relay_settled(&state, &session, &from.id, &to.id).unwrap();

        let frames: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("settled final"));
    }

    #[test]
    fn liveness_replaces_dead_chair_with_chair_capable_spare() {
        let (state, store, session, chair, _rev1, _rev2, mut conns) = liveness_setup();
        let chair2 = store.register_bot("chair2", "chair", "h5", "t5").unwrap();
        connect_bot(&state, &mut conns, &chair2.id);

        disconnect_bot(&state, &store, &mut conns, &chair);
        sweep_liveness(&state, 0).unwrap();

        let s = store.session(&session.id).unwrap().unwrap();
        assert_eq!(s.chair_bot.as_deref(), Some(chair2.id.as_str()));
        let roster = store.roster(&session.id).unwrap();
        assert!(!roster.contains(&chair));
        assert!(roster.contains(&chair2.id));
    }

    #[test]
    fn liveness_never_trims_the_chair() {
        let (state, store, session, chair, _rev1, _rev2, mut conns) = liveness_setup();
        disconnect_bot(&state, &store, &mut conns, &chair);
        sweep_liveness(&state, 0).unwrap(); // no chair spare registered
        let roster = store.roster(&session.id).unwrap();
        assert!(
            roster.contains(&chair),
            "chair is replace-only, never trimmed"
        );
        assert_eq!(
            store
                .session(&session.id)
                .unwrap()
                .unwrap()
                .chair_bot
                .as_deref(),
            Some(chair.as_str()),
        );
    }

    #[test]
    fn late_joiner_is_backfilled_with_history() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let latecomer = store.register_bot("late", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                0,
                Some(&chair.id),
                std::slice::from_ref(&chair.id),
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        // history exists before the latecomer joins
        store
            .add_message(&session.id, None, "client", None, None, "the task", None)
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "bot",
                Some(&chair.id),
                None,
                "chair's take",
                None,
            )
            .unwrap();

        // latecomer joins → backfill enqueues the prior messages into its outbox
        assert_eq!(
            add_to_roster(&state, &session.id, &latecomer.id).unwrap(),
            Admission::Added
        );
        let queued: Vec<_> = store.pending_outbox(&latecomer.id).unwrap();
        assert_eq!(queued.len(), 2, "both prior messages backfilled");
        assert!(queued.iter().any(|(_, f)| f.contains("the task")));
        assert!(queued.iter().any(|(_, f)| f.contains("chair's take")));

        // re-adding is a no-op (no duplicate backfill)
        assert_eq!(
            add_to_roster(&state, &session.id, &latecomer.id).unwrap(),
            Admission::AlreadyMember
        );
        assert_eq!(store.pending_outbox(&latecomer.id).unwrap().len(), 2);
    }

    #[test]
    fn replace_roster_bot_backfills_new_member_and_purges_old_outbox() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let old = store.register_bot("old", "reviewer", "h2", "t2").unwrap();
        let new = store.register_bot("new", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), old.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        let msg = store
            .add_message(&session.id, None, "client", None, None, "review this", None)
            .unwrap();

        // The old bot is offline, so the task is waiting in its durable outbox.
        state.deliver_event(
            &old.id,
            &session.id,
            None,
            SenderInfo {
                id: "client".into(),
                name: "client".into(),
                display_name: "client".into(),
                is_bot: false,
            },
            Content::text("review this"),
            vec![],
            &msg.id,
        );
        assert_eq!(store.pending_outbox(&old.id).unwrap().len(), 1);

        assert_eq!(
            replace_roster_bot(&state, &session.id, &old.id, &new.id).unwrap(),
            Replacement::Replaced,
        );
        assert_eq!(
            store.roster(&session.id).unwrap(),
            vec![chair.id.clone(), new.id.clone()]
        );
        assert!(
            store.pending_outbox(&old.id).unwrap().is_empty(),
            "removed bot must not receive stale session frames later"
        );
        let queued = store.pending_outbox(&new.id).unwrap();
        assert_eq!(queued.len(), 1, "replacement gets backfilled history");
        assert!(queued[0].1.contains("review this"));

        handle_reply(&state, &old.id, msg_reply(&session.id, "stale reply")).unwrap();
        assert!(
            store
                .messages(&session.id)
                .unwrap()
                .iter()
                .all(|m| m.content != "stale reply"),
            "removed bot replies must be ignored",
        );
    }

    #[test]
    fn replace_roster_bot_updates_chair_only_with_chair_capable_bot() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let chair2 = store.register_bot("chair2", "chair", "h2", "t2").unwrap();
        let reviewer = store.register_bot("rev", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                0,
                Some(&chair.id),
                std::slice::from_ref(&chair.id),
                "council",
            )
            .unwrap();

        assert_eq!(
            replace_roster_bot(&state, &session.id, &chair.id, &reviewer.id).unwrap(),
            Replacement::Rejected("replacement is not chair-capable"),
        );
        assert_eq!(
            replace_roster_bot(&state, &session.id, &chair.id, &chair2.id).unwrap(),
            Replacement::Replaced,
        );
        let session = store.session(&session.id).unwrap().unwrap();
        assert_eq!(session.chair_bot.as_deref(), Some(chair2.id.as_str()));
        assert_eq!(store.roster(&session.id).unwrap(), vec![chair2.id]);
    }

    #[test]
    fn backfill_skips_other_bots_audience_messages() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let chair2 = store.register_bot("chair2", "chair", "h2", "t2").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h3", "t3").unwrap();
        let late = store.register_bot("late", "reviewer", "h4", "t4").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "client",
                None,
                None,
                "broadcast task",
                None,
            )
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "bot",
                Some(&rev.id),
                None,
                "broadcast finding",
                None,
            )
            .unwrap();
        deliver_system_prompt(&state, &session, &chair.id, "chair-only prompt").unwrap();

        assert_eq!(
            add_to_roster(&state, &session.id, &late.id).unwrap(),
            Admission::Added
        );
        let late_frames = pending_frame_values(&store, &late.id);
        assert_eq!(late_frames.len(), 2);
        assert!(late_frames
            .iter()
            .any(|v| v["content"]["text"].as_str() == Some("broadcast task")));
        assert!(late_frames
            .iter()
            .any(|v| v["content"]["text"].as_str() == Some("broadcast finding")));
        assert!(!late_frames
            .iter()
            .any(|v| v["content"]["text"].as_str() == Some("chair-only prompt")));

        assert_eq!(
            replace_roster_bot(&state, &session.id, &chair.id, &chair2.id).unwrap(),
            Replacement::Replaced
        );
        let chair2_frames = pending_frame_values(&store, &chair2.id);
        assert!(chair2_frames
            .iter()
            .any(|v| v["content"]["text"].as_str() == Some("chair-only prompt")));
    }

    #[test]
    fn backfill_is_capped_but_keeps_the_trigger() {
        let _guard = BACKFILL_ENV_LOCK.lock().unwrap();
        std::env::set_var("OABCP_BACKFILL_MAX", "3");

        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let late = store.register_bot("late", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                0,
                Some(&chair.id),
                std::slice::from_ref(&chair.id),
                "council",
            )
            .unwrap();
        store
            .add_message(
                &session.id,
                None,
                "client",
                None,
                None,
                "opening trigger",
                None,
            )
            .unwrap();
        for i in 0..12 {
            store
                .add_message(
                    &session.id,
                    None,
                    "bot",
                    Some(&chair.id),
                    None,
                    &format!("history {i}"),
                    None,
                )
                .unwrap();
        }

        assert_eq!(
            add_to_roster(&state, &session.id, &late.id).unwrap(),
            Admission::Added
        );
        std::env::remove_var("OABCP_BACKFILL_MAX");

        let frames = pending_frame_values(&store, &late.id);
        assert_eq!(frames.len(), 3);
        assert!(frames
            .iter()
            .any(|v| v["content"]["text"].as_str() == Some("opening trigger")));
        assert!(frames
            .iter()
            .any(|v| v["content"]["text"].as_str() == Some("history 10")));
        assert!(frames
            .iter()
            .any(|v| v["content"]["text"].as_str() == Some("history 11")));
    }

    #[test]
    fn first_topic_redelivers_trigger_to_non_starter_chair() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "plain",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        let trigger = post_client_message(&state, &session.id, "investigate the incident").unwrap();

        handle_reply(
            &state,
            &rev.id,
            create_topic_reply(&session.id, &trigger.id),
        )
        .unwrap();
        let chair_frames = pending_frame_values(&store, &chair.id);
        let redelivered: Vec<_> = chair_frames
            .iter()
            .filter(|v| {
                v["sender"]["id"].as_str() == Some("system")
                    && v["content"]["text"]
                        .as_str()
                        .is_some_and(|text| text.contains("investigate the incident"))
            })
            .collect();
        assert_eq!(redelivered.len(), 1);
        let stored = store.messages(&session.id).unwrap();
        let stored_redelivery = stored
            .iter()
            .filter(|m| {
                m.author_kind == "system"
                    && m.audience.as_deref() == Some(chair.id.as_str())
                    && m.content.contains("investigate the incident")
            })
            .count();
        assert_eq!(stored_redelivery, 1);

        handle_reply(
            &state,
            &rev.id,
            create_topic_reply(&session.id, &trigger.id),
        )
        .unwrap();
        let duplicate_count = store
            .messages(&session.id)
            .unwrap()
            .iter()
            .filter(|m| {
                m.author_kind == "system"
                    && m.audience.as_deref() == Some(chair.id.as_str())
                    && m.content.contains("investigate the incident")
            })
            .count();
        assert_eq!(duplicate_count, 1);
    }

    #[test]
    fn first_topic_redelivers_the_chairs_targeted_opening_input() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let roster = vec![rev.id.clone(), chair.id.clone()];
        let inputs = vec![
            crate::store::OpeningInput {
                recipient: rev.id.clone(),
                content: "reviewer task".into(),
            },
            crate::store::OpeningInput {
                recipient: chair.id.clone(),
                content: "chair task".into(),
            },
        ];
        let (session, _) = store
            .create_session_superseding(
                "targeted",
                None,
                None,
                1,
                Some(&chair.id),
                &roster,
                "council",
                &inputs,
            )
            .unwrap();
        let reviewer_trigger = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .find(|message| message.audience.as_deref() == Some(rev.id.as_str()))
            .unwrap();

        handle_reply(
            &state,
            &rev.id,
            create_topic_reply(&session.id, &reviewer_trigger.id),
        )
        .unwrap();

        let chair_frames = pending_frame_values(&store, &chair.id);
        assert!(chair_frames.iter().any(|frame| {
            frame["sender"]["id"] == "system" && frame["content"]["text"] == "chair task"
        }));
        assert!(!chair_frames
            .iter()
            .any(|frame| frame["content"]["text"] == "reviewer task"));
    }

    #[test]
    fn normal_close_purges_session_outbox() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev1 = store.register_bot("rev1", "reviewer", "h2", "t2").unwrap();
        let offline = store
            .register_bot("offline", "reviewer", "h3", "t3")
            .unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev1.id.clone(), offline.id.clone()],
                "council",
            )
            .unwrap();

        post_client_message(&state, &session.id, "review this").unwrap();
        assert!(
            pending_frames_for_session(&store, &offline.id, &session.id) > 0,
            "offline reviewer should hold queued session frames before close"
        );

        handle_reply(&state, &rev1.id, msg_reply(&session.id, "findings [done]")).unwrap();
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Quorum,
        );
        handle_reply(
            &state,
            &chair.id,
            msg_reply(&session.id, "final verdict [done]"),
        )
        .unwrap();

        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Closed,
        );
        assert_eq!(
            pending_frames_for_session(&store, &offline.id, &session.id),
            0,
            "closed session frames must not replay when the offline reviewer reconnects"
        );
    }

    #[test]
    fn a_verdict_landing_at_the_deadline_defers_the_watchdog_close() {
        // #335: an 18-minute round's verdict settled at 18:11:50.5Z and the
        // watchdog fired at effectively the same moment — the timeout close
        // won the CAS and GitHub got an abandon tombstone while the plane held
        // a valid verdict. The staleness predicate now rides inside the close
        // transaction: any message newer than the cutoff makes the timeout
        // close a no-op, so the in-flight normal close delivers the verdict.
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        post_client_message(&state, &session.id, "review this").unwrap();

        // The watchdog scanned before the chair's verdict message landed: its
        // cutoff predates all activity. The close must no-op and the session
        // must stay open for the normal close that is already in flight.
        assert!(
            !force_close_timeout(&state, &session.id, 0).unwrap(),
            "fresh activity inside the close transaction defers the timeout"
        );
        assert_ne!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Closed,
        );

        // A genuinely stale session (cutoff after all activity) still closes.
        assert!(force_close_timeout(&state, &session.id, i64::MAX).unwrap());
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Closed,
        );
    }

    #[test]
    fn watchdog_close_purges_session_outbox() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();

        post_client_message(&state, &session.id, "review this").unwrap();
        assert!(
            pending_frames_for_session(&store, &rev.id, &session.id) > 0,
            "offline reviewer should hold queued session frames before watchdog close"
        );

        assert!(force_close_timeout(&state, &session.id, i64::MAX).unwrap());
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Closed,
        );
        assert_eq!(
            pending_frames_for_session(&store, &rev.id, &session.id),
            0,
            "watchdog close must purge stale reconnect frames"
        );
    }

    #[test]
    fn admit_policy_decides() {
        assert_eq!(admit(true, false, 3, 16), Admission::Added);
        assert_eq!(
            admit(false, false, 3, 16),
            Admission::Rejected("unknown bot")
        );
        assert_eq!(
            admit(true, false, 16, 16),
            Admission::Rejected("roster full")
        );
        // already-a-member wins over both unknown and full (idempotent re-add)
        assert_eq!(admit(false, true, 99, 16), Admission::AlreadyMember);
    }

    #[test]
    fn parse_recruit_extracts_target() {
        assert_eq!(parse_recruit("let's add [[recruit:rev3]] please"), None);
        assert_eq!(parse_recruit("[[recruit:  spaced  ]]"), Some("spaced"));
        assert_eq!(parse_recruit("no directive here"), None);
        assert_eq!(parse_recruit("[[recruit:]]"), None); // empty target
    }

    #[test]
    fn parse_recruit_requires_own_line_outside_fences() {
        assert_eq!(parse_recruit("[[recruit:rev3]]"), Some("rev3"));
        assert_eq!(parse_recruit("\n\n  [[recruit:rev3]]  \n\n"), Some("rev3"));
        assert_eq!(parse_recruit("let's add [[recruit:rev3]] please"), None);
        assert_eq!(parse_recruit("```\n[[recruit:rev3]]\n```"), None);
        assert_eq!(parse_recruit("> [[recruit:rev3]]"), None);
    }

    #[test]
    fn parse_intent_extracts_verb_and_raw_args() {
        assert_eq!(
            parse_intent(r#"[[intent:delegate to=rev2 task="dig into X"]]"#),
            Some(("delegate", r#"to=rev2 task="dig into X""#))
        );
        assert_eq!(parse_intent("[[intent:status]]"), Some(("status", "")));
        assert_eq!(parse_intent("[[intent:  ]]"), None); // empty verb
        assert_eq!(parse_intent("no directive here"), None);
    }

    #[test]
    fn parse_intent_requires_own_line_outside_fences() {
        assert_eq!(
            parse_intent("\n  [[intent:status task=t1]]  \n"),
            Some(("status", "task=t1"))
        );
        assert_eq!(parse_intent("I will [[intent:status]] now"), None);
        assert_eq!(parse_intent("```\n[[intent:status]]\n```"), None);
    }

    #[test]
    fn unfenced_lines_drops_fenced_segments_fail_closed() {
        assert_eq!(
            unfenced_lines("alpha\n```\n[[recruit:x]]\n```\nbeta"),
            vec!["alpha", "beta"]
        );
        assert_eq!(
            unfenced_lines("alpha\n```\n[[recruit:x]]\nbeta"),
            vec!["alpha"]
        );
    }

    #[test]
    fn recruit_parsed_on_edit_finalize() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev3 = store.register_bot("rev3", "reviewer", "h3", "t3").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                std::slice::from_ref(&chair.id),
                "council",
            )
            .unwrap();

        handle_reply(&state, &chair.id, msg_reply(&session.id, "…")).unwrap();
        let msg = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .find(|m| m.author_id.as_deref() == Some(chair.id.as_str()))
            .unwrap();
        let mut north = state.north_tx.subscribe();

        handle_reply(
            &state,
            &chair.id,
            edit_reply(
                &session.id,
                &msg.id,
                &format!("please include rev3\n[[recruit:{}]]", rev3.id),
            ),
        )
        .unwrap();
        handle_reply(
            &state,
            &chair.id,
            edit_reply(
                &session.id,
                &msg.id,
                &format!("please include rev3\n[[recruit:{}]]", rev3.id),
            ),
        )
        .unwrap();

        assert!(store.roster(&session.id).unwrap().contains(&rev3.id));
        let mut recruit_events = 0;
        while let Ok(raw) = north.try_recv() {
            let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
            if event["type"] == "recruit" {
                recruit_events += 1;
                assert_eq!(event["payload"]["target"], rev3.id);
            }
        }
        assert_eq!(recruit_events, 1, "repeat edits must not duplicate recruit");
    }

    #[test]
    fn recruit_rate_limit_bounds_distinct_targets() {
        std::env::set_var("OABCP_RECRUIT_SESSION_CAP", "2");
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                std::slice::from_ref(&chair.id),
                "council",
            )
            .unwrap();
        let mut north = state.north_tx.subscribe();

        for target in ["missing1", "missing2", "missing3"] {
            handle_reply(
                &state,
                &chair.id,
                msg_reply(&session.id, &format!("[[recruit:{target}]]")),
            )
            .unwrap();
        }

        let mut provision_requested = 0;
        let mut rejected = Vec::new();
        while let Ok(raw) = north.try_recv() {
            let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
            match event["type"].as_str() {
                Some("provision_requested") => provision_requested += 1,
                Some("recruit_rejected") => rejected.push(event),
                _ => {}
            }
        }
        std::env::remove_var("OABCP_RECRUIT_SESSION_CAP");

        assert_eq!(provision_requested, 2);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["payload"]["target"], "missing3");
        assert_eq!(rejected[0]["payload"]["reason"], "rate_limited");
    }

    /// PR 381 F2: the full `handle_reply` → `on_send`/`on_edit` →
    /// `maybe_intent` wiring, against a controller-owned session — a dropped
    /// call site, wrong message id, or broken enqueue all fail here.
    #[test]
    fn intent_through_handle_reply_enqueues_once_for_owned_session() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                std::slice::from_ref(&chair.id),
                "council",
            )
            .unwrap();
        store
            .upsert_controller_installation("ctrl-w", 4, 60)
            .unwrap();
        assert!(store
            .configure_controller_events(
                "ctrl-w",
                "https://ctrl.example/events",
                1,
                &["session.intent".into()],
                crate::store::now_ms(),
            )
            .unwrap());
        store
            .bind_test_controller_session("ctrl-w", &session.id)
            .unwrap();
        let mut north = state.north_tx.subscribe();

        handle_reply(
            &state,
            &chair.id,
            msg_reply(&session.id, "checking in\n[[intent:status task=t1]]"),
        )
        .unwrap();
        let msg = store
            .messages(&session.id)
            .unwrap()
            .into_iter()
            .find(|m| m.author_id.as_deref() == Some(chair.id.as_str()))
            .unwrap();
        // A streamed finalize re-delivers the same message: still one intent.
        handle_reply(
            &state,
            &chair.id,
            edit_reply(
                &session.id,
                &msg.id,
                "checking in\n[[intent:status task=t1]]",
            ),
        )
        .unwrap();

        let events = store
            .claim_controller_events(crate::store::now_ms(), 10, 1_000)
            .unwrap();
        let intents: Vec<_> = events
            .iter()
            .filter(|e| e.event_type == "session.intent")
            .collect();
        assert_eq!(intents.len(), 1, "one event per intent-carrying message");
        let body: serde_json::Value = serde_json::from_str(&intents[0].body_json).unwrap();
        assert_eq!(body["payload"]["verb"], "status");
        assert_eq!(body["payload"]["args"], "task=t1");
        assert_eq!(body["payload"]["bot_id"], chair.id);
        assert_eq!(body["payload"]["message_id"], msg.id);

        let mut north_intents = 0;
        while let Ok(raw) = north.try_recv() {
            let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
            if event["type"] == "intent" {
                north_intents += 1;
                assert_eq!(event["payload"]["by"], chair.id);
            }
        }
        assert_eq!(north_intents, 1, "edit re-parse must not duplicate intent");
    }

    /// PR 381 F1: the intent budget is per bot — one bot at its cap must not
    /// starve another roster member's intent channel.
    #[test]
    fn intent_cap_is_per_bot_not_per_session() {
        std::env::set_var("OABCP_INTENT_SESSION_CAP", "1");
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev1", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        let mut north = state.north_tx.subscribe();

        handle_reply(
            &state,
            &chair.id,
            msg_reply(&session.id, "[[intent:status a]]"),
        )
        .unwrap();
        handle_reply(
            &state,
            &chair.id,
            msg_reply(&session.id, "[[intent:status b]]"),
        )
        .unwrap();
        handle_reply(
            &state,
            &rev.id,
            msg_reply(&session.id, "[[intent:status c]]"),
        )
        .unwrap();
        std::env::remove_var("OABCP_INTENT_SESSION_CAP");

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        while let Ok(raw) = north.try_recv() {
            let event: serde_json::Value = serde_json::from_str(&raw).unwrap();
            match event["type"].as_str() {
                Some("intent") => accepted.push(event["payload"]["by"].clone()),
                Some("intent_rejected") => rejected.push(event["payload"]["by"].clone()),
                _ => {}
            }
        }
        assert_eq!(accepted, vec![json!(chair.id), json!(rev.id)]);
        assert_eq!(
            rejected,
            vec![json!(chair.id)],
            "only the over-cap bot is limited"
        );
    }

    #[test]
    fn is_done_signal_matches_text_done_not_passing_ok() {
        assert!(is_done_signal("🆗")); // bare done emoji
        assert!(is_done_signal("review: LGTM [done]")); // trailing token
        assert!(is_done_signal("  VERDICT: approved [done]  "));
        assert!(!is_done_signal("🆗 Rev1, good point")); // ack in passing — NOT done
        assert!(!is_done_signal("I'll post [done] when finished")); // not trailing
        assert!(!is_done_signal("still reviewing the diff"));
    }

    #[test]
    fn recruit_event_routes_unknown_bot_to_provisioner() {
        assert_eq!(recruit_event(&Admission::Added), Some("recruit"));
        assert_eq!(recruit_event(&Admission::AlreadyMember), None);
        // inc3: an unregistered target is a provisioning cue, not a dead end
        assert_eq!(
            recruit_event(&Admission::Rejected("unknown bot")),
            Some("provision_requested")
        );
        // a full roster is a genuine rejection (no pod would help)
        assert_eq!(
            recruit_event(&Admission::Rejected("roster full")),
            Some("recruit_rejected")
        );
    }

    #[test]
    fn may_recruit_is_chair_only() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        assert!(may_recruit(&session, &chair.id), "chair may recruit");
        assert!(!may_recruit(&session, &rev.id), "reviewer may not recruit");
    }

    #[test]
    fn add_to_roster_rejects_unregistered_bot() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let session = store
            .create_session(
                "t",
                None,
                0,
                Some(&chair.id),
                std::slice::from_ref(&chair.id),
                "council",
            )
            .unwrap();

        // a bot id that was never POST /v1/bots'd must not enter the roster
        let outcome = add_to_roster(&state, &session.id, "ghost-bot").unwrap();
        assert_eq!(outcome, Admission::Rejected("unknown bot"));
        assert!(!store
            .roster(&session.id)
            .unwrap()
            .iter()
            .any(|b| b == "ghost-bot"));
        assert!(
            store.pending_outbox("ghost-bot").unwrap().is_empty(),
            "no backfill for a rejected bot"
        );
    }

    #[test]
    fn roster_authorization_gates_non_members() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let member = store.register_bot("member", "chair", "h1", "t1").unwrap();
        let outsider = store
            .register_bot("outsider", "reviewer", "h2", "t2")
            .unwrap();
        let session = store
            .create_session(
                "t",
                None,
                0,
                Some(&member.id),
                std::slice::from_ref(&member.id),
                "council",
            )
            .unwrap();

        // outsider holds a valid token but is not in the roster → reply dropped
        handle_reply(&state, &outsider.id, msg_reply(&session.id, "sneaky")).unwrap();
        assert!(
            store
                .messages(&session.id)
                .unwrap()
                .iter()
                .all(|m| m.content != "sneaky"),
            "non-roster bot's message must not be stored"
        );

        // roster member → accepted
        handle_reply(&state, &member.id, msg_reply(&session.id, "legit")).unwrap();
        assert!(
            store
                .messages(&session.id)
                .unwrap()
                .iter()
                .any(|m| m.content == "legit"),
            "roster member's message must be stored"
        );
    }

    #[test]
    fn watchdog_force_closes_stuck_session_once() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let chair = store.register_bot("chair", "chair", "h1", "t1").unwrap();
        let rev = store.register_bot("rev", "reviewer", "h2", "t2").unwrap();
        // quorum needs 1 reviewer done; nobody signals → QuorumCouncil hangs forever
        let session = store
            .create_session(
                "t",
                None,
                1,
                Some(&chair.id),
                &[chair.id.clone(), rev.id.clone()],
                "council",
            )
            .unwrap();
        store
            .advance_state(&session.id, SessionState::Open, SessionState::Deliberating)
            .unwrap();

        // the watchdog's scan finds it; the close drives it terminal
        assert!(store
            .active_sessions_before(crate::store::now_ms() + 1)
            .unwrap()
            .contains(&session.id));
        assert!(
            force_close_timeout(&state, &session.id, i64::MAX).unwrap(),
            "stuck session is closed"
        );
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Closed,
        );
        // once-only: a second fire (or a normal close racing) is a no-op, and the
        // session no longer appears as a watchdog candidate
        assert!(
            !force_close_timeout(&state, &session.id, i64::MAX).unwrap(),
            "second fire is a no-op"
        );
        assert!(!store
            .active_sessions_before(crate::store::now_ms() + 1)
            .unwrap()
            .contains(&session.id));
    }

    #[test]
    fn watchdog_spares_reopened_solo_session_that_just_spoke() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let bot = store.register_bot("allen", "allen", "h1", "t1").unwrap();
        let session = store
            .create_session(
                "forum-support",
                Some("forum:ticket:SUP-2"),
                0,
                Some(&bot.id),
                std::slice::from_ref(&bot.id),
                "solo",
            )
            .unwrap();
        store.set_state(&session.id, SessionState::Closed).unwrap();

        post_client_message(&state, &session.id, "please continue").unwrap();

        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Deliberating,
        );
        // The reopening message is itself activity, so a real deadline (10 min of
        // silence) spares the session instead of cutting the turn short.
        assert!(!store
            .active_sessions_before(crate::store::now_ms() - 600_000)
            .unwrap()
            .contains(&session.id));
        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Deliberating,
        );
        // Going silent past the deadline still trips the watchdog.
        assert!(store
            .active_sessions_before(crate::store::now_ms() + 1)
            .unwrap()
            .contains(&session.id));
        assert!(force_close_timeout(&state, &session.id, i64::MAX).unwrap());
    }

    /// The store tests inject a synthetic span; this one drives a real close and
    /// asserts the span→body mapping the orchestrator performs — the closing
    /// text reaches the controller verbatim. Deliberately an opaque sentinel,
    /// not a provider trailer: this layer must not know what the text means
    /// (ADR 031, and the kernel purity gate in CI enforces it).
    #[test]
    fn terminal_event_final_messages_carry_the_real_chair_text() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        store
            .upsert_controller_installation("ctrl-x", 4, 60)
            .unwrap();
        assert!(store
            .configure_controller_events(
                "ctrl-x",
                "https://ctrl.example/events",
                1,
                &["session.terminal".into()],
                crate::store::now_ms(),
            )
            .unwrap());
        let bot = store.register_bot("allen", "allen", "h1", "t1").unwrap();
        let session = store
            .create_session(
                "controller-owned",
                Some("github:pr/o/r#7"),
                0,
                Some(&bot.id),
                std::slice::from_ref(&bot.id),
                "solo",
            )
            .unwrap();
        store
            .bind_test_controller_session("ctrl-x", &session.id)
            .unwrap();

        post_client_message(&state, &session.id, "please look").unwrap();
        // Opaque to this layer by design: only the controller parses it.
        let closing = "body text\nOPAQUE-TAIL-SENTINEL-42 [done]";
        handle_reply(&state, &bot.id, msg_reply(&session.id, closing)).unwrap();
        assert_eq!(store.session(&session.id).unwrap().unwrap().state, "closed");

        let events = store
            .claim_controller_events(crate::store::now_ms(), 10, 1_000)
            .unwrap();
        let terminal = events
            .iter()
            .find(|e| e.event_type == "session.terminal")
            .expect("terminal event enqueued");
        let body: serde_json::Value = serde_json::from_str(&terminal.body_json).unwrap();
        let kept = body["payload"]["final_messages"].as_array().unwrap();
        assert!(!kept.is_empty(), "the closing text must ride along");
        let joined = kept
            .iter()
            .map(|m| m.as_str().unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("OPAQUE-TAIL-SENTINEL-42"),
            "the tail must survive the span mapping: {joined}"
        );
        assert!(joined.contains("body text"));
    }

    #[test]
    fn post_client_message_reopens_closed_session_for_staff_followup() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let bot = store.register_bot("allen", "allen", "h1", "t1").unwrap();
        let session = store
            .create_session(
                "forum-support",
                Some("forum:ticket:SUP-1"),
                0,
                Some(&bot.id),
                std::slice::from_ref(&bot.id),
                "solo",
            )
            .unwrap();
        store.set_state(&session.id, SessionState::Closed).unwrap();

        post_client_message(&state, &session.id, "please dig deeper").unwrap();

        assert_eq!(
            SessionState::from_db_str(&store.session(&session.id).unwrap().unwrap().state),
            SessionState::Deliberating,
        );
    }

    /// ADR 028: a reopen (follow-up turn) clears the recorded result identity,
    /// and a subsequent timeout-style close records nothing — the previous
    /// turn's span never survives as the reopened session's result.
    #[test]
    fn reopen_clears_recorded_result_and_timeout_close_keeps_it_null() {
        let store = Arc::new(SqliteStore::memory().unwrap());
        let state = AppState::new(store.clone());
        let bot = store.register_bot("allen", "allen", "h1", "t1").unwrap();
        let session = store
            .create_session(
                "forum-support",
                Some("forum:ticket:SUP-3"),
                0,
                Some(&bot.id),
                std::slice::from_ref(&bot.id),
                "solo",
            )
            .unwrap();
        post_client_message(&state, &session.id, "first question").unwrap();
        handle_reply(
            &state,
            &bot.id,
            msg_reply(&session.id, "first answer [done]"),
        )
        .unwrap();

        let row = store.session(&session.id).unwrap().unwrap();
        assert_eq!(row.state, "closed");
        assert_eq!(row.result_author_id.as_deref(), Some(bot.id.as_str()));
        assert!(row.result_message_ids.is_some());

        // The follow-up reopens the session AND clears the stale result.
        post_client_message(&state, &session.id, "follow-up question").unwrap();
        let row = store.session(&session.id).unwrap().unwrap();
        assert_eq!(row.state, "deliberating");
        assert!(
            row.result_author_id.is_none(),
            "reopen must clear the result"
        );
        assert!(row.result_message_ids.is_none());

        // A timeout close never guesses a result — it stays null.
        assert!(force_close_timeout(&state, &session.id, i64::MAX).unwrap());
        let row = store.session(&session.id).unwrap().unwrap();
        assert_eq!(row.state, "closed");
        assert!(row.result_author_id.is_none());
        assert!(row.result_message_ids.is_none());
    }
}
