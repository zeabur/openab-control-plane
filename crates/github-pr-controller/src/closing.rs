//! Turning a closed session into GitHub writes.
//!
//! A `session.terminal` event arrives naming only a session id and carrying the
//! chair's final text. This module decides what that means for the pull
//! request, persists the round, and queues the writes. Nothing here talks to
//! GitHub — the outbox drain does, and only when a write client exists.
//!
//! The split matters: deciding is pure and testable, sending is fallible and
//! retried. A redelivered event re-decides the same way and the outbox's
//! `UNIQUE(session_id, kind)` swallows the duplicate.

use serde_json::{json, Value};

use crate::store::{ReviewFinding, SessionTarget};
use crate::verdict::{ParsedResult, VerdictTrailer};

/// The commit status context this controller owns. Same string the embedded
/// plugin uses, so a canary repo's branch protection needs no change.
pub const STATUS_CONTEXT: &str = "openab/council";

pub const KIND_COMMENT: &str = "comment";
pub const KIND_STATUS: &str = "status";
pub const KIND_REVIEW: &str = "review";
// The round comment's two pre-verdict states: posted the moment the council
// convenes (create only if the session's marker is absent, so a fast close
// can never be clobbered), and rewritten if the session ends without a
// verdict (update only if the marker exists; markers are per-session, and a
// session gets exactly one terminal state, so this can never touch a
// verdict).
pub const KIND_COMMENT_OPEN: &str = "comment_open";
pub const KIND_COMMENT_ABANDON: &str = "comment_abandon";

/// A Git object id is evidence only when it is the complete SHA-1 shape the
/// controller's current policy admits. This intentionally works on bytes so
/// non-ASCII lookalikes cannot pass a character-count check.
pub(crate) fn canonical_commit_id(value: &str) -> Option<String> {
    (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// The invisible identity a write carries so a retry can recognise its own
/// earlier success. A crash between sending and marking done replays the write
/// after the claim lease lapses, and neither a comment nor a review is
/// idempotent on GitHub's side — this marker is what the pre-send reconcile
/// looks for (council F5 on #305; the P7 gate).
pub fn round_marker(session_id: &str) -> String {
    format!("<!-- openab-round:{session_id} -->")
}

/// The opening post's own identity, distinct from the verdict's
/// `round_marker` so the two are separate comments: the verdict's pre-send
/// reconcile must never adopt the "started" post (operator decision
/// 2026-08-02 — keep the started notice in the timeline instead of
/// rewriting it in place). The abandon tombstone still rewrites the
/// opening post, so it reconciles on this marker too.
pub fn open_marker(session_id: &str) -> String {
    format!("<!-- openab-round-open:{session_id} -->")
}

/// What a terminal event turns into. `round` is persisted first; `writes` are
/// queued in this order and drained independently.
#[derive(Debug, Clone, PartialEq)]
pub struct ClosingPlan {
    pub decision: String,
    pub red: i64,
    pub yellow: i64,
    pub green: i64,
    /// What the council says it read — recorded with the round and its
    /// findings. NOT what the commit status is posted against; see `plan_close`.
    pub head_sha: Option<String>,
    /// Explicit proof used by authority-bearing writes. None is intentional
    /// for failed, unparseable, reviewer-insufficient, and ask outcomes.
    pub verified_commit_id: Option<String>,
    /// Controller-derived integrity result persisted with the round.
    pub integrity_disposition: String,
    pub findings: Vec<ReviewFinding>,
    /// ADR 035: waiver ids named by `status:"waived"` findings — the terminal
    /// path bumps their repo-scoped fired counters once per first-time round.
    pub fired_waivers: Vec<String>,
    pub writes: Vec<(&'static str, Value)>,
}

/// Fail-closed projection for a review that reached terminal state without the
/// reviewer evidence captured by this controller at open. It deliberately
/// emits an error status and a diagnostic comment, but no formal review.
pub fn plan_insufficient_reviewers(
    target: &SessionTarget,
    session_id: &str,
    required: Option<i64>,
    valid: Option<i64>,
) -> ClosingPlan {
    let marker = round_marker(session_id);
    let counts = match (valid, required) {
        (Some(valid), Some(required)) => format!(" ({valid}/{required} valid reviewers)"),
        _ => " (reviewer evidence missing)".to_string(),
    };
    let mut writes = vec![(
        KIND_COMMENT,
        json!({
            "repo": target.repo,
            "pr_number": target.pr_number,
            "comment_id": Value::Null,
            "body": format!(
                "⚠️ The council failed closed{counts}; no approval or change-request review was submitted. Re-run after reviewer readiness is restored.\n\n{marker}"
            ),
        }),
    )];
    if let Some(sha) = target.head_sha.as_deref().and_then(canonical_commit_id) {
        writes.push((
            KIND_STATUS,
            json!({
                "repo": target.repo,
                "sha": sha,
                "commit_id": sha,
                "state": "error",
                "context": STATUS_CONTEXT,
                "description": "council error - insufficient valid reviewers",
            }),
        ));
    }
    ClosingPlan {
        decision: "unknown".to_string(),
        red: 0,
        yellow: 0,
        green: 0,
        head_sha: target.head_sha.clone(),
        verified_commit_id: None,
        integrity_disposition: "insufficient_valid_reviewers".into(),
        findings: vec![],
        fired_waivers: vec![],
        writes,
    }
}

/// Decide the round from the parsed chair text.
///
/// The unparseable case is deliberate and not an error: the session really did
/// close, so we say so with a comment and an `error` status — but we submit
/// **no formal review**, because we have no verdict to stand behind. Silence
/// here is what made two failed rounds on PR #304 look identical to rounds
/// still in flight.
pub fn plan_close(
    target: &SessionTarget,
    parsed: &ParsedResult,
    comment_id: Option<i64>,
    session_id: &str,
    is_ask: bool,
) -> ClosingPlan {
    let marker = round_marker(session_id);
    if is_ask {
        // A follow-up question, not a review round (SEI-929). Its settled final
        // message IS the answer — the ask template forbids tool narration and
        // self-posting — so post it as a plain comment with no verdict, no
        // status, and no review. No "no parseable verdict" warning either: an
        // ask legitimately has no verdict.
        return ClosingPlan {
            decision: "ask".to_string(),
            red: 0,
            yellow: 0,
            green: 0,
            head_sha: target.head_sha.clone(),
            verified_commit_id: None,
            integrity_disposition: "ask".into(),
            findings: vec![],
            fired_waivers: vec![],
            writes: vec![(
                KIND_COMMENT,
                json!({
                    "repo": target.repo,
                    "pr_number": target.pr_number,
                    "comment_id": comment_id,
                    "body": format!("{}\n\n{marker}", answer_body(parsed)),
                }),
            )],
        };
    }
    let trailer = parsed.trailer.as_ref();
    let (red, yellow, green) = trailer
        .map(|t| {
            (
                t.red.unwrap_or_default(),
                t.yellow.unwrap_or_default(),
                t.green.unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let decision = trailer
        .map(|t| t.decision.clone())
        .unwrap_or_else(|| "unknown".to_string());
    // The target is controller-owned evidence; the findings SHA is only a
    // claim until it is complete, canonical, and equal to that target. Do this
    // before touching findings or waiver bookkeeping so neither verdict can
    // turn an unproven result into an authority-bearing write.
    let integrity = if trailer.is_some() {
        classify_integrity(target, parsed)
    } else {
        // Keep the existing unparseable-close behavior. There is no verdict
        // that could become authority, so the SHA claim is only historical
        // data and must not turn this path into an integrity diagnostic.
        IntegrityDecision {
            disposition: "unparseable",
            target_commit_id: target.head_sha.as_deref().and_then(canonical_commit_id),
            verified_commit_id: None,
            reviewed_sha: parsed
                .findings
                .as_ref()
                .and_then(|block| block.head_sha.clone())
                .or_else(|| target.head_sha.clone()),
        }
    };
    if trailer.is_some() && integrity.disposition != "verified" {
        return plan_sha_integrity_failure(target, trailer, comment_id, session_id, integrity);
    }
    let status_sha = integrity.target_commit_id.clone();
    let reviewed_sha = integrity.reviewed_sha.clone();

    let findings = parsed
        .findings
        .as_ref()
        .map(|block| {
            block
                .findings
                .iter()
                .map(|f| ReviewFinding {
                    stable_id: f.id.clone(),
                    severity: f.severity.clone(),
                    status: f.status.clone(),
                    title: f.title.clone(),
                    path: f.path.clone(),
                    line: f.line,
                    raised_by: f.raised_by.clone(),
                    angle: f.angle.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    let fired_waivers: Vec<String> = parsed
        .findings
        .as_ref()
        .map(|block| {
            block
                .findings
                .iter()
                .filter(|f| f.status == "waived")
                .filter_map(|f| f.waiver_id.clone())
                .collect()
        })
        .unwrap_or_default();

    let mut writes = vec![(
        KIND_COMMENT,
        json!({
            "repo": target.repo,
            "pr_number": target.pr_number,
            // Present → PATCH that comment, absent → create a new one. The
            // round's own id is learned from the response.
            "comment_id": comment_id,
            "body": format!("{}\n\n{marker}", comment_body(parsed, trailer)),
        }),
    )];
    if let Some(sha) = status_sha.as_deref() {
        writes.push((
            KIND_STATUS,
            json!({
                "repo": target.repo,
                "sha": sha,
                "commit_id": sha,
                "state": status_state(trailer),
                "context": STATUS_CONTEXT,
                "description": status_description(trailer),
            }),
        ));
    }
    if let Some(trailer) = trailer {
        writes.push((
            KIND_REVIEW,
            json!({
                "repo": target.repo,
                "pr_number": target.pr_number,
                // Blocking counts outrank the word; `VerdictTrailer` has
                // already applied that rule, so this reads the decision.
                "event": if trailer.blocking() || trailer.decision == "request_changes" {
                    "REQUEST_CHANGES"
                } else {
                    "APPROVE"
                },
                "commit_id": integrity
                    .verified_commit_id
                    .as_deref()
                    .expect("verified integrity has a commit id"),
                "body": format!("{}\n\n{marker}", review_body(trailer, reviewed_sha.as_deref())),
            }),
        ));
    }

    ClosingPlan {
        decision,
        red,
        yellow,
        green,
        head_sha: reviewed_sha,
        verified_commit_id: integrity.verified_commit_id,
        integrity_disposition: integrity.disposition.to_string(),
        findings,
        fired_waivers,
        writes,
    }
}

#[derive(Debug)]
struct IntegrityDecision {
    disposition: &'static str,
    target_commit_id: Option<String>,
    verified_commit_id: Option<String>,
    /// The raw claimed value retained only as historical provenance.
    reviewed_sha: Option<String>,
}

fn classify_integrity(target: &SessionTarget, parsed: &ParsedResult) -> IntegrityDecision {
    let target_raw = target.head_sha.as_deref();
    let target_commit_id = match target_raw {
        None | Some("") => {
            return IntegrityDecision {
                disposition: "missing_target",
                target_commit_id: None,
                verified_commit_id: None,
                reviewed_sha: target.head_sha.clone(),
            }
        }
        Some(raw) => match canonical_commit_id(raw) {
            Some(canonical) => canonical,
            None => {
                return IntegrityDecision {
                    disposition: "invalid_target",
                    target_commit_id: None,
                    verified_commit_id: None,
                    reviewed_sha: target.head_sha.clone(),
                }
            }
        },
    };

    let Some(block) = parsed.findings.as_ref() else {
        return IntegrityDecision {
            disposition: "missing_reviewed_sha",
            target_commit_id: Some(target_commit_id),
            verified_commit_id: None,
            reviewed_sha: None,
        };
    };
    let Some(reviewed_raw) = block.head_sha.as_deref() else {
        return IntegrityDecision {
            disposition: "missing_reviewed_sha",
            target_commit_id: Some(target_commit_id),
            verified_commit_id: None,
            reviewed_sha: None,
        };
    };
    if reviewed_raw.is_empty() {
        return IntegrityDecision {
            disposition: "missing_reviewed_sha",
            target_commit_id: Some(target_commit_id),
            verified_commit_id: None,
            reviewed_sha: Some(reviewed_raw.to_string()),
        };
    }
    let Some(reviewed_commit_id) = canonical_commit_id(reviewed_raw) else {
        return IntegrityDecision {
            disposition: "invalid_reviewed_sha",
            target_commit_id: Some(target_commit_id),
            verified_commit_id: None,
            reviewed_sha: Some(reviewed_raw.to_string()),
        };
    };
    if reviewed_commit_id != target_commit_id {
        return IntegrityDecision {
            disposition: "reviewed_sha_mismatch",
            target_commit_id: Some(target_commit_id),
            verified_commit_id: None,
            reviewed_sha: Some(reviewed_raw.to_string()),
        };
    }
    // Integrity is about SHA provenance, and that is now fully established: the
    // machine-readable findings block named a reviewed SHA and it equals the
    // target. It deliberately does NOT also require the chair's prose to carry
    // the `<!-- openab-council -->` anchor or a literal `Reviewed at <sha>`
    // line. Those were a second, LLM-typed copy of a fact the controller already
    // holds authoritatively, and withholding the review when the copy was
    // missing discarded three fully-deliberated verdicts in 50 minutes
    // (nuphos#1232 r2, #1233 r4, #1237 r2 — all `missing_report`). The
    // no-anchor case stays safe without this gate: `comment_body` never
    // publishes unanchored raw text, it rebuilds a `degraded_body` from the
    // trailer and the findings block.
    //
    // The gate was also wrong by construction, not merely unreliable in
    // transport. It read the window after the LAST `REPORT_START` via
    // `rsplit_once`, so a report that *quotes* the anchor — which any review of
    // this controller's own code does — pushed the real `Reviewed at` line
    // outside the window. The round that reviewed this very commit proved it:
    // the chair emitted both the anchor and `Reviewed at
    // 579387339581043528e0b8325d19cb7df19f881a (round 1)`, and its
    // `request_changes` was still withheld as `missing_reviewed_at`. A gate
    // that fails on correct input cannot be the thing authorizing a review.
    // What authorizes it instead is the pair the chair finds hardest to emit by
    // accident and that survives at the tail: a parseable verdict trailer and a
    // findings block whose `head_sha` equals the webhook's head.
    IntegrityDecision {
        disposition: "verified",
        target_commit_id: Some(reviewed_commit_id.clone()),
        verified_commit_id: Some(reviewed_commit_id.clone()),
        reviewed_sha: Some(reviewed_commit_id),
    }
}

fn plan_sha_integrity_failure(
    target: &SessionTarget,
    trailer: Option<&VerdictTrailer>,
    comment_id: Option<i64>,
    session_id: &str,
    integrity: IntegrityDecision,
) -> ClosingPlan {
    let (red, yellow, green) = trailer
        .map(|trailer| {
            (
                trailer.red.unwrap_or_default(),
                trailer.yellow.unwrap_or_default(),
                trailer.green.unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let verdict = trailer
        .map(|trailer| trailer.decision.as_str())
        .unwrap_or("unknown");
    let marker = round_marker(session_id);
    let diagnostic = format!(
        "⚠️ Review integrity failed ({}) for `{verdict}`. Approval or change-request review was withheld; no findings or waiver effects were recorded. Re-run the council for this pull request.\n\n{marker}",
        integrity.disposition
    );
    let mut writes = vec![(
        KIND_COMMENT,
        json!({
            "repo": target.repo,
            "pr_number": target.pr_number,
            "comment_id": comment_id,
            "body": diagnostic,
        }),
    )];
    if let Some(sha) = integrity.target_commit_id.as_deref() {
        writes.push((
            KIND_STATUS,
            json!({
                "repo": target.repo,
                "sha": sha,
                "commit_id": sha,
                "state": "error",
                "context": STATUS_CONTEXT,
                "description": format!("council error - integrity failed ({})", integrity.disposition),
            }),
        ));
    }
    ClosingPlan {
        decision: "sha_integrity_failed".into(),
        red,
        yellow,
        green,
        head_sha: integrity.reviewed_sha,
        verified_commit_id: integrity.verified_commit_id,
        integrity_disposition: integrity.disposition.into(),
        findings: vec![],
        fired_waivers: vec![],
        writes,
    }
}

fn status_state(trailer: Option<&VerdictTrailer>) -> &'static str {
    match trailer {
        None => "error",
        Some(t) if t.blocking() || t.decision == "request_changes" => "failure",
        Some(_) => "success",
    }
}

fn status_description(trailer: Option<&VerdictTrailer>) -> String {
    // Commit status descriptions reject 4-byte UTF-8 ("Description doesn't
    // accept 4-byte Unicode", 422) — no emoji here, unlike the review body.
    match trailer {
        None => "council closed without a parseable verdict".to_string(),
        Some(t) => format!(
            "{} · red {} · yellow {} · green {}",
            t.decision,
            t.red.unwrap_or_default(),
            t.yellow.unwrap_or_default(),
            t.green.unwrap_or_default()
        ),
    }
}

fn review_body(trailer: &VerdictTrailer, reviewed_sha: Option<&str>) -> String {
    let at = reviewed_sha
        .map(|sha| format!(" Reviewed at {sha}."))
        .unwrap_or_default();
    format!(
        "Council {} — 🔴{} 🟡{} 🟢{}.{at} Details in the review comment.",
        trailer.decision,
        trailer.red.unwrap_or_default(),
        trailer.yellow.unwrap_or_default(),
        trailer.green.unwrap_or_default()
    )
}

/// The follow-up answer as posted (SEI-929). The settled final message is the
/// answer; only machine tails are removed — a trailing `[done]` and any stray
/// `[[verdict:…]]` line the model added out of habit. No council anchor and no
/// "no verdict" warning: an ask legitimately has neither. An empty answer
/// becomes a short notice, never a blank comment.
fn answer_body(parsed: &ParsedResult) -> String {
    let text = parsed.source.trim_end();
    let mut lines: Vec<&str> = text.lines().collect();
    if let Some(at) = lines.iter().position(|line| line.contains("[[verdict:")) {
        lines.truncate(at);
    }
    while let Some(last) = lines.last() {
        let stripped = last.trim();
        if stripped.is_empty() || stripped == "[done]" {
            lines.pop();
        } else {
            break;
        }
    }
    // The ask path has no report anchor, so the template is its primary boundary
    // — but a misbehaving agent can still narrate. Drop the structured machine
    // shapes the template forbids (the CLI's `✅ `…`` tool/task echoes and the
    // runtime error banner) as a fail-closed floor (review #395 F1). Free-form
    // prose cannot be denylisted, so this is a floor, not a fence.
    lines.retain(|line| !is_machine_noise_line(line));
    let body = unfence_tables(lines).join("\n").trim().to_string();
    if body.is_empty() {
        return "This follow-up produced no answer.".to_string();
    }
    body
}

/// A structured runtime/CLI transcript line, not model output: the Kiro CLI's
/// `✅ `…`` tool/task-list echo, or the prepended agent-error banner. These have
/// stable shapes (unlike free-form narration), so they can be positively
/// recognised and dropped from an ask answer.
fn is_machine_noise_line(line: &str) -> bool {
    let t = line.trim();
    if t.starts_with("✅ `") {
        return true;
    }
    if t.starts_with('\u{26A0}') {
        let lc = t.to_ascii_lowercase();
        return lc.contains("-32603") || lc.contains("internal error");
    }
    false
}

/// Where the chair's report begins. The task template requires the verdict
/// comment to start with this line, which makes it a protocol anchor: anything
/// before it in the settled text is working noise, not report.
const REPORT_START: &str = "<!-- openab-council -->";

/// Posted when the session closed with no verdict we can stand behind.
const NO_VERDICT_NOTICE: &str = "⚠️ The council closed without a parseable verdict. \
     No formal review was submitted.";

/// The structured findings block by its own delimiters. It survives an
/// anchorless close because — unlike the free-form report prose — it has stable
/// markers, so it can be lifted out of a broken settled text and kept with the
/// degraded comment to keep the round self-describing.
fn findings_block(text: &str) -> Option<&str> {
    let start = text.find("<!-- openab-findings")?;
    let end = text[start..].find("-->").map(|rel| start + rel + 3)?;
    Some(&text[start..end])
}

/// The comment for an anchorless close that still parsed a verdict (a chair
/// whose synthesis turn failed mid-write). We refuse to publish the raw text,
/// but the verdict and findings are structured data we trust — the status and
/// review are posted from the same trailer — so the comment states the verdict
/// and carries the findings block, without the lost report prose.
fn degraded_body(trailer: &VerdictTrailer, findings: Option<&str>) -> String {
    let mut body = format!(
        "⚠️ The council reached **{}** — 🔴{} 🟡{} 🟢{} — but its written report \
         could not be recovered (the synthesis turn failed mid-write). The \
         verdict and findings stand; comment `@opencodezebra review` to re-run \
         the council for a full report.",
        trailer.decision,
        trailer.red.unwrap_or_default(),
        trailer.yellow.unwrap_or_default(),
        trailer.green.unwrap_or_default(),
    );
    if let Some(block) = findings {
        body.push_str("\n\n");
        body.push_str(block);
    }
    body
}

/// The chair's report is the comment. The settled text arrives with working
/// noise around it — the Kiro CLI transcribes its tool calls into message
/// bodies, and the chair thinks aloud before the report — so the body starts
/// at the `<!-- openab-council -->` anchor the template mandates (everything
/// before it is dropped), and machine parts are stripped from the tail: the
/// verdict trailer and the `[done]` marker. The findings block stays — it is
/// an HTML comment, so it is invisible in the rendered comment and keeps the
/// round self-describing.
fn comment_body(parsed: &ParsedResult, trailer: Option<&VerdictTrailer>) -> String {
    let text = parsed.source.trim_end();
    // LAST anchor, not first: the working noise can itself contain the anchor
    // (nuphos#725 round 3 — a Kiro task echo of the report template opened the
    // settled text, and anchoring there published 4KB of tool transcript), and
    // the protocol puts the real report last. A re-draft supersedes its draft
    // the same way.
    //
    // The anchor is authoritative: it is the ONLY marker that says "the report
    // starts here". Without it we cannot separate report from working-noise —
    // not by denylisting tool lines (the chair's free-form narration has no
    // stable shape and reads exactly like report prose), so we must never
    // publish the raw text. A mid-synthesis error is the real no-anchor case:
    // the runtime prepends a banner and the chair never emits the anchor
    // (backend#2418 round 4, a -32603 error that leaked the whole transcript;
    // infra-zeabur-system#208, a Solo follow-up). Rebuild from structured data.
    let Some(at) = text.rfind(REPORT_START) else {
        return match trailer {
            None => NO_VERDICT_NOTICE.to_string(),
            Some(t) => degraded_body(t, findings_block(text)),
        };
    };
    let text = &text[at..];
    if trailer.is_none() {
        // A real report (it has the anchor) that only failed to emit its
        // verdict line — keep it, flag the missing verdict below.
        return format!("{text}\n\n---\n{NO_VERDICT_NOTICE}");
    }
    let mut lines: Vec<&str> = text.lines().collect();
    // The report ends at its trailer. Anything after that line is working
    // noise the chair emitted past the verdict (nuphos#725 round 6 carried
    // octobroker transcript between the trailer and a second draft), so the
    // cut is at the first trailer line, not just trailing machine lines.
    if let Some(at) = lines.iter().position(|line| line.contains("[[verdict:")) {
        lines.truncate(at);
    }
    while let Some(last) = lines.last() {
        let stripped = last.trim();
        if stripped.is_empty() || stripped == "[done]" {
            lines.pop();
        } else {
            break;
        }
    }
    unfence_tables(lines).join("\n").trim_end().to_string()
}

/// Every chair model tried (Kiro and Claude alike) wraps the Findings tables
/// in code fences when writing the report as a chat message — GitHub then
/// renders them as preformatted text. The steering rule against it is
/// ignored, so the fence is undone here: a fenced block whose non-empty
/// lines all start with `|` (and at least one does) is unwrapped.
fn unfence_tables(lines: Vec<&str>) -> Vec<&str> {
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim().starts_with("```") {
            if let Some(close) = lines[i + 1..]
                .iter()
                .position(|line| line.trim().starts_with("```"))
            {
                let block = &lines[i + 1..i + 1 + close];
                let is_table = block.iter().any(|line| line.trim_start().starts_with('|'))
                    && block
                        .iter()
                        .all(|line| line.trim().is_empty() || line.trim_start().starts_with('|'));
                if is_table {
                    out.extend_from_slice(block);
                    i += close + 2;
                    continue;
                }
            }
        }
        out.push(lines[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{parse_final_messages, parse_verdict_trailer, FindingsBlock};

    fn target() -> SessionTarget {
        SessionTarget {
            repo: "example/repo".into(),
            pr_number: 7,
            head_sha: Some("0123456789abcdef0123456789abcdef01234567".into()),
            reason: None,
            required_valid_reviewers: Some(2),
        }
    }

    fn kinds(plan: &ClosingPlan) -> Vec<&str> {
        plan.writes.iter().map(|(kind, _)| *kind).collect()
    }

    fn write<'a>(plan: &'a ClosingPlan, kind: &str) -> &'a Value {
        &plan
            .writes
            .iter()
            .find(|(k, _)| *k == kind)
            .expect("write present")
            .1
    }

    fn valid_parsed(source: &str, trailer: &str) -> ParsedResult {
        ParsedResult {
            trailer: parse_verdict_trailer(trailer),
            findings: Some(FindingsBlock {
                head_sha: Some("0123456789abcdef0123456789abcdef01234567".into()),
                findings: vec![],
            }),
            source: if source.contains(REPORT_START) {
                source.into()
            } else {
                format!("<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n{source}")
            },
        }
    }

    #[test]
    fn an_approve_becomes_a_comment_a_success_status_and_a_formal_approval() {
        let parsed = valid_parsed(
            "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\nLGTM\n[[verdict:approve r=0 y=0 g=2]] [done]",
            "[[verdict:approve r=0 y=0 g=2]] [done]",
        );
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        assert_eq!(kinds(&plan), [KIND_COMMENT, KIND_STATUS, KIND_REVIEW]);
        assert_eq!(plan.decision, "approve");
        assert_eq!((plan.red, plan.yellow, plan.green), (0, 0, 2));
        assert_eq!(write(&plan, KIND_STATUS)["state"], "success");
        let description = write(&plan, KIND_STATUS)["description"].as_str().unwrap();
        assert!(
            description.chars().all(|c| c <= '\u{FFFF}'),
            "GitHub rejects 4-byte Unicode in status descriptions: {description}"
        );
        assert_eq!(description, "approve · red 0 · yellow 0 · green 2");
        assert_eq!(write(&plan, KIND_REVIEW)["event"], "APPROVE");
        assert_eq!(
            write(&plan, KIND_REVIEW)["commit_id"],
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(
            write(&plan, KIND_STATUS)["commit_id"],
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(
            write(&plan, KIND_COMMENT)["body"],
            format!("<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\nLGTM\n\n{}", round_marker("ses_t")),
            "the comment carries its round marker"
        );
    }

    fn full_target() -> SessionTarget {
        SessionTarget {
            repo: "example/repo".into(),
            pr_number: 7,
            head_sha: Some("0123456789abcdef0123456789abcdef01234567".into()),
            reason: None,
            required_valid_reviewers: Some(2),
        }
    }

    fn findings_result(trailer: &str, head_sha: Option<&str>) -> ParsedResult {
        let body = match head_sha {
            Some(head_sha) => format!(
                "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\nreport\n<!-- openab-findings\n{{\"head_sha\":\"{head_sha}\",\"findings\":[{{\"id\":\"F1\",\"severity\":\"yellow\",\"title\":\"finding\"}}]}}\n-->\n{trailer}"
            ),
            None => format!("report\n{trailer}"),
        };
        parse_final_messages(&[body])
    }

    fn assert_sha_integrity_failure(plan: &ClosingPlan) {
        assert_eq!(plan.decision, "sha_integrity_failed");
        assert_eq!(kinds(plan), [KIND_COMMENT, KIND_STATUS]);
        assert!(plan.findings.is_empty());
        assert!(plan.fired_waivers.is_empty());
        assert_eq!(write(plan, KIND_STATUS)["state"], "error");
        assert_eq!(
            write(plan, KIND_STATUS)["sha"],
            "0123456789abcdef0123456789abcdef01234567"
        );
    }

    #[test]
    fn missing_reviewed_sha_cannot_approve() {
        let parsed = findings_result("[[verdict:approve r=0 y=0 g=1]] [done]", None);
        let plan = plan_close(&full_target(), &parsed, None, "ses_missing_approve", false);
        assert_sha_integrity_failure(&plan);
    }

    #[test]
    fn missing_reviewed_sha_cannot_request_changes() {
        let parsed = findings_result("[[verdict:request_changes r=1 y=0 g=0]] [done]", None);
        let plan = plan_close(&full_target(), &parsed, None, "ses_missing_request", false);
        assert_sha_integrity_failure(&plan);
    }

    #[test]
    fn malformed_reviewed_sha_cannot_approve() {
        let parsed = findings_result("[[verdict:approve r=0 y=0 g=1]] [done]", Some("not-a-sha"));
        let plan = plan_close(
            &full_target(),
            &parsed,
            None,
            "ses_malformed_approve",
            false,
        );
        assert_sha_integrity_failure(&plan);
    }

    #[test]
    fn malformed_reviewed_sha_cannot_request_changes() {
        let parsed = findings_result(
            "[[verdict:request_changes r=1 y=0 g=0]] [done]",
            Some("not-a-sha"),
        );
        let plan = plan_close(
            &full_target(),
            &parsed,
            None,
            "ses_malformed_request",
            false,
        );
        assert_sha_integrity_failure(&plan);
    }

    #[test]
    fn mismatched_reviewed_sha_cannot_approve() {
        let parsed = findings_result(
            "[[verdict:approve r=0 y=0 g=1]] [done]",
            Some("fedcba9876543210fedcba9876543210fedcba98"),
        );
        let plan = plan_close(&full_target(), &parsed, None, "ses_mismatch_approve", false);
        assert_sha_integrity_failure(&plan);
    }

    #[test]
    fn mismatched_reviewed_sha_cannot_request_changes() {
        let parsed = findings_result(
            "[[verdict:request_changes r=1 y=0 g=0]] [done]",
            Some("fedcba9876543210fedcba9876543210fedcba98"),
        );
        let plan = plan_close(&full_target(), &parsed, None, "ses_mismatch_request", false);
        assert_sha_integrity_failure(&plan);
    }

    #[test]
    fn empty_reviewed_sha_cannot_authorize_either_verdict() {
        for (session_id, trailer) in [
            (
                "ses_empty_approve",
                "[[verdict:approve r=0 y=0 g=1]] [done]",
            ),
            (
                "ses_empty_request",
                "[[verdict:request_changes r=1 y=0 g=0]] [done]",
            ),
        ] {
            let parsed = findings_result(trailer, Some(""));
            let plan = plan_close(&full_target(), &parsed, None, session_id, false);
            assert_sha_integrity_failure(&plan);
            assert_eq!(plan.integrity_disposition, "missing_reviewed_sha");
        }
    }

    #[test]
    fn invalid_target_cannot_authorize_either_verdict() {
        for (session_id, trailer) in [
            (
                "ses_bad_target_approve",
                "[[verdict:approve r=0 y=0 g=1]] [done]",
            ),
            (
                "ses_bad_target_request",
                "[[verdict:request_changes r=1 y=0 g=0]] [done]",
            ),
        ] {
            let parsed = findings_result(trailer, Some("0123456789abcdef0123456789abcdef01234567"));
            let mut target = full_target();
            target.head_sha = Some("placeholder".into());
            let plan = plan_close(&target, &parsed, None, session_id, false);
            assert_eq!(plan.decision, "sha_integrity_failed");
            assert_eq!(plan.integrity_disposition, "invalid_target");
            assert_eq!(kinds(&plan), [KIND_COMMENT]);
            assert!(plan.findings.is_empty());
            assert!(plan.fired_waivers.is_empty());
        }
    }

    #[test]
    fn matching_full_reviewed_sha_remains_authoritative() {
        let parsed = findings_result(
            "[[verdict:approve r=0 y=0 g=1]] [done]",
            Some("0123456789ABCDEF0123456789ABCDEF01234567"),
        );
        let plan = plan_close(&full_target(), &parsed, None, "ses_matching", false);
        assert_eq!(kinds(&plan), [KIND_COMMENT, KIND_STATUS, KIND_REVIEW]);
        assert_eq!(plan.decision, "approve");
        assert_eq!(write(&plan, KIND_STATUS)["state"], "success");
        assert_eq!(write(&plan, KIND_REVIEW)["event"], "APPROVE");
    }

    #[test]
    fn fenced_findings_tables_are_unwrapped_but_code_blocks_survive() {
        // Shape of nuphos#664: the chair fences the table header and body as
        // separate blocks. A real code block in the same report must remain.
        let report =
            "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n\
             CHANGES REQUESTED ⚠️ — summary.\n\n\
             ## Findings\n\n\
             ```\n\
             | ID | Severity | Title |\n\
             ```\n\
             ```\n\
             | -- | -------- | ----- |\n\
             | F1 | 🟡 | tab reset |\n\
             ```\n\n\
             ```rust\n\
             let keep = me;\n\
             ```\n\
             [[verdict:request_changes r=0 y=1 g=0]] [done]";
        let parsed = valid_parsed(report, "[[verdict:request_changes r=0 y=1 g=0]] [done]");
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(!body.contains("```\n| ID"), "table header unfenced");
        assert!(body.contains("| ID | Severity | Title |\n| -- | -------- | ----- |"));
        assert!(body.contains("```rust\nlet keep = me;\n```"));
    }

    #[test]
    fn the_comment_starts_at_the_report_anchor_not_the_working_noise() {
        // Shape of #309 round 3: the Kiro chair transcribes tool calls and
        // thinks aloud before the report in one message, and the footer,
        // findings block, and trailer arrive in a later message.
        let synthesis = "✅ `Creating task list: Synthesize round 3 verdict`\n\
             ✅ `Running: printf '%s' '{\"pullNumber\":309}' | octobroker-mcp call pull_request_read`\n\
             Good — the head SHA is unchanged. I've verified the file. No issues.\
             <!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n\
             LGTM ✅ — Docs-only change.\n\
             Reviewed at 701a1bf (round 3)\n\n\
             ## Delta since d3fbb56\n\n- One appended line.";
        let closing = "🔴×0 🟡×0 🟢×1 · 💬 Comment `@bot <question>` for a follow-up\n\n\
             <!-- openab-findings\n\
             {\"head_sha\":\"0123456789ABCDEF0123456789ABCDEF01234567\",\"findings\":[]}\n\
             -->\n\
             [[verdict:approve r=0 y=0 g=1]] [done]";
        let parsed = parse_final_messages(&[synthesis.into(), closing.into()]);
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(
            body.starts_with("<!-- openab-council -->"),
            "report anchor opens the comment: {body}"
        );
        assert!(
            !body.contains("✅ `") && !body.contains("No issues."),
            "tool echoes and self-talk are dropped: {body}"
        );
        assert!(
            body.contains("## Delta since") && body.contains("🔴×0 🟡×0 🟢×1"),
            "the report and its footer survive: {body}"
        );
        assert!(
            body.contains("openab-findings") && !body.contains("[[verdict:"),
            "findings block stays, trailer goes: {body}"
        );
    }

    #[test]
    fn noise_containing_the_anchor_cannot_steal_the_report() {
        // Shape of nuphos#725 round 3: a Kiro task echo QUOTES the report
        // template — anchor string included — before the tool transcript, so
        // anchoring on the first occurrence published the whole transcript.
        // The real report is the last anchor.
        let noisy = "<!-- openab-council --> ; CHANGES REQUESTED ⚠️ — draft title ; R...`\n\
             ✅ `Running: /home/agent/bin/octobroker-mcp comment zeabur nuphos 725 < /tmp/verdict.md`\n\
             Now I need to verify the finding myself before writing the verdict.\n\
             <!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n\
             CHANGES REQUESTED ⚠️ — the real report.\n\n\
             ## Findings\n\n| F1 | 🟡 | real |\n\n\
             [[verdict:request_changes r=0 y=1 g=0]] [done]";
        let parsed = valid_parsed(noisy, "[[verdict:request_changes r=0 y=1 g=0]] [done]");
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(
            body.starts_with("<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\nCHANGES REQUESTED ⚠️ — the real report."),
            "the LAST anchor opens the comment: {body}"
        );
        assert!(
            !body.contains("octobroker") && !body.contains("Now I need"),
            "the quoted-anchor noise is dropped: {body}"
        );
    }

    #[test]
    fn nothing_past_the_trailer_is_published() {
        // Shape of nuphos#725 round 6: the chair emitted a full report, its
        // trailer, MORE tool transcript, then a second draft. Everything from
        // the first trailer line on is machine tail, except that a re-draft
        // with its own anchor supersedes the lot.
        let one_draft_then_noise = "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n\
             CHANGES REQUESTED ⚠️ — the report.\n\n\
             [[verdict:request_changes r=0 y=2 g=1]] [done]\n\
             ✅ `Running: printf '%s' '{\"pullNumber\":725}' | /home/agent/bin/octobroker-mcp call pull_request_read`\n\
             Let me fetch the head SHA again.";
        let parsed = valid_parsed(
            &format!(
                "{one_draft_then_noise}\nfooter\n[[verdict:request_changes r=0 y=2 g=1]] [done]"
            ),
            "[[verdict:request_changes r=0 y=2 g=1]] [done]",
        );
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(
            !body.contains("octobroker") && !body.contains("Let me fetch"),
            "post-trailer transcript is dropped: {body}"
        );
        assert!(
            body.contains("CHANGES REQUESTED ⚠️ — the report.\n\n<!-- openab-round:"),
            "the report ends at its trailer, then the round marker: {body}"
        );

        let redraft =
            "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n\
             CHANGES REQUESTED ⚠️ — superseded draft.\n\
             [[verdict:request_changes r=0 y=2 g=1]] [done]\n\
             ✅ `Running: octobroker-mcp call pull_request_read`\n\
             <!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n\
             CHANGES REQUESTED ⚠️ — the final draft.\n\
             [[verdict:request_changes r=0 y=2 g=1]] [done]";
        let parsed = valid_parsed(redraft, "[[verdict:request_changes r=0 y=2 g=1]] [done]");
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(
            body.contains("the final draft") && !body.contains("superseded draft"),
            "a re-draft with its own anchor supersedes the lot: {body}"
        );
        assert!(
            !body.contains("octobroker"),
            "transcript between drafts is dropped: {body}"
        );
    }

    #[test]
    fn the_review_names_the_sha_it_stands_behind() {
        let parsed = parse_final_messages(&[
            "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\nreport\n<!-- openab-findings\n{\"head_sha\":\"0123456789ABCDEF0123456789ABCDEF01234567\",\"findings\":[]}\n-->\n[[verdict:approve r=0 y=0 g=1]] [done]".into(),
        ]);
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_REVIEW)["body"].as_str().unwrap();
        assert!(
            body.contains("Reviewed at 0123456789abcdef0123456789abcdef01234567"),
            "review timeline entry must name the reviewed sha: {body}"
        );
    }

    #[test]
    fn anything_blocking_becomes_a_request_changes_review() {
        // 🟡 alone blocks, and it blocks even when the chair wrote `approve` —
        // the counts already overrode the word in the parser.
        let parsed = valid_parsed(
            "report\n[[verdict:approve r=0 y=1 g=2]] [done]",
            "[[verdict:approve r=0 y=1 g=2]] [done]",
        );
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        assert_eq!(plan.decision, "request_changes");
        assert_eq!(write(&plan, KIND_STATUS)["state"], "failure");
        assert_eq!(write(&plan, KIND_REVIEW)["event"], "REQUEST_CHANGES");
    }

    #[test]
    fn an_unparseable_close_says_so_and_submits_no_review() {
        let parsed = parse_final_messages(&["the council rambled and stopped".into()]);
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        assert_eq!(kinds(&plan), [KIND_COMMENT, KIND_STATUS]);
        assert_eq!(plan.decision, "unknown");
        assert_eq!(write(&plan, KIND_STATUS)["state"], "error");
        assert!(write(&plan, KIND_COMMENT)["body"]
            .as_str()
            .unwrap()
            .contains("without a parseable verdict"));
    }

    #[test]
    fn an_anchorless_unparseable_close_never_publishes_the_transcript() {
        // A Solo follow-up (@bot reply) whose settled text is a raw Kiro
        // transcript with no report anchor and no verdict must not be dumped
        // into the PR — infra-zeabur-system#208 leaked 7KB of tool log this way.
        let transcript =
            "✅ Running: gh pr diff 208\n<thinking>secret plan</thinking>\nanswer.md\n[done]";
        let parsed = parse_final_messages(&[transcript.into()]);
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(body.contains("without a parseable verdict"));
        assert!(
            !body.contains("Running") && !body.contains("thinking"),
            "raw transcript leaked into the comment: {body}"
        );
    }

    #[test]
    fn an_anchored_close_missing_only_its_trailer_keeps_the_report() {
        // The other no-trailer case: a real report (has the anchor) that just
        // failed to emit a verdict line. That body is trustworthy — keep it.
        let parsed = parse_final_messages(&[format!(
            "noise before\n{REPORT_START}\nThe report body says X."
        )]);
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(body.contains("The report body says X."));
        assert!(!body.contains("noise before"));
        assert!(body.contains("without a parseable verdict"));
    }

    #[test]
    fn an_ask_close_posts_only_a_plain_answer_comment() {
        // A follow-up (@bot <question>): the settled message is the answer.
        // No status, no review, no verdict warning — just the comment (SEI-929).
        let parsed = parse_final_messages(&[
            "Regarding F1: the mapping is keyed by request region, so cgk1 is correct.\n[done]"
                .into(),
        ]);
        let plan = plan_close(&target(), &parsed, None, "ses_ask", true);
        assert_eq!(kinds(&plan), [KIND_COMMENT]);
        assert_eq!(plan.decision, "ask");
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(body.contains("cgk1 is correct"));
        assert!(!body.contains("[done]"), "machine tail leaked: {body}");
        assert!(
            !body.contains("parseable verdict"),
            "ask has no verdict — must not warn: {body}"
        );
    }

    #[test]
    fn an_ask_close_strips_a_stray_verdict_trailer_the_model_added() {
        let parsed = parse_final_messages(&[
            "Short answer here.\n[[verdict:approve r=0 y=0 g=0]]\n[done]".into(),
        ]);
        let plan = plan_close(&target(), &parsed, None, "ses_ask", true);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(body.contains("Short answer here."));
        assert!(
            !body.contains("[[verdict:"),
            "verdict trailer leaked: {body}"
        );
        assert_eq!(kinds(&plan), [KIND_COMMENT]);
    }

    #[test]
    fn an_ask_answer_strips_leaked_machine_noise_lines() {
        // #395 F1: the template forbids tool narration, but if the agent emits
        // it anyway the known machine shapes (`✅ `…`` echoes, error banner) are
        // dropped as a fail-closed floor; the real answer survives.
        let parsed = parse_final_messages(&[concat!(
            "⚠️ **Internal Error** (code: -32603)\n",
            "✅ `Running: gh pr view 208`\n",
            "The answer is that cgk1 is a request region.\n",
            "✅ `Completing #1`\n",
            "[done]"
        )
        .into()]);
        let plan = plan_close(&target(), &parsed, None, "ses_ask", true);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(body.contains("cgk1 is a request region"));
        assert!(
            !body.contains("Running") && !body.contains("Internal Error") && !body.contains("✅"),
            "machine noise leaked: {body}"
        );
    }

    #[test]
    fn an_empty_ask_close_posts_a_notice_not_a_blank_comment() {
        let parsed = parse_final_messages(&["[done]".into()]);
        let plan = plan_close(&target(), &parsed, None, "ses_ask", true);
        let body = write(&plan, KIND_COMMENT)["body"].as_str().unwrap();
        assert!(body.contains("produced no answer"), "got: {body}");
    }

    #[test]
    /// A report whose prose anchor did not survive transport still publishes.
    /// The bot-side gateway clips an over-long chair report from the FRONT
    /// (a `…`-prefixed message), and the `<!-- openab-council -->` anchor sits
    /// at the front by protocol — so demanding it in the prose discarded three
    /// fully-deliberated verdicts in 50 minutes (nuphos#1232 r2, #1233 r4,
    /// #1237 r2). Provenance comes from the findings block, which survives at
    /// the tail together with the trailer; `comment_body` still refuses to
    /// publish unanchored raw text and falls back to the degraded body.
    #[test]
    fn a_report_without_its_prose_anchor_still_publishes_the_verdict() {
        for (verdict, counts) in [("approve", "r=0 y=0 g=0"), ("request_changes", "r=1 y=0 g=0")] {
            for prefix in [
                "",
                "<!-- openab-council -->\n",
                "<!-- openab-council -->\nReviewed at deadbeef\n",
            ] {
                let source = format!("{prefix}Report prose\n<!-- openab-findings\n{{\"head_sha\":\"0123456789abcdef0123456789abcdef01234567\",\"findings\":[]}}\n-->\n[[verdict:{verdict} {counts}]] [done]");
                let parsed = parse_final_messages(&[source]);
                let plan = plan_close(&target(), &parsed, None, "ses_incomplete", false);
                assert_eq!(kinds(&plan), [KIND_COMMENT, KIND_STATUS, KIND_REVIEW]);
                assert_ne!(write(&plan, KIND_STATUS)["state"], "error");
                assert_eq!(plan.decision, verdict);
                assert_eq!(
                    plan.verified_commit_id.as_deref(),
                    Some("0123456789abcdef0123456789abcdef01234567")
                );
            }
        }
    }

    /// The provenance gate that must stay: a findings block naming some other
    /// commit can never authorize a review on the webhook's head sha.
    #[test]
    fn a_findings_block_for_another_commit_still_fails_closed() {
        let parsed = parse_final_messages(&[concat!(
            "<!-- openab-council -->\nReport prose\n",
            "<!-- openab-findings\n{\"head_sha\":\"ffffffffffffffffffffffffffffffffffffffff\",\"findings\":[]}\n-->\n",
            "[[verdict:approve r=0 y=0 g=0]] [done]"
        )
        .into()]);
        let plan = plan_close(&target(), &parsed, None, "ses_mismatch", false);
        assert_eq!(plan.decision, "sha_integrity_failed");
        assert_eq!(plan.integrity_disposition, "reviewed_sha_mismatch");
        assert!(plan.verified_commit_id.is_none());
    }

    #[test]
    fn the_status_is_pinned_to_the_webhook_sha_not_the_one_the_chair_claims() {
        // An agent-named sha must never decide where a green status lands: it
        // could park one on a commit nobody reviewed (council F1, #305). The
        // claimed sha is still recorded — it describes what was read.
        let parsed = parse_final_messages(&[concat!(
            "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\nreport\n",
            "<!-- openab-findings\n",
            "{\"head_sha\":\"0123456789ABCDEF0123456789ABCDEF01234567\",\"findings\":[",
            "{\"id\":\"F1\",\"severity\":\"yellow\",\"title\":\"races\"}]}\n-->\n",
            "[[verdict:request_changes r=0 y=1 g=0]] [done]"
        )
        .into()]);
        let plan = plan_close(&target(), &parsed, None, "ses_t", false);
        assert_eq!(
            plan.head_sha.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            write(&plan, KIND_STATUS)["sha"],
            "0123456789abcdef0123456789abcdef01234567",
            "the status goes to the commit GitHub told us about"
        );
        assert_eq!(plan.findings.len(), 1);
        assert_eq!(plan.findings[0].stable_id, "F1");
    }

    #[test]
    fn a_known_comment_id_turns_the_comment_into_an_upsert() {
        let parsed = parse_final_messages(&["LGTM\n[[verdict:approve r=0 y=0 g=1]] [done]".into()]);
        let plan = plan_close(&target(), &parsed, Some(4242), "ses_t", false);
        assert_eq!(write(&plan, KIND_COMMENT)["comment_id"], 4242);
    }

    #[test]
    fn a_session_with_no_head_sha_anywhere_skips_the_status_rather_than_guessing() {
        let mut target = target();
        target.head_sha = None;
        let parsed = parse_final_messages(&["LGTM\n[[verdict:approve r=0 y=0 g=1]] [done]".into()]);
        let plan = plan_close(&target, &parsed, None, "ses_t", false);
        assert_eq!(kinds(&plan), [KIND_COMMENT]);
        assert_eq!(plan.decision, "sha_integrity_failed");
        assert!(plan.writes[0].1["body"]
            .as_str()
            .unwrap()
            .contains("missing_target"));
    }

    #[test]
    fn the_comment_drops_machine_tails_but_keeps_the_findings_block() {
        let parsed = parse_final_messages(&[concat!(
            "<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n## Verdict\n\nprose here\n\n",
            "<!-- openab-findings\n{\"head_sha\":\"0123456789ABCDEF0123456789ABCDEF01234567\",\"findings\":[]}\n-->\n",
            "[[verdict:approve r=0 y=0 g=0]] [done]"
        )
        .into()]);
        let body = write(
            &plan_close(&target(), &parsed, None, "ses_t", false),
            KIND_COMMENT,
        )["body"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(body.starts_with("<!-- openab-council -->\nReviewed at 0123456789abcdef0123456789abcdef01234567\n## Verdict"));
        assert!(
            body.contains("openab-findings"),
            "block is invisible, keep it"
        );
        assert!(!body.contains("[[verdict:"), "{body}");
        assert!(!body.contains("[done]"), "{body}");
    }
}
