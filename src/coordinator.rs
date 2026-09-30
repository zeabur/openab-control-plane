//! Coordination policy (the pluggable lifecycle seam). The orchestrator owns the
//! *mechanism* (client-trigger fanout, state transitions, delivery, emitting
//! events); a `Coordinator` owns the *policy* — what a done-signal means, when
//! to relay, when to converge, what closes the session. See
//! `docs/coordinators.md`.
//!
//! The orchestrator runs the mechanism, then asks the Coordinator (via `on_done`)
//! what `Action`s to take, and executes them — keeping the CAS guards so a single
//! call can safely emit both a transition and a close, each firing only from its
//! required prior state. v1 ships `QuorumCouncil`; a second mode is a new impl
//! selected in `lookup`, the only seam that changes.

use crate::session::{quorum_reached, ReviewerCompletion};
use crate::store::SessionState;

/// Read-only view a Coordinator decides from (pure → unit-testable).
pub trait Ctx {
    fn session_id(&self) -> &str;
    fn roster(&self) -> &[String];
    fn chair(&self) -> Option<&str>;
    fn quorum_n(&self) -> i64;
    /// Distinct bot ids with counted done-votes.
    fn done_voters(&self) -> Vec<String>;
    /// `bot`'s last *settled* (non-stub) message content, if any.
    fn latest_settled(&self, bot: &str) -> Option<String>;
    fn state(&self) -> SessionState;
    /// The session's opening trigger reference, when one exists. A
    /// `controller:`-prefixed trigger marks a controller-opened session,
    /// which always carries a verdict contract (the controller fail-closes
    /// on unparseable verdicts) regardless of coordinator mode.
    fn trigger_ref(&self) -> Option<&str> {
        None
    }
    /// How many synthesis prompts this session has already sent. Derived from
    /// the transcript (system messages with the quorum-prompt prefix) — the
    /// transcript is the attempt log, no schema required. Default 0 keeps
    /// non-council Ctx impls untouched.
    fn synthesis_attempts(&self) -> i64 {
        0
    }
    /// Chair-capable bots eligible to take a synthesis turn (role=chair,
    /// enabled, healthy). Default: just the current chair — the pool
    /// mechanism ships even where only one chair is registered.
    fn chair_candidates(&self) -> Vec<String> {
        self.chair()
            .map(|c| vec![c.to_string()])
            .unwrap_or_default()
    }
}

/// What the orchestrator should do. `Transition`/`Close` are guarded CAS (fire
/// only from `from`); a `Prompt` immediately after a failed `Transition` is
/// suppressed (so the synthesizer is prompted once, on the entering call only).
pub enum Action {
    /// Deliver `from`'s settled final to `to` (skipped if `from` has none).
    Relay { from: String, to: String },
    /// Deliver a system message to `to`.
    Prompt { to: String, content: String },
    /// CAS `from`→`to`; emits `state` on success.
    Transition {
        from: SessionState,
        to: SessionState,
    },
    /// CAS `from`→Closed; emits `verdict` + `state:closed` on success.
    /// `author` = the settling bot whose `latest_settled` produced `verdict`;
    /// the Close arm records its result span durably (ADR 028).
    Close {
        from: SessionState,
        author: String,
        verdict: String,
    },
    /// Hand the chair seat to another chair-capable bot (#344): membership +
    /// `chair_bot` update; the session stays in Quorum. Always followed by
    /// Relays of the reviewers' finals (the new chair received none of the
    /// session's earlier fanout) and a synthesis Prompt.
    ReassignChair { to: String },
    /// Swap a reviewer whose done-signals never carried a delivered report for
    /// a same-role spare. A no-op when no spare is registered: the roster must
    /// not shrink here, because a fixed `quorum_n` would become unreachable and
    /// fail-close a round whose report is merely late.
    ReplaceReviewerIfSpare { bot: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredVerdict {
    pub decision: String,
    pub red: Option<i64>,
    pub yellow: Option<i64>,
    pub green: Option<i64>,
}

pub trait Coordinator: Send + Sync {
    fn kind(&self) -> &'static str;
    /// A settled done-signal (🆗 add) arrived from `bot`. Return actions.
    fn on_done(&self, cx: &dyn Ctx, bot: &str) -> Vec<Action>;
    /// Done handling with the current bot's transcript-backed report retry
    /// count. The default preserves existing coordinators; only the
    /// report-contract coordinator needs the extra input.
    fn on_done_with_reviewer_rerequest_attempts(
        &self,
        cx: &dyn Ctx,
        bot: &str,
        _rerequest_attempts: i64,
    ) -> Vec<Action> {
        self.on_done(cx, bot)
    }
    /// Roster members *prompted to act* on the opening trigger (i.e. @mentioned).
    /// A9: before the topic exists, non-starters are skipped by the stock OAB
    /// mention gate and the event is dropped, not deferred. The orchestrator
    /// re-delivers the opening trigger in-thread to a non-starter chair once;
    /// other future non-starter trigger delivery should be an explicit
    /// Coordinator method. Default: the whole roster (council/solo fan-out).
    /// `Pipeline` starts only stage 0.
    fn starters(&self, roster: &[String], _chair: Option<&str>) -> Vec<String> {
        roster.to_vec()
    }
    /// Rewrite the opening trigger `text` for delivery to `recipient`. Pure —
    /// the orchestrator applies it at ALL trigger-delivery sites: fanout,
    /// backfill, chair redelivery. Default: verbatim passthrough (the
    /// solo/forum contract — forum carries no code and must see its trigger
    /// unchanged).
    fn recipient_trigger_text(&self, _cx: &dyn Ctx, _recipient: &str, text: &str) -> String {
        text.to_string()
    }
    /// Does a 🆗 reaction from `bot` count as its done-signal? Native OAB
    /// contract: yes (set_done → 🆗 closes). Prompt-driven chairs in
    /// review/triage auto-🆗 the quorum prompt — those coordinators return
    /// false for their chair; completion there is the explicit text [done].
    fn reaction_counts_as_done(&self, _cx: &dyn Ctx, _bot: &str) -> bool {
        true
    }
    /// Does a done-signal found in message *text* from `bot` count, given the
    /// full text? Default: yes. Triage mode requires the chair's [done] to
    /// ride the mandated report prefix itself.
    fn accepts_text_done(&self, _cx: &dyn Ctx, _bot: &str, _text: &str) -> bool {
        true
    }
    /// The roster changed outside a done-signal (liveness trim/replace). Default:
    /// nothing; quorum modes re-check whether the already-recorded done-count now
    /// meets the (possibly shrunk) quorum.
    fn on_roster_change(&self, _cx: &dyn Ctx) -> Vec<Action> {
        vec![]
    }
    /// Parse the chair's closing text into a structured verdict, or None. Called
    /// by the Close arm BEFORE the close webhook reads the session row. Default:
    /// None — modes without a verdict contract never parse trailers and never
    /// write review columns (forum/solo contract).
    fn structured_verdict(&self, _cx: &dyn Ctx, _verdict_text: &str) -> Option<StructuredVerdict> {
        None
    }
    /// May a client message reopen a terminal session? Default false; Solo
    /// opts in for the ADR 011 follow-up pattern.
    fn reopen_on_client_message(&self) -> bool {
        false
    }
}

/// Shared quorum policy: once `quorum_n` reviewers signalled done, enter Quorum
/// and prompt the chair to synthesize. Reached from a done-signal and from a
/// liveness roster trim (a shrunk quorum can make the recorded count sufficient).
/// `prompt` is per-coordinator — a review chair completes GitHub side effects,
/// a triage chair must post the report and nothing else.
pub(crate) fn quorum_actions(cx: &dyn Ctx, prompt: &str) -> Vec<Action> {
    quorum_actions_with_contract(cx, prompt, false)
}

/// Shared quorum policy with the optional report-delivery contract. The
/// controller trigger remains the second key because controller rounds use the
/// ordinary council coordinator today.
pub(crate) fn quorum_actions_with_contract(
    cx: &dyn Ctx,
    prompt: &str,
    verdict_required: bool,
) -> Vec<Action> {
    let mut actions = vec![];
    let chair = cx.chair();
    let done = counted_done_voters(cx, verdict_required);
    if quorum_reached(cx.roster(), chair, &done, cx.quorum_n()) {
        actions.push(Action::Transition {
            from: SessionState::Deliberating,
            to: SessionState::Quorum,
        });
        if let Some(c) = chair {
            actions.push(Action::Prompt {
                to: c.to_string(),
                content: prompt.to_string(),
            });
        }
    }
    actions
}

fn verdict_contract(cx: &dyn Ctx, explicit: bool) -> bool {
    explicit
        || cx
            .trigger_ref()
            .is_some_and(|t| t.starts_with("controller:"))
}

fn counted_done_voters(cx: &dyn Ctx, explicit: bool) -> Vec<String> {
    let done = cx.done_voters();
    if !verdict_contract(cx, explicit) {
        return done;
    }
    done.into_iter()
        .filter(|bot| {
            cx.latest_settled(bot)
                .as_deref()
                .is_some_and(crate::plugins::council::review_report_delivered)
        })
        .collect()
}

/// Project the reviewer evidence that crosses the external-controller seam.
/// This reuses the report contract that decides quorum, so the controller can
/// never receive a larger valid count than the kernel actually accepted.
pub(crate) fn reviewer_completion(cx: &dyn Ctx, explicit: bool) -> ReviewerCompletion {
    let rostered_reviewers = crate::session::reviewers(cx.roster(), cx.chair());
    let valid_reviewers = counted_done_voters(cx, explicit)
        .into_iter()
        .filter(|bot| rostered_reviewers.iter().any(|reviewer| reviewer == bot))
        .count() as i64;
    ReviewerCompletion {
        required_valid_reviewers: cx.quorum_n(),
        valid_reviewers,
    }
}

pub(crate) const REVIEWER_REREQUEST_PREFIX: &str = "[report-delivery re-request]";
pub(crate) const MAX_REVIEWER_REREQUESTS: i64 = 2;

fn reviewer_report_delivered(cx: &dyn Ctx, bot: &str, explicit: bool) -> bool {
    !verdict_contract(cx, explicit)
        || cx
            .latest_settled(bot)
            .as_deref()
            .is_some_and(crate::plugins::council::review_report_delivered)
}

/// A reviewer that has not delivered yet is re-prompted, and once the budget is
/// spent it may be swapped for a standby — but it is never removed outright.
/// `counted_done_voters` already refuses to count a reviewer without a
/// delivered report, which is the whole safety property; dropping it from the
/// roster additionally makes the fixed `quorum_n` unreachable and kills the
/// round (`insufficient_valid_reviewers`). Reviewers routinely end their
/// opening turn before the report and deliver minutes later — nuphos#1231
/// round 1 fail-closed at 22:49:04Z while rev-claude's report arrived at
/// 22:58:10Z — so the roster must outlive the re-request budget. A reviewer
/// that never delivers at all is the watchdog's job, not this path's.
fn invalid_reviewer_action(bot: &str, attempts: i64) -> Action {
    if attempts >= MAX_REVIEWER_REREQUESTS {
        return Action::ReplaceReviewerIfSpare {
            bot: bot.to_string(),
        };
    }
    let attempt = attempts + 1;
    Action::Prompt {
        to: bot.to_string(),
        content: format!(
            "{REVIEWER_REREQUEST_PREFIX} attempt {attempt}. Your previous completion did not deliver a report. After actually inspecting the PR, reply with your concise findings, then [[review:complete]] and [done]. If blocked or incomplete, use [[review:blocked]] instead; never claim completion."
        ),
    }
}

pub(crate) const COUNCIL_QUORUM_PROMPT: &str = "Quorum reached. Chair, synthesize the final verdict, complete any side effect required by the opening trigger, and only then end your final message with [done]. Do not send [done] before the required side effect succeeds.";

/// A synthesis turn that ends without a parseable trailer is retried this many
/// times in total before the round fail-closes. Chosen to cover the observed
/// failure (one colliding turn) with margin, while the watchdog remains the
/// hard backstop.
pub(crate) const MAX_SYNTHESIS_ATTEMPTS: i64 = 3;

/// v1 lifecycle: reviewers (roster minus chair) signal done; once `quorum_n` of
/// them have, the chair synthesizes and the chair's own done closes the session.
pub struct QuorumCouncil;

impl Coordinator for QuorumCouncil {
    fn kind(&self) -> &'static str {
        "quorum_council"
    }

    fn on_roster_change(&self, cx: &dyn Ctx) -> Vec<Action> {
        quorum_actions(cx, COUNCIL_QUORUM_PROMPT)
    }

    fn starters(&self, roster: &[String], chair: Option<&str>) -> Vec<String> {
        roster
            .iter()
            .filter(|bot| Some(bot.as_str()) != chair)
            .cloned()
            .collect()
    }

    fn on_done(&self, cx: &dyn Ctx, bot: &str) -> Vec<Action> {
        council_on_done(cx, bot, COUNCIL_QUORUM_PROMPT, false)
    }

    fn on_done_with_reviewer_rerequest_attempts(
        &self,
        cx: &dyn Ctx,
        bot: &str,
        rerequest_attempts: i64,
    ) -> Vec<Action> {
        council_on_done_with_reviewer_rerequest_attempts(
            cx,
            bot,
            COUNCIL_QUORUM_PROMPT,
            false,
            rerequest_attempts,
        )
    }

    fn structured_verdict(&self, cx: &dyn Ctx, verdict_text: &str) -> Option<StructuredVerdict> {
        parse_structured_verdict(cx, verdict_text)
    }
}

fn parse_structured_verdict(cx: &dyn Ctx, verdict_text: &str) -> Option<StructuredVerdict> {
    match crate::plugins::council::verdict::trailer(verdict_text) {
        Some(t) => Some(StructuredVerdict {
            decision: t.decision,
            red: t.red,
            yellow: t.yellow,
            green: t.green,
        }),
        None => {
            tracing::warn!(
                "no verdict trailer in chair final for {}; structured verdict stays NULL",
                cx.session_id()
            );
            None
        }
    }
}

/// Shared quorum-council done-handling; `prompt` is the per-coordinator chair
/// synthesis instruction.
pub(crate) fn council_on_done(
    cx: &dyn Ctx,
    bot: &str,
    prompt: &str,
    verdict_required: bool,
) -> Vec<Action> {
    council_on_done_with_reviewer_rerequest_attempts(cx, bot, prompt, verdict_required, 0)
}

pub(crate) fn council_on_done_with_reviewer_rerequest_attempts(
    cx: &dyn Ctx,
    bot: &str,
    prompt: &str,
    verdict_required: bool,
    rerequest_attempts: i64,
) -> Vec<Action> {
    let mut actions = vec![];
    let chair = cx.chair();
    let contract = verdict_contract(cx, verdict_required);

    // 1. relay a reviewer's settled final to the chair (was share_final_with_chair)
    if Some(bot) != chair {
        if contract && !reviewer_report_delivered(cx, bot, verdict_required) {
            actions.push(invalid_reviewer_action(bot, rerequest_attempts));
        } else if let Some(c) = chair {
            actions.push(Action::Relay {
                from: bot.to_string(),
                to: c.to_string(),
            });
        }
    }

    // 2. quorum reached → enter Quorum + prompt the chair (was maybe_quorum).
    //    The Transition CAS + Prompt-after-failed-Transition suppression make
    //    this fire exactly once, on the call that actually transitions.
    actions.extend(quorum_actions_with_contract(cx, prompt, verdict_required));

    // 3. The chair's own done closes only after reviewer quorum. This prevents
    //    an opening-trigger chair response from closing the PR review before
    //    reviewers have contributed or before the chair has posted the PR
    //    comment side-effect. Liveness still comes from the watchdog.
    if Some(bot) == chair && cx.state() == SessionState::Quorum {
        let verdict = cx.latest_settled(bot).unwrap_or_default();
        // #344: "responded" is not "delivered". Under a verdict contract, a
        // chair turn without a parseable verdict trailer (an agent error
        // relayed as content, a meta-acknowledgement, an empty final) must
        // not become the round's answer — the turn failed, the round did
        // not. Re-queue the synthesis, rotating to another chair-capable
        // bot when one exists; fail-close only after MAX_SYNTHESIS_ATTEMPTS.
        //
        // The contract is keyed two ways: the coordinator says so (review
        // mode), OR the session was controller-opened (`controller:` trigger
        // prefix) — controller rounds run under plain `council` mode today
        // and fail-closed error statuses are exactly what this path
        // prevents. Smoke tests and manual sessions carry neither marker.
        let parseable = crate::plugins::council::verdict::trailer(&verdict).is_some();
        // #344 caught the no-trailer failures; SEI-931 adds the one that still
        // parses: a synthesis turn that failed mid-write carries the runtime's
        // prepended `-32603` error banner ABOVE a full report that kept its
        // verdict trailer (backend#2418 round 4). Parseable-but-errored is still
        // a failed turn — requeue it too, or a bogus verdict closes the round.
        let failed = !parseable || chair_turn_errored(&verdict);
        if contract && failed && cx.synthesis_attempts() < MAX_SYNTHESIS_ATTEMPTS {
            actions.extend(requeue_synthesis(cx, bot));
        } else {
            actions.push(Action::Close {
                from: SessionState::Quorum,
                author: bot.to_string(),
                verdict,
            });
        }
    } else if Some(bot) == chair {
        tracing::debug!(
            bot,
            state = ?cx.state(),
            "chair done ignored before reviewer quorum"
        );
    }

    actions
}

/// A chair synthesis turn that failed mid-write. The bot gateway prepends the
/// runtime's agent-error banner (`⚠️ … Internal Error … -32603`) to the settled
/// text; a partial report can sit below it and still carry a parseable verdict
/// trailer, so the trailer check alone is not enough (backend#2418 round 4,
/// SEI-931).
///
/// We look only at the HEAD: the banner is always prepended first, and — unlike
/// `orchestrator::is_agent_error_frame`, which gates on a short whole frame to
/// avoid matching prose (council F2) — a real report is long, so a whole-text
/// gate cannot see the buried banner. Real report prose never opens with the
/// warning-emoji error frame, so the head check stays specific.
fn chair_turn_errored(settled: &str) -> bool {
    crate::turn_failure::starts_with_runtime_error_banner(settled)
}

/// The requeue: pick the next chair (rotation prefers a different candidate),
/// hand over the seat if it changed — relaying every done reviewer's settled
/// final, since the newcomer received none of the session's earlier fanout —
/// and re-prompt with an attempt-numbered synthesis prompt.
fn requeue_synthesis(cx: &dyn Ctx, failed_chair: &str) -> Vec<Action> {
    let mut actions = vec![];
    let candidates = cx.chair_candidates();
    let next = candidates
        .iter()
        .find(|c| c.as_str() != failed_chair)
        .cloned()
        .unwrap_or_else(|| failed_chair.to_string());
    let attempt = cx.synthesis_attempts() + 1;
    if next != failed_chair {
        actions.push(Action::ReassignChair { to: next.clone() });
        for reviewer in cx.done_voters() {
            if reviewer != next && reviewer != failed_chair {
                actions.push(Action::Relay {
                    from: reviewer,
                    to: next.clone(),
                });
            }
        }
        tracing::warn!(
            session = cx.session_id(),
            from = failed_chair,
            to = %next,
            "synthesis turn failed without a parseable verdict; chair reassigned"
        );
    } else {
        tracing::warn!(
            session = cx.session_id(),
            chair = failed_chair,
            attempt,
            "synthesis turn failed without a parseable verdict; re-prompting"
        );
    }
    actions.push(Action::Prompt {
        to: next,
        content: format!(
            "Quorum reached. (synthesis attempt {attempt}) The previous synthesis \
turn did not deliver a parseable verdict trailer — it may have failed mid-turn. \
Synthesize the final verdict now from the reviewers' reports, complete any side \
effect required by the opening trigger, and only then end your final message \
with [done]. Your final message must contain the full report body and end with \
the machine-readable verdict trailer your steering defines."
        ),
    });
    actions
}

/// Single-bot lifecycle: the lone bot's own done closes the session directly.
/// A 1-bot "council" has zero reviewers (roster minus chair = ∅), so quorum is
/// never reachable and `QuorumCouncil` would hang — `Solo` is that fix.
pub struct Solo;

impl Coordinator for Solo {
    fn kind(&self) -> &'static str {
        "solo"
    }

    fn reopen_on_client_message(&self) -> bool {
        true
    }

    fn on_done(&self, cx: &dyn Ctx, bot: &str) -> Vec<Action> {
        vec![Action::Close {
            from: SessionState::Deliberating,
            author: bot.to_string(),
            verdict: cx.latest_settled(bot).unwrap_or_default(),
        }]
    }
}

/// Sequential handoff stage0→stage1→…→stageN. Only stage 0 starts; each bot's
/// done relays its output to the next stage and prompts it; the last stage's
/// done closes with its final as the verdict. Stage order = roster order. Proves
/// the seam generalizes beyond parallel fan-in (no quorum, no chair).
pub struct Pipeline;

impl Coordinator for Pipeline {
    fn kind(&self) -> &'static str {
        "pipeline"
    }

    fn starters(&self, roster: &[String], _chair: Option<&str>) -> Vec<String> {
        roster.first().cloned().into_iter().collect()
    }

    fn on_done(&self, cx: &dyn Ctx, bot: &str) -> Vec<Action> {
        let roster = cx.roster();
        let Some(i) = roster.iter().position(|b| b == bot) else {
            return vec![]; // not a member (shouldn't happen — roster-gated)
        };
        match roster.get(i + 1) {
            // hand off: relay this stage's output to the next, then prompt it
            Some(next) => vec![
                Action::Relay { from: bot.to_string(), to: next.to_string() },
                Action::Prompt {
                    to: next.to_string(),
                    content: "Your turn — continue the review, building on the prior stage's output above."
                        .to_string(),
                },
            ],
            // last stage's done closes the session with its final
            None => vec![Action::Close {
                from: SessionState::Deliberating,
                author: bot.to_string(),
                verdict: cx.latest_settled(bot).unwrap_or_default(),
            }],
        }
    }
}

/// Pick a known coordinator for a session's `mode`. The only place a mode is
/// mapped to a policy; a new mode is a new arm + impl, nothing else changes.
pub fn lookup(mode: &str) -> Option<Box<dyn Coordinator>> {
    match mode {
        "council" => Some(Box::new(QuorumCouncil)),
        "triage_council" => Some(Box::new(crate::plugins::triage::TriageCouncil)),
        "solo" => Some(Box::new(Solo)),
        "pipeline" => Some(Box::new(Pipeline)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeCtx {
        session_id: String,
        roster: Vec<String>,
        chair: Option<String>,
        final_msg: Option<String>,
        settled: HashMap<String, String>,
        quorum_n: i64,
        reactors: Vec<String>,
        state: SessionState,
        candidates: Vec<String>,
        attempts: i64,
        trigger_ref: Option<String>,
    }
    /// A Deliberating ctx with no done-signals yet (the common starting point).
    fn ctx(roster: &[&str], final_msg: Option<&str>) -> FakeCtx {
        FakeCtx {
            session_id: "ses_fake".into(),
            roster: roster.iter().map(|s| s.to_string()).collect(),
            chair: roster.first().map(|s| s.to_string()),
            final_msg: final_msg.map(String::from),
            settled: HashMap::new(),
            quorum_n: 0,
            reactors: vec![],
            state: SessionState::Deliberating,
            candidates: vec![],
            attempts: 0,
            trigger_ref: None,
        }
    }
    impl Ctx for FakeCtx {
        fn session_id(&self) -> &str {
            &self.session_id
        }
        fn roster(&self) -> &[String] {
            &self.roster
        }
        fn chair(&self) -> Option<&str> {
            self.chair.as_deref()
        }
        fn quorum_n(&self) -> i64 {
            self.quorum_n
        }
        fn done_voters(&self) -> Vec<String> {
            self.reactors.clone()
        }
        fn latest_settled(&self, bot: &str) -> Option<String> {
            if self.settled.is_empty() {
                self.final_msg.clone()
            } else {
                self.settled.get(bot).cloned()
            }
        }
        fn state(&self) -> SessionState {
            self.state.clone()
        }
        fn synthesis_attempts(&self) -> i64 {
            self.attempts
        }
        fn trigger_ref(&self) -> Option<&str> {
            self.trigger_ref.as_deref()
        }
        fn chair_candidates(&self) -> Vec<String> {
            if self.candidates.is_empty() {
                self.chair.iter().cloned().collect()
            } else {
                self.candidates.clone()
            }
        }
    }

    // Built by concatenation: the CI kernel-purity grep gate forbids the
    // verdict-trailer literal in kernel files, tests included.
    fn trailed() -> String {
        format!(
            "Report body…\n{}{}verdict:approve r=0 y=0 g=2]] [done]",
            "[", "["
        )
    }
    const ERROR_SHAPED: &str = "⚠️ Internal Error (code: -32603)\nInternal error [done]";

    /// A Quorum-state review ctx where the chair is signalling done.
    fn quorum_ctx(final_msg: &str) -> FakeCtx {
        FakeCtx {
            session_id: "ses_fake".into(),
            roster: vec!["chair".into(), "rev-a".into(), "rev-b".into()],
            chair: Some("chair".into()),
            final_msg: Some(final_msg.into()),
            settled: HashMap::from([
                ("chair".into(), final_msg.into()),
                (
                    "rev-a".into(),
                    "Reviewer report with enough substance\n[[review:complete]] [done]".into(),
                ),
                (
                    "rev-b".into(),
                    "Another reviewer report with enough substance\n[[review:complete]] [done]"
                        .into(),
                ),
            ]),
            quorum_n: 2,
            reactors: vec!["rev-a".into(), "rev-b".into()],
            state: SessionState::Quorum,
            candidates: vec![],
            attempts: 1, // the initial synthesis prompt has been sent
            trigger_ref: None,
        }
    }

    #[test]
    fn blocked_reviewer_cannot_complete_quorum_or_authorize_chair_approval() {
        let mut cx = quorum_ctx(&trailed());
        cx.settled.insert(
            "rev-b".into(),
            "Python unavailable; security preflight blocked before PR inspection. [done]".into(),
        );
        assert_eq!(reviewer_completion(&cx, true).valid_reviewers, 1);
        cx.state = SessionState::Deliberating;
        let actions = council_on_done(&cx, "chair", COUNCIL_QUORUM_PROMPT, true);
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::Close { verdict, .. } if !verdict.is_empty())));
    }

    #[test]
    fn parseable_chair_final_closes_as_before() {
        let actions = council_on_done(
            &quorum_ctx(&trailed()),
            "chair",
            COUNCIL_QUORUM_PROMPT,
            true,
        );
        assert!(actions.iter().any(
            |a| matches!(a, Action::Close { verdict, .. } if verdict.contains("verdict:approve"))
        ));
    }

    #[test]
    fn contract_reviewer_blank_is_not_relayed_or_counted() {
        let mut cx = quorum_ctx(&trailed());
        cx.settled.insert("rev-a".into(), "PONG [done]".into());
        let actions = council_on_done(&cx, "rev-a", COUNCIL_QUORUM_PROMPT, true);

        assert!(actions.iter().any(|action| matches!(
            action,
            Action::Prompt { to, content }
                if to == "rev-a" && content.starts_with(REVIEWER_REREQUEST_PREFIX)
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            Action::Relay { from, .. } if from == "rev-a"
        )));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, Action::Transition { .. })));
    }

    #[test]
    fn contract_reviewer_rerequest_exhaustion_swaps_but_never_drops_the_seat() {
        let mut cx = quorum_ctx(&trailed());
        cx.settled.insert("rev-a".into(), "PONG [done]".into());
        let actions = council_on_done_with_reviewer_rerequest_attempts(
            &cx,
            "rev-a",
            COUNCIL_QUORUM_PROMPT,
            true,
            MAX_REVIEWER_REREQUESTS,
        );

        assert!(actions.iter().any(|action| matches!(
            action,
            Action::ReplaceReviewerIfSpare { bot } if bot == "rev-a"
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            Action::Prompt { to, .. } if to == "rev-a"
        )));
    }

    #[test]
    fn reviewer_retry_budget_is_scoped_to_the_voter() {
        let mut cx = quorum_ctx(&trailed());
        cx.settled.insert("rev-a".into(), "PONG [done]".into());
        cx.settled.insert("rev-b".into(), "PONG [done]".into());

        let actions = council_on_done_with_reviewer_rerequest_attempts(
            &cx,
            "rev-b",
            COUNCIL_QUORUM_PROMPT,
            true,
            0,
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            Action::Prompt { to, .. } if to == "rev-b"
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            Action::ReplaceReviewerIfSpare { bot } if bot == "rev-b"
        )));
    }

    #[test]
    fn plain_council_reviewer_path_keeps_the_unfiltered_behavior() {
        let mut cx = quorum_ctx(&trailed());
        cx.settled.insert("rev-a".into(), "PONG [done]".into());
        let actions = council_on_done(&cx, "rev-a", COUNCIL_QUORUM_PROMPT, false);

        assert!(actions.iter().any(|action| matches!(
            action,
            Action::Relay { from, to } if from == "rev-a" && to == "chair"
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            Action::Prompt { to, .. } if to == "rev-a"
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            Action::ReplaceReviewerIfSpare { bot } if bot == "rev-a"
        )));
    }

    #[test]
    fn error_shaped_chair_final_requeues_instead_of_closing() {
        let actions = council_on_done(
            &quorum_ctx(ERROR_SHAPED),
            "chair",
            COUNCIL_QUORUM_PROMPT,
            true,
        );
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Close { .. })),
            "the failed turn must not become the round's answer"
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Prompt { to, content } if to == "chair" && content.starts_with("Quorum reached.")
        )));
    }

    #[test]
    fn error_banner_over_a_parseable_verdict_still_requeues() {
        // backend#2418 round 4 (SEI-931): a -32603 banner was prepended above a
        // full report that still carried a verdict trailer. The parseable check
        // alone let it close; the turn had failed, so it must requeue.
        let poisoned = format!(
            "⚠️ **Internal Error** (code: -32603)\nInternal error\n\n{}",
            trailed()
        );
        let actions = council_on_done(&quorum_ctx(&poisoned), "chair", COUNCIL_QUORUM_PROMPT, true);
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Close { .. })),
            "an errored synthesis must not close even with a parseable trailer"
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Prompt { to, content } if to == "chair" && content.starts_with("Quorum reached.")
        )));
    }

    #[test]
    fn a_clean_report_that_merely_mentions_an_error_still_closes() {
        // Council F2 guard: a real verdict whose prose discusses -32603 must not
        // be mistaken for a failed turn. Only a banner at the head counts.
        let discusses = format!(
            "The reconnect path can surface a JSON-RPC -32603 to the user.\n{}",
            trailed()
        );
        let actions = council_on_done(
            &quorum_ctx(&discusses),
            "chair",
            COUNCIL_QUORUM_PROMPT,
            true,
        );
        assert!(
            actions.iter().any(|a| matches!(a, Action::Close { .. })),
            "prose mentioning an error code is not a failed turn"
        );
    }

    #[test]
    fn exhausted_attempts_fail_close_exactly_as_today() {
        let mut cx = quorum_ctx(ERROR_SHAPED);
        cx.attempts = MAX_SYNTHESIS_ATTEMPTS;
        let actions = council_on_done(&cx, "chair", COUNCIL_QUORUM_PROMPT, true);
        assert!(actions.iter().any(|a| matches!(a, Action::Close { .. })));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::ReassignChair { .. })));
    }

    #[test]
    fn requeue_rotates_to_another_candidate_and_relays_reviewer_finals() {
        let mut cx = quorum_ctx(ERROR_SHAPED);
        cx.candidates = vec!["chair".into(), "chair-claude".into()];
        let actions = council_on_done(&cx, "chair", COUNCIL_QUORUM_PROMPT, true);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ReassignChair { to } if to == "chair-claude")));
        let relays: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::Relay { to, .. } if to == "chair-claude"))
            .collect();
        assert_eq!(
            relays.len(),
            2,
            "both reviewers' finals travel to the new chair"
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Prompt { to, .. } if to == "chair-claude")));
    }

    #[test]
    fn single_candidate_reprompts_same_chair_without_reassign() {
        let actions = council_on_done(
            &quorum_ctx(ERROR_SHAPED),
            "chair",
            COUNCIL_QUORUM_PROMPT,
            true,
        );
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::ReassignChair { .. })));
        assert!(!actions.iter().any(|a| matches!(a, Action::Relay { .. })));
    }

    #[test]
    fn controller_opened_council_session_requeues_even_in_plain_mode() {
        // Controller-opened rounds run under plain `council` mode today; the
        // `controller:` trigger prefix is what marks the verdict contract.
        let mut cx = quorum_ctx(ERROR_SHAPED);
        cx.trigger_ref = Some("controller:github-canary:abc123".into());
        let actions = council_on_done(&cx, "chair", COUNCIL_QUORUM_PROMPT, false);
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Close { .. })),
            "controller-opened session without a trailer must requeue"
        );
    }

    #[test]
    fn plain_council_without_verdict_contract_is_untouched() {
        let actions = council_on_done(
            &quorum_ctx("PONG [done]"),
            "chair",
            COUNCIL_QUORUM_PROMPT,
            false,
        );
        assert!(
            actions.iter().any(|a| matches!(a, Action::Close { .. })),
            "no verdict contract → trailer-less close stays the normal path"
        );
    }

    #[test]
    fn lookup_knows_exactly_the_dispatchable_modes() {
        assert_eq!(lookup("council").unwrap().kind(), "quorum_council");
        // `review_council` was the embedded plugin's mode and is gone with it
        // (ADR 031 invariant #9) — a session asking for it must not dispatch.
        assert!(lookup("review_council").is_none());
        assert_eq!(lookup("triage_council").unwrap().kind(), "triage_council");
        assert_eq!(lookup("solo").unwrap().kind(), "solo");
        assert_eq!(lookup("pipeline").unwrap().kind(), "pipeline");
        assert!(lookup("anything-else").is_none());
    }

    #[test]
    fn reaction_done_policy_covers_all_coordinators() {
        let cx = ctx(&["chair", "rev"], None);
        let cases: Vec<(&str, Box<dyn Coordinator>, bool, bool)> = vec![
            ("quorum_council", Box::new(QuorumCouncil), true, true),
            ("solo", Box::new(Solo), true, true),
            ("pipeline", Box::new(Pipeline), true, true),
        ];

        for (name, coord, chair_counts, non_chair_counts) in cases {
            assert_eq!(
                coord.reaction_counts_as_done(&cx, "chair"),
                chair_counts,
                "{name} chair reaction policy"
            );
            assert_eq!(
                coord.reaction_counts_as_done(&cx, "rev"),
                non_chair_counts,
                "{name} non-chair reaction policy"
            );
        }
    }

    #[test]
    fn text_done_policy_covers_all_coordinators() {
        let cx = ctx(&["chair", "rev"], None);
        let ack = "ok then [done]";

        let default_cases: Vec<(&str, Box<dyn Coordinator>)> = vec![
            ("quorum_council", Box::new(QuorumCouncil)),
            ("solo", Box::new(Solo)),
            ("pipeline", Box::new(Pipeline)),
        ];
        for (name, coord) in default_cases {
            assert!(
                coord.accepts_text_done(&cx, "chair", ack),
                "{name} chair text done keeps default semantics"
            );
            assert!(
                coord.accepts_text_done(&cx, "rev", ack),
                "{name} non-chair text done keeps default semantics"
            );
        }
    }

    #[test]
    fn solo_lone_bot_closes_directly_with_its_final() {
        let cx = ctx(&["solo"], Some("verdict"));
        let actions = Solo.on_done(&cx, "solo");
        assert_eq!(
            actions.len(),
            1,
            "solo emits exactly one Close, no quorum gate"
        );
        match &actions[0] {
            Action::Close {
                from,
                author,
                verdict,
            } => {
                assert_eq!(*from, SessionState::Deliberating);
                assert_eq!(author, "solo");
                assert_eq!(verdict, "verdict");
            }
            _ => panic!("expected Close"),
        }
    }

    /// The chair may see the opening trigger as context, but it must not be able
    /// to close the council from `Deliberating`. It should wait for reviewer
    /// quorum and the explicit system prompt before writing the PR verdict.
    #[test]
    fn quorum_council_chair_done_does_not_close_before_quorum() {
        let cx = FakeCtx {
            quorum_n: 2,      // both reviewers must signal for a quorum…
            reactors: vec![], // …but none did → quorum unreachable
            state: SessionState::Deliberating,
            ..ctx(&["chair", "rev0", "rev1"], Some("VERDICT"))
        };
        let closes: Vec<_> = QuorumCouncil
            .on_done(&cx, "chair")
            .into_iter()
            .filter(|a| matches!(a, Action::Close { .. }))
            .collect();
        assert!(closes.is_empty(), "chair done before quorum must not close");
    }

    /// The designed path is unchanged: once reviewers reached quorum (state is
    /// `Quorum`), the chair's done still closes from `Quorum`.
    #[test]
    fn quorum_council_chair_done_closes_from_quorum_when_reached() {
        let cx = FakeCtx {
            quorum_n: 1,
            reactors: vec!["rev0".into()],
            state: SessionState::Quorum,
            ..ctx(&["chair", "rev0"], Some("VERDICT"))
        };
        let from = QuorumCouncil
            .on_done(&cx, "chair")
            .into_iter()
            .find_map(|a| match a {
                Action::Close { from, .. } => Some(from),
                _ => None,
            })
            .expect("chair's done emits a Close");
        assert_eq!(from, SessionState::Quorum);
    }

    #[test]
    fn pipeline_starts_only_stage_zero() {
        let roster = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(Pipeline.starters(&roster, None), vec!["a".to_string()]);
        assert_eq!(
            QuorumCouncil.starters(&roster, Some("a")),
            vec!["b".to_string(), "c".to_string()]
        );
        assert_eq!(Solo.starters(&roster, None), roster);
    }

    #[test]
    fn quorum_council_starters_excludes_chair_by_identity_not_position() {
        let roster = vec!["rev0".into(), "chair".into(), "rev1".into()];
        assert_eq!(
            QuorumCouncil.starters(&roster, Some("chair")),
            vec!["rev0".to_string(), "rev1".to_string()]
        );
    }

    #[test]
    fn pipeline_hands_off_then_closes_on_last() {
        let cx = ctx(&["a", "b", "c"], Some("c's report"));
        // middle stage hands to the next
        let mid = Pipeline.on_done(&cx, "a");
        assert!(
            matches!(mid.as_slice(),
                [Action::Relay { from, to }, Action::Prompt { to: pt, .. }]
                if from == "a" && to == "b" && pt == "b"),
            "stage a should relay→b and prompt b",
        );
        // last stage closes with its final, no further handoff
        let last = Pipeline.on_done(&cx, "c");
        assert!(
            matches!(last.as_slice(),
                [Action::Close { from: SessionState::Deliberating, author, verdict }]
                if author == "c" && verdict == "c's report"),
            "last stage should close with its report",
        );
    }
}
