pub mod verdict;

/// The v1 report gate only rejects the two shapes that are unambiguously not a
/// report: a very short settled turn and a bare tool/error echo. It deliberately
/// does not impose a report grammar; a concise human finding remains valid.
pub const MIN_REPORT_CHARS: usize = 20;

pub fn report_delivered(text: &str) -> bool {
    let text = text.trim();
    text.chars().count() >= MIN_REPORT_CHARS
        && crate::turn_failure::classify_legacy_turn_failure(text).is_none()
        && !is_bare_tool_echo(text)
}

/// Formal reviews require an explicit completed inspection, not just prose or
/// a transport done reaction. Blocked and partial turns omit this trailer.
pub fn review_report_delivered(text: &str) -> bool {
    let text = text
        .trim()
        .strip_suffix("[done]")
        .unwrap_or(text.trim())
        .trim_end();
    let Some(report) = text.strip_suffix("[[review:complete]]") else {
        return false;
    };
    report_delivered(report) && !report.contains("[[review:blocked]]")
}

fn is_bare_tool_echo(text: &str) -> bool {
    let first_line = text.lines().next().unwrap_or_default().trim();
    let lower = text.to_ascii_lowercase();
    let first_lower = lower.lines().next().unwrap_or_default().trim();
    let tool_marker = first_lower.starts_with("tool result")
        || first_lower.starts_with("tool output")
        || first_lower.starts_with("tool_result")
        || first_lower.starts_with("<tool_result")
        || first_lower.starts_with("{\"tool_result\"")
        || first_lower.starts_with("{\"type\":\"tool_result\"");
    let json_error = first_line.starts_with('{')
        && lower.contains("\"error\"")
        && (lower.contains("jsonrpc") || lower.contains("\"code\""));
    (tool_marker || json_error) && text.lines().count() <= 4
}

/// The review policy the kernel still owns, assembled once at the process
/// boundary.
///
/// Everything GitHub-shaped that used to live here — bot handle, repo
/// allowlist, round budget, hourly cap, review mode, preset — left with the
/// embedded ingress (ADR 031). `github-pr-controller` owns those now. What
/// remains is the standing roster the liveness/failover swap falls back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CouncilConfig {
    pub council_roster: Vec<String>,
}

impl Default for CouncilConfig {
    fn default() -> Self {
        Self {
            council_roster: vec!["chair".into(), "rev1".into(), "rev2".into()],
        }
    }
}

impl CouncilConfig {
    /// Build from an explicit key/value source. The composition root owns the
    /// actual environment lookup; this only owns normalization/defaults.
    pub(crate) fn from_values(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        let mut config = Self::default();
        config.council_roster = csv_value(lookup("OABCP_COUNCIL_ROSTER"))
            .filter(|roster| !roster.is_empty())
            .unwrap_or_else(|| config.council_roster.clone());
        config
    }
}

fn csv_value(value: Option<String>) -> Option<Vec<String>> {
    value.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect()
    })
}

/// Effective standing roster. A DB override lets operators replace bots
/// without restarting the control-plane; injected process configuration
/// remains the fallback and bootstrap source.
pub fn runtime_council_roster(
    state: &std::sync::Arc<crate::state::AppState>,
) -> anyhow::Result<(Vec<String>, &'static str)> {
    match state.store.standing_roster()? {
        Some(roster) => Ok((roster, "override")),
        None => Ok((state.council_config.council_roster.clone(), "config")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn formal_review_requires_completed_inspection_not_a_done_vote() {
        for report in [
            "Python is unavailable; security preflight blocked before inspection. [done]",
            "I will inspect the changed files next. [done]",
            "⚠️ Service Busy All agent sessions are in use, please try again shortly.\n[[review:complete]] [done]",
            "⚠️ Internal Error (code: -32603)\nPartial findings with enough content.\n[[review:complete]] [done]",
            "Inspection blocked by repository permissions. [[review:blocked]] [done]",
            "[[review:complete]] [done]",
        ] {
            assert!(!review_report_delivered(report), "{report}");
        }
        assert!(review_report_delivered(
            "Inspected auth.rs:42 and its callers; the token check is sound.\n[[review:complete]]\n[done]"
        ));
        assert!(!review_report_delivered(include_str!(
            "../../../tests/fixtures/claude-subscription-disabled.txt"
        )));
    }

    #[test]
    fn report_delivery_rejects_short_echoes_but_keeps_concise_findings() {
        assert!(!report_delivered("PONG [done]"));
        assert!(report_delivered("Nil input can panic."));
        assert!(report_delivered(
            "Risk: nil input can panic; add a guard before dereferencing."
        ));
        assert!(report_delivered(
            "One short finding: the retry path drops the request id."
        ));
    }

    #[test]
    fn report_delivery_rejects_bare_tool_echo_shapes() {
        assert!(!report_delivered(
            "tool_result: command completed successfully but returned no report"
        ));
        assert!(!report_delivered(
            r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal Error"}}"#
        ));
        assert!(!report_delivered(
            "{\n  \"jsonrpc\": \"2.0\",\n  \"error\": {\"code\": -32603}\n}"
        ));
    }

    #[test]
    fn report_delivery_rejects_the_production_subscription_failure() {
        let frame = include_str!("../../../tests/fixtures/claude-subscription-disabled.txt");
        assert!(!report_delivered(frame));
    }

    #[test]
    fn explicit_config_source_normalizes_every_review_policy_value() {
        let values = HashMap::from([
            ("OABCP_COUNCIL_ROSTER", "chair, security, tests"),
            // Retired with the embedded ingress — reading them must not
            // resurrect a field or panic.
            ("OABCP_BOT_HANDLE", " @nellen "),
            ("OABCP_ALLOWED_REPOS", "nuphos/core, nuphos/ops"),
            ("OABCP_REVIEW_ROUND_BUDGET", "7"),
            ("OABCP_COUNCIL_REVIEW_MODE", "enforce"),
        ]);
        let config = CouncilConfig::from_values(|name| values.get(name).map(|v| v.to_string()));

        assert_eq!(config.council_roster, vec!["chair", "security", "tests"]);
    }

    #[test]
    fn invalid_explicit_config_preserves_safe_defaults() {
        let values = HashMap::from([("OABCP_COUNCIL_ROSTER", " , ")]);
        let config = CouncilConfig::from_values(|name| values.get(name).map(|v| v.to_string()));

        assert_eq!(config, CouncilConfig::default());
    }
}
