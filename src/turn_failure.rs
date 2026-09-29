//! Migration adapter for failures that arrive as message text.
//!
//! OpenAB will eventually put a typed turn outcome on the gateway envelope.
//! Until every lane speaks that contract, this module is the single authority
//! for recognizing the legacy error frames that must not become review output.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyTurnFailureKind {
    SubscriptionDisabled,
    Protocol,
    LocalCapacity,
}

const CLAUDE_SUBSCRIPTION_DISABLED: &str =
    "your organization has disabled claude subscription access for claude code";

/// The runtime prepends this banner to a failed turn even when partial model
/// text follows. Chair synthesis uses the head-only predicate so clean verdict
/// prose can discuss protocol failures without invalidating itself.
pub fn starts_with_runtime_error_banner(content: &str) -> bool {
    let content = content.trim_start();
    let first_line = content.lines().next().unwrap_or_default().trim();
    let first_lower = first_line.to_ascii_lowercase();
    first_line.starts_with('\u{26a0}')
        && (first_lower.contains("-32603")
            || first_lower.contains("internal error")
            || first_lower.contains("service busy"))
}

/// Classify a settled legacy gateway frame without treating ordinary review
/// prose that merely discusses an error as a failed turn.
pub fn classify_legacy_turn_failure(content: &str) -> Option<LegacyTurnFailureKind> {
    let content = content.trim();
    if content.is_empty() {
        return None;
    }

    let lower = content.to_ascii_lowercase();
    let runtime_banner = starts_with_runtime_error_banner(content);

    if lower
        .lines()
        .next()
        .is_some_and(|line| line.starts_with('⚠') && line.contains("service busy"))
    {
        return Some(LegacyTurnFailureKind::LocalCapacity);
    }
    if runtime_banner && lower.contains(CLAUDE_SUBSCRIPTION_DISABLED) {
        return Some(LegacyTurnFailureKind::SubscriptionDisabled);
    }
    if runtime_banner {
        return Some(LegacyTurnFailureKind::Protocol);
    }

    // Older adapters sent a short plain error or a JSON-RPC object without the
    // warning banner. Keep that compatibility, but require an error-shaped
    // frame so long review prose mentioning -32603 remains valid.
    let error_shaped =
        content.len() <= 200 || lower.contains("jsonrpc") || lower.contains("\"code\"");
    if error_shaped && (content.contains("-32603") || lower.contains("internal error")) {
        return Some(LegacyTurnFailureKind::Protocol);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLAUDE_SUBSCRIPTION_DISABLED_FRAME: &str =
        include_str!("../tests/fixtures/claude-subscription-disabled.txt");

    #[test]
    fn production_subscription_disabled_frame_is_a_permanent_failure() {
        let frame = CLAUDE_SUBSCRIPTION_DISABLED_FRAME.trim_end();
        assert_eq!(frame.chars().count(), 446);
        assert_eq!(frame.len(), 452);
        assert_eq!(
            classify_legacy_turn_failure(frame),
            Some(LegacyTurnFailureKind::SubscriptionDisabled)
        );
    }

    #[test]
    fn review_prose_can_discuss_the_incident_without_becoming_an_error() {
        let prose = "The reviewer returned `Your organization has disabled Claude \
                     subscription access for Claude Code`; classify that response \
                     before quorum so the controller fails closed.";
        assert_eq!(classify_legacy_turn_failure(prose), None);
    }

    #[test]
    fn short_and_json_rpc_legacy_errors_remain_classified() {
        assert_eq!(
            classify_legacy_turn_failure("Internal error"),
            Some(LegacyTurnFailureKind::Protocol)
        );
        assert_eq!(
            classify_legacy_turn_failure(
                r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal Error"}}"#
            ),
            Some(LegacyTurnFailureKind::Protocol)
        );
    }
}
