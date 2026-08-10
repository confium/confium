//! Policy engine — enforces access-control rules on session requests.
//!
//! The coordinator evaluates all registered rules before creating a
//! signing session. If any rule denies the request, the session is
//! rejected with a typed `PolicyDenial`.
//!
//! ## OCP design
//!
//! New rules are added by implementing the [`Rule`] trait — no existing
//! code is modified. The [`PolicyEngine`] collects rules and evaluates
//! them in order.

use crate::coordinator::session::SessionRequest;
use chrono::{DateTime, Timelike, Utc};

/// Context provided to rules during evaluation.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// Current time (injectable for testing).
    pub now: DateTime<Utc>,
    /// Active session count for the requesting quorum.
    pub quorum_active_sessions: usize,
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            quorum_active_sessions: 0,
        }
    }
}

/// Why a policy denied a request.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyDenial {
    /// Request falls outside the allowed time window.
    #[error("request outside allowed hours: {hour:02}:00 (allowed {start:02}:00–{end:02}:00)")]
    OutsideTimeWindow {
        /// The hour that was denied.
        hour: u32,
        /// Allowed start hour (inclusive).
        start: u32,
        /// Allowed end hour (exclusive).
        end: u32,
    },
    /// Too many concurrent sessions for this quorum.
    #[error("too many concurrent sessions: {active} (max {max})")]
    TooManySessions {
        /// Active session count.
        active: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Message exceeds size limit.
    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Threshold exceeds maximum allowed.
    #[error("threshold {threshold} exceeds maximum {max}")]
    ThresholdTooHigh {
        /// Requested threshold.
        threshold: u32,
        /// Maximum allowed.
        max: u32,
    },
}

/// A single policy rule. Implementations decide whether to allow
/// or deny a session request based on the request and context.
pub trait Rule: Send + Sync {
    /// Evaluate the rule. Returns `Ok(())` if allowed, `Err(PolicyDenial)` if denied.
    fn evaluate(&self, request: &SessionRequest, ctx: &PolicyContext) -> Result<(), PolicyDenial>;
}

/// Policy engine — evaluates a collection of rules.
pub struct PolicyEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl PolicyEngine {
    /// Create an empty policy engine.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    /// Evaluate all rules. Returns the first denial encountered, or
    /// `Ok(())` if all rules pass.
    pub fn evaluate(
        &self,
        request: &SessionRequest,
        ctx: &PolicyContext,
    ) -> Result<(), PolicyDenial> {
        for rule in &self.rules {
            rule.evaluate(request, ctx)?;
        }
        Ok(())
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Allow signing only during the specified hour range (UTC).
pub struct TimeWindowRule {
    /// Start hour (inclusive), 0–23.
    pub start_hour: u32,
    /// End hour (exclusive), 1–24.
    pub end_hour: u32,
}

impl Rule for TimeWindowRule {
    fn evaluate(&self, _request: &SessionRequest, ctx: &PolicyContext) -> Result<(), PolicyDenial> {
        let hour = ctx.now.hour();
        if hour >= self.start_hour && hour < self.end_hour {
            Ok(())
        } else {
            Err(PolicyDenial::OutsideTimeWindow {
                hour,
                start: self.start_hour,
                end: self.end_hour,
            })
        }
    }
}

/// Limit concurrent sessions per quorum.
pub struct MaxConcurrentSessionsRule {
    /// Maximum simultaneous active sessions.
    pub max: usize,
}

impl Rule for MaxConcurrentSessionsRule {
    fn evaluate(&self, _request: &SessionRequest, ctx: &PolicyContext) -> Result<(), PolicyDenial> {
        if ctx.quorum_active_sessions >= self.max {
            Err(PolicyDenial::TooManySessions {
                active: ctx.quorum_active_sessions,
                max: self.max,
            })
        } else {
            Ok(())
        }
    }
}

/// Enforce a maximum message size.
pub struct MessageSizeRule {
    /// Maximum message size in bytes.
    pub max_bytes: usize,
}

impl Rule for MessageSizeRule {
    fn evaluate(&self, request: &SessionRequest, _ctx: &PolicyContext) -> Result<(), PolicyDenial> {
        if request.message.len() > self.max_bytes {
            Err(PolicyDenial::MessageTooLarge {
                size: request.message.len(),
                max: self.max_bytes,
            })
        } else {
            Ok(())
        }
    }
}

/// Enforce a maximum threshold.
pub struct MaxThresholdRule {
    /// Maximum allowed threshold.
    pub max: u32,
}

impl Rule for MaxThresholdRule {
    fn evaluate(&self, request: &SessionRequest, _ctx: &PolicyContext) -> Result<(), PolicyDenial> {
        if request.threshold > self.max {
            Err(PolicyDenial::ThresholdTooHigh {
                threshold: request.threshold,
                max: self.max,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::session::SessionRequest;

    fn make_request(threshold: u32, message: Vec<u8>) -> SessionRequest {
        SessionRequest {
            quorum_id: "test-quorum".into(),
            scheme: "CMP20".into(),
            message,
            threshold,
            num_parties: 5,
            unlock_window_minutes: 60,
            requested_by: "tester".into(),
        }
    }

    #[test]
    fn empty_engine_allows_all() {
        let engine = PolicyEngine::new();
        let req = make_request(2, vec![0; 32]);
        let ctx = PolicyContext::default();
        assert!(engine.evaluate(&req, &ctx).is_ok());
    }

    #[test]
    fn time_window_allows_during_business_hours() {
        let rule = TimeWindowRule {
            start_hour: 9,
            end_hour: 17,
        };
        let req = make_request(2, vec![0; 32]);
        let mut ctx = PolicyContext::default();
        ctx.now = Utc::now()
            .with_hour(12)
            .unwrap();
        assert!(rule.evaluate(&req, &ctx).is_ok());
    }

    #[test]
    fn time_window_denies_outside_hours() {
        let rule = TimeWindowRule {
            start_hour: 9,
            end_hour: 17,
        };
        let req = make_request(2, vec![0; 32]);
        let mut ctx = PolicyContext::default();
        ctx.now = Utc::now()
            .with_hour(23)
            .unwrap();
        assert!(rule.evaluate(&req, &ctx).is_err());
    }

    #[test]
    fn max_sessions_denies_when_exceeded() {
        let rule = MaxConcurrentSessionsRule { max: 3 };
        let req = make_request(2, vec![0; 32]);
        let mut ctx = PolicyContext::default();
        ctx.quorum_active_sessions = 3;
        assert!(rule.evaluate(&req, &ctx).is_err());
    }

    #[test]
    fn max_sessions_allows_under_limit() {
        let rule = MaxConcurrentSessionsRule { max: 3 };
        let req = make_request(2, vec![0; 32]);
        let mut ctx = PolicyContext::default();
        ctx.quorum_active_sessions = 2;
        assert!(rule.evaluate(&req, &ctx).is_ok());
    }

    #[test]
    fn message_size_denies_too_large() {
        let rule = MessageSizeRule { max_bytes: 64 };
        let req = make_request(2, vec![0; 128]);
        let ctx = PolicyContext::default();
        assert!(rule.evaluate(&req, &ctx).is_err());
    }

    #[test]
    fn threshold_denies_too_high() {
        let rule = MaxThresholdRule { max: 5 };
        let req = make_request(7, vec![0; 32]);
        let ctx = PolicyContext::default();
        assert!(rule.evaluate(&req, &ctx).is_err());
    }

    #[test]
    fn multiple_rules_first_denial_wins() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(Box::new(MaxThresholdRule { max: 5 }));
        engine.add_rule(Box::new(MessageSizeRule { max_bytes: 64 }));

        let req = make_request(7, vec![0; 128]);
        let ctx = PolicyContext::default();
        let result = engine.evaluate(&req, &ctx);
        match result {
            Err(PolicyDenial::ThresholdTooHigh { threshold, .. }) => {
                assert_eq!(threshold, 7);
            }
            _ => panic!("expected ThresholdTooHigh"),
        }
    }

    #[test]
    fn multiple_rules_all_pass() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(Box::new(MaxThresholdRule { max: 10 }));
        engine.add_rule(Box::new(MessageSizeRule { max_bytes: 1024 }));
        engine.add_rule(Box::new(MaxConcurrentSessionsRule { max: 5 }));

        let req = make_request(3, vec![0; 32]);
        let ctx = PolicyContext {
            quorum_active_sessions: 2,
            ..Default::default()
        };
        assert!(engine.evaluate(&req, &ctx).is_ok());
    }
}
