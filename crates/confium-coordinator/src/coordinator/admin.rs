//! Coordinator admin API — privileged operations for operators.

use crate::coordinator::session::SessionState;
use serde::{Deserialize, Serialize};

/// Admin request types (require elevated privileges).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AdminRequest {
    /// Force-expire a specific session.
    ForceExpireSession { session_id: String },
    /// Drain: stop accepting new sessions, let active ones complete.
    Drain,
    /// List all sessions with their states.
    ListSessions,
    /// Purge all sessions for a quorum.
    PurgeQuorum { quorum_id: String },
    /// Get diagnostics report.
    GetDiagnostics,
}

/// Admin response types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdminResponse {
    /// Operation succeeded.
    Ok { message: String },
    /// Session was expired.
    SessionExpired { session_id: String },
    /// Drain initiated.
    Draining { active_sessions: usize },
    /// Session list.
    SessionList { sessions: Vec<SessionSummary> },
    /// Quorum purged.
    QuorumPurged { quorum_id: String, count: usize },
    /// Diagnostics report.
    Diagnostics { report_json: String },
    /// Error.
    Error { message: String },
}

/// Summary of a session for admin listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub state: String,
    pub threshold: u32,
    pub commitments: usize,
    pub shares: usize,
}

/// Errors during admin operations.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("operation not permitted")]
    NotPermitted,
}

/// Check if a requester has admin privileges. In production, this
/// would check an admin token or mTLS client cert.
pub fn is_admin(token: &str) -> bool {
    !token.is_empty() && token.starts_with("admin-")
}

/// Execute an admin request against the coordinator.
pub fn execute_admin(
    request: &AdminRequest,
    session_ids: &[String],
    session_states: &dyn Fn(&str) -> Option<SessionState>,
    session_threshold: &dyn Fn(&str) -> Option<u32>,
    session_commitments: &dyn Fn(&str) -> Option<usize>,
    session_shares: &dyn Fn(&str) -> Option<usize>,
) -> AdminResponse {
    match request {
        AdminRequest::ForceExpireSession { session_id } => {
            if !session_ids.contains(session_id) {
                return AdminResponse::Error {
                    message: format!("session not found: {session_id}"),
                };
            }
            AdminResponse::SessionExpired {
                session_id: session_id.clone(),
            }
        }
        AdminRequest::Drain => {
            let active = session_ids
                .iter()
                .filter(|sid| session_states(sid) == Some(SessionState::Pending))
                .count();
            AdminResponse::Draining {
                active_sessions: active,
            }
        }
        AdminRequest::ListSessions => {
            let sessions: Vec<SessionSummary> = session_ids
                .iter()
                .filter_map(|sid| {
                    let state = session_states(sid)?;
                    let threshold = session_threshold(sid).unwrap_or(0);
                    let commitments = session_commitments(sid).unwrap_or(0);
                    let shares = session_shares(sid).unwrap_or(0);
                    Some(SessionSummary {
                        session_id: sid.clone(),
                        state: format!("{state:?}"),
                        threshold,
                        commitments,
                        shares,
                    })
                })
                .collect();
            AdminResponse::SessionList { sessions }
        }
        AdminRequest::PurgeQuorum { quorum_id: _ } => AdminResponse::QuorumPurged {
            quorum_id: "placeholder".into(),
            count: 0,
        },
        AdminRequest::GetDiagnostics => AdminResponse::Diagnostics {
            report_json: "{}".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_token_check() {
        assert!(is_admin("admin-secret-123"));
        assert!(!is_admin(""));
        assert!(!is_admin("user-token"));
    }

    #[test]
    fn force_expire_unknown_session_errors() {
        let req = AdminRequest::ForceExpireSession {
            session_id: "x".into(),
        };
        let resp = execute_admin(&req, &[], &|_| None, &|_| None, &|_| None, &|_| None);
        match resp {
            AdminResponse::Error { .. } => {}
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn force_expire_known_session() {
        let req = AdminRequest::ForceExpireSession {
            session_id: "s1".into(),
        };
        let resp = execute_admin(
            &req,
            &["s1".into()],
            &|_| Some(SessionState::Pending),
            &|_| Some(2),
            &|_| Some(1),
            &|_| Some(0),
        );
        match resp {
            AdminResponse::SessionExpired { session_id } => assert_eq!(session_id, "s1"),
            _ => panic!("expected SessionExpired"),
        }
    }

    #[test]
    fn drain_counts_active() {
        let req = AdminRequest::Drain;
        let ids = vec!["s1".into(), "s2".into(), "s3".into()];
        let resp = execute_admin(
            &req,
            &ids,
            &|sid| {
                if sid == "s3" {
                    Some(SessionState::Completed)
                } else {
                    Some(SessionState::Pending)
                }
            },
            &|_| Some(2),
            &|_| Some(0),
            &|_| Some(0),
        );
        match resp {
            AdminResponse::Draining { active_sessions } => assert_eq!(active_sessions, 2),
            _ => panic!("expected Draining"),
        }
    }

    #[test]
    fn list_sessions_returns_summaries() {
        let req = AdminRequest::ListSessions;
        let ids = vec!["s1".into(), "s2".into()];
        let resp = execute_admin(
            &req,
            &ids,
            &|_| Some(SessionState::Pending),
            &|_| Some(2),
            &|sid| if sid == "s1" { Some(1) } else { Some(0) },
            &|_| Some(0),
        );
        match resp {
            AdminResponse::SessionList { sessions } => {
                assert_eq!(sessions.len(), 2);
                assert_eq!(sessions[0].commitments, 1);
            }
            _ => panic!("expected SessionList"),
        }
    }

    #[test]
    fn admin_request_serializes() {
        let req = AdminRequest::ForceExpireSession {
            session_id: "s1".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("force_expire_session"));
    }

    #[test]
    fn admin_response_serializes() {
        let resp = AdminResponse::Ok {
            message: "done".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ok"));
    }
}
