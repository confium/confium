//! Coordinator leader election — Raft-like leader election for HA.
//!
//! Multiple coordinator instances elect a leader via term-based voting.
//! The leader handles session creation; followers replicate state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Node role in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Follower,
    Candidate,
    Leader,
}

/// Vote request from a candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

/// Vote response from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

/// Election state for one coordinator instance.
#[derive(Debug, Clone)]
pub struct ElectionState {
    pub node_id: String,
    pub role: NodeRole,
    pub current_term: u64,
    pub voted_for: Option<String>,
    pub leader_id: Option<String>,
    pub last_heartbeat: DateTime<Utc>,
    pub cluster_size: usize,
    pub votes_received: HashMap<String, bool>,
}

impl ElectionState {
    pub fn new(node_id: String, cluster_size: usize) -> Self {
        Self {
            node_id,
            role: NodeRole::Follower,
            current_term: 0,
            voted_for: None,
            leader_id: None,
            last_heartbeat: Utc::now(),
            cluster_size,
            votes_received: HashMap::new(),
        }
    }

    pub fn become_follower(&mut self, term: u64, leader_id: Option<String>) {
        self.role = NodeRole::Follower;
        self.current_term = term;
        self.leader_id = leader_id;
        self.voted_for = None;
        self.last_heartbeat = Utc::now();
        self.votes_received.clear();
    }

    pub fn become_candidate(&mut self) {
        self.current_term += 1;
        self.role = NodeRole::Candidate;
        self.voted_for = Some(self.node_id.clone());
        self.leader_id = None;
        self.votes_received.clear();
        self.votes_received.insert(self.node_id.clone(), true);
        // Check if self-vote constitutes majority (single-node cluster)
        let votes = self.votes_received.values().filter(|&&v| v).count();
        let majority = self.cluster_size / 2 + 1;
        if votes >= majority {
            self.role = NodeRole::Leader;
            self.leader_id = Some(self.node_id.clone());
            self.last_heartbeat = Utc::now();
        }
    }

    pub fn become_leader(&mut self) {
        self.role = NodeRole::Leader;
        self.leader_id = Some(self.node_id.clone());
        self.last_heartbeat = Utc::now();
    }

    pub fn record_vote(&mut self, voter_id: &str, granted: bool) -> bool {
        self.votes_received.insert(voter_id.into(), granted);
        let votes = self.votes_received.values().filter(|&&v| v).count();
        let majority = self.cluster_size / 2 + 1;
        if votes >= majority && self.role == NodeRole::Candidate {
            self.become_leader();
            true
        } else {
            false
        }
    }

    pub fn handle_vote_request(&mut self, req: &VoteRequest) -> VoteResponse {
        if req.term > self.current_term {
            self.become_follower(req.term, None);
        }
        let grant = req.term >= self.current_term
            && (self.voted_for.is_none() || self.voted_for.as_deref() == Some(&req.candidate_id));
        if grant {
            self.voted_for = Some(req.candidate_id.clone());
        }
        VoteResponse {
            term: self.current_term,
            vote_granted: grant,
        }
    }

    pub fn handle_vote_response(&mut self, voter: &str, resp: VoteResponse) -> bool {
        if resp.term > self.current_term {
            self.become_follower(resp.term, None);
            return false;
        }
        self.record_vote(voter, resp.vote_granted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_node_is_follower() {
        let state = ElectionState::new("node-1".into(), 3);
        assert_eq!(state.role, NodeRole::Follower);
        assert_eq!(state.current_term, 0);
    }

    #[test]
    fn become_candidate_increments_term() {
        let mut state = ElectionState::new("node-1".into(), 3);
        state.become_candidate();
        assert_eq!(state.role, NodeRole::Candidate);
        assert_eq!(state.current_term, 1);
        assert_eq!(state.voted_for.as_deref(), Some("node-1"));
    }

    #[test]
    fn majority_votes_elects_leader() {
        let mut state = ElectionState::new("node-1".into(), 5);
        state.become_candidate();
        // Need 3 of 5 votes (self + 2)
        let resp1 = VoteResponse {
            term: 1,
            vote_granted: true,
        };
        assert!(!state.handle_vote_response("node-2", resp1));
        let resp2 = VoteResponse {
            term: 1,
            vote_granted: true,
        };
        assert!(state.handle_vote_response("node-3", resp2));
        assert_eq!(state.role, NodeRole::Leader);
    }

    #[test]
    fn higher_term_causes_stepdown() {
        let mut state = ElectionState::new("node-1".into(), 3);
        state.become_candidate();
        state.become_leader();
        let resp = VoteResponse {
            term: 10,
            vote_granted: false,
        };
        state.handle_vote_response("node-2", resp);
        assert_eq!(state.role, NodeRole::Follower);
        assert_eq!(state.current_term, 10);
    }

    #[test]
    fn vote_request_granted_when_not_voted() {
        let mut state = ElectionState::new("node-1".into(), 3);
        let req = VoteRequest {
            term: 1,
            candidate_id: "node-2".into(),
            last_log_index: 0,
            last_log_term: 0,
        };
        let resp = state.handle_vote_request(&req);
        assert!(resp.vote_granted);
        assert_eq!(state.voted_for.as_deref(), Some("node-2"));
    }

    #[test]
    fn vote_denied_for_lower_term() {
        let mut state = ElectionState::new("node-1".into(), 3);
        state.current_term = 5;
        let req = VoteRequest {
            term: 3,
            candidate_id: "node-2".into(),
            last_log_index: 0,
            last_log_term: 0,
        };
        let resp = state.handle_vote_request(&req);
        assert!(!resp.vote_granted);
    }

    #[test]
    fn become_leader_sets_leader_id() {
        let mut state = ElectionState::new("node-A".into(), 3);
        state.become_leader();
        assert_eq!(state.leader_id.as_deref(), Some("node-A"));
    }

    #[test]
    fn vote_serializes() {
        let req = VoteRequest {
            term: 1,
            candidate_id: "x".into(),
            last_log_index: 0,
            last_log_term: 0,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("candidate_id"));
    }

    #[test]
    fn single_node_cluster_wins_immediately() {
        let mut state = ElectionState::new("solo".into(), 1);
        state.become_candidate();
        assert_eq!(state.role, NodeRole::Leader);
    }

    #[test]
    fn denied_vote_does_not_elect() {
        let mut state = ElectionState::new("n1".into(), 3);
        state.become_candidate();
        let resp = VoteResponse {
            term: 1,
            vote_granted: false,
        };
        assert!(!state.handle_vote_response("n2", resp));
        assert_eq!(state.role, NodeRole::Candidate);
    }
}
