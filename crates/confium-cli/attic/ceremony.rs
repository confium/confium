// `confium ceremony` — key ceremony orchestration.
//
// Manages the lifecycle of a threshold key generation ceremony:
// init → join → run → finalize.

use crate::cli::{CeremonyAction, CeremonyArgs};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Ceremony lifecycle states.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyState {
    /// Created, waiting for parties to join.
    Init,
    /// All parties joined, ready to run.
    Ready,
    /// DKG in progress.
    Running,
    /// Shares produced successfully.
    Completed,
    /// Ceremony failed or was cancelled.
    Aborted,
}

/// A participant in the ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Signer identity.
    pub signer_id: String,
    /// When they joined.
    pub joined_at: chrono::DateTime<Utc>,
}

/// Persisted ceremony state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyStatus {
    /// Ceremony identifier.
    pub ceremony_id: String,
    /// Quorum this ceremony is for.
    pub quorum_id: String,
    /// Threshold scheme (e.g., "CMP20", "FROST-P256").
    pub scheme: String,
    /// Threshold T.
    pub threshold: u32,
    /// Total party count N.
    pub party_count: u32,
    /// Current lifecycle state.
    pub state: CeremonyState,
    /// Participants who have joined.
    pub participants: Vec<Participant>,
    /// When the ceremony was created.
    pub created_at: chrono::DateTime<Utc>,
    /// When the ceremony completed (if done).
    pub completed_at: Option<chrono::DateTime<Utc>>,
}

impl CeremonyStatus {
    /// Create a new ceremony in the Init state.
    pub fn new(
        ceremony_id: &str,
        quorum_id: &str,
        scheme: &str,
        threshold: u32,
        party_count: u32,
    ) -> Self {
        Self {
            ceremony_id: ceremony_id.into(),
            quorum_id: quorum_id.into(),
            scheme: scheme.into(),
            threshold,
            party_count,
            state: CeremonyState::Init,
            participants: Vec::new(),
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    /// A party joins the ceremony.
    pub fn join(&mut self, signer_id: &str) -> Result<(), String> {
        if self.state != CeremonyState::Init {
            return Err(format!("ceremony is in state {:?}, not Init", self.state));
        }
        if self.participants.iter().any(|p| p.signer_id == signer_id) {
            return Err(format!("signer {signer_id} already joined"));
        }
        if self.participants.len() >= self.party_count as usize {
            return Err(format!(
                "ceremony is full ({}/{})",
                self.participants.len(),
                self.party_count
            ));
        }
        self.participants.push(Participant {
            signer_id: signer_id.into(),
            joined_at: Utc::now(),
        });
        if self.participants.len() == self.party_count as usize {
            self.state = CeremonyState::Ready;
        }
        Ok(())
    }

    /// Transition to Running state.
    pub fn start_run(&mut self) -> Result<(), String> {
        if self.state != CeremonyState::Ready {
            return Err(format!("ceremony is in state {:?}, not Ready", self.state));
        }
        self.state = CeremonyState::Running;
        Ok(())
    }

    /// Mark the ceremony as completed.
    pub fn complete(&mut self) -> Result<(), String> {
        if self.state != CeremonyState::Running {
            return Err(format!(
                "ceremony is in state {:?}, not Running",
                self.state
            ));
        }
        self.state = CeremonyState::Completed;
        self.completed_at = Some(Utc::now());
        Ok(())
    }

    /// Abort the ceremony.
    pub fn abort(&mut self, _reason: &str) {
        self.state = CeremonyState::Aborted;
    }

    /// Load from a JSON file.
    pub fn load(path: &PathBuf) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&contents).map_err(|e| e.to_string())
    }

    /// Save to a JSON file.
    pub fn save(&self, path: &PathBuf) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    /// Render a human-readable summary.
    pub fn summary(&self) -> String {
        let participant_list: Vec<&str> = self
            .participants
            .iter()
            .map(|p| p.signer_id.as_str())
            .collect();
        format!(
            "Ceremony {}: quorum={} scheme={} T={}/N={} state={:?} participants=[{}] ({}/{})",
            self.ceremony_id,
            self.quorum_id,
            self.scheme,
            self.threshold,
            self.party_count,
            self.state,
            participant_list.join(", "),
            self.participants.len(),
            self.party_count,
        )
    }
}

pub fn run(args: CeremonyArgs) {
    let code = match args.action {
        CeremonyAction::Init(sub) => {
            let ceremony = CeremonyStatus::new(
                &sub.ceremony_id,
                &sub.quorum_id,
                &sub.scheme,
                sub.threshold,
                sub.party_count,
            );
            match ceremony.save(&sub.state_file) {
                Ok(()) => {
                    println!("{}", ceremony.summary());
                    0
                }
                Err(e) => {
                    eprintln!("Error saving ceremony: {e}");
                    1
                }
            }
        }
        CeremonyAction::Join(sub) => {
            let mut ceremony = match CeremonyStatus::load(&sub.state_file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error loading ceremony: {e}");
                    return;
                }
            };
            match ceremony.join(&sub.signer_id) {
                Ok(()) => {
                    if let Err(e) = ceremony.save(&sub.state_file) {
                        eprintln!("Error saving: {e}");
                        return;
                    }
                    println!("{}", ceremony.summary());
                }
                Err(e) => eprintln!("Error joining: {e}"),
            }
            0
        }
        CeremonyAction::Status(sub) => {
            let ceremony = match CeremonyStatus::load(&sub.state_file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error loading ceremony: {e}");
                    return;
                }
            };
            println!("{}", ceremony.summary());
            0
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ceremony_starts_in_init() {
        let c = CeremonyStatus::new("c1", "q1", "CMP20", 3, 5);
        assert_eq!(c.state, CeremonyState::Init);
        assert_eq!(c.participants.len(), 0);
    }

    #[test]
    fn join_adds_participant() {
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 2, 3);
        c.join("alice").unwrap();
        assert_eq!(c.participants.len(), 1);
        assert_eq!(c.state, CeremonyState::Init);
    }

    #[test]
    fn join_fills_to_ready() {
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 2, 2);
        c.join("alice").unwrap();
        c.join("bob").unwrap();
        assert_eq!(c.state, CeremonyState::Ready);
    }

    #[test]
    fn double_join_rejected() {
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 2, 3);
        c.join("alice").unwrap();
        assert!(c.join("alice").is_err());
    }

    #[test]
    fn overfill_rejected() {
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 1, 1);
        c.join("alice").unwrap();
        assert!(c.join("bob").is_err());
    }

    #[test]
    fn lifecycle_init_to_completed() {
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 2, 2);
        c.join("a").unwrap();
        c.join("b").unwrap();
        assert_eq!(c.state, CeremonyState::Ready);
        c.start_run().unwrap();
        assert_eq!(c.state, CeremonyState::Running);
        c.complete().unwrap();
        assert_eq!(c.state, CeremonyState::Completed);
        assert!(c.completed_at.is_some());
    }

    #[test]
    fn start_run_rejects_wrong_state() {
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 2, 3);
        assert!(c.start_run().is_err());
    }

    #[test]
    fn abort_works_from_any_state() {
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 2, 3);
        c.abort("emergency");
        assert_eq!(c.state, CeremonyState::Aborted);
    }

    #[test]
    fn save_load_round_trips() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let path = PathBuf::from(tmp.path().to_str().unwrap());
        let mut c = CeremonyStatus::new("c1", "q1", "CMP20", 2, 3);
        c.join("alice").unwrap();
        c.save(&path).unwrap();
        let loaded = CeremonyStatus::load(&path).unwrap();
        assert_eq!(loaded.ceremony_id, "c1");
        assert_eq!(loaded.participants.len(), 1);
        // Touch the file to suppress unused warning
        tmp.as_file_mut().sync_all().unwrap();
    }

    #[test]
    fn summary_includes_key_info() {
        let c = CeremonyStatus::new("ceremony-42", "quorum-alpha", "CMP20", 3, 5);
        let s = c.summary();
        assert!(s.contains("ceremony-42"));
        assert!(s.contains("quorum-alpha"));
        assert!(s.contains("CMP20"));
        assert!(s.contains("T=3/N=5"));
    }
}
