//! Property-based tests for the coordinator state machine.

#[cfg(test)]
mod proptest {
    use crate::coordinator::coordinator::Coordinator;
    use crate::coordinator::session::{SessionRequest, SessionState};
    use proptest::prelude::*;

    fn make_request(threshold: u32, parties: u32) -> SessionRequest {
        SessionRequest {
            quorum_id: "q".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold,
            num_parties: parties,
            unlock_window_minutes: 60,
            requested_by: "test".into(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_session_count_never_exceeds_created(n in 0u32..20) {
            let mut coord = Coordinator::new();
            let mut ids = Vec::new();
            for _ in 0..n {
                let id = coord.create_session(make_request(2, 3)).unwrap();
                ids.push(id);
            }
            prop_assert_eq!(coord.session_count(), n as usize);
            prop_assert_eq!(coord.session_ids().len(), n as usize);
        }

        #[test]
        fn prop_session_ids_unique(n in 1u32..10) {
            let mut coord = Coordinator::new();
            let mut ids = Vec::new();
            for _ in 0..n {
                ids.push(coord.create_session(make_request(2, 3)).unwrap());
            }
            let mut sorted = ids.clone();
            sorted.sort();
            sorted.dedup();
            prop_assert_eq!(sorted.len(), ids.len(), "session IDs must be unique");
        }

        #[test]
        fn prop_created_session_is_pending(threshold in 1u32..5, parties in 2u32..6) {
            prop_assume!(parties >= threshold);
            let mut coord = Coordinator::new();
            let id = coord.create_session(make_request(threshold, parties)).unwrap();
            let state = coord.session_state(&id);
            prop_assert_eq!(state, Some(SessionState::Pending));
        }

        #[test]
        fn prop_set_state_persists(n in 1u32..5) {
            let mut coord = Coordinator::new();
            let id = coord.create_session(make_request(2, 3)).unwrap();
            coord.set_session_state(&id, SessionState::Completed);
            prop_assert_eq!(coord.session_state(&id), Some(SessionState::Completed));
            let _ = n;
        }

        #[test]
        fn prop_audit_log_grows_with_sessions(n in 0u32..10) {
            let mut coord = Coordinator::new();
            for _ in 0..n {
                coord.create_session(make_request(2, 3)).unwrap();
            }
            let audit = coord.audit_log();
            prop_assert_eq!(audit.count(), n as usize);
        }
    }
}
