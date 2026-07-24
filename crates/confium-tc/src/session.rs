//! Session lifecycle: create, round, result, destroy.
//!
//! A [`Session`] owns the per-party state of one threshold protocol
//! run. The framework drives it round-by-round: feed in the messages
//! received from peers, get back the messages to send, repeat until a
//! round signals `complete`, then read the [`Session::result`].
//!
//! The session delegates all scheme-specific work to a [`SessionImpl`]
//! produced by the registered [`crate::registry::TcScheme`]. The
//! framework layer above this is transport-agnostic — see
//! `TODO.roadmap/05-networking-primitives.md` for how [`crate::message::Message`]s
//! get moved between parties.

use snafu::ensure;

use crate::Result;
use crate::error;
use crate::message::Message;
use crate::party::PartyList;
use crate::registry::{self, RoundResult, SessionImpl, TcSchemeKind};
use crate::share::Share;

/// Parameters handed to [`Session::create`].
///
/// `message` is the per-session input artifact: the message to sign for
/// `Signature` schemes, the ciphertext to decapsulate for `Kem`
/// schemes, or `None` for `Dkg` schemes (which have no external input).
#[derive(Debug, Clone)]
pub struct SessionParams {
    /// Canonical scheme name, e.g. `"FROST-ed25519"`.
    pub scheme: String,
    /// Ordered roster of all N parties.
    pub parties: PartyList,
    /// Threshold T — minimum cooperating party count.
    pub threshold: u32,
    /// Index into `parties` identifying which party we are.
    pub this_party_idx: usize,
    /// Pre-existing share (for signing / decapsulation sessions). `None`
    /// for DKG sessions that produce a share on output.
    pub local_share: Option<Share>,
    /// External input to the session — the message to sign, the
    /// ciphertext to decapsulate, etc.
    pub message: Option<Vec<u8>>,
}

/// One party's view of one threshold protocol run.
///
/// Owns the [`SessionImpl`] produced by the scheme and the bookkeeping
/// the framework needs to validate round calls.
pub struct Session {
    scheme_name: String,
    scheme_kind: TcSchemeKind,
    threshold: u32,
    this_party_idx: usize,
    party_count: usize,
    round: u8,
    complete: bool,
    impl_: Box<dyn SessionImpl>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("scheme_name", &self.scheme_name)
            .field("scheme_kind", &self.scheme_kind)
            .field("threshold", &self.threshold)
            .field("this_party_idx", &self.this_party_idx)
            .field("party_count", &self.party_count)
            .field("round", &self.round)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Resolve `params.scheme` against the link-time registry and build
    /// a fresh session. Validates the roster + threshold + index before
    /// handing control to the scheme.
    pub fn create(params: &SessionParams) -> Result<Self> {
        params.parties.validate(params.threshold)?;
        ensure!(
            params.this_party_idx < params.parties.len(),
            error::ThisPartyIdxOutOfRangeSnafu {
                idx: params.this_party_idx,
                party_count: params.parties.len(),
            }
        );
        if let Some(share) = &params.local_share {
            share.assert_scheme(&params.scheme)?;
        }

        let scheme = registry::find(&params.scheme).ok_or_else(|| {
            error::SchemeNotFoundSnafu {
                name: params.scheme.clone(),
            }
            .build()
        })?;
        let impl_ = scheme.create_session(params)?;
        Ok(Session {
            scheme_name: scheme.name().to_string(),
            scheme_kind: scheme.kind(),
            threshold: params.threshold,
            this_party_idx: params.this_party_idx,
            party_count: params.parties.len(),
            round: 0,
            complete: false,
            impl_,
        })
    }

    pub fn scheme_name(&self) -> &str {
        &self.scheme_name
    }

    pub fn scheme_kind(&self) -> TcSchemeKind {
        self.scheme_kind
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn this_party_idx(&self) -> usize {
        self.this_party_idx
    }

    pub fn party_count(&self) -> usize {
        self.party_count
    }

    /// Current round number. Starts at 0 (no rounds run yet); after the
    /// first [`Session::round`] call it is 1.
    pub fn round(&self) -> u8 {
        self.round
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Step the session forward one round.
    ///
    /// `incoming` is the set of [`Message`]s this party received since
    /// the last round (from all peers). Returns the messages this party
    /// needs to send next. Once a round returns `complete == true`,
    /// [`Session::result`] is ready and further `round` calls error.
    pub fn round_step(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        ensure!(!self.complete, error::SessionAlreadyCompleteSnafu {});
        self.round = self
            .round
            .checked_add(1)
            .ok_or_else(|| error::RoundOverflowSnafu { round: self.round }.build())?;
        let res = self.impl_.round(incoming)?;
        if res.complete {
            self.complete = true;
        }
        Ok(res)
    }

    /// Read the final cryptographic artifact. Errors until a round has
    /// signaled completion.
    pub fn result(&self) -> Result<Vec<u8>> {
        ensure!(self.complete, error::SessionNotCompleteSnafu {});
        self.impl_.result()
    }

    /// For DKG sessions: extract the per-party share and the shared
    /// public key the protocol produced. The default implementation
    /// delegates to [`SessionImpl::result`] for the public-key bytes and
    /// returns `None` for the share unless the scheme overrides this via
    /// its own protocol — the framework reads the share through the
    /// scheme plugin's DKG-specific entry point in a later iteration.
    ///
    /// For the skeleton this is a thin wrapper: `result()` yields the
    /// shared public key; the share is produced by the scheme and read
    /// back via the FFI `cfm_tc_dkg_output_share` entry point.
    pub fn dkg_public_key(&self) -> Result<Vec<u8>> {
        ensure!(self.complete, error::SessionNotCompleteSnafu {});
        ensure!(
            self.scheme_kind == TcSchemeKind::Dkg,
            error::NotADkgSessionSnafu {
                kind: self.scheme_kind,
            }
        );
        self.impl_.result()
    }

    /// Release scheme-owned resources. After `destroy` the session must
    /// not be used again.
    pub fn destroy(&mut self) {
        self.impl_.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::party::{Party, PartyList};

    /// A minimal in-test scheme so the session lifecycle can be
    /// exercised without depending on the registry-test scheme. Two
    /// rounds: round 1 echoes a broadcast, round 2 completes.
    struct TwoRoundScheme;

    impl crate::registry::TcScheme for TwoRoundScheme {
        fn name(&self) -> &'static str {
            "test-two-round"
        }
        fn kind(&self) -> TcSchemeKind {
            TcSchemeKind::Signature
        }
        fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
            let our_id = params.parties.get(params.this_party_idx)?.id.clone();
            Ok(Box::new(TwoRoundSession {
                our_id,
                message: params.message.clone().unwrap_or_default(),
                round_done: 0,
            }))
        }
    }

    struct TwoRoundSession {
        our_id: String,
        message: Vec<u8>,
        round_done: u8,
    }

    impl SessionImpl for TwoRoundSession {
        fn round(&mut self, _incoming: &[Message]) -> Result<RoundResult> {
            self.round_done += 1;
            if self.round_done == 1 {
                let msg = Message::broadcast(&self.our_id, 1, self.message.clone());
                Ok(RoundResult::new(vec![msg], false))
            } else {
                Ok(RoundResult::done())
            }
        }
        fn result(&self) -> Result<Vec<u8>> {
            Ok(self.message.clone())
        }
        fn destroy(&mut self) {
            self.message.fill(0);
        }
    }

    // Register the test scheme at link time.
    inventory::submit! {
        crate::registry::RegisteredScheme {
            scheme: &TwoRoundScheme as &dyn crate::registry::TcScheme
        }
    }

    fn params(scheme: &str, idx: usize, threshold: u32) -> SessionParams {
        SessionParams {
            scheme: scheme.to_string(),
            parties: PartyList::from_parties(vec![
                Party::inproc("a"),
                Party::inproc("b"),
                Party::inproc("c"),
            ]),
            threshold,
            this_party_idx: idx,
            local_share: None,
            message: Some(b"hello".to_vec()),
        }
    }

    #[test]
    fn session_create_resolves_registered_scheme() {
        let params = params("test-two-round", 0, 2);
        let session = Session::create(&params).expect("session created");
        assert_eq!(session.scheme_name(), "test-two-round");
        assert_eq!(session.scheme_kind(), TcSchemeKind::Signature);
        assert_eq!(session.threshold(), 2);
        assert_eq!(session.this_party_idx(), 0);
        assert_eq!(session.party_count(), 3);
        assert_eq!(session.round(), 0);
        assert!(!session.is_complete());
    }

    #[test]
    fn session_create_unknown_scheme_errors() {
        let mut params = params("test-two-round", 0, 2);
        params.scheme = "no-such-scheme".to_string();
        let err = Session::create(&params).unwrap_err();
        assert!(matches!(err, error::Error::SchemeNotFound { .. }));
    }

    #[test]
    fn session_create_rejects_bad_party_index() {
        let params = params("test-two-round", 99, 2);
        let err = Session::create(&params).unwrap_err();
        assert!(matches!(
            err,
            error::Error::ThisPartyIdxOutOfRange {
                idx: 99,
                party_count: 3,
                ..
            }
        ));
    }

    #[test]
    fn session_create_rejects_threshold_above_party_count() {
        let params = params("test-two-round", 0, 99);
        let err = Session::create(&params).unwrap_err();
        assert!(matches!(err, error::Error::ThresholdTooLarge { .. }));
    }

    #[test]
    fn session_create_rejects_share_scheme_mismatch() {
        let mut params = params("test-two-round", 0, 2);
        params.local_share = Some(Share::new("wrong-scheme", vec![1]));
        let err = Session::create(&params).unwrap_err();
        assert!(matches!(err, error::Error::ShareSchemeMismatch { .. }));
    }

    #[test]
    fn session_round_progresses_then_completes() {
        let params = params("test-two-round", 0, 2);
        let mut session = Session::create(&params).expect("session");

        // Round 1: no incoming (first round), one outgoing broadcast.
        let r1 = session.round_step(&[]).expect("round 1");
        assert!(!r1.complete);
        assert_eq!(r1.outgoing.len(), 1);
        assert!(r1.outgoing[0].is_broadcast());
        assert_eq!(session.round(), 1);

        // Round 2: completes.
        let r2 = session.round_step(&[]).expect("round 2");
        assert!(r2.complete);
        assert!(session.is_complete());

        let result = session.result().expect("result");
        assert_eq!(result, b"hello");
    }

    #[test]
    fn session_round_after_complete_errors() {
        let params = params("test-two-round", 0, 2);
        let mut session = Session::create(&params).expect("session");
        session.round_step(&[]).expect("round 1");
        session.round_step(&[]).expect("round 2 completes");
        let err = session.round_step(&[]).unwrap_err();
        assert!(matches!(err, error::Error::SessionAlreadyComplete { .. }));
    }

    #[test]
    fn session_result_before_complete_errors() {
        let params = params("test-two-round", 0, 2);
        let session = Session::create(&params).expect("session");
        let err = session.result().unwrap_err();
        assert!(matches!(err, error::Error::SessionNotComplete { .. }));
    }

    #[test]
    fn session_dkg_public_key_rejects_non_dkg() {
        let params = params("test-two-round", 0, 2);
        let mut session = Session::create(&params).expect("session");
        session.round_step(&[]).expect("round 1");
        session.round_step(&[]).expect("round 2 completes");
        let err = session.dkg_public_key().unwrap_err();
        assert!(matches!(err, error::Error::NotADkgSession { .. }));
    }
}
