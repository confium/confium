//! Link-time registry of in-process threshold schemes.
//!
//! Each TC scheme (FROST-ed25519, GG18-ECDSA-P256, a Pedersen DKG, …)
//! registers itself with [`register_tc_scheme!`]. The session layer
//! looks schemes up by name and dispatches lifecycle calls through the
//! [`TcScheme`] trait.
//!
//! This registry is for **in-process** Rust schemes linked into the
//! same binary as `confium-tc`. Out-of-process plugins (loaded via
//! `libloading`) advertise the `"tc"` interface name through the core
//! plugin loader and are dispatched separately — see
//! `confium-core::ffi::registry`.
//!
//! The registry name advertised for plugins is `"tc"` and covers both
//! `tc-signature` and `tc-kem` via the scheme name; max version 0.

use std::fmt;

use crate::Result;
use crate::message::Message;
use crate::session::SessionParams;

/// Broad category of a threshold scheme. Drives which lifecycle entry
/// points apply (e.g. DKG produces a share on output; signing consumes
/// a share on input).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TcSchemeKind {
    /// Threshold signing — parties cooperatively produce a signature.
    Signature,
    /// Threshold key encapsulation — parties cooperatively derive a
    /// shared secret.
    Kem,
    /// Distributed key generation — parties produce a fresh shared
    /// secret and per-party shares.
    Dkg,
}

/// A registered threshold scheme.
///
/// Implementations are `Send + Sync` so a scheme can be looked up from
/// any thread. Each `create_session` call yields a fresh [`SessionImpl`]
/// that owns the per-session mutable state.
pub trait TcScheme: Send + Sync {
    /// Canonical scheme name, e.g. `"FROST-ed25519"`, `"GG18-ECDSA-P256"`.
    fn name(&self) -> &'static str;

    /// What kind of artifact this scheme produces.
    fn kind(&self) -> TcSchemeKind;

    /// Build a new session for this scheme. The returned [`SessionImpl`]
    /// owns all per-session state; the framework drives it via
    /// [`SessionImpl::round`] / [`SessionImpl::result`] /
    /// [`SessionImpl::destroy`].
    fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>>;
}

/// Per-session scheme state, driven round-by-round by the framework.
///
/// A `SessionImpl` is **not** `Sync` — it owns mutable protocol state
/// for exactly one party's view of one session. The framework moves it
/// between threads via the owning [`crate::session::Session`] handle.
pub trait SessionImpl: Send {
    /// Advance one round. Consumes the messages received since the last
    /// round and returns the messages to send next, plus a `complete`
    /// flag indicating the session has produced its output and no more
    /// rounds are needed.
    fn round(&mut self, incoming: &[Message]) -> Result<RoundResult>;

    /// Extract the final cryptographic artifact (signature bytes, DKG
    /// output, KEM shared secret, …). Only valid once a round returned
    /// `complete == true`.
    fn result(&self) -> Result<Vec<u8>>;

    /// Release any scheme-owned resources. Called exactly once when the
    /// framework drops the session. Implementations should zeroize
    /// sensitive state.
    fn destroy(&mut self);
}

/// Outcome of one [`SessionImpl::round`] call.
#[derive(Debug, Clone, Default)]
pub struct RoundResult {
    /// Messages to send for the next round.
    pub outgoing: Vec<Message>,
    /// `true` once the protocol is finished and [`SessionImpl::result`]
    /// is ready to read.
    pub complete: bool,
}

impl RoundResult {
    pub fn new(outgoing: Vec<Message>, complete: bool) -> Self {
        RoundResult { outgoing, complete }
    }

    /// Convenience: an empty result that signals the session is done.
    pub fn done() -> Self {
        RoundResult {
            outgoing: Vec::new(),
            complete: true,
        }
    }
}

/// Wrapper so a `&'static dyn TcScheme` can be collected by `inventory`.
pub struct RegisteredScheme {
    pub scheme: &'static dyn TcScheme,
}

inventory::collect!(RegisteredScheme);

/// Iterator over every scheme registered at link time.
pub fn iter() -> impl Iterator<Item = &'static dyn TcScheme> {
    inventory::iter::<RegisteredScheme>().map(|r| r.scheme)
}

/// Look up a scheme by canonical name. Returns the first match — scheme
/// name collisions are a registration bug and surface here as
/// [`crate::error::Error::SchemeNotFound`].
pub fn find(name: &str) -> Option<&'static dyn TcScheme> {
    iter().find(|s| s.name() == name)
}

/// Submit a scheme implementation to the link-time registry.
///
/// ```ignore
/// use confium_tc::register_tc_scheme;
/// use confium_tc::registry::{TcScheme, TcSchemeKind};
/// use confium_tc::{SessionImpl, SessionParams};
/// # use confium_tc::Error;
/// # struct MyScheme;
/// # impl TcScheme for MyScheme {
/// #     fn name(&self) -> &'static str { "demo" }
/// #     fn kind(&self) -> TcSchemeKind { TcSchemeKind::Signature }
/// #     fn create_session(&self, _: &SessionParams)
/// #         -> std::result::Result<Box<dyn SessionImpl>, Error> { unimplemented!() }
/// # }
/// register_tc_scheme!(MyScheme);
/// ```
#[macro_export]
macro_rules! register_tc_scheme {
    ($scheme:ident) => {
        ::inventory::submit! {
            $crate::registry::RegisteredScheme { scheme: &$scheme }
        }
    };
}

impl fmt::Debug for dyn TcScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcScheme")
            .field("name", &self.name())
            .field("kind", &self.kind())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error;
    use crate::session::SessionParams;
    use crate::share::Share;

    /// A no-op scheme used to exercise the registry + session lifecycle
    /// end-to-end. It "completes" on the first round and produces a
    /// fixed result; no real cryptography happens here.
    struct NoopScheme;

    impl TcScheme for NoopScheme {
        fn name(&self) -> &'static str {
            "test-noop"
        }
        fn kind(&self) -> TcSchemeKind {
            TcSchemeKind::Signature
        }
        fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
            Ok(Box::new(NoopSession {
                result: params
                    .message
                    .clone()
                    .unwrap_or_else(|| b"noop-result".to_vec()),
                done: false,
            }))
        }
    }

    struct NoopSession {
        result: Vec<u8>,
        done: bool,
    }

    impl SessionImpl for NoopSession {
        fn round(&mut self, _incoming: &[Message]) -> Result<RoundResult> {
            self.done = true;
            Ok(RoundResult::done())
        }
        fn result(&self) -> Result<Vec<u8>> {
            if !self.done {
                return Err(error::SessionNotCompleteSnafu {}.build());
            }
            Ok(self.result.clone())
        }
        fn destroy(&mut self) {
            self.result.fill(0);
        }
    }

    // Force the scheme into the link-time registry for these tests.
    inventory::submit! {
        RegisteredScheme { scheme: &NoopScheme as &dyn TcScheme }
    }

    fn make_params() -> SessionParams {
        use crate::party::{Party, PartyList};
        SessionParams {
            scheme: "test-noop".to_string(),
            parties: PartyList::from_parties(vec![
                Party::inproc("a"),
                Party::inproc("b"),
                Party::inproc("c"),
            ]),
            threshold: 2,
            this_party_idx: 0,
            local_share: None,
            message: None,
        }
    }

    #[test]
    fn registry_finds_registered_scheme() {
        let scheme = find("test-noop").expect("noop scheme must be registered");
        assert_eq!(scheme.name(), "test-noop");
        assert_eq!(scheme.kind(), TcSchemeKind::Signature);
    }

    #[test]
    fn registry_find_missing_returns_none() {
        assert!(find("does-not-exist").is_none());
    }

    #[test]
    fn scheme_create_session_runs_full_lifecycle() {
        let scheme = find("test-noop").expect("registered");
        let params = make_params();
        let mut session = scheme.create_session(&params).expect("session created");

        let rr = session.round(&[]).expect("round ok");
        assert!(rr.complete);
        assert!(rr.outgoing.is_empty());

        let result = session.result().expect("result ok");
        assert_eq!(result, b"noop-result");

        session.destroy();
    }

    #[test]
    fn scheme_create_session_propagates_message_param() {
        let scheme = find("test-noop").expect("registered");
        let mut params = make_params();
        params.message = Some(vec![0x11, 0x22]);
        let mut session = scheme.create_session(&params).expect("session created");
        session.round(&[]).expect("round ok");
        let result = session.result().expect("result ok");
        assert_eq!(result, vec![0x11, 0x22]);
    }

    #[test]
    fn result_before_complete_errors() {
        let scheme = find("test-noop").expect("registered");
        let params = make_params();
        let session = scheme.create_session(&params).expect("session created");
        let err = session.result().unwrap_err();
        assert!(matches!(err, error::Error::SessionNotComplete { .. }));
    }

    #[test]
    fn share_param_does_not_panic_when_absent() {
        // Sanity: SessionParams.local_share is optional and unused by
        // the noop scheme; ensure the field is constructible.
        let params = make_params();
        assert!(params.local_share.is_none());
        let _ = Share::new("test-noop", vec![]);
    }
}
