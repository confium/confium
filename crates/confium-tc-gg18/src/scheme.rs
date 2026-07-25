//! GG18 scheme registration.
//!
//! Two logical operations — DKG and signing — exposed as two scheme
//! names so the framework's single-name/single-kind `TcScheme` trait
//! can route each.
//!
//! | Name                    | Kind        | Produces                          |
//! |------------------------|-------------|-----------------------------------|
//! | `GG18-ECDSA-P256`       | `Dkg`       | per-party `Gg18Share` + pubkey    |
//! | `GG18-ECDSA-P256-SIGN`  | `Signature` | 64-byte `(r, s)` ECDSA signature  |

use confium_tc::Result;
use confium_tc::registry::{SessionImpl, TcScheme, TcSchemeKind};
use confium_tc::session::SessionParams;

use crate::keygen::Gg18DkgP256;
use crate::sign::Gg18SignP256;

/// GG18 DKG scheme (registered as `GG18-ECDSA-P256`).
pub struct Gg18EcdsaP256;

impl TcScheme for Gg18EcdsaP256 {
    fn name(&self) -> &'static str {
        crate::DKG_SCHEME_NAME
    }
    fn kind(&self) -> TcSchemeKind {
        TcSchemeKind::Dkg
    }
    fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
        Gg18DkgP256::build_session(params)
    }
}

/// GG18 signing scheme (registered as `GG18-ECDSA-P256-SIGN`).
pub struct Gg18EcdsaP256Sign;

impl TcScheme for Gg18EcdsaP256Sign {
    fn name(&self) -> &'static str {
        crate::SIGN_SCHEME_NAME
    }
    fn kind(&self) -> TcSchemeKind {
        TcSchemeKind::Signature
    }
    fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
        Gg18SignP256::build_session(params)
    }
}

confium_tc::register_tc_scheme!(Gg18EcdsaP256);
confium_tc::register_tc_scheme!(Gg18EcdsaP256Sign);
