//! CMP20 scheme registration.
//!
//! Two logical operations — DKG and signing — exposed as two scheme
//! names so the framework's single-name/single-kind `TcScheme` trait
//! can route each.
//!
//! | Name                    | Kind        | Produces                          |
//! |------------------------|-------------|-----------------------------------|
//! | `CMP20-ECDSA-P256`       | `Dkg`       | per-party `Cmp20Share` + pubkey    |
//! | `CMP20-ECDSA-P256-SIGN`  | `Signature` | 64-byte `(r, s)` ECDSA signature  |

use confium_tc::Result;
use confium_tc::registry::{SessionImpl, TcScheme, TcSchemeKind};
use confium_tc::session::SessionParams;

use crate::keygen::Cmp20DkgP256;
use crate::sign::Cmp20SignP256;

/// CMP20 DKG scheme (registered as `CMP20-ECDSA-P256`).
pub struct Cmp20EcdsaP256;

impl TcScheme for Cmp20EcdsaP256 {
    fn name(&self) -> &'static str {
        crate::DKG_SCHEME_NAME
    }
    fn kind(&self) -> TcSchemeKind {
        TcSchemeKind::Dkg
    }
    fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
        Cmp20DkgP256::build_session(params)
    }
}

/// CMP20 signing scheme (registered as `CMP20-ECDSA-P256-SIGN`).
pub struct Cmp20EcdsaP256Sign;

impl TcScheme for Cmp20EcdsaP256Sign {
    fn name(&self) -> &'static str {
        crate::SIGN_SCHEME_NAME
    }
    fn kind(&self) -> TcSchemeKind {
        TcSchemeKind::Signature
    }
    fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
        Cmp20SignP256::build_session(params)
    }
}

confium_tc::register_tc_scheme!(Cmp20EcdsaP256);
confium_tc::register_tc_scheme!(Cmp20EcdsaP256Sign);
