//! Threshold crypto deployment patterns.
//!
//! Two patterns inspired by Thunderbird's revocation escrow and key backup
//! designs, generalized to T-of-N threshold cryptography:
//!
//! - **Escrow**: A user's key is encrypted to a threshold public key; recovery
//!   requires T-of-N custodians to participate in an async decryption ceremony.
//! - **Revocation service**: Threshold-backed revocation service replacing
//!   single-party authorization (eliminates compelled-revocation risk).
//!
//! See `TODO.roadmap/41-thunderbird-patterns-integration.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod escrow {
    //! Threshold key escrow.

    mod blob;
    mod metadata;
    mod service;

    pub use blob::*;
    pub use metadata::*;
    pub use service::*;
}

pub mod revocation {
    //! Threshold-backed revocation service.

    mod revocation_blob;
    mod revocation_service;
    mod revocation_submission;

    pub use revocation_blob::*;
    pub use revocation_service::*;
    pub use revocation_submission::*;
}
