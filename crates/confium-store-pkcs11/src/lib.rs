//! Confium Store PKCS#11 backend.
//!
//! Wraps the [PKCS#11] standard via the [`cryptoki`] Rust crate
//! (Apache-2.0), giving Confium a hardware-backed `StoreBackend` for
//! HSMs (YubiHSM, Thales, Utimaco), smartcards, and software tokens
//! such as [SoftHSM2].
//!
//! The backend implements [`confium_store::backend::StoreBackend`] and
//! registers itself at link time under the wire name `"pkcs11"`. It is
//! a drop-in replacement for the filesystem and memory backends that
//! ship in `confium-store` — same Rust API, different storage.
//!
//! # Configuration
//!
//! Open-time options (passed via
//! [`confium_store::backend::Options`]):
//!
//! | key              | meaning                                            |
//! |------------------|----------------------------------------------------|
//! | `pkcs11_module`  | filesystem path to the PKCS#11 `.so` / `.dylib`    |
//! | `slot_id`        | HSM slot, as a decimal `u64`                       |
//! | `pin`            | user PIN (prompted at runtime if absent)           |
//! | `token_label`    | token label for slot discovery (optional)          |
//!
//! # Status
//!
//! This is a skeleton crate. The factory loads and initializes the
//! PKCS#11 module, resolves the configured slot, and opens a logged-in
//! R/W session. The actual HSM object operations (`put_secret`,
//! `get_secret`, …) return
//! [`confium_store::error::Error::NotImplemented`]. Filling them in is
//! tracked in `TODO.roadmap/18-hardware-keystore-backends.md`.
//!
//! # Tests
//!
//! Integration tests exercise a real HSM via SoftHSM2; they are skipped
//! automatically when the `TEST_PKCS11_MODULE` environment variable is
//! unset (so CI environments without an HSM do not spuriously fail).
//!
//! [PKCS#11]: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
//! [SoftHSM2]: https://www.opendnssec.org/softhsm/

pub mod backend;
pub mod config;
pub mod error;
pub mod instance;

pub use backend::Pkcs11Backend;
pub use config::{Config, OPT_PIN, OPT_PKCS11_MODULE, OPT_SLOT_ID, OPT_TOKEN_LABEL};
pub use instance::Pkcs11Instance;
