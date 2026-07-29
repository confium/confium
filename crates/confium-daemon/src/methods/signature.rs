//! Signature methods.
//!
//! Skeleton handlers pending per-connection handle management.

use crate::pending_method;

pending_method!(signature_keypair_generate, "signature_keypair_generate", "requires per-connection handle management (pending)");
pending_method!(signature_signer_update, "signature_signer_update", "requires per-connection handle management (pending)");
pending_method!(signature_signer_finalize, "signature_signer_finalize", "requires per-connection handle management (pending)");
pending_method!(signature_verifier_update, "signature_verifier_update", "requires per-connection handle management (pending)");
pending_method!(signature_verifier_finalize, "signature_verifier_finalize", "requires per-connection handle management (pending)");
