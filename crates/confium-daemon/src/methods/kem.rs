//! KEM (Key Encapsulation Mechanism) methods.
//!
//! Skeleton handlers pending per-connection handle management.

use crate::pending_method;

pending_method!(kem_keypair_generate, "kem_keypair_generate", "requires per-connection handle management (pending)");
pending_method!(kem_encapsulate, "kem_encapsulate", "requires per-connection handle management (pending)");
pending_method!(kem_decapsulate, "kem_decapsulate", "requires per-connection handle management (pending)");
