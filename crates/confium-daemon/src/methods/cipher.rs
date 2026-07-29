//! Cipher methods: `cipher_create`, `cipher_update`, `cipher_finalize`.
//!
//! Skeleton handlers. The core `Cipher` API requires a loaded provider
//! and per-connection handle management; these handlers return an
//! `Engine` error until the handle store is wired.

use crate::pending_method;

pending_method!(cipher_create, "cipher_create", "requires per-connection handle management (pending)");
pending_method!(cipher_update, "cipher_update", "requires per-connection handle management (pending)");
pending_method!(cipher_finalize, "cipher_finalize", "requires per-connection handle management (pending)");
