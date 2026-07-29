//! AEAD methods: `aead_create`, `aead_encrypt_update`, `aead_decrypt_update`, `aead_finalize`.
//!
//! Skeleton handlers pending per-connection handle management.

use crate::pending_method;

pending_method!(aead_create, "aead_create", "requires per-connection handle management (pending)");
pending_method!(aead_encrypt_update, "aead_encrypt_update", "requires per-connection handle management (pending)");
pending_method!(aead_decrypt_update, "aead_decrypt_update", "requires per-connection handle management (pending)");
pending_method!(aead_finalize, "aead_finalize", "requires per-connection handle management (pending)");
