//! Identity types used to index the public compartment.
//!
//! The public compartment is identity-indexed: a `(module_id, app_id)`
//! pair scopes a namespace, and within it each entry is addressed by an
//! `Identity`. Identities are deliberately a small sum type so the Store
//! can validate shape before touching the backend.
//!
//! Concretely the variants mirror the README's identity-based signature
//! scheme: the public key is the user's unique info (e.g. email), and
//! `put_public` requires the caller to supply a detached signature over
//! the identity so verifiers can check authenticity before trusting the
//! key.

use std::fmt;

/// One of the supported identity shapes. Stored as the key of the public
/// compartment's HashMap; serialised to a canonical string for FFI and
/// backend persistence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identity {
    /// RFC 5321 mailbox, e.g. `alice@example.com`.
    Email(String),
    /// Opaque key identifier (hex, base32, fingerprint — the Store does
    /// not impose a format; it only uses the bytes for lookup).
    KeyId(String),
    /// Raw cryptographic hash of an identity document, hex-encoded.
    Hash(String),
}

impl Identity {
    /// Parse a `(kind, value)` pair coming from the FFI into a typed
    /// identity. `kind` is ASCII, case-sensitive. Unknown kinds return
    /// the raw string as a [`Identity::Hash`] so legacy callers keep
    /// working — a future stricter revision can promote this to an error.
    pub fn from_kind(kind: &str, value: &str) -> Self {
        match kind {
            "email" => Identity::Email(value.to_string()),
            "key-id" => Identity::KeyId(value.to_string()),
            _ => Identity::Hash(value.to_string()),
        }
    }

    /// Canonical string form used as the HashMap key inside backends.
    /// The scheme prefix keeps Email / KeyId / Hash namespaces disjoint
    /// even when their textual values collide.
    pub fn canonical(&self) -> String {
        match self {
            Identity::Email(v) => format!("email:{v}"),
            Identity::KeyId(v) => format!("key-id:{v}"),
            Identity::Hash(v) => format!("hash:{v}"),
        }
    }

    /// The bare identity value without the scheme prefix. Useful for
    /// logging or when the caller already knows the kind.
    pub fn value(&self) -> &str {
        match self {
            Identity::Email(v) | Identity::KeyId(v) | Identity::Hash(v) => v,
        }
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_canonicalises_with_prefix() {
        let id = Identity::Email("alice@example.com".to_string());
        assert_eq!(id.canonical(), "email:alice@example.com");
        assert_eq!(id.value(), "alice@example.com");
    }

    #[test]
    fn from_kind_routes_known_prefixes() {
        assert_eq!(
            Identity::from_kind("email", "b@b"),
            Identity::Email("b@b".to_string())
        );
        assert_eq!(
            Identity::from_kind("key-id", "deadbeef"),
            Identity::KeyId("deadbeef".to_string())
        );
    }

    #[test]
    fn from_kind_defaults_unknown_to_hash() {
        assert_eq!(
            Identity::from_kind("fingerprint", "abcd"),
            Identity::Hash("abcd".to_string())
        );
    }

    #[test]
    fn distinct_kinds_are_distinct_keys() {
        // Same textual value, different kinds — must not collide as map
        // keys. This is the invariant the public compartment relies on.
        let a = Identity::Email("x".to_string());
        let b = Identity::KeyId("x".to_string());
        assert_ne!(a.canonical(), b.canonical());
    }
}
