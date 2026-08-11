//! Property and integration tests for cert path validation.
//!
//! These tests exercise `confium_pki::validate_path` against real X.509
//! chains generated on the fly with `rcgen`. The unit-test module in
//! `src/path.rs` cannot do this because it has no way to construct
//! syntactically valid `Certificate` values without a generator.

use chrono::{Duration, Utc};
use confium_pki::{
    PathFailure,
    cert::Certificate,
    path::{CertPath, validate_path},
};
use proptest::prelude::*;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

/// A cert plus the key it was issued with. The `rcgen::Certificate`
/// is kept around so we can use it to sign child certs (rcgen requires
/// `&Certificate`, not just the DER bytes).
struct CertWithKey {
    /// The signing-able rcgen form (also stores the issuer-relevant SPKI).
    rcgen: rcgen::Certificate,
    /// The confium-pki wrapper around the same DER bytes, used for path validation.
    cfm: Certificate,
    /// The key pair this cert's subject public key corresponds to.
    key: KeyPair,
}

/// Build a self-signed root with the given validity window.
fn make_root(not_before: chrono::DateTime<Utc>, not_after: chrono::DateTime<Utc>) -> CertWithKey {
    let key = KeyPair::generate().expect("keygen");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.not_before = to_offset_dt(not_before);
    params.not_after = to_offset_dt(not_after);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Confium Proptest Root");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let rcgen_cert = params.self_signed(&key).expect("self-signed");
    let der = rcgen_cert.der().to_vec();
    let cfm = Certificate::from_der(&der).expect("DER parse");
    CertWithKey {
        rcgen: rcgen_cert,
        cfm,
        key,
    }
}

/// Issue a leaf or intermediate cert signed by `issuer`.
fn make_issued(
    not_before: chrono::DateTime<Utc>,
    not_after: chrono::DateTime<Utc>,
    is_ca: bool,
    issuer: &CertWithKey,
) -> CertWithKey {
    let key = KeyPair::generate().expect("keygen");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.not_before = to_offset_dt(not_before);
    params.not_after = to_offset_dt(not_after);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Confium Proptest Issued");
    params.distinguished_name = dn;
    if is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    }
    let rcgen_cert = params
        .signed_by(&key, &issuer.rcgen, &issuer.key)
        .expect("signed_by");
    let der = rcgen_cert.der().to_vec();
    let cfm = Certificate::from_der(&der).expect("DER parse");
    CertWithKey {
        rcgen: rcgen_cert,
        cfm,
        key,
    }
}

fn to_offset_dt(t: chrono::DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(t.timestamp()).unwrap()
}

fn window_days(
    center: chrono::DateTime<Utc>,
    half_width_days: i64,
) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    (
        center - Duration::days(half_width_days),
        center + Duration::days(half_width_days),
    )
}

/// Build a chain of `total_certs` certs (root + intermediates + leaf).
/// All certs share the same validity window centered on `now`.
fn build_chain(
    total_certs: usize,
    half_width_days: i64,
    now: chrono::DateTime<Utc>,
) -> (CertWithKey, Vec<CertWithKey>, CertWithKey) {
    assert!(total_certs >= 2, "chain must have at least root + leaf");
    let (nb, na) = window_days(now, half_width_days);
    let root = make_root(nb, na);

    let n_intermediates = total_certs.checked_sub(2).unwrap();
    let mut intermediates: Vec<CertWithKey> = Vec::with_capacity(n_intermediates);

    let mut current_parent: &CertWithKey = &root;
    for _ in 0..n_intermediates {
        let new = make_issued(nb, na, true, current_parent);
        // Push then re-borrow the last element as the next parent.
        intermediates.push(new);
        current_parent = intermediates.last().unwrap();
    }

    let leaf = make_issued(nb, na, false, current_parent);
    (root, intermediates, leaf)
}

#[test]
fn valid_chain_passes() {
    let now = Utc::now();
    let (root, inters, leaf) = build_chain(3, 30, now);
    let int_refs: Vec<&Certificate> = inters.iter().map(|c| &c.cfm).collect();
    let path = CertPath {
        leaf: &leaf.cfm,
        intermediates: int_refs,
        root: &root.cfm,
    };
    let result = validate_path(&path, now);
    assert!(result.valid, "expected valid, got {:?}", result.checks);
}

#[test]
fn expired_intermediate_fails() {
    let now = Utc::now();
    let (root_nb, root_na) = window_days(now, 365);
    let root = make_root(root_nb, root_na);

    let (int_nb, int_na) = (now - Duration::days(100), now - Duration::days(1));
    let intermediate = make_issued(int_nb, int_na, true, &root);

    let (leaf_nb, leaf_na) = window_days(now, 30);
    let leaf = make_issued(leaf_nb, leaf_na, false, &intermediate);

    let path = CertPath {
        leaf: &leaf.cfm,
        intermediates: vec![&intermediate.cfm],
        root: &root.cfm,
    };
    let result = validate_path(&path, now);
    assert!(!result.valid);
    assert!(result.checks.contains(&PathFailure::Expired));
}

#[test]
fn not_yet_valid_leaf_fails() {
    let now = Utc::now();
    let (nb, na) = window_days(now, 365);
    let root = make_root(nb, na);

    let leaf = make_issued(
        now + Duration::days(7),
        now + Duration::days(30),
        false,
        &root,
    );

    let path = CertPath {
        leaf: &leaf.cfm,
        intermediates: vec![],
        root: &root.cfm,
    };
    let result = validate_path(&path, now);
    assert!(!result.valid);
    assert!(result.checks.contains(&PathFailure::NotYetValid));
}

#[test]
fn chain_length_boundary_16_passes_17_fails() {
    let now = Utc::now();
    let (root, inters16, leaf16) = build_chain(16, 3650, now);
    let int_refs16: Vec<&Certificate> = inters16.iter().map(|c| &c.cfm).collect();
    let path16 = CertPath {
        leaf: &leaf16.cfm,
        intermediates: int_refs16,
        root: &root.cfm,
    };
    let result16 = validate_path(&path16, now);
    assert!(
        result16.valid,
        "16-cert chain should be within limit, got {:?}",
        result16.checks
    );

    let (_root17, inters17, leaf17) = build_chain(17, 3650, now);
    let int_refs17: Vec<&Certificate> = inters17.iter().map(|c| &c.cfm).collect();
    let path17 = CertPath {
        leaf: &leaf17.cfm,
        intermediates: int_refs17,
        root: &root.cfm,
    };
    let result17 = validate_path(&path17, now);
    assert!(!result17.valid);
    assert!(result17.checks.contains(&PathFailure::ChainTooLong));
}

#[test]
fn self_signed_root_only_validates() {
    let now = Utc::now();
    let (nb, na) = window_days(now, 30);
    let root = make_root(nb, na);

    let path = CertPath {
        leaf: &root.cfm,
        intermediates: vec![],
        root: &root.cfm,
    };
    let result = validate_path(&path, now);
    assert!(result.valid, "self-signed root path should be valid");
}

proptest! {
    /// For any "current time" within a cert's validity window,
    /// validate_path must accept it. For any time strictly outside
    /// the window, it must reject it with the appropriate variant.
    #[test]
    fn prop_validity_window_behavior(offset_days in -1000i64..1000) {
        let center = Utc::now();
        let (nb, na) = window_days(center, 30);
        let root = make_root(nb, na);
        let now = center + Duration::days(offset_days);

        let path = CertPath {
            leaf: &root.cfm,
            intermediates: vec![],
            root: &root.cfm,
        };
        let result = validate_path(&path, now);

        if now >= nb && now <= na {
            prop_assert!(result.valid, "time inside window should validate: {:?}", result.checks);
        } else if now < nb {
            prop_assert!(!result.valid);
            prop_assert!(result.checks.contains(&PathFailure::NotYetValid));
        } else {
            prop_assert!(!result.valid);
            prop_assert!(result.checks.contains(&PathFailure::Expired));
        }
    }

    /// Any chain longer than 16 certs must fail with ChainTooLong.
    /// Any chain of length 1..=16 must NOT have ChainTooLong.
    #[test]
    fn prop_chain_length_bound(n_intermediates in 0usize..18) {
        let now = Utc::now();
        let total = 2 + n_intermediates;
        let (root, inters, leaf) = build_chain(total, 3650, now);
        let int_refs: Vec<&Certificate> = inters.iter().map(|c| &c.cfm).collect();
        let path = CertPath {
            leaf: &leaf.cfm,
            intermediates: int_refs,
            root: &root.cfm,
        };
        let result = validate_path(&path, now);

        if total > 16 {
            prop_assert!(!result.valid);
            prop_assert!(result.checks.contains(&PathFailure::ChainTooLong));
        } else {
            prop_assert!(!result.checks.contains(&PathFailure::ChainTooLong));
        }
    }
}
