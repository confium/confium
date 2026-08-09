//! Integration tests for the consolidated confium-pki crate.
//!
//! Verifies that all four submodules (cert, delegation, cms, xmldsig)
//! work together via the public API.

use chrono::Utc;
use confium_pki::{
    PathFailure,
    // Result
    VerificationResult,
    // Cert
    cert::{CertError, Certificate, CertificateSigningRequest},
    // CMS
    cms::{SignedData, build_detached_signature, verify_signed_data},
    // Delegation
    delegation::{
        Constraint, DelegationScope, Operation, ScopeValue, SignCertSpec, validate_delegation,
    },
};

#[test]
fn verification_result_aggregates_across_concerns() {
    let r1 = VerificationResult {
        valid: true,
        checks: vec![],
    };
    let r2 = VerificationResult {
        valid: false,
        checks: vec![PathFailure::Expired],
    };
    let combined = VerificationResult::aggregate(&[r1, r2]);
    assert!(!combined.valid);
    assert_eq!(combined.checks.len(), 1);
}

#[test]
fn delegation_scope_can_reference_cert_types() {
    // Build a delegation scope that authorizes SignCert for instance certs.
    let scope = DelegationScope::new()
        .allow_operation(Operation::SignCert(SignCertSpec::default()))
        .constrain(Constraint::ModelBound {
            model_id: "FM-2026-A".into(),
        })
        .constrain(Constraint::TimeBound {
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
        });

    let values = vec![
        ScopeValue::ModelId("FM-2026-A"),
        ScopeValue::Time(Utc::now()),
    ];
    let result = validate_delegation(
        &scope,
        &Operation::SignCert(SignCertSpec::default()),
        &values,
    );
    assert!(result.permitted);
}

#[test]
fn cms_signed_data_reports_failure_on_unresolvable_cert() {
    // Since per-signer cert resolution, the verifier resolves each
    // signer's certificate before calling the callback. A fake
    // all-zero cert won't parse as DER, so resolution fails and
    // all_verified is false — even though the callback would
    // return Ok(()). This is correct behavior.
    let sd = build_detached_signature(
        vec![0u8; 32],
        "1.2.840.113549.1.1.11",
        vec![0u8; 256],
        vec![vec![0u8; 100]],
    )
    .unwrap();
    let result = verify_signed_data(&sd, b"payload", |_, _, _, _| Ok(())).unwrap();
    assert!(!result.all_verified);
    assert_eq!(result.per_signer.len(), 1);
    assert!(result.per_signer[0].error.is_some());
}

#[test]
fn der_encode_round_trips_through_signed_data_construction() {
    use confium_pki::cms::{
        AlgorithmIdentifier, EncapContentInfo, SignerIdentifier, SignerInfo, encode_signed_data_der,
    };
    let sd = SignedData {
        version: 1,
        digest_algorithms: vec![AlgorithmIdentifier {
            oid: "2.16.840.1.101.3.4.2.1".into(), // SHA-256
            parameters: None,
        }],
        encap_content_info: EncapContentInfo {
            content_type: "1.2.840.113549.1.7.1".into(),
            content: None,
        },
        certificates: vec![],
        signer_infos: vec![SignerInfo {
            version: 1,
            sid: SignerIdentifier::SubjectKeyIdentifier {
                key_identifier: vec![0xAA; 20],
            },
            digest_algorithm: AlgorithmIdentifier {
                oid: "2.16.840.1.101.3.4.2.1".into(),
                parameters: None,
            },
            signed_attrs: vec![],
            signature_algorithm: AlgorithmIdentifier {
                oid: "1.2.840.113549.1.1.11".into(),
                parameters: None,
            },
            signature: vec![0u8; 256],
            unsigned_attrs: vec![],
        }],
    };
    let der = encode_signed_data_der(&sd).unwrap();
    assert_eq!(der[0], 0x30); // outer SEQUENCE tag
    assert!(der.len() > 50);
}

#[test]
fn xmldsig_canonicalize_then_sha256() {
    use confium_pki::xmldsig::{canonicalize, sha256_digest};
    let xml = "<root>test data</root>";
    let canon = canonicalize(xml).unwrap();
    let digest = sha256_digest(canon.as_bytes());
    assert_eq!(digest.len(), 32);
}

#[test]
fn xmldsig_idempotent_canonicalization() {
    use confium_pki::xmldsig::canonicalize;
    let xml = "<root><child>data</child></root>";
    let once = canonicalize(xml).unwrap();
    let twice = canonicalize(&once).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn csr_round_trip_via_synthetic_der() {
    // Construct a minimal valid CSR DER (SEQUENCE starting with 0x30).
    let der = vec![0x30, 0x00];
    let csr = CertificateSigningRequest::from_der(&der).unwrap();
    let re_der = csr.to_der();
    assert_eq!(re_der, der);
}

#[test]
fn cert_error_propagates_through_result_chain() {
    let result: Result<Certificate, CertError> = Err(CertError::Invalid("test".into()));
    assert!(result.is_err());
}
