# 32 — X.509 certificates, scoped delegation, CMS, XMLDSig

## Purpose

Standard PKI envelopes that Confium-produced threshold signatures
fit into. Verifiers use existing tools (OpenSSL, xmlsec1, browser-
native XMLDSig) without knowing Confium was involved.

## Scope

Four concerns, MECE-separated:

1. **X.509 cert + CSR types** — `confium-cert`
2. **Scoped delegation templates** — `confium-pki` (delegation feature)
3. **CMS (PKCS#7) envelopes** — `confium-pki` (cms feature)
4. **XMLDSig + Exclusive C14N** — `confium-pki` (xmldsig feature)

## Crate scope

### `confium-cert` (P0)

X.509 v3 certificate and CSR types built on the `x509-cert` crate.
Path validation. Aware of Confium-specific extensions (delegation
scope, threshold metadata).

```rust
pub struct Certificate(pub x509_cert::Certificate);
pub struct CertificateSigningRequest(pub reqwest::Certificate);

pub fn parse_cert(der: &[u8]) -> Result<Certificate>;
pub fn parse_cert_pem(pem: &str) -> Result<Certificate>;
pub fn cert_to_der(cert: &Certificate) -> Result<Vec<u8>>;
pub fn cert_to_pem(cert: &Certificate) -> Result<String>;

pub struct CertPath<'a> {
    leaf: &'a Certificate,
    intermediates: Vec<&'a Certificate>,
    root: &'a Certificate,
}

pub fn validate_path(path: &CertPath, now: DateTime<Utc>) -> Result<PathValidation>;
pub struct PathValidation {
    pub valid: bool,
    pub failures: Vec<PathFailure>,
}

pub enum PathFailure {
    Expired,
    NotYetValid,
    SignatureInvalid,
    ScopeViolation { expected: String, actual: String },
    ChainTooLong,
    UntrustedRoot,
    Revoked { crl_url: String, serial: String },
}
```

### `confium-pki` (delegation feature) (P0)

Scoped delegation templates. Parent cert delegates bounded authority
to child cert. Used for OIML Manufacturer Model Cert → Instance Cert
pattern, and similar patterns in other deployments.

```rust
pub struct DelegationScope {
    pub allowed_operations: Vec<Operation>,
    pub constraints: Vec<Constraint>,
}

pub enum Operation {
    SignCert(SignCertSpec),
    SignDocument(SignDocSpec),
    ThresholdSign(ThresholdSignSpec),
}

pub enum Constraint {
    ModelBound { model_id: String },
    NameBound { name_pattern: String },
    TimeBound { not_before: DateTime, not_after: DateTime },
    CountBound { max_issuances: u32 },
    GeographicBound { regions: Vec<String> },
}

pub fn build_model_cert(
    issuer: &Certificate,
    issuer_key: &SigningKey,
    subject: &Subject,
    model: &ModelSpec,
    validity: Duration,
) -> Result<Certificate>;

pub fn validate_delegation(
    parent: &Certificate,
    child: &Certificate,
    scope: &DelegationScope,
) -> Result<DelegationValidation>;
```

OIML-specific template included; users can define their own.

### `confium-pki` (cms feature) (P0)

CMS (PKCS#7 / RFC 5652) SignedData envelope. Takes (payload, cert
chain, signature) → CMS SignedData bytes. Standard format verifiable
by OpenSSL, Thunderbird/RNP, Adobe, etc.

```rust
pub struct SignedData {
    pub version: u32,
    pub digest_algorithms: Vec<AlgorithmIdentifier>,
    pub encap_content_info: EncapContentInfo,
    pub certificates: Vec<Certificate>,
    pub signer_infos: Vec<SignerInfo>,
}

pub fn build_signed_data(
    payload: &[u8],
    payload_type: &Oid,
    signers: &[Signer],
) -> Result<Vec<u8>>;

pub fn parse_signed_data(der: &[u8]) -> Result<SignedData>;
pub fn verify_signed_data(signed_data: &SignedData, trusted_roots: &[Certificate]) -> Result<VerificationResult>;
```

This is the bridge to **email signing** (S/MIME), **document
signing** (PAdES), and **code signing** (Authenticode).

### `confium-pki` (xmldsig feature) (P0)

XMLDSig + Exclusive C14N for CNML-style XML documents. Direct
integration point with OIML CNML project.

```rust
pub struct XmlDSigSignature {
    pub signed_info: SignedInfo,
    pub signature_value: Vec<u8>,
    pub key_info: KeyInfo,
    pub objects: Vec<XmlObject>,
}

pub fn sign_xml(
    xml: &str,
    references: &[Reference],
    signer: &Signer,
    transform: Canonicalization,
) -> Result<String>;

pub fn verify_xml(
    signed_xml: &str,
    trusted_roots: &[Certificate],
) -> Result<VerificationResult>;

pub enum Canonicalization {
    ExclusiveC14N,
    ExclusiveC14NWithComments,
    InclusiveC14N,
}
```

CNML's 6-check verify pipeline includes XMLDSig verification via
this crate.

## Verification result unified

All four crates produce a unified `VerificationResult`:

```rust
pub struct VerificationResult {
    pub valid: bool,
    pub checks_run: Vec<CheckResult>,
}

pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: Option<String>,
}
```

This composes with CNML's check pipeline (each check returns a
CheckResult; pipeline aggregates).

## Standards compliance

- RFC 5280: X.509 PKI
- RFC 5652: CMS
- RFC 6960: OCSP
- RFC 5280: CRL
- XML-Signature Syntax and Processing (W3C)
- Exclusive XML Canonicalization (W3C)

## References

- `TODO.roadmap/26-confium-framework.md`
- `~/src/oimlsmart/digital-certificates/README.md` — CNML's existing XMLDSig implementation
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 5652 CMS](https://www.rfc-editor.org/rfc/rfc5652)
- [W3C XMLDSig](https://www.w3.org/TR/xmldsig-core/)
