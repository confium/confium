# 38 — Attribute-based threshold signing

## Purpose

Not just "any T of N" but "any T of N satisfying attribute predicate
P". Enables policies like:

- Geographic distribution (≥ K regions must be represented)
- Subject-matter expertise (≥ M domain experts)
- Conflict-of-interest exclusion (signer must NOT be from country
  of the manufacturer)
- Time-of-day (live human signers only)
- Role-based (≥ 1 officer + ≥ 2 directors)

## Predicates

Predicate language over signer attributes:

```rust
pub enum Predicate {
    /// At least K signers have attribute
    MinCount { attribute: String, count: usize },
    /// At least K distinct values of attribute (e.g., K regions)
    MinDistinct { attribute: String, count: usize },
    /// No signer has attribute
    None { attribute: String },
    /// At least one signer has attribute
    Any { attribute: String },
    /// All signers have attribute
    All { attribute: String },
    /// Boolean combination
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
}

pub struct AttributePredicate(pub Predicate);

pub fn evaluate(predicate: &Predicate, signers: &[&SignerAttributes]) -> Result<bool>;
```

## Attributes per signer

```rust
pub struct SignerAttributes {
    pub signer_id: String,
    pub region: Option<String>,           // "europe", "asia-pacific", "americas"
    pub expertise: Vec<String>,           // ["metrology", "gas-flow", "high-precision"]
    pub nationality: Option<String>,      // for COI exclusion
    pub role: Vec<String>,                // ["director", "officer", "expert"]
    pub available_until: Option<DateTime<Utc>>,
    pub custom: HashMap<String, String>,
}
```

## Sample CNML predicates

```rust
// Standard BIML quorum: 5-of-7 directors
let biml_standard = Predicate::MinCount {
    attribute: "role:director".into(),
    count: 5,
};

// Geographic distribution: 5-of-7 with at least 3 distinct regions
let biml_geographic = Predicate::And(vec![
    Predicate::MinCount { attribute: "role:director".into(), count: 5 },
    Predicate::MinDistinct { attribute: "region".into(), count: 3 },
]);

// High-precision class: requires metrology expert
let high_precision = Predicate::And(vec![
    Predicate::MinCount { attribute: "role:director".into(), count: 5 },
    Predicate::MinDistinct { attribute: "region".into(), count: 3 },
    Predicate::MinCount { attribute: "expertise:metrology".into(), count: 2 },
]);

// COI exclusion: no signer from manufacturer's country
let coi_aware = Predicate::And(vec![
    high_precision.clone(),
    Predicate::None { attribute: format!("nationality:{}", manufacturer_country) },
]);
```

## Integration with threshold session

The predicate is part of session params. Coordinator enforces:

```rust
pub struct SessionParams {
    pub scheme: String,
    pub quorum_id: String,
    pub threshold: usize,
    pub attribute_predicate: Option<AttributePredicate>,  // NEW
    pub unlock_window: Duration,
    // ...
}
```

Coordinator accepts commitments only from signers whose attributes
satisfy the predicate. If predicate not satisfied when threshold
commitments arrive, session fails with predicate-violation error.

## Cryptographic enforcement

Beyond coordinator enforcement, attributes can be cryptographically
bound:

- Each signer's identity cert contains attribute extensions
- Predicate satisfaction verified from cert chain, not just
  coordinator's word
- Verifier can independently confirm predicate was satisfied

This is closer to attribute-based signatures (ABS) in formal
cryptography literature. Confium provides practical subset.

## Manifest expression

```toml
[[quorum]]
name = "biml_high_precision"
threshold = { t = 5, n = 7 }
predicate = """
  and(
    min_count("role:director", 5),
    min_distinct("region", 3),
    min_count("expertise:metrology", 2)
  )
"""
```

DSL parsed by `confium-attributes` crate.

## Crate scope

### `confium-attributes` (P2)

- Predicate AST
- DSL parser (string → Predicate)
- Evaluator
- Cert extension encoding/decoding (attribute bindings)
- Integration with `confium-tc` session params

## Security

- Coordinator enforces predicate before accepting commitments
- Verifier can independently re-check predicate from cert chain
- Predicate violation aborts session with signed error
- Audit log includes predicate and signer attributes (anonymized
  if ring signature mode — see `TODO.roadmap/39`)

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/27-cnml-deployment.md` — CNML uses predicates
- [Attribute-Based Signatures](https://eprint.iacr.org/2010/595)
