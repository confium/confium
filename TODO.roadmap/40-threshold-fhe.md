# 40 — Threshold FHE (research)

## Purpose

Threshold Fully Homomorphic Encryption (FHE) enables computation
on encrypted data without decryption. Plus threshold: computation
requires quorum agreement.

For OIML: statistical analysis of test reports without decrypting
individual reports. Compute aggregate quality metrics across
manufacturers without revealing individual measurements.

Long horizon research. Separate track from main framework.

## FHE overview

FHE allows arbitrary computation on ciphertexts:

```
encrypt(x), encrypt(y)
   ↓ homomorphic computation (e.g., add, multiply)
encrypt(x + y), encrypt(x * y)
```

Decryption reveals only the result, not the inputs.

## BFV scheme

BFV (Brakerski-Fan-Vercauteren) operates on integer arithmetic
over polynomial rings. Suitable for arithmetic-heavy computation
(statistics, machine learning).

BFV parameters trade off between:
- **Security**: large polynomial degree, large coefficient modulus
- **Performance**: smaller parameters
- **Correctness**: noise budget degrades with each operation

## Threshold BFV

Each party holds a share of the BFV decryption key. Decryption
requires T-of-N shares:

```
Encryptor:
  - Run BFV encrypt on plaintext → ciphertext
  - Ciphertext published

Computor (anyone, including non-quorum):
  - Run homomorphic operations on ciphertext
  - Result is still encrypted

Decryptor (T-of-N quorum):
  - Each party computes partial decryption
  - Coordinator aggregates partials → full decryption
  - Plaintext result revealed
```

The "computor" can be anyone — that's the point. Computation on
encrypted data doesn't require key access. Only decryption requires
quorum.

## Use cases (research)

- **Aggregate statistics** across encrypted test reports
- **Privacy-preserving benchmarking** across manufacturers
- **Outlier detection** without revealing individual reports
- **Regulatory analytics** without compromising trade secrets

For OIML: "across 200 gas flow meter type approvals, the average
calibration drift is X, with no individual report revealed."

## Crate scope (future, P3)

### `confium-tc-fhe-bfv` (P3 — research)

```rust
pub struct BfvParams {
    pub polynomial_degree: usize,           // typically 4096-32768
    pub plaintext_modulus: u64,
    pub coefficient_modulus: Vec<u64>,
    pub security_level: SecurityLevel,      // 128-bit target
}

pub struct BfvPublicKey(pub Vec<u8>);
pub struct BfvSecretKeyShare(pub Vec<u8>);
pub struct BfvCiphertext(pub Vec<u8>);

pub fn bfv_dkg(parties: &[PartyId], params: &BfvParams) -> Result<DkgResult>;

pub fn bfv_encrypt(pk: &BfvPublicKey, plaintext: &Plaintext) -> Result<BfvCiphertext>;
pub fn bfv_add(a: &BfvCiphertext, b: &BfvCiphertext) -> Result<BfvCiphertext>;
pub fn bfv_mul(a: &BfvCiphertext, b: &BfvCiphertext) -> Result<BfvCiphertext>;

pub fn bfv_decrypt_partial(share: &BfvSecretKeyShare, ct: &BfvCiphertext) -> Result<PartialDecryption>;
pub fn bfv_combine_partials(partials: &[PartialDecryption]) -> Result<Plaintext>;
```

## Implementation challenges

- **Performance**: FHE operations are 1000-100000x slower than
  equivalent plaintext operations. Minutes to hours per operation.
- **Parameter selection**: choosing secure parameters is hard;
  requires expertise
- **Bootstrapping**: deep computations require "refreshing" noise
  budget, which is expensive
- **Threshold BFV**: combining shares adds complexity

## Alternative: threshold computation oracles

For some use cases, simpler than full FHE:

- **MPC** (multi-party computation): parties collaboratively compute
  on plaintext inputs without revealing them. Confium's threshold
  signing infrastructure partially reusable.
- **Secure aggregation**: parties send encrypted aggregates;
  quorum combines. Less expressive than FHE but much faster.

For Mode 3 deployments needing aggregate analytics, MPC via
`confium-tc` may suffice without FHE.

## Deployment phasing

- **Phase 1 (through 2027)**: no FHE. Aggregates computed by
  trusted coordinator.
- **Phase 2 (2028+)**: research threshold BFV prototype. Not for
  production deployment.
- **Phase 3 (2030+)**: if FHE matures, deploy for niche use cases.

## Out of scope for initial framework

Threshold FHE is research output, not framework primitive. Tracked
for completeness; not blocking Q2 2027 NIST submission.

## References

- `TODO.roadmap/26-confium-framework.md`
- [BFV paper](https://eprint.iacr.org/2012/144)
- [Microsoft SEAL](https://github.com/microsoft/SEAL) (reference FHE library)
- [Zama Concrete](https://www.zama.ai/concrete) (Rust FHE library)
