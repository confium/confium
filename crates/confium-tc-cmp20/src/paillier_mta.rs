//! Paillier-based Multiplicative-to-Additive (MtA) share conversion.
//!
//! Two surfaces:
//!
//! - The **legacy** functions ([`full_mta`] and friends): the
//!   demonstration path exactly as shipped in 0.8.x — no proofs, the
//!   mask sampled mod N. Deprecated: it cannot detect a misbehaving
//!   peer. Real deployments use the proved path.
//! - The **proved** functions ([`full_mta_proved`] and friends): the
//!   GG18/GG20 §3 + Appendix A protocol, which spec 70-cmp20
//!   requires — every ciphertext carries a zero-knowledge proof, the
//!   responder refuses unproven input, the initiator refuses unbound
//!   responses, and the mask is the paper's small `β′ ∈ [0, q⁵)` so
//!   honest shares never wrap: `α − β′ = k_i·x_j` exactly.
//!
//! Trust direction for the commitment keys: each party generates its
//! own `(Ñ, h₁, h₂)` and the OTHER party proves against it — see
//! `mta_proofs` for why a party must never prove to its own key.

use confium_tc::paillier::{
    PaillierError, PaillierKeypair, PaillierPrivateKey, PaillierPublicKey, add as paillier_add,
    decrypt as paillier_decrypt, encrypt as paillier_encrypt, scalar_mul as paillier_scalar_mul,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use rand::rngs::OsRng;

use crate::mta_proofs::CommitmentKey;
use crate::mta_proofs::RangeProof;
use crate::mta_proofs::RespondentProof;
use crate::mta_proofs::prove_range;
use crate::mta_proofs::prove_respondent;
use crate::mta_proofs::verify_range;
use crate::mta_proofs::verify_respondent;

// ---- legacy (deprecated) demonstration path ---------------------------

/// Message from party i to party j (round 1 of MtA).
#[derive(Debug, Clone)]
pub struct MtaMessage1 {
    /// Encrypted k_i under j's Paillier public key.
    pub ciphertext: BigUint,
}

/// Message from party j to party i (round 2 of MtA).
#[derive(Debug, Clone)]
pub struct MtaMessage2 {
    /// Encrypted k_i * x_j − β_ji under j's Paillier public key.
    pub ciphertext: BigUint,
    /// The mask β_ji that party j keeps (as additive share).
    pub beta: BigUint,
}

/// Errors during MtA.
#[derive(Debug)]
pub enum MtaError {
    Paillier(PaillierError),
    ValueTooLarge,
}

impl std::fmt::Display for MtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paillier(e) => write!(f, "paillier error: {e}"),
            Self::ValueTooLarge => write!(f, "value too large for Paillier modulus"),
        }
    }
}

impl std::error::Error for MtaError {}

impl From<PaillierError> for MtaError {
    fn from(e: PaillierError) -> Self {
        Self::Paillier(e)
    }
}

/// Party i initiates the (legacy, unproved) MtA.
#[deprecated(since = "0.8.4", note = "no proofs — use party_i_init_proved")]
pub fn party_i_init(j_public: &PaillierPublicKey, k_i: &BigUint) -> Result<MtaMessage1, MtaError> {
    let r = random_below(&j_public.n);
    let ciphertext = paillier_encrypt(j_public, k_i, &r)?;
    Ok(MtaMessage1 { ciphertext })
}

/// Party j responds in the (legacy, unproved) MtA.
#[deprecated(since = "0.8.4", note = "no proofs — use party_j_respond_proved")]
pub fn party_j_respond(
    j_keypair: &PaillierKeypair,
    msg: &MtaMessage1,
    x_j: &BigUint,
) -> Result<(MtaMessage2, BigUint), MtaError> {
    let beta = random_below(&j_keypair.public.n);
    let c_mul = paillier_scalar_mul(&j_keypair.public, &msg.ciphertext, x_j);
    let neg_beta = &j_keypair.public.n - &beta;
    let r_prime = random_below(&j_keypair.public.n);
    let c_beta = paillier_encrypt(&j_keypair.public, &neg_beta, &r_prime)?;
    let c_prime = paillier_add(&j_keypair.public, &c_mul, &c_beta);
    Ok((
        MtaMessage2 {
            ciphertext: c_prime,
            beta: beta.clone(),
        },
        beta,
    ))
}

/// Party i finishes the (legacy, unproved) MtA.
#[deprecated(since = "0.8.4", note = "no proofs — use party_i_finish_proved")]
pub fn party_i_finish(
    j_public: &PaillierPublicKey,
    j_private: &PaillierPrivateKey,
    msg: &MtaMessage2,
) -> Result<BigUint, MtaError> {
    let alpha = paillier_decrypt(j_private, j_public, &msg.ciphertext)?;
    Ok(alpha)
}

/// Run the full (legacy, unproved) MtA between party i and party j.
///
/// Returns `(α_ij, β_ji)` with `α_ij + β_ji ≡ k_i * x_j (mod N)`.
#[deprecated(since = "0.8.4", note = "no proofs — use full_mta_proved")]
pub fn full_mta(
    j_keypair: &PaillierKeypair,
    k_i: &BigUint,
    x_j: &BigUint,
) -> Result<(BigUint, BigUint), MtaError> {
    #[allow(deprecated)]
    let msg1 = party_i_init(&j_keypair.public, k_i)?;
    #[allow(deprecated)]
    let (msg2, beta) = party_j_respond(j_keypair, &msg1, x_j)?;
    #[allow(deprecated)]
    let alpha = party_i_finish(&j_keypair.public, &j_keypair.private, &msg2)?;
    Ok((alpha, beta))
}

// ---- proved path (GG18 §3 + Appendix A) --------------------------------

/// Proved round-1 message: ciphertext plus its range proof.
#[derive(Debug, Clone)]
pub struct ProvedMessage1 {
    /// Encrypted k_i under j's Paillier public key.
    pub ciphertext: BigUint,
    /// ZK range proof that the encrypted value is `< q³`.
    pub range_proof: RangeProof,
}

/// Proved round-2 message: bound ciphertext plus its respondent proof.
#[derive(Debug, Clone)]
pub struct ProvedMessage2 {
    /// Encrypted k_i·x_j + β′ under j's Paillier public key.
    pub ciphertext: BigUint,
    /// ZK proof that this ciphertext is `c₁^x·Γ^{β'}·r^N` with
    /// `x < q³`, `β′ < q⁷`.
    pub respondent_proof: RespondentProof,
    /// The mask β′ (party j's negated additive share).
    pub beta: BigUint,
}

/// Errors on the proved MtA path.
#[derive(Debug)]
pub enum MtaProofError {
    /// Underlying Paillier failure.
    Paillier(PaillierError),
    /// A ZK proof failed verification — the peer deviated from the
    /// protocol.
    InvalidProof,
}

impl std::fmt::Display for MtaProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paillier(e) => write!(f, "paillier error: {e}"),
            Self::InvalidProof => write!(f, "MtA ZK proof failed verification"),
        }
    }
}

impl std::error::Error for MtaProofError {}

impl From<PaillierError> for MtaProofError {
    fn from(e: PaillierError) -> Self {
        Self::Paillier(e)
    }
}

/// Party i initiates the proved MtA: encrypt k_i under j's public key
/// and prove it is in range.
///
/// `ck_j` is party j's commitment key (j verifies this proof);
/// `q` is the ECDSA group order.
pub fn party_i_init_proved(
    j_public: &PaillierPublicKey,
    ck_j: &CommitmentKey,
    q: &BigUint,
    k_i: &BigUint,
) -> Result<ProvedMessage1, MtaProofError> {
    let r = random_below(&j_public.n);
    let ciphertext = paillier_encrypt(j_public, k_i, &r)?;
    let range_proof = prove_range(q, j_public, ck_j, &ciphertext, k_i, &r);
    Ok(ProvedMessage1 {
        ciphertext,
        range_proof,
    })
}

/// Party j responds in the proved MtA: verify the range proof, then
/// multiply by x_j and mask with β′.
///
/// `ck_j` is j's own commitment key (the initiator proved against
/// it); `ck_i` is party i's key (i verifies the respondent proof j
/// produces). Returns the response for i plus j's own share β′.
#[allow(clippy::too_many_arguments)]
pub fn party_j_respond_proved(
    j_keypair: &PaillierKeypair,
    ck_i: &CommitmentKey,
    ck_j: &CommitmentKey,
    q: &BigUint,
    msg: &ProvedMessage1,
    x_j: &BigUint,
) -> Result<(ProvedMessage2, BigUint), MtaProofError> {
    if !verify_range(
        q,
        &j_keypair.public,
        ck_j,
        &msg.ciphertext,
        &msg.range_proof,
    ) {
        return Err(MtaProofError::InvalidProof);
    }

    // Small mask per the paper: β′ ∈ [0, q⁵) so k·x + β′ never wraps
    // mod N and the respondent proof's range checks are satisfiable.
    let q5 = {
        let q2 = q * q;
        &q2 * &q2 * q
    };
    let mut rng = OsRng;
    let beta_prime = rng.gen_biguint_range(&BigUint::zero(), &q5);

    // c' = c^{x_j} · Γ^{β'} · r'^N = E(k·x + β')
    let c_mul = paillier_scalar_mul(&j_keypair.public, &msg.ciphertext, x_j);
    let r_prime = random_below(&j_keypair.public.n);
    let c_beta = paillier_encrypt(&j_keypair.public, &beta_prime, &r_prime)?;
    let c_prime = paillier_add(&j_keypair.public, &c_mul, &c_beta);

    let respondent_proof = prove_respondent(
        q,
        &j_keypair.public,
        ck_i,
        &msg.ciphertext,
        &c_prime,
        x_j,
        &beta_prime,
        &r_prime,
    );

    Ok((
        ProvedMessage2 {
            ciphertext: c_prime,
            respondent_proof,
            beta: beta_prime.clone(),
        },
        beta_prime,
    ))
}

/// Party i finishes the proved MtA: verify the respondent proof,
/// then decrypt.
///
/// `ck_i` is party i's commitment key (the proof is addressed to i).
/// Returns `α = k_i·x_j + β′`; pair with j's `β′` via `α − β′`.
#[allow(clippy::too_many_arguments)]
pub fn party_i_finish_proved(
    j_public: &PaillierPublicKey,
    ck_i: &CommitmentKey,
    q: &BigUint,
    msg1_ciphertext: &BigUint,
    j_private: &PaillierPrivateKey,
    msg: &ProvedMessage2,
) -> Result<BigUint, MtaProofError> {
    if !verify_respondent(
        q,
        j_public,
        ck_i,
        msg1_ciphertext,
        &msg.ciphertext,
        &msg.respondent_proof,
    ) {
        return Err(MtaProofError::InvalidProof);
    }
    let alpha = paillier_decrypt(j_private, j_public, &msg.ciphertext)?;
    Ok(alpha)
}

/// Run the full proved MtA protocol between party i and party j.
///
/// `ck_i`/`ck_j` are the parties' commitment keys (each proves against
/// the OTHER's). Returns `(α, β′)` with `α − β′ = k_i·x_j` exactly
/// (hence also mod q and mod N) — honest shares never wrap.
pub fn full_mta_proved(
    j_keypair: &PaillierKeypair,
    ck_i: &CommitmentKey,
    ck_j: &CommitmentKey,
    q: &BigUint,
    k_i: &BigUint,
    x_j: &BigUint,
) -> Result<(BigUint, BigUint), MtaProofError> {
    let msg1 = party_i_init_proved(&j_keypair.public, ck_j, q, k_i)?;
    let (msg2, beta) = party_j_respond_proved(j_keypair, ck_i, ck_j, q, &msg1, x_j)?;
    let alpha = party_i_finish_proved(
        &j_keypair.public,
        ck_i,
        q,
        &msg1.ciphertext,
        &j_keypair.private,
        &msg2,
    )?;
    Ok((alpha, beta))
}

fn random_below(n: &BigUint) -> BigUint {
    let mut rng = OsRng;
    loop {
        let r = rng.gen_biguint(n.bits());
        if r < *n && !r.is_zero() {
            return r;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confium_tc::paillier::generate_keypair;

    // Honest execution needs N > k·x + β' < q⁵ + q² ≈ 2^1282, so the
    // test Paillier key uses 642-bit primes (~1284-bit N). Shared
    // across the module's tests — keygen at this size takes seconds.
    pub(super) fn shared_fixtures()
    -> &'static (PaillierKeypair, CommitmentKey, CommitmentKey, BigUint) {
        use std::sync::OnceLock;
        static FIX: OnceLock<(PaillierKeypair, CommitmentKey, CommitmentKey, BigUint)> =
            OnceLock::new();
        FIX.get_or_init(|| {
            let kp = generate_keypair(642);
            // 64-bit safe primes: enough structure for tests (NOT
            // production strength — see the module docs).
            let ck_i = crate::mta_proofs::generate_commitment_key(64);
            let ck_j = crate::mta_proofs::generate_commitment_key(64);
            // P-256 group order.
            let q = BigUint::parse_bytes(
                b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                16,
            )
            .unwrap();
            (kp, ck_i, ck_j, q)
        })
    }

    #[test]
    fn proved_mta_shares_subtract_to_product() {
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let (alpha, beta) = full_mta_proved(kp, ck_i, ck_j, q, &k_i, &x_j).unwrap();
        // α − β' = k_i * x_j exactly (the paper's share contract).
        assert_eq!((&alpha - &beta) % q, (&k_i * &x_j) % q);
    }

    #[test]
    fn proved_mta_no_modular_wrap() {
        // With k, x < q the honest α = k·x + β' must be < N (no wrap).
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        let k_i = q - BigUint::from(1u32);
        let x_j = q - BigUint::from(2u32);
        let (alpha, beta) = full_mta_proved(kp, ck_i, ck_j, q, &k_i, &x_j).unwrap();
        assert!(alpha < kp.public.n);
        assert_eq!((&alpha - &beta) % q, (&k_i * &x_j) % q);
    }

    #[test]
    fn proved_mta_multiple_pairs() {
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        for (k, x) in [(10u32, 20u32), (100u32, 50u32), (7u32, 13u32)] {
            let k_i = BigUint::from(k);
            let x_j = BigUint::from(x);
            let (alpha, beta) = full_mta_proved(kp, ck_i, ck_j, q, &k_i, &x_j).unwrap();
            assert_eq!((&alpha - &beta) % q, (&k_i * &x_j) % q, "pair ({k}, {x})");
        }
    }

    #[test]
    fn proved_mta_shares_neither_reveals_product() {
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let (alpha, beta) = full_mta_proved(kp, ck_i, ck_j, q, &k_i, &x_j).unwrap();
        let product = &k_i * &x_j;
        assert_ne!(alpha, product);
        assert_ne!(beta, product);
    }

    #[test]
    fn proved_mta_beta_is_random() {
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let (_, beta1) = full_mta_proved(kp, ck_i, ck_j, q, &k_i, &x_j).unwrap();
        let (_, beta2) = full_mta_proved(kp, ck_i, ck_j, q, &k_i, &x_j).unwrap();
        assert_ne!(beta1, beta2);
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_mta_still_adds_to_product() {
        // The deprecated demo path keeps its historical contract.
        let kp = generate_keypair(128);
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let (alpha, beta) = full_mta(&kp, &k_i, &x_j).unwrap();
        assert_eq!(
            (&alpha + &beta) % &kp.public.n,
            (&k_i * &x_j) % &kp.public.n
        );
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Paired rejects-forgery tests for every proof verifier.

    use super::*;

    fn shared_fixtures() -> &'static (PaillierKeypair, CommitmentKey, CommitmentKey, BigUint) {
        crate::paillier_mta::tests::shared_fixtures()
    }

    #[test]
    fn responder_rejects_tampered_ciphertext() {
        // A ciphertext not built as c₁^x·Γ^{β'}·r^N must fail the
        // respondent proof even if the proof itself is honest.
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let msg1 = party_i_init_proved(&kp.public, ck_j, q, &k_i).unwrap();
        let (mut msg2, _) = party_j_respond_proved(kp, ck_i, ck_j, q, &msg1, &x_j).unwrap();
        msg2.ciphertext = &msg2.ciphertext * BigUint::from(2u32) % &kp.public.n_squared;
        let err = party_i_finish_proved(&kp.public, ck_i, q, &msg1.ciphertext, &kp.private, &msg2);
        assert!(matches!(err, Err(MtaProofError::InvalidProof)));
    }

    #[test]
    fn responder_rejects_proof_for_different_statement() {
        // Valid (c₁, proof) pair presented against a different c₁ —
        // Fiat-Shamir binds the statement, so it must fail.
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let msg1 = party_i_init_proved(&kp.public, ck_j, q, &k_i).unwrap();
        let (msg2, _) = party_j_respond_proved(kp, ck_i, ck_j, q, &msg1, &x_j).unwrap();
        let other_c1 = party_i_init_proved(&kp.public, ck_j, q, &BigUint::from(7u32))
            .unwrap()
            .ciphertext;
        let err = party_i_finish_proved(&kp.public, ck_i, q, &other_c1, &kp.private, &msg2);
        assert!(matches!(err, Err(MtaProofError::InvalidProof)));
    }

    #[test]
    fn responder_rejects_tampered_response() {
        let (kp, ck_i, ck_j, q) = shared_fixtures();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let msg1 = party_i_init_proved(&kp.public, ck_j, q, &k_i).unwrap();
        let (mut msg2, _) = party_j_respond_proved(kp, ck_i, ck_j, q, &msg1, &x_j).unwrap();
        msg2.respondent_proof.s1 += BigUint::from(1u32);
        let err = party_i_finish_proved(&kp.public, ck_i, q, &msg1.ciphertext, &kp.private, &msg2);
        assert!(matches!(err, Err(MtaProofError::InvalidProof)));
    }

    #[test]
    fn responder_rejects_secret_above_bound() {
        // The responder's secret x = q⁵ (far past the proven q³ bound)
        // must fail the s₁ ≤ q³ integer check. (The mask bound t₁ ≤ q⁷
        // only becomes reachable with paper-sized N > q⁸; at test key
        // sizes every encryptable mask is below q⁷ by construction.)
        let (kp, ck_i, _ck_j, q) = shared_fixtures();
        let k_i = BigUint::from(42u32);
        let x_j = {
            let q2 = q * q;
            &q2 * &q2 * q
        };
        let msg1 = party_i_init_proved(&kp.public, ck_i, q, &k_i).unwrap();

        let mut rng = OsRng;
        let beta_prime = rng.gen_biguint_range(&BigUint::zero(), &(q * q));
        let r_prime = random_below(&kp.public.n);
        let c_mul = paillier_scalar_mul(&kp.public, &msg1.ciphertext, &x_j);
        let c_beta = paillier_encrypt(&kp.public, &beta_prime, &r_prime).unwrap();
        let c_prime = paillier_add(&kp.public, &c_mul, &c_beta);
        let proof = prove_respondent(
            q,
            &kp.public,
            ck_i,
            &msg1.ciphertext,
            &c_prime,
            &x_j,
            &beta_prime,
            &r_prime,
        );
        let msg2 = ProvedMessage2 {
            ciphertext: c_prime,
            respondent_proof: proof,
            beta: beta_prime,
        };
        let err = party_i_finish_proved(&kp.public, ck_i, q, &msg1.ciphertext, &kp.private, &msg2);
        assert!(matches!(err, Err(MtaProofError::InvalidProof)));
    }

    #[test]
    fn initiator_rejects_out_of_range_plaintext() {
        // An honest proof over m = q⁵ (way past the q³ bound) fails
        // the s₁ ≤ q³ check — the wrap-around attack is blocked.
        let (kp, _ck_i, ck_j, q) = shared_fixtures();
        let q5 = {
            let q2 = q * q;
            &q2 * &q2 * q
        };
        let r = random_below(&kp.public.n);
        let c = paillier_encrypt(&kp.public, &q5, &r).unwrap();
        let proof = prove_range(q, &kp.public, ck_j, &c, &q5, &r);
        assert!(!verify_range(q, &kp.public, ck_j, &c, &proof));
    }

    #[test]
    fn initiator_rejects_proof_for_a_different_ciphertext() {
        let (kp, _ck_i, ck_j, q) = shared_fixtures();
        let m = BigUint::from(12345u32);
        let r = random_below(&kp.public.n);
        let c = paillier_encrypt(&kp.public, &m, &r).unwrap();
        let proof = prove_range(q, &kp.public, ck_j, &c, &m, &r);
        let other_c = paillier_encrypt(&kp.public, &m, &random_below(&kp.public.n)).unwrap();
        assert!(!verify_range(q, &kp.public, ck_j, &other_c, &proof));
    }

    #[test]
    fn initiator_rejects_wrong_commitment_key() {
        // A proof verified under a different commitment key must
        // fail — the transcript binds the key.
        let (kp, _ck_i, ck_j, q) = shared_fixtures();
        let m = BigUint::from(12345u32);
        let r = random_below(&kp.public.n);
        let c = paillier_encrypt(&kp.public, &m, &r).unwrap();
        let proof = prove_range(q, &kp.public, ck_j, &c, &m, &r);
        let wrong_ck = crate::mta_proofs::generate_commitment_key(64);
        assert!(!verify_range(q, &kp.public, &wrong_ck, &c, &proof));
    }
}
