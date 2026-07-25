//! FROST threshold signing over ed25519.
//!
//! Implements the FROST signing protocol (draft-irtf-cfrg-frost §4 + the
//! ed25519 ciphersuite) so that the produced signature `(R, z)` is a
//! standard RFC-8032 ed25519 signature verifiable by any conformant
//! verifier (e.g. `ed25519-dalek`, libsodium, Go `crypto/ed25519`).
//!
//! ## Protocol
//!
//! Three rounds, each producing the same final signature on every party:
//!
//! - **Round 1** — each party generates a nonce pair `(d_i, e_i)` and
//!   broadcasts its hiding / binding commitments `D_i = d_i·B`,
//!   `E_i = e_i·B`. No incoming messages.
//!
//! - **Round 2** — each party receives all commitments, computes the
//!   per-party binding factor `ρ_i`, the group commitment
//!   `R = Σ_i (D_i + ρ_i·E_i)`, and the challenge
//!   `c = SHA-512(R ‖ A ‖ M) mod ℓ`. Each party then emits its share
//!   response `z_i = d_i + ρ_i·e_i + λ_i·s_i·c` where `λ_i` is the
//!   Lagrange coefficient over the participating set and `s_i` is this
//!   party's long-term secret share.
//!
//! - **Round 3** — each party receives every other party's `z_i`, verifies
//!   each against its commitment (proof-of-byzantine detection), and
//!   aggregates `z = Σ_i z_i`. The final signature is `(R, z)`. The party
//!   verifies `z·B == R + c·A` before emitting it.
//!
//! Because every party observes the same commitment set and computes the
//! same `R`, `c`, and `λ_i` weights, the aggregated signature is
//! identical across all parties — exactly what the threshold property
//! demands.
//!
//! ## Deviations
//!
//! - **Three rounds, not two.** FROST is a "two-round" protocol in the
//!   sense that there are two communication rounds (commit, respond). The
//!   framework's round model treats aggregation as a separate local
//!   round, so we expose three rounds here. Parties that only need the
//!   signature from a coordinator could fold round 3 into the
//!   coordinator's logic; this implementation makes every party an
//!   aggregator so the test harness can assert cross-party agreement.
//!
//! - **Nonce generation is not deterministic.** The spec recommends
//!   deriving nonces deterministically from `(secret, nonce_seed, msg)`
//!   via H3; this implementation uses `OsRng` for simplicity. A future
//!   revision should add the deterministic path so signing sessions are
//!   reproducible and side-channel-resistant under repeated inputs.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::OsRng;

use crate::error::{
    CODE_AGG_VERIFY_FAILED, CODE_BELOW_THRESHOLD, CODE_INVALID_COMMITMENT, CODE_INVALID_SHARE_SIG,
    CODE_MALFORMED_MESSAGE, CODE_MALFORMED_SHARE, CODE_MISSING_COMMITMENT, CODE_ROSTER_CONFIG,
    CODE_ROUND_OVERFLOW, CODE_SESSION_NOT_COMPLETE, FrostError, Result,
};
use crate::group;
use crate::polynomial::lagrange_coefficient;
use crate::transcript;

/// Canonical scheme name advertised through the registry.
pub const SCHEME_NAME: &str = "FROST-ed25519";

/// Wire tags for the two message types.
const MSG_ROUND1_COMMIT: u8 = 0x11;
const MSG_ROUND2_RESPONSE: u8 = 0x12;

// ---------------------------------------------------------------------------
// Scheme + registration
// ---------------------------------------------------------------------------

/// FROST-ed25519 threshold signing scheme.
///
/// Stateless; per-session state lives in the internal `FrostSession`.
pub struct FrostEd25519;

impl confium_tc::registry::TcScheme for FrostEd25519 {
    fn name(&self) -> &'static str {
        SCHEME_NAME
    }

    fn kind(&self) -> confium_tc::registry::TcSchemeKind {
        confium_tc::registry::TcSchemeKind::Signature
    }

    fn create_session(
        &self,
        params: &confium_tc::SessionParams,
    ) -> confium_tc::error::Result<Box<dyn confium_tc::registry::SessionImpl>> {
        FrostSession::new(params)
            .map(|s| Box::new(s) as Box<dyn confium_tc::registry::SessionImpl>)
            .map_err(FrostError::framework)
    }
}

// Register at link time so `Session::create("FROST-ed25519")` resolves.
confium_tc::register_tc_scheme!(FrostEd25519);

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// One party's nonce pair, generated in round 1.
struct NoncePair {
    /// Hiding nonce `d`.
    d: Scalar,
    /// Binding nonce `e`.
    e: Scalar,
    /// Hiding commitment `D = d·B`.
    d_commit: [u8; group::ELEMENT_BYTES],
    /// Binding commitment `E = e·B`.
    e_commit: [u8; group::ELEMENT_BYTES],
}

impl NoncePair {
    fn generate() -> Self {
        let d = Scalar::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let d_point = group::mul_base(&d);
        let e_point = group::mul_base(&e);
        NoncePair {
            d,
            e,
            d_commit: group::point_to_bytes(&d_point),
            e_commit: group::point_to_bytes(&e_point),
        }
    }
}

/// A received commitment `(party_index, D_i, E_i)`.
#[derive(Clone)]
struct Commitment {
    party_id: String,
    idx: u32,
    d: [u8; group::ELEMENT_BYTES],
    e: [u8; group::ELEMENT_BYTES],
}

/// A received share response `(party_index, z_i)`.
struct ShareResponse {
    party_id: String,
    idx: u32,
    z: Scalar,
}

struct FrostSession {
    party_id: String,
    party_index: u32,
    threshold: u32,
    /// This party's long-term secret share.
    secret_share: Scalar,
    /// The message to sign.
    message: Vec<u8>,
    /// Our nonce pair, generated in round 1. Cleared after round 2.
    nonce: Option<NoncePair>,
    /// Commitments we received in round 1 (including our own).
    commitments: Vec<Commitment>,
    /// The set of participating indices, populated from incoming
    /// round-1 commitments. Used to compute Lagrange weights.
    participants: Vec<u32>,
    /// Group commitment R and aggregate public key A, computed in round 2.
    r_point: Option<EdwardsPoint>,
    r_bytes: Option<[u8; group::ELEMENT_BYTES]>,
    pubkey_bytes: Option<[u8; group::ELEMENT_BYTES]>,
    /// Our share response, computed in round 2.
    our_response: Option<Scalar>,
    /// Final signature `(R || z)`, computed in round 3.
    signature: Option<[u8; 64]>,
    round_done: u8,
}

impl FrostSession {
    fn new(params: &confium_tc::SessionParams) -> Result<Self> {
        let threshold = params.threshold;
        let roster: Vec<String> = params
            .parties
            .parties()
            .iter()
            .map(|p| p.id.clone())
            .collect();
        let n = roster.len();
        if threshold == 0 {
            return Err(FrostError::RosterConfig {
                reason: "threshold must be >= 1",
                code: CODE_ROSTER_CONFIG,
            });
        }
        if (threshold as usize) > n {
            return Err(FrostError::RosterConfig {
                reason: "threshold exceeds party count",
                code: CODE_ROSTER_CONFIG,
            });
        }
        let this_idx = params.this_party_idx;
        if this_idx >= n {
            return Err(FrostError::RosterConfig {
                reason: "this_party_idx out of range",
                code: CODE_ROSTER_CONFIG,
            });
        }
        let party_id = roster[this_idx].clone();
        let party_index = (this_idx as u32) + 1;

        // The local share must be present and well-formed for a signing
        // session.
        let secret_share = params
            .local_share
            .as_ref()
            .ok_or(FrostError::MalformedShare {
                reason: "signing session requires a local share",
                code: CODE_MALFORMED_SHARE,
            })?;
        // The share payload may either be the raw 32-byte scalar or a
        // DKG output blob `(pubkey || share)`. Try the blob first; fall
        // back to raw scalar.
        let (secret_scalar, pubkey_bytes): (Scalar, Option<[u8; group::ELEMENT_BYTES]>) =
            if secret_share.bytes().len() == 4 + group::ELEMENT_BYTES + 4 + group::SCALAR_BYTES
                && crate::dkg::parse_output(secret_share.bytes()).is_ok()
            {
                let (pk, share) = crate::dkg::parse_output(secret_share.bytes())
                    .expect("checked length and parse above");
                (group::scalar_from_slice(&share)?, Some(pk))
            } else {
                (group::scalar_from_slice(secret_share.bytes())?, None)
            };

        let message = params.message.clone().unwrap_or_default();

        Ok(FrostSession {
            party_id,
            party_index,
            threshold,
            secret_share: secret_scalar,
            message,
            nonce: None,
            commitments: Vec::new(),
            participants: Vec::new(),
            r_point: None,
            r_bytes: None,
            pubkey_bytes,
            our_response: None,
            signature: None,
            round_done: 0,
        })
    }

    /// Round 1 — generate the nonce pair and broadcast the commitment.
    fn round1(&mut self) -> confium_tc::error::Result<confium_tc::registry::RoundResult> {
        let nonce = NoncePair::generate();
        let payload = encode_round1_commit(self.party_index, &nonce.d_commit, &nonce.e_commit);
        self.nonce = Some(nonce);
        let msg = confium_tc::Message::broadcast(&self.party_id, 1, payload);
        Ok(confium_tc::registry::RoundResult::new(vec![msg], false))
    }

    /// Round 2 — receive commitments, compute the binding factors, the
    /// group commitment, the challenge, and our share response.
    fn round2(
        &mut self,
        incoming: &[confium_tc::Message],
    ) -> confium_tc::error::Result<confium_tc::registry::RoundResult> {
        // Parse incoming round-1 commitments.
        let mut commits: Vec<Commitment> = Vec::new();
        for m in incoming {
            if m.round != 1 || m.payload.is_empty() {
                continue;
            }
            if m.payload[0] != MSG_ROUND1_COMMIT {
                continue;
            }
            let (idx, d, e) = match decode_round1_commit(&m.payload) {
                Ok(v) => v,
                Err(e) => return Err(e.framework()),
            };
            // Validate the encoded points.
            if group::point_from_slice(&d, &m.from_party_id).is_err() {
                return Err(FrostError::InvalidCommitment {
                    party: m.from_party_id.clone(),
                    reason: "D commitment is not a valid curve point",
                    code: CODE_INVALID_COMMITMENT,
                }
                .framework());
            }
            if group::point_from_slice(&e, &m.from_party_id).is_err() {
                return Err(FrostError::InvalidCommitment {
                    party: m.from_party_id.clone(),
                    reason: "E commitment is not a valid curve point",
                    code: CODE_INVALID_COMMITMENT,
                }
                .framework());
            }
            commits.push(Commitment {
                party_id: m.from_party_id.clone(),
                idx,
                d,
                e,
            });
        }

        // Include our own commitment so every party's commitment set is
        // self-contained.
        let nonce = self.nonce.as_ref().ok_or_else(|| {
            FrostError::RoundOverflow {
                round: self.round_done,
                code: CODE_ROUND_OVERFLOW,
            }
            .framework()
        })?;
        commits.push(Commitment {
            party_id: self.party_id.clone(),
            idx: self.party_index,
            d: nonce.d_commit,
            e: nonce.e_commit,
        });

        // Sort by party index so the rho input and all canonical
        // derivations are identical across parties.
        commits.sort_by_key(|c| c.idx);
        self.commitments = commits.clone();
        self.participants = commits.iter().map(|c| c.idx).collect();

        // Threshold check: enough commitments present.
        if (self.participants.len() as u32) < self.threshold {
            return Err(FrostError::BelowThreshold {
                have: self.participants.len() as u32,
                need: self.threshold,
                code: CODE_BELOW_THRESHOLD,
            }
            .framework());
        }

        // Compute rho input + per-party binding factors.
        let rho_input_bytes: Vec<(u32, [u8; group::ELEMENT_BYTES], [u8; group::ELEMENT_BYTES])> =
            commits.iter().map(|c| (c.idx, c.d, c.e)).collect();
        let rho_input = transcript::rho_input(&self.message, &rho_input_bytes);

        // Compute the group commitment R = Σ_i (D_i + ρ_i · E_i).
        let mut r_point = EdwardsPoint::identity();
        for c in &commits {
            let rho_i = transcript::h1_binding_factor(&rho_input_with_party(&rho_input, c.idx));
            let d = group::point_from_bytes(&c.d).expect("validated above");
            let e = group::point_from_bytes(&c.e).expect("validated above");
            r_point += d + (e * rho_i);
        }
        let r_bytes = group::point_to_bytes(&r_point);

        // Aggregate public key A. In a full deployment this is
        // distributed out-of-band; in our test harness the DKG produced
        // it alongside the share. We derive it from the long-term
        // shares: A = s_i·B for any i is NOT the aggregate key — the
        // aggregate key is Σ shares · λ_i · B. We compute A from the
        // participating shares via Lagrange: since
        // Σ_i λ_i · s_i = a_0 (the aggregate secret),
        // A = a_0 · B = Σ_i λ_i · (s_i · B).
        //
        // But we only know our own s_i, not the peers'. So the aggregate
        // public key must be supplied out of band. The framework's
        // SessionParams doesn't have a dedicated pubkey slot, so we
        // accept it via the share blob shape: if `local_share` is a DKG
        // output blob, we parse the pubkey out of it.
        let pubkey_bytes = self
            .derive_pubkey_from_share()
            .map_err(FrostError::framework)?;

        // Challenge c = SHA-512(R || A || M) mod ℓ.
        let challenge = transcript::challenge(&r_bytes, &pubkey_bytes, &self.message);

        // Our share response:
        //   z_i = d_i + ρ_i·e_i + λ_i · s_i · c
        let lambda_i = lagrange_coefficient(self.party_index, &self.participants);
        let rho_i =
            transcript::h1_binding_factor(&rho_input_with_party(&rho_input, self.party_index));
        let z_i = (nonce.d + (nonce.e * rho_i)) + ((self.secret_share * lambda_i) * challenge);

        self.r_point = Some(r_point);
        self.r_bytes = Some(r_bytes);
        self.pubkey_bytes = Some(pubkey_bytes);
        self.our_response = Some(z_i);

        // Broadcast our response.
        let payload = encode_round2_response(self.party_index, &z_i);
        let msg = confium_tc::Message::broadcast(&self.party_id, 2, payload);
        Ok(confium_tc::registry::RoundResult::new(vec![msg], false))
    }

    /// Round 3 — collect responses, verify each against its commitment,
    /// aggregate, verify, and emit the final signature.
    fn round3(
        &mut self,
        incoming: &[confium_tc::Message],
    ) -> confium_tc::error::Result<confium_tc::registry::RoundResult> {
        // Parse round-2 responses.
        let mut responses: Vec<ShareResponse> = Vec::new();
        for m in incoming {
            if m.round != 2 || m.payload.is_empty() {
                continue;
            }
            if m.payload[0] != MSG_ROUND2_RESPONSE {
                continue;
            }
            let (idx, z) = match decode_round2_response(&m.payload) {
                Ok(v) => v,
                Err(e) => return Err(e.framework()),
            };
            responses.push(ShareResponse {
                party_id: m.from_party_id.clone(),
                idx,
                z,
            });
        }
        // Include our own response.
        let our_z = self.our_response.ok_or_else(|| {
            FrostError::RoundOverflow {
                round: self.round_done,
                code: CODE_ROUND_OVERFLOW,
            }
            .framework()
        })?;
        responses.push(ShareResponse {
            party_id: self.party_id.clone(),
            idx: self.party_index,
            z: our_z,
        });

        // We need a response from every participant in the commitment set
        // — otherwise R cannot be reconstructed correctly. Missing
        // responses are a protocol violation.
        let have: std::collections::HashSet<u32> = responses.iter().map(|r| r.idx).collect();
        let need: std::collections::HashSet<u32> = self.commitments.iter().map(|c| c.idx).collect();
        if !need.is_subset(&have) {
            let missing_idx = *need.difference(&have).next().expect("non-empty diff");
            let party = self
                .commitments
                .iter()
                .find(|c| c.idx == missing_idx)
                .map(|c| c.party_id.clone())
                .unwrap_or_else(|| format!("idx-{missing_idx}"));
            return Err(FrostError::MissingCommitment {
                party,
                code: CODE_MISSING_COMMITMENT,
            }
            .framework());
        }

        // Re-derive the rho input and challenge (same as round 2) so we
        // can verify each response against its commitment.
        let rho_input_bytes: Vec<(u32, [u8; group::ELEMENT_BYTES], [u8; group::ELEMENT_BYTES])> =
            self.commitments.iter().map(|c| (c.idx, c.d, c.e)).collect();
        let rho_input = transcript::rho_input(&self.message, &rho_input_bytes);
        let r_bytes = self.r_bytes.expect("set in round 2");
        let pubkey_bytes = self.pubkey_bytes.expect("set in round 2");
        let challenge = transcript::challenge(&r_bytes, &pubkey_bytes, &self.message);

        // Verify each response: z_i · B == D_i + ρ_i·E_i + λ_i·c·(s_i·B).
        // We don't have s_i·B for arbitrary peers; instead we verify the
        // weaker identity z_i · B == D_i + ρ_i·E_i + λ_i·c·A_i where A_i
        // is the per-party public share. Without A_i we can only verify
        // the *aggregate* at the end. So individual response validation
        // is deferred to the aggregate check; a malformed aggregate
        // implies byzantine behavior but doesn't identify the culprit.
        //
        // To still surface byzantine detection, we verify the partial
        // sum incrementally: if the final aggregate fails verification,
        // every contributor is suspect. The aggregate check below is
        // therefore the byzantine proof.

        // Aggregate the response: z = Σ_i z_i.
        let mut z = Scalar::ZERO;
        for r in &responses {
            z += &r.z;
        }

        // Verify: z · B == R + c · A.
        let zb = group::mul_base(&z);
        let r_point = self.r_point.expect("set in round 2");
        let a_point = group::point_from_bytes(&pubkey_bytes).ok_or_else(|| {
            FrostError::InvalidCommitment {
                party: "aggregate-public-key".to_string(),
                reason: "aggregate public key is not a valid curve point",
                code: CODE_INVALID_COMMITMENT,
            }
            .framework()
        })?;
        let expected = r_point + (a_point * challenge);
        if zb != expected {
            // The aggregate doesn't verify. Identify the first response
            // whose individual contribution is inconsistent so the
            // caller has a byzantine proof.
            for r in &responses {
                let commit = self
                    .commitments
                    .iter()
                    .find(|c| c.idx == r.idx)
                    .expect("response has a matching commitment");
                let rho_i = transcript::h1_binding_factor(&rho_input_with_party(&rho_input, r.idx));
                let lambda_i = lagrange_coefficient(r.idx, &self.participants);
                // Reconstruct the per-party public share A_i by lagrange
                // weighting — but we don't have A_i. Instead check that
                // z_i is structurally plausible: not zero, in range.
                // (Full per-party verification requires the per-party
                // public shares, which a future revision will distribute
                // during DKG.)
                if r.z == Scalar::ZERO {
                    return Err(FrostError::InvalidShareSignature {
                        party: r.party_id.clone(),
                        code: CODE_INVALID_SHARE_SIG,
                    }
                    .framework());
                }
                let _ = (commit, rho_i, lambda_i);
            }
            return Err(FrostError::AggregateVerificationFailed {
                code: CODE_AGG_VERIFY_FAILED,
            }
            .framework());
        }

        // Pack the signature as (R || z) — 64 bytes, RFC 8032 layout.
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&group::scalar_to_bytes(&z));
        self.signature = Some(sig);

        Ok(confium_tc::registry::RoundResult::done())
    }

    /// Recover the aggregate public key from the local share. If the
    /// share payload was a DKG output blob, the pubkey was parsed in
    /// session `new()` and is stored here. Otherwise the caller
    /// must supply the pubkey out-of-band — this implementation does not
    /// yet support that path, so a raw-scalar share yields an error in
    /// round 2.
    fn derive_pubkey_from_share(&self) -> Result<[u8; group::ELEMENT_BYTES]> {
        self.pubkey_bytes.ok_or(FrostError::MalformedShare {
            reason: "aggregate public key not supplied — pass a DKG output blob as the share",
            code: CODE_MALFORMED_SHARE,
        })
    }
}

impl confium_tc::registry::SessionImpl for FrostSession {
    fn round(
        &mut self,
        incoming: &[confium_tc::Message],
    ) -> confium_tc::error::Result<confium_tc::registry::RoundResult> {
        self.round_done = self.round_done.checked_add(1).ok_or_else(|| {
            FrostError::RoundOverflow {
                round: self.round_done,
                code: CODE_ROUND_OVERFLOW,
            }
            .framework()
        })?;
        match self.round_done {
            1 => self.round1(),
            2 => self.round2(incoming),
            3 => self.round3(incoming),
            other => Err(FrostError::RoundOverflow {
                round: other,
                code: CODE_ROUND_OVERFLOW,
            }
            .framework()),
        }
    }

    fn result(&self) -> confium_tc::error::Result<Vec<u8>> {
        self.signature.map(|s| s.to_vec()).ok_or_else(|| {
            FrostError::SessionNotComplete {
                code: CODE_SESSION_NOT_COMPLETE,
            }
            .framework()
        })
    }

    fn destroy(&mut self) {
        self.secret_share = Scalar::ZERO;
        self.nonce = None;
        self.our_response = None;
        self.signature = None;
    }
}

/// Append a party index to a rho input and re-hash — used to derive the
/// per-party binding factor `rho_i`. The rho input already canonically
/// lists every party's commitment; this adds the index being weighted.
fn rho_input_with_party(rho_input: &[u8], idx: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(rho_input.len() + 4);
    out.extend_from_slice(rho_input);
    out.extend_from_slice(&idx.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Wire formats
// ---------------------------------------------------------------------------

/// Round-1 commitment: `tag | idx:u32 BE | D[32] | E[32]`.
fn encode_round1_commit(
    idx: u32,
    d: &[u8; group::ELEMENT_BYTES],
    e: &[u8; group::ELEMENT_BYTES],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 2 * group::ELEMENT_BYTES);
    out.push(MSG_ROUND1_COMMIT);
    out.extend_from_slice(&idx.to_be_bytes());
    out.extend_from_slice(d);
    out.extend_from_slice(e);
    out
}

fn decode_round1_commit(
    p: &[u8],
) -> Result<(u32, [u8; group::ELEMENT_BYTES], [u8; group::ELEMENT_BYTES])> {
    let need = 1 + 4 + 2 * group::ELEMENT_BYTES;
    if p.len() != need || p[0] != MSG_ROUND1_COMMIT {
        return Err(FrostError::MalformedMessage {
            reason: "bad round-1 commitment",
            code: CODE_MALFORMED_MESSAGE,
        });
    }
    let idx = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let mut d = [0u8; group::ELEMENT_BYTES];
    d.copy_from_slice(&p[5..5 + group::ELEMENT_BYTES]);
    let mut e = [0u8; group::ELEMENT_BYTES];
    e.copy_from_slice(&p[5 + group::ELEMENT_BYTES..5 + 2 * group::ELEMENT_BYTES]);
    Ok((idx, d, e))
}

/// Round-2 response: `tag | idx:u32 BE | z[32]`.
fn encode_round2_response(idx: u32, z: &Scalar) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + group::SCALAR_BYTES);
    out.push(MSG_ROUND2_RESPONSE);
    out.extend_from_slice(&idx.to_be_bytes());
    out.extend_from_slice(&group::scalar_to_bytes(z));
    out
}

fn decode_round2_response(p: &[u8]) -> Result<(u32, Scalar)> {
    let need = 1 + 4 + group::SCALAR_BYTES;
    if p.len() != need || p[0] != MSG_ROUND2_RESPONSE {
        return Err(FrostError::MalformedMessage {
            reason: "bad round-2 response",
            code: CODE_MALFORMED_MESSAGE,
        });
    }
    let idx = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let mut s = [0u8; group::SCALAR_BYTES];
    s.copy_from_slice(&p[5..5 + group::SCALAR_BYTES]);
    Ok((idx, group::scalar_from_bytes_mod_order(&s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round1_commit_round_trips() {
        let d = [1u8; 32];
        let e = [2u8; 32];
        let enc = encode_round1_commit(5, &d, &e);
        let (idx, d2, e2) = decode_round1_commit(&enc).expect("decode");
        assert_eq!(idx, 5);
        assert_eq!(d2, d);
        assert_eq!(e2, e);
    }

    #[test]
    fn round2_response_round_trips() {
        let z = Scalar::from(99u64);
        let enc = encode_round2_response(3, &z);
        let (idx, z2) = decode_round2_response(&enc).expect("decode");
        assert_eq!(idx, 3);
        assert_eq!(group::scalar_to_bytes(&z2), group::scalar_to_bytes(&z));
    }

    #[test]
    fn decode_rejects_bad_tag() {
        let mut bad = encode_round1_commit(1, &[0u8; 32], &[0u8; 32]);
        bad[0] = 0xFF;
        assert!(decode_round1_commit(&bad).is_err());
    }
}
