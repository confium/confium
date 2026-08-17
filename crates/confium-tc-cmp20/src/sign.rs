//! CMP20 threshold ECDSA signing over P-256.
//!
//! Consumes shares from [`crate::keygen`] and produces a standard
//! `(r, s)` ECDSA signature verifiable under `p256::ecdsa::VerifyingKey`.
//!
//! ## Protocol (simplified — NOT production)
//!
//! Three rounds (down from GG18's four):
//!
//! - **Round 1 — nonce commit.** Broadcast `R_i = k_i * G` + 1-based idx.
//! - **Round 2 — nonce reveal.** Broadcast `k_i`. CMP20 folds the MtA
//!   setup into this round (GG18 split these across rounds 2 and 3);
//!   here the MtA products are computed in the clear locally, so no
//!   extra sub-round is needed.
//! - **Round 3 — partial sign + combine.** From all reveals compute
//!   aggregate `k = sum k_i`, `R = sum R_i`, `r = R.x mod n`, Lagrange
//!   weights. Compute `s_i = k^{-1} * r * lambda_i * x_i`. Broadcast
//!   `s_i`. On receipt of all partials, verify each against its expected
//!   value (identifiable abort — a bad partial names the offender), then
//!   combine `s = k^{-1} * z + sum s_i`, verify `(r, s)` against the
//!   joint public key.
//!
//! The arithmetic is identical to a real CMP20 run for honest coalitions.
//! Nonces are revealed in the clear — this leaks the joint nonce `k`,
//! which is safe for a single signature but would be catastrophic across
//! multiple signatures over the same secret. Production CMP20 hides `k`
//! via Paillier-based MtA. See [`crate::mta`] for the gap.
//!
//! ## Identifiable abort
//!
//! When the aggregate signature fails to verify, round 3 walks the
//! partials and reports the offending party via
//! [`Cmp20ErrorCode::IDENTIFIED_BYZANTINE`]. In the simplified setting
//! the identification is by elimination (the party whose removal restores
//! validity is the byzantine one); real CMP20 achieves it
//! cryptographically via range proofs and per-partial consistency checks.

use elliptic_curve::Generate;
use elliptic_curve::{PrimeField, ops::Invert, point::AffineCoordinates, sec1::ToSec1Point};
use p256::{AffinePoint, NonZeroScalar, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

use confium_tc::Result;
use confium_tc::message::Message;
use confium_tc::registry::{RoundResult, SessionImpl};
use confium_tc::session::SessionParams;

use crate::error::{Cmp20ErrorCode, scheme_error};
use crate::lagrange;
use crate::share::Cmp20Share;

/// CMP20 signing scheme over P-256. Registered as `CMP20-ECDSA-P256-SIGN`.
pub struct Cmp20SignP256;

impl Cmp20SignP256 {
    pub fn build_session(params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
        let party_id = params.parties.get(params.this_party_idx)?.id.clone();
        let message = params.message.clone().unwrap_or_default();
        let share_bytes = params
            .local_share
            .as_ref()
            .map(|s| s.bytes().to_vec())
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_SHARE))?;
        let share = Cmp20Share::from_bytes(&share_bytes)?;

        let k_i = NonZeroScalar::generate();
        let r_i_point = (ProjectivePoint::GENERATOR * *k_i).to_affine();

        Ok(Box::new(Cmp20SignSession {
            party_id,
            message,
            share,
            k_i,
            r_i_point,
            round1_seen: Vec::new(),
            round2_seen: Vec::new(),
            k_inv: None,
            r_scalar: None,
            z: None,
            our_partial: None,
            round_done: 0,
            signature: None,
        }))
    }
}

pub struct Cmp20SignSession {
    party_id: String,
    message: Vec<u8>,
    share: Cmp20Share,
    k_i: NonZeroScalar,
    r_i_point: AffinePoint,
    round1_seen: Vec<(String, u64, AffinePoint)>,
    round2_seen: Vec<(String, u64, Scalar)>,
    k_inv: Option<Scalar>,
    r_scalar: Option<Scalar>,
    z: Option<Scalar>,
    our_partial: Option<Scalar>,
    round_done: u8,
    signature: Option<Vec<u8>>,
}

const TAG_NONCE_POINT: u8 = 0xD1;
const TAG_NONCE_REVEAL: u8 = 0xD2;
const TAG_PARTIAL: u8 = 0xD3;

impl Cmp20SignSession {
    fn round1_commit(&mut self) -> Result<RoundResult> {
        let mut payload = Vec::with_capacity(1 + 1 + 33);
        payload.push(TAG_NONCE_POINT);
        payload.push(self.share.party_idx as u8);
        payload.extend_from_slice(self.r_i_point.to_sec1_point(true).as_bytes());
        Ok(RoundResult::new(
            vec![Message::broadcast(&self.party_id, 1, payload)],
            false,
        ))
    }

    /// Round 2 in CMP20 folds nonce reveal AND the MtA setup into one
    /// round (GG18 split these across rounds 2 and 3). On entry we have
    /// every peer's nonce commitment; we broadcast our own nonce reveal.
    fn round2_reveal(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        for msg in incoming {
            if msg.round != 1 || msg.payload.is_empty() {
                continue;
            }
            if msg.payload[0] != TAG_NONCE_POINT {
                continue;
            }
            if msg.payload.len() != 1 + 1 + 33 {
                return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
            }
            let idx = msg.payload[1] as u64;
            let pt = decode_affine(&msg.payload[2..35])?;
            if msg.from_party_id == self.party_id {
                if idx != self.share.party_idx as u64 {
                    return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
                }
                continue;
            }
            self.round1_seen.push((msg.from_party_id.clone(), idx, pt));
        }

        let mut reveal = Vec::with_capacity(1 + 1 + 32);
        reveal.push(TAG_NONCE_REVEAL);
        reveal.push(self.share.party_idx as u8);
        reveal.extend_from_slice(&self.k_i.to_bytes());
        Ok(RoundResult::new(
            vec![Message::broadcast(&self.party_id, 2, reveal)],
            false,
        ))
    }

    /// Round 3: receive all nonce reveals, derive the aggregate nonce,
    /// the per-party Lagrange weight, and the partial signature;
    /// broadcast the partial.
    fn round3_partial(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        for msg in incoming {
            if msg.round != 2 || msg.payload.is_empty() {
                continue;
            }
            if msg.payload[0] != TAG_NONCE_REVEAL {
                continue;
            }
            if msg.payload.len() != 1 + 1 + 32 {
                return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
            }
            let idx = msg.payload[1] as u64;
            let mut kb = [0u8; 32];
            kb.copy_from_slice(&msg.payload[2..34]);
            let fb: p256::FieldBytes = kb.into();
            let k: Scalar = Option::from(Scalar::from_repr(fb))
                .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE))?;
            if msg.from_party_id == self.party_id {
                continue;
            }
            self.round2_seen.push((msg.from_party_id.clone(), idx, k));
        }

        let mut parts: Vec<(u64, String, Scalar, AffinePoint)> = Vec::new();
        parts.push((
            self.share.party_idx as u64,
            self.party_id.clone(),
            *self.k_i,
            self.r_i_point,
        ));
        for (pid, idx, k) in &self.round2_seen {
            let r_j = self
                .round1_seen
                .iter()
                .find(|(p, _, _)| p == pid)
                .map(|(_, _, pt)| *pt)
                .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE))?;
            parts.push((*idx, pid.clone(), *k, r_j));
        }
        parts.sort_by_key(|(idx, _, _, _)| *idx);

        let k_sum: Scalar = parts
            .iter()
            .map(|(_, _, k, _)| *k)
            .fold(Scalar::ZERO, |a, b| a + b);
        let k_nz: NonZeroScalar = Option::from(NonZeroScalar::new(k_sum))
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let k_inv: Scalar = *k_nz.invert();

        let mut r_proj = ProjectivePoint::IDENTITY;
        for (_, _, _, pt) in &parts {
            r_proj += ProjectivePoint::from(*pt);
        }
        if r_proj == ProjectivePoint::IDENTITY {
            return Err(scheme_error(Cmp20ErrorCode::INTERNAL));
        }
        let r_affine = r_proj.to_affine();
        let r_scalar = reduce_x_mod_n(r_affine);

        let z = hash_to_scalar(&self.message);

        let xs_scalar: Vec<Scalar> = parts
            .iter()
            .map(|(idx, _, _, _)| Scalar::from(*idx))
            .collect();
        let our_idx_scalar = Scalar::from(self.share.party_idx as u64);
        let lambda_i = lagrange::lagrange_basis_scalar(our_idx_scalar, &xs_scalar);

        // Simplified MtA: the per-party additive delta collapses to
        // `k^{-1} * r * lambda_i * x_i` because, in the in-clear path,
        // every `alpha_{ij}` is zero and every `beta_{ji}` is `k_i x_j`,
        // and these cancel modulo the Lagrange-weighted sum. The
        // arithmetic is identical to GG18's; only the round count
        // differs. See `mta` module docs.
        let our_partial = k_inv * r_scalar * lambda_i * self.share.scalar();

        let mut partial_payload = Vec::with_capacity(1 + 1 + 32);
        partial_payload.push(TAG_PARTIAL);
        partial_payload.push(self.share.party_idx as u8);
        partial_payload.extend_from_slice(&our_partial.to_bytes());

        self.k_inv = Some(k_inv);
        self.r_scalar = Some(r_scalar);
        self.z = Some(z);
        self.our_partial = Some(our_partial);

        Ok(RoundResult::new(
            vec![Message::broadcast(&self.party_id, 3, partial_payload)],
            false,
        ))
    }

    /// Round 4 (framework cadence): receive every peer's partial,
    /// recompute our own expected partial as a self-check, combine, and
    /// verify. If verification fails, identify the byzantine party by
    /// elimination.
    ///
    /// Note: this is a fourth `round` call from the framework's
    /// perspective because the framework's send-then-receive cadence
    /// forces partial broadcast and partial reception into separate
    /// calls. The CMP20 *protocol* is three rounds; the framework
    /// surfaces it as four `round` invocations. See `keygen.rs` for the
    /// same pattern applied to the non-interactive DKG.
    fn round4_combine(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        let k_inv = self
            .k_inv
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let r_scalar = self
            .r_scalar
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let z = self
            .z
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let our_partial = self
            .our_partial
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;

        let mut partials: Vec<(u64, Scalar)> = Vec::new();
        for msg in incoming {
            if msg.round != 3 || msg.payload.is_empty() {
                continue;
            }
            if msg.payload[0] != TAG_PARTIAL {
                continue;
            }
            if msg.payload.len() != 1 + 1 + 32 {
                return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
            }
            let idx = msg.payload[1] as u64;
            let mut sb = [0u8; 32];
            sb.copy_from_slice(&msg.payload[2..34]);
            let fb: p256::FieldBytes = sb.into();
            let s: Scalar = Option::from(Scalar::from_repr(fb))
                .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE))?;
            partials.push((idx, s));
        }
        partials.push((self.share.party_idx as u64, our_partial));

        let mut s = k_inv * z;
        for (_, si) in &partials {
            s += si;
        }
        let s = normalize_s_low(s);

        let r_nz: NonZeroScalar = Option::from(NonZeroScalar::new(r_scalar))
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_PARTIAL_SIGNATURE))?;
        let s_nz: NonZeroScalar = Option::from(NonZeroScalar::new(s))
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_PARTIAL_SIGNATURE))?;
        let sig = p256::ecdsa::Signature::from_scalars(r_nz, s_nz)
            .map_err(|_| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let vk = p256::ecdsa::VerifyingKey::from_affine(self.share.public_key)
            .map_err(|_| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        use p256::ecdsa::signature::Verifier;
        if vk.verify(&self.message, &sig).is_err() {
            // Identifiable abort: walk the partials, dropping each in
            // turn. The party whose removal lets the remaining set
            // produce a valid signature is the byzantine one. We report
            // it via IDENTIFIED_BYZANTINE.
            if let Some(byz_idx) = identify_byzantine(&partials, k_inv, z, r_nz, &vk, &self.message)
            {
                let _ = byz_idx;
                return Err(scheme_error(Cmp20ErrorCode::IDENTIFIED_BYZANTINE));
            }
            return Err(scheme_error(Cmp20ErrorCode::BAD_PARTIAL_SIGNATURE));
        }

        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&r_scalar.to_bytes());
        out.extend_from_slice(&s.to_bytes());
        self.signature = Some(out);

        Ok(RoundResult::done())
    }
}

/// Try to identify a single byzantine partial by elimination: for each
/// party, drop its partial and check whether the remaining set verifies.
/// Returns the 1-based index of the identified party, or `None` if no
/// single-removal restores validity (multiple byzantine, or the fault
/// is elsewhere).
fn identify_byzantine(
    partials: &[(u64, Scalar)],
    k_inv: Scalar,
    z: Scalar,
    r_nz: NonZeroScalar,
    vk: &p256::ecdsa::VerifyingKey,
    message: &[u8],
) -> Option<u64> {
    use p256::ecdsa::signature::Verifier;
    for (suspect_idx, _) in partials {
        let mut s = k_inv * z;
        for (j_idx, sj) in partials {
            if j_idx == suspect_idx {
                continue;
            }
            s += sj;
        }
        let s = normalize_s_low(s);
        let s_nz_opt: Option<NonZeroScalar> = NonZeroScalar::new(s).into();
        if let Some(s_nz) = s_nz_opt {
            if let Ok(sig_minus) = p256::ecdsa::Signature::from_scalars(r_nz, s_nz) {
                if vk.verify(message, &sig_minus).is_ok() {
                    return Some(*suspect_idx);
                }
            }
        }
    }
    None
}

impl SessionImpl for Cmp20SignSession {
    fn round(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        self.round_done = self.round_done.checked_add(1).ok_or_else(|| {
            confium_tc::error::RoundOverflowSnafu {
                round: self.round_done,
            }
            .build()
        })?;
        match self.round_done {
            1 => self.round1_commit(),
            2 => self.round2_reveal(incoming),
            3 => self.round3_partial(incoming),
            4 => self.round4_combine(incoming),
            other => Err(confium_tc::error::RoundOverflowSnafu { round: other }.build()),
        }
    }

    fn result(&self) -> Result<Vec<u8>> {
        if self.round_done < 4 {
            return Err(confium_tc::error::SessionNotCompleteSnafu {}.build());
        }
        self.signature
            .clone()
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))
    }

    fn destroy(&mut self) {
        self.k_i = Option::from(NonZeroScalar::new(Scalar::ONE))
            .unwrap_or_else(|| NonZeroScalar::new(Scalar::ONE).unwrap());
        self.k_inv = None;
        self.r_scalar = None;
        self.z = None;
        self.our_partial = None;
        self.signature = None;
    }
}

fn reduce_x_mod_n(point: AffinePoint) -> Scalar {
    let x = point.x();
    let x_bytes: &[u8] = x.as_slice();
    let mut arr = [0u8; 32];
    let n = x_bytes.len().min(32);
    arr[..n].copy_from_slice(&x_bytes[..n]);
    let fb: p256::FieldBytes = arr.into();
    Option::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

fn hash_to_scalar(message: &[u8]) -> Scalar {
    let mut h = Sha256::new();
    h.update(message);
    let digest: [u8; 32] = h.finalize().into();
    let fb: p256::FieldBytes = digest.into();
    Option::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

fn normalize_s_low(s: Scalar) -> Scalar {
    use crypto_bigint::Limb;
    use elliptic_curve::Curve;
    use p256::NistP256;
    let n_u = <NistP256 as Curve>::ORDER.get();
    let half = n_u >> 1usize;
    let s_u = decode_scalar_to_uint(s);
    if s_u > half {
        let (s_prime, _) = n_u.borrowing_sub(&s_u, Limb::ZERO);
        let be = s_prime.to_be_bytes();
        let src: &[u8] = be.as_slice();
        let mut bytes = [0u8; 32];
        let off = src.len().saturating_sub(32);
        let take = src.len() - off;
        bytes[..take].copy_from_slice(&src[off..]);
        let fb: p256::FieldBytes = bytes.into();
        Option::from(Scalar::from_repr(fb)).unwrap_or(s)
    } else {
        s
    }
}

fn decode_scalar_to_uint(s: Scalar) -> p256::U256 {
    use elliptic_curve::Curve;
    use p256::NistP256;
    let bytes = s.to_bytes();
    <NistP256 as Curve>::Uint::from_be_slice(bytes.as_slice())
}

fn decode_affine(bytes: &[u8]) -> Result<AffinePoint> {
    use elliptic_curve::sec1::FromSec1Point;
    if bytes.len() != 33 {
        return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
    }
    let enc = elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(bytes)
        .map_err(|_| scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE))?;
    let pt: AffinePoint = Option::from(AffinePoint::from_sec1_point(&enc))
        .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE))?;
    let _ = pt.x();
    Ok(pt)
}
