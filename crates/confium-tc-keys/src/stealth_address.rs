//! Stealth address derivation.

use getrandom::SysRng;
use p256::elliptic_curve::rand_core::UnwrapErr;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// A scanning key (public) used by the scanner to detect stealth addresses.
#[derive(Debug, Clone)]
pub struct ScanPubkey {
    pub point: AffinePoint,
}

/// The spending key (secret) used to spend from stealth addresses.
#[derive(Debug, Clone)]
pub struct SpendKeypair {
    pub secret: Scalar,
    pub public: AffinePoint,
}

/// A stealth address output.
#[derive(Debug, Clone)]
pub struct StealthAddress {
    /// The ephemeral point published by the sender.
    pub ephemeral: AffinePoint,
    /// The one-time public key for this address.
    pub one_time_pubkey: AffinePoint,
}

/// Generate a spending keypair.
pub fn generate_spend_keypair() -> SpendKeypair {
    let secret = Scalar::random(&mut UnwrapErr(SysRng));
    let public = (ProjectivePoint::GENERATOR * secret).to_affine();
    SpendKeypair { secret, public }
}

/// Generate a scanning keypair.
pub fn generate_scan_keypair() -> (Scalar, ScanPubkey) {
    let secret = Scalar::random(&mut UnwrapErr(SysRng));
    let public = (ProjectivePoint::GENERATOR * secret).to_affine();
    (secret, ScanPubkey { point: public })
}

/// Sender creates a stealth address for the recipient.
/// Uses the recipient's scan pubkey and spend pubkey.
pub fn create_stealth_address(
    scan_pubkey: &ScanPubkey,
    spend_pubkey: &AffinePoint,
) -> (StealthAddress, Scalar) {
    // Sender picks ephemeral key r
    let r = Scalar::random(&mut UnwrapErr(SysRng));
    let ephemeral = (ProjectivePoint::GENERATOR * r).to_affine();

    // Shared secret: r * scan_pubkey = scan_secret * ephemeral
    let shared_point = (ProjectivePoint::from(scan_pubkey.point) * r).to_affine();

    // Derive one-time key adjustment: hash(shared)
    let adjustment = hash_to_scalar(&shared_point);

    // One-time public key: spend_pubkey + adjustment * G
    let one_time_pubkey = (ProjectivePoint::from(*spend_pubkey)
        + ProjectivePoint::GENERATOR * adjustment)
        .to_affine();

    (
        StealthAddress {
            ephemeral,
            one_time_pubkey,
        },
        r,
    )
}

/// Recipient scans for stealth addresses using their scan secret.
/// Returns the one-time secret key if this address belongs to them.
pub fn scan_stealth_address(
    scan_secret: &Scalar,
    spend_secret: &Scalar,
    address: &StealthAddress,
) -> Option<Scalar> {
    // Shared secret: scan_secret * ephemeral
    let shared_point = (ProjectivePoint::from(address.ephemeral) * scan_secret).to_affine();
    let adjustment = hash_to_scalar(&shared_point);

    // One-time secret: spend_secret + adjustment
    let one_time_secret = spend_secret + &adjustment;

    // Verify: one_time_secret * G == one_time_pubkey
    let expected_pubkey = (ProjectivePoint::GENERATOR * one_time_secret).to_affine();
    if expected_pubkey == address.one_time_pubkey {
        Some(one_time_secret)
    } else {
        None
    }
}

/// Reduce 32 bytes to a scalar by rejection sampling with re-hash.
/// Never falls back to a constant: a zero result here would void the
/// derivation or proof guarantees.
fn reduce_to_scalar(mut bytes: [u8; 32]) -> Scalar {
    loop {
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(bytes))) {
            return s;
        }
        let mut h = Sha256::new();
        h.update(b"confium-scalar-reduce-v1");
        h.update(bytes);
        bytes = h.finalize().into();
    }
}

fn hash_to_scalar(point: &AffinePoint) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"stealth-hash");
    hasher.update(point.to_sec1_point(true).as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    reduce_to_scalar(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_scan() {
        let (scan_secret, scan_pubkey) = generate_scan_keypair();
        let spend_kp = generate_spend_keypair();

        let (address, _r) = create_stealth_address(&scan_pubkey, &spend_kp.public);

        let one_time_sk = scan_stealth_address(&scan_secret, &spend_kp.secret, &address);

        assert!(one_time_sk.is_some());
    }

    #[test]
    fn wrong_scan_secret_fails() {
        let (_, scan_pubkey) = generate_scan_keypair();
        let spend_kp = generate_spend_keypair();
        let (address, _) = create_stealth_address(&scan_pubkey, &spend_kp.public);

        let wrong_scan = Scalar::random(&mut UnwrapErr(SysRng));
        let result = scan_stealth_address(&wrong_scan, &spend_kp.secret, &address);
        assert!(result.is_none());
    }

    #[test]
    fn wrong_spend_secret_fails() {
        let (scan_secret, scan_pubkey) = generate_scan_keypair();
        let spend_kp = generate_spend_keypair();
        let (address, _) = create_stealth_address(&scan_pubkey, &spend_kp.public);

        let wrong_spend = Scalar::random(&mut UnwrapErr(SysRng));
        let result = scan_stealth_address(&scan_secret, &wrong_spend, &address);
        assert!(result.is_none());
    }

    #[test]
    fn different_senders_different_addresses() {
        let (_, scan_pubkey) = generate_scan_keypair();
        let spend_kp = generate_spend_keypair();

        let (addr1, _) = create_stealth_address(&scan_pubkey, &spend_kp.public);
        let (addr2, _) = create_stealth_address(&scan_pubkey, &spend_kp.public);

        assert_ne!(addr1.ephemeral, addr2.ephemeral);
        assert_ne!(addr1.one_time_pubkey, addr2.one_time_pubkey);
    }

    #[test]
    fn one_time_secret_matches_pubkey() {
        let (scan_secret, scan_pubkey) = generate_scan_keypair();
        let spend_kp = generate_spend_keypair();
        let (address, _) = create_stealth_address(&scan_pubkey, &spend_kp.public);

        let one_time_sk = scan_stealth_address(&scan_secret, &spend_kp.secret, &address).unwrap();
        let derived_pk = (ProjectivePoint::GENERATOR * one_time_sk).to_affine();
        assert_eq!(derived_pk, address.one_time_pubkey);
    }

    #[test]
    fn ephemeral_published() {
        let (_, scan_pubkey) = generate_scan_keypair();
        let spend_kp = generate_spend_keypair();
        let (address, _) = create_stealth_address(&scan_pubkey, &spend_kp.public);
        // Ephemeral must not be identity
        assert!(address.ephemeral != AffinePoint::IDENTITY);
    }
}
