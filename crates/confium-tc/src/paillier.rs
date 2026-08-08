//! Paillier homomorphic encryption.

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};
use rand_core::OsRng;

#[derive(Debug, Clone)]
pub struct PaillierPublicKey {
    pub n: BigUint,
    pub n_squared: BigUint,
    pub g: BigUint,
}

#[derive(Debug, Clone)]
pub struct PaillierPrivateKey {
    pub lambda: BigUint,
    pub mu: BigUint,
}

#[derive(Debug, Clone)]
pub struct PaillierKeypair {
    pub public: PaillierPublicKey,
    pub private: PaillierPrivateKey,
}

#[derive(Debug, thiserror::Error)]
pub enum PaillierError {
    #[error("invalid key parameters")]
    InvalidKey,
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
}

pub fn generate_keypair(prime_bits: u32) -> PaillierKeypair {
    loop {
        let p = generate_prime(prime_bits);
        let q = generate_prime(prime_bits);
        if p == q {
            continue;
        }
        let n = &p * &q;
        let n_squared = &n * &n;

        let p_minus_one = &p - &BigUint::one();
        let q_minus_one = &q - &BigUint::one();
        let gcd_val = p_minus_one.gcd(&q_minus_one);
        let lambda = (&p_minus_one * &q_minus_one) / &gcd_val;

        let g = &n + &BigUint::one();

        let g_lambda = g.modpow(&lambda, &n_squared);
        if g_lambda < BigUint::one() {
            continue;
        }
        let l_val = (&g_lambda - &BigUint::one()) / &n;

        let mu = match modinv_biguint(&lambda, &n) {
            Some(m) => m,
            None => continue,
        };

        let _ = l_val;
        return PaillierKeypair {
            public: PaillierPublicKey { n, n_squared, g },
            private: PaillierPrivateKey { lambda, mu },
        };
    }
}

pub fn encrypt(
    public: &PaillierPublicKey,
    message: &BigUint,
    randomness: &BigUint,
) -> Result<BigUint, PaillierError> {
    if message >= &public.n {
        return Err(PaillierError::Encryption("message >= N".into()));
    }
    let g_m = public.g.modpow(message, &public.n_squared);
    let r_n = randomness.modpow(&public.n, &public.n_squared);
    Ok((&g_m * &r_n) % &public.n_squared)
}

pub fn decrypt(
    private: &PaillierPrivateKey,
    public: &PaillierPublicKey,
    ciphertext: &BigUint,
) -> Result<BigUint, PaillierError> {
    let c_lambda = ciphertext.modpow(&private.lambda, &public.n_squared);
    if c_lambda < BigUint::one() {
        return Err(PaillierError::Decryption("c^λ underflow".into()));
    }
    let l_val = (&c_lambda - &BigUint::one()) / &public.n;
    Ok((&l_val * &private.mu) % &public.n)
}

pub fn add(public: &PaillierPublicKey, ca: &BigUint, cb: &BigUint) -> BigUint {
    (ca * cb) % &public.n_squared
}

pub fn scalar_mul(public: &PaillierPublicKey, c: &BigUint, k: &BigUint) -> BigUint {
    c.modpow(k, &public.n_squared)
}

fn generate_prime(bits: u32) -> BigUint {
    let mut rng = OsRng;
    loop {
        let candidate = rng.gen_biguint(bits as u64);
        if candidate < BigUint::from(2u32) {
            continue;
        }
        let candidate = candidate | BigUint::one();
        if miller_rabin(&candidate, 20) {
            return candidate;
        }
    }
}

fn miller_rabin(n: &BigUint, rounds: u32) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if n == &two || n == &three {
        return true;
    }
    if (n & &BigUint::one()) == BigUint::zero() || n < &three {
        return false;
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;

    let mut d = n_minus_one.clone();
    let mut r: u32 = 0;
    loop {
        let test = &d & &one;
        if test == BigUint::zero() {
            d >>= 1;
            r += 1;
        } else {
            break;
        }
    }

    let mut rng = OsRng;
    'outer: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &n_minus_one);
        if a < two || a >= n_minus_one {
            continue;
        }
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n_minus_one {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

fn modinv_biguint(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_int = a.to_bigint()?;
    let m_int = m.to_bigint()?;
    let result = modinv(&a_int, &m_int)?;
    result.to_biguint()
}

fn modinv(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = extended_gcd(a, m);
    if g != BigInt::one() {
        None
    } else {
        let r = &x % m;
        if r.sign() == num_bigint::Sign::Minus {
            Some(r + m)
        } else {
            Some(r)
        }
    }
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b == &BigInt::zero() {
        (a.clone(), BigInt::one(), BigInt::zero())
    } else {
        let (g, x1, y1) = extended_gcd(b, &(a % b));
        (g, y1.clone(), x1 - (a / b) * &y1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypair() -> PaillierKeypair {
        generate_keypair(128)
    }

    fn random_below(n: &BigUint) -> BigUint {
        let mut rng = OsRng;
        loop {
            let r = rng.gen_biguint(n.bits());
            if r < *n && r > BigUint::zero() {
                return r;
            }
        }
    }

    #[test]
    fn keypair_generates() {
        let kp = make_keypair();
        assert!(kp.public.n > BigUint::zero());
        assert_eq!(kp.public.g, &kp.public.n + &BigUint::one());
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let kp = make_keypair();
        let m = BigUint::from(42u32);
        let r = random_below(&kp.public.n);
        let c = encrypt(&kp.public, &m, &r).unwrap();
        let m_dec = decrypt(&kp.private, &kp.public, &c).unwrap();
        assert_eq!(m_dec, m);
    }

    #[test]
    fn different_randomness_different_ciphertexts() {
        let kp = make_keypair();
        let m = BigUint::from(100u32);
        let c1 = encrypt(&kp.public, &m, &random_below(&kp.public.n)).unwrap();
        let c2 = encrypt(&kp.public, &m, &random_below(&kp.public.n)).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn encrypt_message_geq_n_fails() {
        let kp = make_keypair();
        let r = random_below(&kp.public.n);
        assert!(encrypt(&kp.public, &kp.public.n, &r).is_err());
    }

    #[test]
    fn homomorphic_addition() {
        let kp = make_keypair();
        let m1 = BigUint::from(17u32);
        let m2 = BigUint::from(25u32);
        let c1 = encrypt(&kp.public, &m1, &random_below(&kp.public.n)).unwrap();
        let c2 = encrypt(&kp.public, &m2, &random_below(&kp.public.n)).unwrap();
        let c_sum = add(&kp.public, &c1, &c2);
        let m_sum = decrypt(&kp.private, &kp.public, &c_sum).unwrap();
        assert_eq!(m_sum, BigUint::from(42u32));
    }

    #[test]
    fn homomorphic_addition_with_mod() {
        let kp = make_keypair();
        let m1 = BigUint::from(10u32);
        let m2 = &kp.public.n - &BigUint::from(5u32);
        let c1 = encrypt(&kp.public, &m1, &random_below(&kp.public.n)).unwrap();
        let c2 = encrypt(&kp.public, &m2, &random_below(&kp.public.n)).unwrap();
        let c_sum = add(&kp.public, &c1, &c2);
        let m_sum = decrypt(&kp.private, &kp.public, &c_sum).unwrap();
        assert_eq!(m_sum, BigUint::from(5u32));
    }

    #[test]
    fn scalar_multiplication() {
        let kp = make_keypair();
        let m = BigUint::from(7u32);
        let c = encrypt(&kp.public, &m, &random_below(&kp.public.n)).unwrap();
        let c5 = scalar_mul(&kp.public, &c, &BigUint::from(5u32));
        let m5 = decrypt(&kp.private, &kp.public, &c5).unwrap();
        assert_eq!(m5, BigUint::from(35u32));
    }

    #[test]
    fn scalar_mul_zero() {
        let kp = make_keypair();
        let m = BigUint::from(123u32);
        let c = encrypt(&kp.public, &m, &random_below(&kp.public.n)).unwrap();
        let c0 = scalar_mul(&kp.public, &c, &BigUint::zero());
        let m0 = decrypt(&kp.private, &kp.public, &c0).unwrap();
        assert_eq!(m0, BigUint::zero());
    }

    #[test]
    fn public_key_consistent() {
        let kp = make_keypair();
        assert_eq!(kp.public.g, &kp.public.n + &BigUint::one());
        assert_eq!(kp.public.n_squared, &kp.public.n * &kp.public.n);
    }

    #[test]
    fn multiple_messages() {
        let kp = make_keypair();
        for m_val in [1u32, 100, 1000, 10000] {
            let m = BigUint::from(m_val);
            let c = encrypt(&kp.public, &m, &random_below(&kp.public.n)).unwrap();
            let m_dec = decrypt(&kp.private, &kp.public, &c).unwrap();
            assert_eq!(m_dec, m);
        }
    }

    #[test]
    fn additive_homomorphism_chained() {
        let kp = make_keypair();
        let c1 = encrypt(
            &kp.public,
            &BigUint::from(10u32),
            &random_below(&kp.public.n),
        )
        .unwrap();
        let c2 = encrypt(
            &kp.public,
            &BigUint::from(20u32),
            &random_below(&kp.public.n),
        )
        .unwrap();
        let c3 = encrypt(
            &kp.public,
            &BigUint::from(30u32),
            &random_below(&kp.public.n),
        )
        .unwrap();
        let c_sum = add(&kp.public, &c1, &c2);
        let c_sum = add(&kp.public, &c_sum, &c3);
        let m_sum = decrypt(&kp.private, &kp.public, &c_sum).unwrap();
        assert_eq!(m_sum, BigUint::from(60u32));
    }
}
