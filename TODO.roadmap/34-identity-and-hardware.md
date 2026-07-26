# 34 — Identity management and hardware backends

## Purpose

Each actor in a Confium deployment (manufacturer, lab, IA officer,
BIML director) has cryptographic identity. This identity binds to:

- A signing keypair (signs artifacts)
- An encryption keypair (decrypts incoming encrypted data)
- A certificate chain (proves identity to verifiers)
- Optional hardware token (YubiKey, OpenPGP card) for key protection

Hardware backends store keys securely. Standards-only — no vendor
SDKs.

## Actor identity model

```rust
pub struct ActorIdentity {
    pub actor_id: String,                    // "biml-director-alice", "ia-france-officer-1"
    pub actor_type: ActorType,
    pub signing_key: SigningKeyHandle,
    pub encryption_key: EncryptionKeyHandle,
    pub certificate_chain: Vec<Certificate>,
    pub hardware_token: Option<HardwareToken>,
}

pub enum ActorType {
    Manufacturer,
    TestingLab,
    IssuingAuthorityOfficer,
    BimlDirector,
    QuorumCoordinator,
}

pub enum SigningKeyHandle {
    Software(SoftwareKey),                   // in-process
    Hardware(HardwareKeyRef),                // PKCS#11/TPM/OpenPGP card
}

pub enum HardwareToken {
    YubiKeyPiv { slot: PivSlot, pin_policy: PinPolicy },
    YubiKeyOpenpgp { slot: OpenpgpSlot },
    OpenpgpCard { card_id: String, slot: OpenpgpSlot },
    Tpm { handle: u32 },
}
```

## Hardware backends

### `confium-store-pkcs11` (existing, extended)

PKCS#11 v3.0 wrapping backend. HSM holds AES-256 wrapping key;
share on disk encrypted under that key.

```rust
pub struct Pkcs11WrappingBackend {
    module: Pkcs11Module,
    wrapping_key_handle: ObjectHandle,
}

impl StoreBackend for Pkcs11WrappingBackend {
    fn store(&self, key_id: &str, plaintext: &[u8]) -> Result<()>;
    fn load(&self, key_id: &str) -> Result<Vec<u8>>;
    fn delete(&self, key_id: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<String>>;
}
```

Wraps AES-256-GCM encryption with `C_WrapKey` / `C_UnwrapKey`. All
major HSMs support this.

### `confium-store-tpm` (existing, extended)

TPM 2.0 sealed storage. Uses TPM-internal AES key to seal arbitrary
data. Bound to PCR state (optional).

### `confium-store-cloud` (existing, extended)

AWS KMS / GCP KMS / Azure KV via REST. Wrapping key lives in cloud
KMS; share on local disk encrypted.

### `confium-store-openpgp-card` (P0, new)

OpenPGP card support. YubiKey OpenPGP applet, Nitrokey, Gnuk.

```rust
pub struct OpenpgpCardBackend {
    card: Card<Open>,
    signing_slot: KeySlot,
    encryption_slot: KeySlot,
    auth_slot: KeySlot,
}

impl StoreBackend for OpenpgpCardBackend { ... }
impl SigningBackend for OpenpgpCardBackend { ... }
impl DecryptionBackend for OpenpgpCardBackend { ... }
```

OpenPGP card spec supports both signing and decryption natively —
the card performs the operation, the key never leaves the device.

## Two-tier protection pattern

For high-value actors (BIML directors, IA officers):

```
YubiKey / OpenPGP card holds:
  - Identity signing key (signs protocol messages for non-repudiation)
  - AES wrapping key (decrypts threshold share from disk)

Laptop holds:
  - Wrapped threshold share (encrypted under YubiKey's wrapping key)
  - Confium session state

At signing time:
  1. Director enters passphrase → unlocks YubiKey
  2. App asks YubiKey to decrypt wrapped share
  3. Plaintext share lives briefly in Sensitive<T> (mlock + zeroize)
  4. Protocol runs on laptop
  5. Share zeroized when session ends
  6. Every protocol message signed by YubiKey identity key
```

Two-tier protection: compromised laptop alone insufficient; attacker
needs physical YubiKey + passphrase.

## Director identity cert chain

Director identity keys (on YubiKey) are certified under a separate
BIML identity CA, distinct from the root signing cert.

```
BIML Identity CA (separate from root)
   │ signs
   ▼
Director Identity Cert (per director)
   │ binds YubiKey-held public key to director name
   ▼
Used to verify director signatures on protocol messages
```

Why separate? Because the root signing cert is threshold-held by
directors — using it to certify director identity would be circular.
Identity CA can be a simpler offline single-party CA, or a separate
threshold quorum.

## Hardware token distribution

- OIML procures standard hardware (YubiKey 5 CSPN, OpenPGP card v3.4)
  centrally
- Distributed at annual ceremony (in-person verification)
- Director generates own keys on-device at ceremony (no OIML escrow)
- Public identity keys registered with BIML, certified under BIML Identity CA

For non-ceremony enrollment (lab onboarding, manufacturer
registration): remote identity verification + physical token ship
via secure courier.

## Crate scope

### `confium-deployment` (P0)

```rust
pub struct IdentityStore {
    backend: Box<dyn StoreBackend>,
}

impl IdentityStore {
    pub fn register_actor(&self, actor: ActorIdentity) -> Result<()>;
    pub fn lookup_actor(&self, actor_id: &str) -> Result<ActorIdentity>;
    pub fn list_actors_by_type(&self, actor_type: ActorType) -> Result<Vec<ActorIdentity>>;
    pub fn revoke_actor(&self, actor_id: &str, reason: &str) -> Result<()>;
}
```

### `confium-store-openpgp-card` (P0)

Uses `openpgp-card` crate (Rust). Supports YubiKey OpenPGP, Nitrokey,
Gnuk, any OpenPGP card v3+.

## Failure modes

| Scenario | Recovery |
|---|---|
| Director loses YubiKey | Emergency re-share excludes old identity key; new YubiKey at next ceremony |
| YubiKey firmware bug | Re-place with new model; re-share to new identity keys |
| Laptop compromised | Proactive refresh invalidates exfiltrated shares |
| Director forgets passphrase | Duress code path: YubiKey admin PIN resets, but share is wiped; re-share required |

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/30-tc-reshare-protocol.md` — emergency re-share on token loss
- [OpenPGP card spec](https://g10code.com/docs/openpgp-card-3.0.pdf)
- [PKCS#11 v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [TCG TPM 2.0](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
