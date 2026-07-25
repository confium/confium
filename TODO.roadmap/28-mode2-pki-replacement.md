# 28 — Mode 2: TC PKI replacement

## Scope

Mode 2 deployments replace single-party PKI with threshold PKI
**without changing the surrounding ecosystem**. Existing apps
continue to use PKCS#11, OpenSSL, Java KeyStore, TLS — they don't
know the keys are threshold-held.

This is the enterprise Trojan horse: every PKCS#11 app in the world
is a potential Confium consumer.

## Audience

Corporate security teams, CA operators, DevSecOps architects,
HSM-using enterprises, government PKI operators.

## Architecture

```
Existing app (nginx, OpenSSL, OpenSSH, Java app, etc.)
   │ standard PKCS#11 / OpenSSL provider / JCE interface
   ▼
Confium compatibility shim
   ├─ confium-pkcs11-server    (PKCS#11 v3.0 server)
   ├─ confium-openssl-provider (OpenSSL 3.0 provider)
   ├─ confium-jce-provider     (Java Cryptography Extension)
   └─ confium-tls-signer       (TLS 1.3 callback)
   │ Confium threshold dispatch protocol
   ▼
Confium coordinator + threshold quorum
```

## Crate scope

### `confium-pkcs11-server` (P0 — cornerstone)

Exposes PKCS#11 v3.0 API; dispatches internally to threshold
protocol. Implemented as a shared library loaded by PKCS#11
consumers (via `p11-kit` or direct `CK_C_Initialize`).

**MVP functions** (covering ~95% of real-world PKCS#11 usage):

| Function | Behavior |
|---|---|
| `C_Initialize` | Connect to coordinator, register session |
| `C_Finalize` | Disconnect |
| `C_GetInfo` | Report Confium as crypto backend |
| `C_GetSlotList` | One slot per quorum |
| `C_GetTokenInfo` | Quorum metadata as token info |
| `C_OpenSession` | Open coordinator session |
| `C_CloseSession` | Close session |
| `C_GenerateKeyPair` | Trigger DKG; threshold keypair generated |
| `C_SignInit` | Begin threshold signing session |
| `C_Sign` | Synchronous threshold sign |
| `C_SignUpdate` / `C_SignFinal` | Streaming threshold sign |
| `C_VerifyInit` / `C_Verify` | Standard single-party verify (no threshold needed) |
| `C_EncryptInit` / `C_Encrypt` | Standard single-party encrypt |
| `C_DecryptInit` / `C_Decrypt` | Threshold decryption |
| `C_GenerateRandom` | Standard RNG |
| `C_SeedRandom` | No-op (threshold RNG not seedable) |
| `C_GetAttributeValue` | Object metadata |
| `C_FindObjectsInit` / `C_FindObjects` | Find threshold key objects |

**Out of MVP**: certificate objects, secret key objects, key
derivation, wrapping/unwrapping (deferred).

### `confium-openssl-provider` (P0)

OpenSSL 3.0 provider exposing Confium signing via the OpenSSL
provider API. Consumers configure OpenSSL to load the Confium
provider; subsequent signing operations via OpenSSL use threshold.

### `confium-tls-signer` (P1)

TLS 1.3 signature callback that satisfies `CertificateVerify` via
threshold protocol. Useful for high-value TLS endpoints (root CAs,
payment gateways).

### `confium-jce-provider` (P2)

Java Cryptography Extension provider. Java KeyStore and JCA apps
use Confium-backed keys transparently.

## Configuration (Mode 2 manifest)

```toml
[deployment]
name = "Acme Corp PKI"
mode = "pkcs11_replacement"
manifest_version = 1

[pkcs11_server]
slot_count = 8
default_signing_algorithm = "FROST-P256"
default_threshold = { t = 3, n = 5 }
share_storage = "pkcs11-wrap"
hsm_module = "/usr/lib/pkcs11/yubihsm.so"

[quorum.enterprise_root]
threshold = { t = 3, n = 5 }
coordinator = "coordinator.acme.corp:443"

[quorum.code_signing]
threshold = { t = 2, n = 3 }
coordinator = "coordinator.acme.corp:443"

[pqc_migration]
current = "ECDSA-P256"
target_2027 = "composite-ECDSA-P256-ML-DSA-65"
target_2029 = "ML-DSA-65"
```

## Deployment pattern

1. Deploy coordinator service (one per quorum)
2. Deploy Confium share daemons on threshold party machines
3. Install `confium-pkcs11-server` shared library on app machines
4. Configure app's PKCS#11 module path to point at Confium
5. App continues working unchanged

## PQC migration path

The killer Mode 2 feature. Enterprises facing PQ transition:

- **Without Confium**: upgrade all HSMs to PQ-capable firmware
  (years of vendor cooperation), re-do threshold protocols for
  new algorithms, re-issue all credentials.
- **With Confium**: software upgrade. PKCS#11 interface unchanged.

Algorithm choices per quorum via manifest. Migration via composite
signatures (classical + PQ) for verifier back-compat. See
`TODO.roadmap/35-pq-composite-signatures.md`.

## References

- `TODO.roadmap/26-confium-framework.md` — three-mode framework vision
- `TODO.roadmap/29-tc-coordinator-design.md` — coordinator details
- `TODO.roadmap/35-pq-composite-signatures.md` — PQC migration
- [OASIS PKCS#11 v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [OpenSSL 3.0 Provider](https://www.openssl.org/docs/manmaster/man7/provider.html)
