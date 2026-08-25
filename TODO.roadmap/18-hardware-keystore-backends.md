# 18 — Hardware-backed keystore backends

**Status**: SHIPPED (skeletons). Real operations pending.

Three backend crates:
- confium-store-pkcs11: via cryptoki crate, real open/session/login path,
  NotImplemented for actual put/get (pending cfmp_sign_with_handle contract)
- confium-store-tpm: via tss-esapi (feature-gated, doesn't compile on
  macOS without tpm2-tss), NotImplemented stubs
- confium-store-cloud: AWS/GCP/Azure KMS via feature flags. Client
  construction is REAL for all three (lazy; credentials/region/
  endpoint/vault from options + env); aws-kms enumerate lists real
  key IDs via ListKeys (wiremock-tested).
- REMOTE SIGN SHIPPED: StoreInstance::sign(module, app, key_id,
  algorithm, message) is the sign-with-handle contract surface;
  Keystore::sign + FFI cfm_keystore_sign expose it to the engine.
  AWS KMS Sign (message_type RAW, provider algorithm names, wiremock
  E2E), GCP AsymmetricSign (bare key id from project/location/
  key_ring options or full cryptoKeyVersion path), Azure Key Vault
  sign (ES256/ES256K/PS256/RS256; client-side SHA-256 since Vault
  signs digests). Local backends keep the NotImplemented default.
  put_secret/get_secret remain NotImplemented by design (cloud KMS
  never exports key material).

All three implement the StoreBackend trait from confium-store,
registered via register_backend! macro. Drop-in for filesystem/memory.
