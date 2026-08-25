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
  key IDs via ListKeys (wiremock-tested). Secret/public put/get stay
  NotImplemented pending cfmp_sign_with_handle (cloud KMS never
  exports key material - remote sign is the only path)

All three implement the StoreBackend trait from confium-store,
registered via register_backend! macro. Drop-in for filesystem/memory.
