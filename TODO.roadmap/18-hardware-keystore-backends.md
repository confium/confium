# 18 — Hardware-backed keystore backends

**Status**: SHIPPED (skeletons). Real operations pending.

Three backend crates:
- confium-store-pkcs11: via cryptoki crate, real open/session/login path,
  NotImplemented for actual put/get (pending cfmp_sign_with_handle contract)
- confium-store-tpm: via tss-esapi (feature-gated, doesn't compile on
  macOS without tpm2-tss), NotImplemented stubs
- confium-store-cloud: AWS/GCP/Azure KMS via feature flags,
  NotImplemented stubs (actual REST/gRPC calls pending)

All three implement the StoreBackend trait from confium-store,
registered via register_backend! macro. Drop-in for filesystem/memory.
