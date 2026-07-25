//! End-to-end integration test for the WASM sandbox.
//!
//! Compiles a small WAT module inline via wasmtime's `wat` feature,
//! loads it through `WasmSandbox`, and exercises:
//!
//! 1. A plain exported function with no host imports.
//! 2. An exported function that calls the `confium.cfm_hash_update`
//!    host import — verifies the import is wired up.
//! 3. Capability gating: the host import returns the sentinel `-1`
//!    when `InterfaceAccess { name: "hash" }` is NOT granted, and
//!    the real value when it IS granted.
//! 4. Revocation: granting then revoking flips the import's response.

use confium_sandbox_wasm::Capability;
use confium_sandbox_wasm::Sandbox;
use confium_sandbox_wasm::Value;
use confium_sandbox_wasm::WasmSandbox;

/// WAT module that imports `cfm_hash_update` and exposes:
///   - `add(a, b) -> i32`       (no host imports; pure arithmetic)
///   - `call_hash(len) -> i64`  (delegates to `cfm_hash_update`)
///
/// `wat::parse_str` compiles the WAT text to WASM bytes in-test.
const WAT: &str = r#"
(module
  (import "confium" "cfm_hash_update"
    (func $cfm_hash_update (param i32) (result i64)))

  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)

  (func (export "call_hash") (param i32) (result i64)
    local.get 0
    call $cfm_hash_update)
)
"#;

fn compile() -> Vec<u8> {
    wat::parse_str(WAT).expect("wat must parse")
}

#[test]
fn sandbox_loads_and_calls_pure_function() {
    let sb = WasmSandbox::new().expect("sandbox builds");
    let bytes = compile();
    let mut inst = sb.load_module(&bytes).expect("module loads");

    let out = inst
        .call("add", &[Value::I32(2), Value::I32(3)])
        .expect("add call");
    assert_eq!(out, vec![Value::I32(5)]);
}

#[test]
fn host_import_is_denied_without_capability() {
    let sb = WasmSandbox::new().expect("sandbox builds");
    let bytes = compile();
    let mut inst = sb.load_module(&bytes).expect("module loads");

    // No InterfaceAccess { name: "hash" } granted: host import
    // returns the -1 deny sentinel.
    let out = inst
        .call("call_hash", &[Value::I32(64)])
        .expect("call returns");
    assert_eq!(out, vec![Value::I64(-1)]);
}

#[test]
fn host_import_is_permitted_with_capability() {
    let sb = WasmSandbox::new().expect("sandbox builds");
    let bytes = compile();
    let mut inst = sb.load_module(&bytes).expect("module loads");

    inst.grant_capability(Capability::InterfaceAccess { name: "hash".into() })
        .expect("grant ok");

    let out = inst
        .call("call_hash", &[Value::I32(64)])
        .expect("call returns");
    // Stub handler echoes the input length.
    assert_eq!(out, vec![Value::I64(64)]);
}

#[test]
fn revoking_capability_re_denies_import() {
    let sb = WasmSandbox::new().expect("sandbox builds");
    let bytes = compile();
    let mut inst = sb.load_module(&bytes).expect("module loads");

    let cap = Capability::InterfaceAccess { name: "hash".into() };
    inst.grant_capability(cap.clone()).expect("grant ok");

    let permitted = inst
        .call("call_hash", &[Value::I32(64)])
        .expect("call returns");
    assert_eq!(permitted, vec![Value::I64(64)]);

    inst.revoke_capability(&cap).expect("revoke ok");

    let denied = inst
        .call("call_hash", &[Value::I32(64)])
        .expect("call returns");
    assert_eq!(denied, vec![Value::I64(-1)]);
}

#[test]
fn unrelated_capability_does_not_grant_hash_access() {
    let sb = WasmSandbox::new().expect("sandbox builds");
    let bytes = compile();
    let mut inst = sb.load_module(&bytes).expect("module loads");

    // Granting key access must NOT open the hash import.
    inst.grant_capability(Capability::KeyAccess { key_id: "k1".into() })
        .expect("grant ok");

    let out = inst
        .call("call_hash", &[Value::I32(64)])
        .expect("call returns");
    assert_eq!(out, vec![Value::I64(-1)]);
}

#[test]
fn sandbox_name_is_wasmtime() {
    let sb = WasmSandbox::new().expect("sandbox builds");
    assert_eq!(sb.name(), "wasmtime");
}

#[test]
fn missing_export_errors_cleanly() {
    let sb = WasmSandbox::new().expect("sandbox builds");
    let bytes = compile();
    let mut inst = sb.load_module(&bytes).expect("module loads");

    let err = inst.call("does_not_exist", &[]).expect_err("must error");
    // Error code in the sandbox range.
    assert!(err.code() >= 0x2000);
}
