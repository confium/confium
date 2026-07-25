//! End-to-end integration tests for the out-of-process sandbox.
//!
//! Spawns the `cfm-echo-plugin` test binary (built via the `test-bin`
//! feature) and drives it through [`ProcessSandbox`], verifying:
//!
//! 1. `load_module` spawns the subprocess.
//! 2. `call("echo", ...)` round-trips values.
//! 3. `call("add", ...)` returns the sum.
//! 4. `call("ping", ...)` works with no args.
//! 5. Unknown methods surface as `Error::PluginError`.
//! 6. Granting / revoking capabilities is tracked (no host-side
//!    observable effect for an echo plugin, but exercises the API
//!    path and confirms idempotency).
//! 7. `name()` reports `"process"`.

use confium_sandbox_process::Capability;
use confium_sandbox_process::Error;
use confium_sandbox_process::ProcessSandbox;
use confium_sandbox_process::Sandbox;
use confium_sandbox_process::Value;

/// Path to the test echo plugin binary. Set by Cargo when the bin
/// target is built; `env!` panics at compile time if the variable is
/// unset, which is the desired behavior (the test cannot run without
/// the fixture binary).
fn echo_plugin_path() -> String {
    env!("CARGO_BIN_EXE_cfm-echo-plugin").to_string()
}

#[test]
fn sandbox_name_is_process() {
    let sb = ProcessSandbox::new();
    assert_eq!(sb.name(), "process");
}

#[test]
fn echo_round_trips_integer_args() {
    let sb = ProcessSandbox::new();
    let path = echo_plugin_path();
    let mut inst = sb.load_module(path.as_bytes()).expect("subprocess spawns");

    // Send I32 and I64. JSON does not preserve integer width, so the
    // echo plugin returns values that fit back into I32 when they are
    // small enough. Use a value that overflows i32 to keep I64.
    let out = inst
        .call("echo", &[Value::I32(7), Value::I64(5_000_000_000)])
        .expect("echo round-trips");
    assert_eq!(out, vec![Value::I32(7), Value::I64(5_000_000_000)]);
}

#[test]
fn add_returns_sum() {
    let sb = ProcessSandbox::new();
    let path = echo_plugin_path();
    let mut inst = sb.load_module(path.as_bytes()).expect("spawns");

    let out = inst
        .call("add", &[Value::I32(2), Value::I32(3)])
        .expect("add round-trips");
    assert_eq!(out, vec![Value::I32(5)]);
}

#[test]
fn ping_works_with_no_args() {
    let sb = ProcessSandbox::new();
    let path = echo_plugin_path();
    let mut inst = sb.load_module(path.as_bytes()).expect("spawns");

    let out = inst.call("ping", &[]).expect("ping round-trips");
    assert_eq!(out, vec![Value::I32(1)]);
}

#[test]
fn echo_round_trips_bytes() {
    let sb = ProcessSandbox::new();
    let path = echo_plugin_path();
    let mut inst = sb.load_module(path.as_bytes()).expect("spawns");

    let payload = vec![0u8, 1, 2, 127, 200, 255];
    let out = inst
        .call("echo", &[Value::Bytes(payload.clone())])
        .expect("echo round-trips");
    assert_eq!(out, vec![Value::Bytes(payload)]);
}

#[test]
fn unknown_method_surfaces_plugin_error() {
    let sb = ProcessSandbox::new();
    let path = echo_plugin_path();
    let mut inst = sb.load_module(path.as_bytes()).expect("spawns");

    let err = inst.call("nope", &[]).expect_err("must error");
    match err {
        Error::PluginError {
            method, message, ..
        } => {
            assert_eq!(method, "nope");
            assert!(message.contains("unknown method"), "got: {message}");
        }
        other => panic!("expected PluginError, got {:?}", other),
    }
}

#[test]
fn capability_grant_and_revoke_are_idempotent() {
    let sb = ProcessSandbox::new();
    let path = echo_plugin_path();
    let mut inst = sb.load_module(path.as_bytes()).expect("spawns");

    let cap = Capability::InterfaceAccess {
        name: "hash".into(),
    };
    // Double grant is a no-op.
    inst.grant_capability(cap.clone()).expect("grant 1");
    inst.grant_capability(cap.clone()).expect("grant 2");
    // Double revoke is a no-op.
    inst.revoke_capability(&cap).expect("revoke 1");
    inst.revoke_capability(&cap).expect("revoke 2");

    // The echo plugin still works regardless of capability state.
    let out = inst.call("ping", &[]).expect("ping works");
    assert_eq!(out, vec![Value::I32(1)]);
}

#[test]
fn multiple_calls_on_one_instance_are_independent() {
    let sb = ProcessSandbox::new();
    let path = echo_plugin_path();
    let mut inst = sb.load_module(path.as_bytes()).expect("spawns");

    let a = inst
        .call("add", &[Value::I32(10), Value::I32(20)])
        .expect("a");
    let b = inst
        .call("add", &[Value::I32(100), Value::I32(1)])
        .expect("b");
    assert_eq!(a, vec![Value::I32(30)]);
    assert_eq!(b, vec![Value::I32(101)]);
}

#[test]
fn load_module_with_bad_path_errors_cleanly() {
    let sb = ProcessSandbox::new();
    // Not a valid UTF-8 path (0xFF is invalid UTF-8 on its own).
    match sb.load_module(&[0xFF]) {
        Err(err) => assert_eq!(err.code(), 0x2100), // InvalidPath
        Ok(_) => panic!("expected load_module to fail on invalid UTF-8 path"),
    }
}

#[test]
fn load_module_with_missing_executable_errors_cleanly() {
    let sb = ProcessSandbox::new();
    match sb.load_module(b"/nonexistent/confium/plugin/does/not/exist") {
        Err(err) => assert_eq!(err.code(), 0x2101), // Spawn
        Ok(_) => panic!("expected load_module to fail on missing executable"),
    }
}
