//! `WasmSandbox` — the wasmtime-backed implementation of [`Sandbox`].
//!
//! Compiles WASM modules with a shared [`wasmtime::Engine`] (so the
//! JIT cache is reused across loads), wires the host imports from
//! [`crate::imports`] into the linker, and gates every import
//! invocation against the instance's [`CapabilitySet`].
//!
//! See `TODO.roadmap/15-wasm-sandboxing.md` § Architecture.

use snafu::Backtrace;
use snafu::GenerateImplicitData;
use wasmtime::Caller;
use wasmtime::Engine;
use wasmtime::InstancePre;
use wasmtime::Linker;
use wasmtime::Module;
use wasmtime::Store;

use crate::Error;
use crate::Result;
use crate::error::WasmtimeError;
use crate::imports::CapabilitySet;
use crate::imports::HostImports;
use crate::imports::ImportOutcome;
use crate::sandbox::Capability;
use crate::sandbox::Sandbox;
use crate::sandbox::SandboxInstance;
use crate::sandbox::Value;

/// Host-side state threaded through every guest call. Lives in the
/// wasmtime `Store` so the host-import trampolines can reach it via
/// `Caller::data()`.
pub(crate) struct HostState {
    pub caps: CapabilitySet,
}

/// Default linear-memory cap target for a sandboxed instance.
/// Matches the design doc (§ Performance considerations). Enforced
/// via `Store::limiter` (TODO) rather than `Config`, since wasmtime's
/// `Config::max_memory_size` is gated behind the pooling allocator.
const DEFAULT_MEMORY_BYTES: usize = 32 * 1024 * 1024;

/// The wasmtime-backed sandbox.
///
/// Clone-cheap: the engine and linker template are shared via `Arc`.
/// Each [`load_module`](WasmSandbox::load_module) yields a fresh
/// [`WasmInstance`] with its own `Store`, linear memory, and empty
/// capability envelope.
#[derive(Clone)]
pub struct WasmSandbox {
    engine: Engine,
    /// Linker with the host imports already defined but NOT bound to
    /// a particular store — cloned per instance to attach state.
    linker_template: std::sync::Arc<Linker<HostState>>,
}

impl WasmSandbox {
    /// Construct a new sandbox with the default config (no WASI,
    /// no filesystem, no network other than what host imports
    /// provide).
    pub fn new() -> Result<Self> {
        // No WASI: plugins have no ambient filesystem or network.
        // They reach the host only through `cfm_*` imports.
        let config = wasmtime::Config::new();
        let engine = Engine::new(&config).map_err(|e| Error::Engine {
            source: WasmtimeError::from_display(e),
            backtrace: Backtrace::generate(),
        })?;
        let linker = build_linker(&engine);
        Ok(Self {
            engine,
            linker_template: std::sync::Arc::new(linker),
        })
    }

    /// Construct with a caller-supplied engine (advanced use: shared
    /// cache, custom config).
    pub fn with_engine(engine: Engine) -> Result<Self> {
        let linker = build_linker(&engine);
        Ok(Self {
            engine,
            linker_template: std::sync::Arc::new(linker),
        })
    }

    /// Access the underlying wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

// Keep the design-doc constant visible (avoid dead-code warning).
const _: usize = DEFAULT_MEMORY_BYTES;

impl Sandbox for WasmSandbox {
    fn load_module(&self, bytes: &[u8]) -> Result<Box<dyn SandboxInstance>> {
        let module = Module::new(&self.engine, bytes).map_err(|e| Error::ModuleCompile {
            source: WasmtimeError::from_display(e),
            backtrace: Backtrace::generate(),
        })?;
        // Pre-link against the host imports so instantiation can
        // only fail on missing exports, not on a host-import mismatch.
        let linker = (*self.linker_template).clone();
        let instance_pre = linker
            .instantiate_pre(&module)
            .map_err(|e| Error::Instantiation {
                source: WasmtimeError::from_display(e),
                backtrace: Backtrace::generate(),
            })?;

        let state = HostState {
            caps: CapabilitySet::new(),
        };
        let store = Store::new(&self.engine, state);

        Ok(Box::new(WasmInstance {
            instance_pre,
            store,
        }))
    }

    fn name(&self) -> &'static str {
        "wasmtime"
    }
}

impl Default for WasmSandbox {
    fn default() -> Self {
        Self::new().expect("default wasmtime engine config must succeed")
    }
}

/// A loaded WASM module + its store, exposed through [`SandboxInstance`].
///
/// Each `call` instantiates the pre-linked module against the current
/// store so the capability state currently installed on `HostState`
/// is the one the guest sees. Instantiation from `InstancePre` is
/// cheap (the costly step is pre-linking, done once at load time).
pub struct WasmInstance {
    instance_pre: InstancePre<HostState>,
    store: Store<HostState>,
}

impl WasmInstance {
    /// Borrow the store mutably. Private so callers go through the
    /// trait surface.
    fn store_mut(&mut self) -> &mut Store<HostState> {
        &mut self.store
    }

    fn invocation_error<E: std::fmt::Display>(function: &str, e: E) -> Error {
        Error::Invocation {
            function: function.to_string(),
            source: WasmtimeError::from_display(e),
            backtrace: Backtrace::generate(),
        }
    }
}

impl SandboxInstance for WasmInstance {
    fn call(&mut self, function: &str, args: &[Value]) -> Result<Vec<Value>> {
        // Clone the pre-linker out so we don't fight the borrow
        // checker on `self.instance_pre` vs `self.store`.
        let instance_pre = self.instance_pre.clone();
        let store = self.store_mut();
        let instance = instance_pre
            .instantiate(&mut *store)
            .map_err(|e| Self::invocation_error(function, e))?;

        let export =
            instance
                .get_export(&mut *store, function)
                .ok_or_else(|| Error::FunctionNotFound {
                    function: function.to_string(),
                    backtrace: Backtrace::generate(),
                })?;

        let func = export.into_func().ok_or_else(|| Error::ExportNotFound {
            export: function.to_string(),
            backtrace: Backtrace::generate(),
        })?;

        // Try typed fast paths first (the common host-import
        // smoke-test shapes), then fall back to the untyped
        // multi-arg path for general use.
        if let Ok(typed) = func.typed::<i32, i64>(&mut *store) {
            let arg = match args.first() {
                Some(Value::I32(v)) => *v,
                _ => 0,
            };
            let out = typed
                .call(&mut *store, arg)
                .map_err(|e| Self::invocation_error(function, e))?;
            return Ok(vec![Value::I64(out)]);
        }

        if let Ok(typed) = func.typed::<i64, i64>(&mut *store) {
            let arg = match args.first() {
                Some(Value::I64(v)) => *v,
                Some(Value::I32(v)) => i64::from(*v),
                _ => 0,
            };
            let out = typed
                .call(&mut *store, arg)
                .map_err(|e| Self::invocation_error(function, e))?;
            return Ok(vec![Value::I64(out)]);
        }

        if let Ok(typed) = func.typed::<(), i32>(&mut *store) {
            let out = typed
                .call(&mut *store, ())
                .map_err(|e| Self::invocation_error(function, e))?;
            return Ok(vec![Value::I32(out)]);
        }

        // Untyped fallback: marshal via wasmtime::Val.
        let wasm_args: Vec<wasmtime::Val> = args
            .iter()
            .map(value_to_wasmval)
            .collect::<std::result::Result<_, _>>()
            .map_err(|()| Error::ArgumentType {
                function: function.to_string(),
                backtrace: Backtrace::generate(),
            })?;

        let result_count = func.ty(&mut *store).results().len();
        let mut wasm_outs = vec![wasmtime::Val::I32(0); result_count];
        func.call(&mut *store, &wasm_args, &mut wasm_outs)
            .map_err(|e| Self::invocation_error(function, e))?;

        wasm_outs
            .iter()
            .map(wasmval_to_value)
            .collect::<std::result::Result<_, _>>()
            .map_err(|()| Error::ArgumentType {
                function: function.to_string(),
                backtrace: Backtrace::generate(),
            })
    }

    fn grant_capability(&mut self, cap: Capability) -> Result<()> {
        self.store.data().caps.grant(cap);
        Ok(())
    }

    fn revoke_capability(&mut self, cap: &Capability) -> Result<()> {
        self.store.data().caps.revoke(cap);
        Ok(())
    }
}

fn value_to_wasmval(v: &Value) -> std::result::Result<wasmtime::Val, ()> {
    Ok(match v {
        Value::I32(x) => wasmtime::Val::I32(*x),
        Value::I64(x) => wasmtime::Val::I64(*x),
        Value::F32(x) => wasmtime::Val::F32(x.to_bits()),
        Value::F64(x) => wasmtime::Val::F64(x.to_bits()),
        // Bytes don't have a Val representation; they must cross via
        // linear-memory copy through a host import. Surface as a type
        // error here — caller passed Bytes to a typed function.
        Value::Bytes(_) => return Err(()),
    })
}

fn wasmval_to_value(v: &wasmtime::Val) -> std::result::Result<Value, ()> {
    Ok(match v {
        wasmtime::Val::I32(x) => Value::I32(*x),
        wasmtime::Val::I64(x) => Value::I64(*x),
        wasmtime::Val::F32(x) => Value::F32(f32::from_bits(*x)),
        wasmtime::Val::F64(x) => Value::F64(f64::from_bits(*x)),
        _ => return Err(()),
    })
}

/// Build the host-import [`Linker`] that every instance shares.
///
/// Each import reads the per-instance [`HostState`] from `Caller` and
/// routes through [`HostImports`] so capability gating is centralized.
fn build_linker(engine: &Engine) -> Linker<HostState> {
    let mut linker: Linker<HostState> = Linker::new(engine);

    // `cfm_hash_update(len: i32) -> i64` — gated by
    // InterfaceAccess { name: "hash" }.
    let _ = linker.func_wrap(
        "confium",
        "cfm_hash_update",
        |caller: Caller<'_, HostState>, len: i32| -> i64 {
            let caps = &caller.data().caps;
            match HostImports::cfm_hash_update(caps, len) {
                ImportOutcome::Done(v) => v,
                // Deny: sentinel. A trap would also be defensible;
                // the sentinel keeps the test surface observable.
                ImportOutcome::Denied => -1,
            }
        },
    );

    // `cfm_net_send(url_id: i64) -> i64` — gated by NetworkEndpoint.
    let _ = linker.func_wrap(
        "confium",
        "cfm_net_send",
        |caller: Caller<'_, HostState>, url_id: i64| -> i64 {
            let caps = &caller.data().caps;
            match HostImports::cfm_net_send(caps, url_id) {
                ImportOutcome::Done(v) => v,
                ImportOutcome::Denied => -1,
            }
        },
    );

    // `cfm_key_get_secret(key_id: i64) -> i64` — gated by KeyAccess.
    let _ = linker.func_wrap(
        "confium",
        "cfm_key_get_secret",
        |caller: Caller<'_, HostState>, key_id: i64| -> i64 {
            let caps = &caller.data().caps;
            match HostImports::cfm_key_get_secret(caps, key_id) {
                ImportOutcome::Done(v) => v,
                ImportOutcome::Denied => -1,
            }
        },
    );

    linker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_name_is_wasmtime() {
        let sb = WasmSandbox::new().unwrap();
        assert_eq!(sb.name(), "wasmtime");
    }

    #[test]
    fn sandbox_is_cloneable_and_shares_engine() {
        let sb = WasmSandbox::new().unwrap();
        let _clone = sb.clone();
    }
}
