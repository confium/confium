// Build script for the integration test that loads the macro-built
// mock plugin. Cargo doesn't expose `CARGO_CDYLIB_FILE_*` for runtime
// use in test binaries (only for build scripts), so we locate the
// artifact at build time and emit a `cfg`-driven path constant that the
// test reads via `env!`.
//
// The plugin crate is built by cargo before this crate's tests run
// (because it's a dependency). We compute the expected cdylib path
// from the target dir and platform file naming.

use std::env;
use std::path::PathBuf;

fn main() {
    // Re-run if the plugin source changes.
    println!("cargo:rerun-if-changed=../confium-mock-plugin/src");

    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            // Walk up from OUT_DIR (which is under target/...) to find
            // the target directory root.
            env::var_os("OUT_DIR").map(PathBuf::from)
        })
        .expect("CARGO_TARGET_DIR or OUT_DIR must be set");

    // OUT_DIR is `<target>/<profile>/<crate-hash>/out`; walk up three
    // levels to get to `<target>/<profile>`.
    let profile_dir = {
        let mut p = target_dir.clone();
        for _ in 0..3 {
            if !p.pop() {
                break;
            }
        }
        p
    };

    // Fallback: if OUT_DIR wasn't usable, default to target/debug.
    let profile_dir = if profile_dir.join("build").exists() {
        profile_dir
    } else {
        // CARGO_TARGET_DIR was used; pick debug profile by default.
        // The test runs in the dev profile so this is correct for
        // `cargo test`. For `cargo test --release`, set the env var.
        target_dir.join("debug")
    };

    let (prefix, suffix) = match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => ("lib", ".dylib"),
        Ok("windows") => ("", ".dll"),
        _ => ("lib", ".so"),
    };

    let filename = format!("{prefix}confium_mock_plugin{suffix}");
    let cdylib_path = profile_dir.join(filename);

    // Tell the test where to find the artifact. The path is an absolute
    // filesystem path.
    println!(
        "cargo:rustc-env=CONFIUM_MOCK_PLUGIN_PATH={}",
        cdylib_path.display()
    );
}
